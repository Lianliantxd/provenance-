"""Append-only transition journal and phase-inclusive new-call budget."""
from __future__ import annotations
import datetime as dt
import time
from pathlib import Path
from safe_paths import SafetyError, atomic_create, sha, strict_json, safe_path

EDGES = {
    'REQUEST_CREATED': {'REQUEST_SENT', 'RESPONSE_RECEIVED', 'FAILED_AND_SEALED'},
    'REQUEST_SENT': {'RESPONSE_RECEIVED', 'REMOTE_COMPLETION_UNKNOWN', 'FAILED_AND_SEALED'},
    'REMOTE_COMPLETION_UNKNOWN': {'FAILED_AND_SEALED'},
    'RESPONSE_RECEIVED': {'RESPONSE_VALIDATED', 'REMOTE_COMPLETION_UNKNOWN', 'FAILED_AND_SEALED'},
    'RESPONSE_VALIDATED': {'SERVER_ACCEPTED', 'FAILED_AND_SEALED'},
    'SERVER_ACCEPTED': {'CONTROLLER_CONTINUED', 'PREDICTION_FROZEN', 'FAILED_AND_SEALED'},
    'CONTROLLER_CONTINUED': {'PREDICTION_FROZEN', 'FAILED_AND_SEALED'},
    'PREDICTION_FROZEN': {'OFFICIAL_EVALUATED', 'FAILED_AND_SEALED'},
    'OFFICIAL_EVALUATED': set(), 'FAILED_AND_SEALED': set(),
}


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class ExchangeState:
    def __init__(self, root: Path, request: dict) -> None:
        self.root, self.request = root, request
        self.state, self.events = None, []
        safe_path(root.parent, root.name)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.transition('REQUEST_CREATED', {'prompt_sha256': request['prompt_sha256']})

    def transition(self, state: str, detail: dict | None = None) -> dict:
        if self.state is not None and state not in EDGES.get(self.state, set()):
            raise SafetyError('INVALID_STATE_TRANSITION:' + str(self.state) + '->' + state)
        if self.state is None and state != 'REQUEST_CREATED':
            raise SafetyError('INVALID_INITIAL_STATE')
        entry = {'utc': utc(), 'state': state, 'run_id': self.request['run_id'],
                 'attempt_id': self.request['attempt_id'], 'case_id': self.request['case_id'],
                 'seq': self.request['seq'], 'phase': self.request['phase'],
                 'previous_event_sha256': self.events[-1]['sha256'] if self.events else None,
                 'detail': detail or {}}
        p = atomic_create(self.root, f'{len(self.events)+1:04d}_{state}.json', entry)
        self.events.append({'state': state, 'sha256': sha(p.read_bytes()), 'path': p.name})
        self.state = state
        return entry


class Budget:
    def __init__(self, root: Path, *, total_limit: int, per_case_limit: int, total_wall: float,
                 case_wall: float, worker_wait: float, synthetic: bool = False) -> None:
        if not (1 <= per_case_limit <= 23 and per_case_limit <= total_limit <= 46
                and 0 < total_wall <= 3600 and 0 < case_wall <= 1800 and 0 < worker_wait <= 360):
            raise SafetyError('BUDGET_EXCEEDS_C13R_PROPOSAL')
        self.root, self.total_limit, self.per_case_limit = root, total_limit, per_case_limit
        self.total_wall, self.case_wall, self.worker_wait = total_wall, case_wall, worker_wait
        self.synthetic = synthetic
        self.started = time.monotonic()
        self.case_starts, self.reservations = {}, []
        safe_path(root.parent, root.name)
        root.mkdir(mode=0o700, parents=True, exist_ok=False)

    def begin_case(self, case_id: str) -> None:
        if case_id in self.case_starts:
            raise SafetyError('CASE_ALREADY_STARTED_NEW_BUDGET_NOT_ALLOWED')
        self.case_starts[case_id] = time.monotonic()

    def wait_seconds(self, case_id: str) -> float:
        now = time.monotonic()
        remaining = min(self.worker_wait, self.total_wall - (now - self.started),
                        self.case_wall - (now - self.case_starts[case_id]))
        if remaining <= 0:
            raise SafetyError('WALL_TIME_BUDGET_EXHAUSTED')
        return remaining

    def reserve(self, q: dict) -> None:
        self.wait_seconds(q['case_id'])
        if any((e['attempt_id'], e['seq']) == (q['attempt_id'], q['seq']) for e in self.reservations):
            raise SafetyError('DUPLICATE_CLI_LAUNCH_FOR_REQUEST')
        if len(self.reservations) >= self.total_limit or sum(e['case_id'] == q['case_id'] for e in self.reservations) >= self.per_case_limit:
            raise SafetyError('NEW_CLI_BUDGET_EXHAUSTED')
        record = {k: q[k] for k in ['case_id', 'run_id', 'attempt_id', 'seq', 'phase', 'prompt_sha256']}
        record.update(utc=utc(), state='LAUNCH_RESERVED', synthetic=self.synthetic,
                      explanation='Reservation never auto-refunded after a launch ambiguity; actual starts tracked separately.')
        atomic_create(self.root, f'{len(self.reservations)+1:04d}_reservation.json', record)
        self.reservations.append(record)

