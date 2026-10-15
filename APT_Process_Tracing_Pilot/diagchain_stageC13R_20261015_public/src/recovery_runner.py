"""Fail-closed CLI transport. Default entry point only checks the approval gate."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
from bridge_state_machine import ExchangeState, Budget, utc
from codex_worker_config import clean_environment, require_authorization, worker_argv
from jsonl_final_message_parser import JsonlParser, ParseFailure
from replay_and_resume import reject_unknown_resend
from safe_paths import SafetyError, atomic_create, safe_path, sha, strict_json
from strict_exchange_validator import make_response, validate_request, validate_response

ROOT = Path(__file__).resolve().parents[1]


def terminate_owned(process: subprocess.Popen) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def capture_process(argv: list[str], q: dict, root: Path, cwd: Path, timeout: float,
                    state: ExchangeState, *, synthetic: bool) -> tuple[bytes, dict]:
    """Only called after real authorization or with the explicitly checked Fake Worker."""
    output = atomic_create(root, 'final_reply_utf8.txt', b'')
    # output is already selected by worker_argv. Fake Worker receives this exact same path.
    if str(output) not in argv:
        raise SafetyError('CANONICAL_OUTPUT_PATH_NOT_BOUND')
    streams = {}
    for kind in ['stdout', 'stderr']:
        p = safe_path(root, kind + '.raw')
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        streams[kind] = os.fdopen(fd, 'wb')
    parser, events = JsonlParser(), queue.Queue(maxsize=256)
    before = time.monotonic()
    process = None
    failure = None
    try:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       cwd=cwd, env=clean_environment(), shell=False, start_new_session=True)
        except OSError:
            state.transition('FAILED_AND_SEALED', {'failure_class': 'PRE_SEND_PROCESS_CREATION_FAILURE',
                                                  'actual_cli_start': False})
            raise
        atomic_create(root, 'cli_start_receipt.json', {'utc': utc(), 'pid': process.pid,
                      'synthetic': synthetic, 'new_real_cli_start': not synthetic,
                      'prompt_sha256': q['prompt_sha256'], 'argv': argv,
                      'parent_codex_marker_names': sorted(k for k in os.environ if k.startswith('CODEX_')),
                      'parent_marker_values_recorded_or_erased': False})
        state.transition('REQUEST_SENT', {'pid': process.pid, 'network_send_instant': 'NOT_IDENTIFIABLE'})
        def pump(name, pipe):
            try:
                while True:
                    chunk = os.read(pipe.fileno(), 4096)
                    if not chunk:
                        break
                    events.put((name, chunk))
            finally:
                events.put((name, None))
        def send_input():
            try:
                process.stdin.write(q['prompt_utf8'].encode('utf-8'))
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass  # Never infer that the remote did not receive anything.
        threads = [threading.Thread(target=pump, args=(name, pipe), daemon=True)
                   for name, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]]
        threads.append(threading.Thread(target=send_input, daemon=True))
        for thread in threads:
            thread.start()
        eof, sizes = set(), {'stdout': 0, 'stderr': 0}
        killed_at = None
        while len(eof) < 2 or process.poll() is None:
            elapsed = time.monotonic() - before
            if failure is None and elapsed >= timeout:
                failure = 'CLI_PROCESS_TIMEOUT'
                terminate_owned(process)
                killed_at = time.monotonic()
            if killed_at is not None and time.monotonic() - killed_at > 5:
                break
            try:
                name, chunk = events.get(timeout=0.02)
            except queue.Empty:
                continue
            if chunk is None:
                eof.add(name)
                continue
            sizes[name] += len(chunk)
            streams[name].write(chunk)
            streams[name].flush()
            if failure is None:
                if sizes[name] > (8388608 if name == 'stdout' else 1048576):
                    failure = 'OUTPUT_BYTE_BUDGET'
                elif name == 'stdout':
                    try:
                        parser.feed(chunk)
                    except ParseFailure as exc:
                        failure = exc.code
                if failure:
                    terminate_owned(process)
                    killed_at = time.monotonic()
        process.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=1)
        raw = output.read_bytes()
        exit_code = process.returncode
        atomic_create(root, 'cli_exit_receipt.json', {'utc': utc(), 'cli_exit_code': exit_code,
                      'elapsed_seconds': time.monotonic() - before, 'failure_class': failure,
                      'final_reply_bytes': len(raw), 'final_reply_sha256': sha(raw),
                      'synthetic': synthetic, 'internal_model_request_count': 'NOT_IDENTIFIABLE'})
        if failure:
            state.transition('REMOTE_COMPLETION_UNKNOWN', {'failure_class': failure, 'new_send_permitted': False})
            state.transition('FAILED_AND_SEALED', {'failure_class': failure})
            raise SafetyError(failure)
        state.transition('RESPONSE_RECEIVED', {'reply_sha256': sha(raw), 'bytes': len(raw)})
        try:
            receipt = parser.finish(raw, exit_code)
        except ParseFailure as exc:
            state.transition('REMOTE_COMPLETION_UNKNOWN', {'failure_class': exc.code, 'new_send_permitted': False})
            state.transition('FAILED_AND_SEALED', {'failure_class': exc.code})
            raise
        atomic_create(root, 'parser_receipt.json', receipt)
        state.transition('RESPONSE_VALIDATED', {'reply_sha256': receipt['reply_sha256'],
                                              'author_json_status': receipt['author_json_status']})
        return raw, receipt
    finally:
        if process is not None:
            terminate_owned(process)
        if process is not None:
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
        for stream in streams.values():
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()


def run_new_exchange(q: dict, root: Path, worker: Path, state: ExchangeState, budget: Budget,
                     gate: dict, client: dict, unknown_history: list[dict]) -> dict:
    require_authorization(gate)
    validate_request(q)
    reject_unknown_resend(q, unknown_history, gate)
    budget.reserve(q)
    atomic_create(root, 'request.json', q)
    argv = worker_argv(client['path'], client['sha256'], worker, root / 'final_reply_utf8.txt')
    raw, receipt = capture_process(argv, q, root, worker, budget.wait_seconds(q['case_id']), state, synthetic=False)
    if list(worker.iterdir()):
        raise SafetyError('WORKER_DIRECTORY_CHANGED')
    response = make_response(q, raw.decode('utf-8'), source='REAL_CHATGPT_CODEX_CLI', parser_receipt=receipt)
    validate_response(q, response)
    atomic_create(root, 'response.json', response)
    return response


def run_fake_exchange(q: dict, root: Path, worker: Path, state: ExchangeState, budget: Budget,
                      fake_script: Path, fixture: Path) -> dict:
    if q.get('data_class') != 'SYNTHETIC_ONLY' or not q['case_id'].startswith('SYNTHETIC_'):
        raise SafetyError('FAKE_WORKER_REJECTS_REAL_CASE')
    validate_request(q, synthetic=True)
    budget.reserve(q)
    import sys
    argv = [sys.executable, '-B', str(fake_script), str(fixture), str(root / 'final_reply_utf8.txt')]
    raw, receipt = capture_process(argv, q, root, worker, budget.wait_seconds(q['case_id']), state, synthetic=True)
    response = make_response(q, raw.decode('utf-8'), source='FAKE_WORKER', parser_receipt=receipt)
    validate_response(q, response, synthetic=True)
    atomic_create(root, 'fake_response.json', response)
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--authorization-file', default='12_authorization_gate.json')
    parser.add_argument('--check-gates', action='store_true')
    parser.add_argument('--run-authorized-two-cases', action='store_true')
    args = parser.parse_args()
    if not args.authorization_file.startswith('12_authorization_gate') or not args.authorization_file.endswith('.json') or Path(args.authorization_file).name != args.authorization_file:
        raise SafetyError('AUTHORIZATION_FILE_SCOPE')
    gate = strict_json(safe_path(ROOT, args.authorization_file).read_text())
    require_authorization(gate)  # Checked before SSH, CLI, real evidence or budget creation.
    if args.check_gates:
        print(json.dumps({'state': 'ALL_AUTHORIZATION_GATES_PASS', 'real_cli_calls': 0}))
    elif args.run_authorized_two_cases:
        from native_recovery_orchestrator import run_two_cases
        run_two_cases(ROOT, gate)
    else:
        parser.error('select --check-gates or --run-authorized-two-cases')


if __name__ == '__main__':
    try:
        main()
    except SafetyError as exc:
        print(json.dumps({'state': str(exc), 'new_real_calls_started_by_this_gate_failure': 0}))
        raise SystemExit(3)
