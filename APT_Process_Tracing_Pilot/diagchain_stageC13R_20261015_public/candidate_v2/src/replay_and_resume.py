"""Same logical run, new attempt namespace; never writes to an exited attempt."""
from __future__ import annotations
from pathlib import Path
from safe_paths import SafetyError, sha, strict_json
from strict_exchange_validator import make_response, validate_response


def verified_replay(q: dict, historical_q: dict, historical_response: dict,
                    regenerated_prompt: bytes, *, old_controller_alive: bool,
                    new_attempt_is_fresh: bool, synthetic: bool = False) -> dict:
    if old_controller_alive or not new_attempt_is_fresh:
        raise SafetyError('NEW_INDEPENDENT_ATTEMPT_REQUIRED')
    if q['attempt_id'] == historical_q.get('attempt_id'):
        raise SafetyError('EXITED_ATTEMPT_BACKFILL_REJECTED')
    for key in ['case_id', 'run_id', 'seq', 'phase', 'prompt_sha256']:
        if type(q[key]) is not type(historical_q[key]) or q[key] != historical_q[key]:
            raise SafetyError('REPLAY_BINDING_MISMATCH:' + key)
    if q['prompt_utf8'].encode() != regenerated_prompt or sha(regenerated_prompt) != historical_q['prompt_sha256']:
        raise SafetyError('REPLAY_REGENERATED_PROMPT_MISMATCH')
    old = dict(historical_response)
    # Original C13 used worker_exit_code and no attempt_id; normalization is explicit.
    old.setdefault('attempt_id', historical_q['attempt_id'])
    old.setdefault('case_id', historical_q['case_id'])
    old.setdefault('cli_exit_code', old.get('worker_exit_code'))
    if old.get('source') == 'REAL_CHATGPT_CODEX_CLI':
        old['source'] = 'REAL_CHATGPT_CODEX_CLI'
    validate_response(historical_q, old, synthetic=synthetic)
    raw = old['raw_reply_utf8']
    res = make_response(q, raw, source='VERIFIED_REPLAY', parser_receipt={
        'cli_exit_code': old['cli_exit_code'], 'tool_verdict': old['tool_verdict'],
        'usage': {}, 'historical_usage_not_new_consumption': old.get('usage', {})})
    res['replay_provenance'] = {'status': 'VERIFIED_REPLAY', 'historical_attempt_id': historical_q['attempt_id'],
                              'historical_response_envelope_sha256': sha(__import__('json').dumps(historical_response, ensure_ascii=False, sort_keys=True)),
                              'historical_reply_sha256': old['reply_sha256'], 'new_cli_invocations': 0,
                              'regenerated_prompt_exact_bytes': True}
    return res


def historical_pair(root: Path, seq: int) -> tuple[dict, dict] | None:
    qp = root / f'exchange/REQUEST_{seq:04d}.json'
    rp = root / f'exchange/RESPONSE_{seq:04d}.json'
    if not qp.is_file() or not rp.is_file():
        return None
    if qp.is_symlink() or rp.is_symlink():
        raise SafetyError('HISTORICAL_SYMLINK')
    q, response = strict_json(qp.read_text()), strict_json(rp.read_text())
    q.setdefault('attempt_id', q['run_id'])
    q.setdefault('controller_turn', q.pop('turn', 1))
    return q, response


def reject_unknown_resend(q: dict, unknown_history: list[dict], authorization: dict) -> None:
    matches = [old for old in unknown_history if all(old.get(k) == q.get(k)
               for k in ['case_id', 'run_id', 'seq', 'phase', 'prompt_sha256'])]
    if matches:
        authorized = authorization.get('explicit_unknown_completion_reissue', [])
        if not any(all(item.get(k) == q.get(k) for k in ['case_id', 'run_id', 'seq', 'phase', 'prompt_sha256'])
                   and item.get('approved') is True for item in authorized):
            raise SafetyError('REMOTE_COMPLETION_UNKNOWN_NO_AUTOMATIC_RESEND')

