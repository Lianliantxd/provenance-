"""Exact byte/identity binding. Author JSON repair receives unmodified raw text."""
from __future__ import annotations
import re
from safe_paths import SafetyError, sha

PHASES = {'controller', 'reflection', 'repair', 'synthesis'}
CASES = {'excytin-incident-34.alert-evidence', 'mordor-apt29-day1.L-noisy'}


def phase_of(prompt: str) -> str:
    for phase, prefix in [('controller', 'You are operating in AGENTIC attack-chain reconstruction mode.'),
                          ('repair', 'The previous controller response was not valid JSON'),
                          ('reflection', 'You are doing the reflection step'),
                          ('synthesis', 'You are finalizing an AGENTIC attack-chain reconstruction run')]:
        if prompt.startswith(prefix):
            return phase
    raise SafetyError('UNKNOWN_AUTHOR_PHASE')


def validate_request(q: dict, *, synthetic: bool = False) -> None:
    for key in ['run_id', 'attempt_id', 'case_id', 'prompt_sha256']:
        if not isinstance(q.get(key), str) or not q[key]:
            raise SafetyError('MISSING_REQUEST_IDENTITY')
    if not synthetic and q['case_id'] not in CASES:
        raise SafetyError('CASE_NOT_AUTHORIZED')
    if type(q.get('seq')) is not int or q['seq'] < 1 or q.get('phase') not in PHASES:
        raise SafetyError('INVALID_SEQUENCE_OR_PHASE')
    if type(q.get('controller_turn')) is not int or not 1 <= q['controller_turn'] <= 15:
        raise SafetyError('INVALID_CONTROLLER_TURN')
    prompt = q.get('prompt_utf8')
    if not isinstance(prompt, str) or len(prompt.encode()) > 2097152 or sha(prompt) != q['prompt_sha256']:
        raise SafetyError('PROMPT_BYTES_OR_SHA_MISMATCH')
    if not synthetic and phase_of(prompt) != q['phase']:
        raise SafetyError('NATIVE_PHASE_MISMATCH')
    forbidden = ('/Users/tianxd/', '/home/tianxiaodan/code/', '-----BEGIN PRIVATE KEY-----',
                 '-----BEGIN OPENSSH PRIVATE KEY-----', '-----BEGIN RSA PRIVATE KEY-----')
    if any(s in prompt for s in forbidden) or re.search(r'\b(?:sk-proj-|sk-ant-|ghp_)[A-Za-z0-9_-]{20,}', prompt):
        raise SafetyError('UNRELATED_PATH_OR_CREDENTIAL_MARKER')


def validate_response(q: dict, response: dict, *, synthetic: bool = False) -> str:
    validate_request(q, synthetic=synthetic)
    for key in ['run_id', 'attempt_id', 'case_id', 'seq', 'phase', 'prompt_sha256']:
        if type(response.get(key)) is not type(q[key]) or response.get(key) != q[key]:
            raise SafetyError('RESPONSE_BINDING_MISMATCH:' + key)
    raw = response.get('raw_reply_utf8')
    if not isinstance(raw, str) or not raw or len(raw.encode()) > 1048576 or sha(raw) != response.get('reply_sha256'):
        raise SafetyError('REPLY_BYTES_OR_SHA_MISMATCH')
    if response.get('model_requested') != 'gpt-6-luna' or response.get('tool_verdict') != 'NO_TOOL_CALL_OBSERVED':
        raise SafetyError('MODEL_OR_TOOL_GUARD_FAILED')
    if type(response.get('cli_exit_code')) is not int or response['cli_exit_code'] != 0:
        raise SafetyError('CLI_EXIT_NOT_CONFIRMED_ZERO')
    allowed = {'REAL_CHATGPT_CODEX_CLI', 'VERIFIED_REPLAY'} | ({'FAKE_WORKER'} if synthetic else set())
    if response.get('source') not in allowed:
        raise SafetyError('UNAUTHORIZED_RESPONSE_SOURCE')
    return raw


def make_response(q: dict, raw: str, *, source: str, parser_receipt: dict) -> dict:
    return {**{k: q[k] for k in ['run_id', 'attempt_id', 'case_id', 'seq', 'phase', 'prompt_sha256']},
            'raw_reply_utf8': raw, 'reply_sha256': sha(raw), 'source': source,
            'model_requested': 'gpt-6-luna', 'model_snapshot': 'UNVERIFIED',
            'cli_exit_code': parser_receipt['cli_exit_code'],
            'tool_verdict': parser_receipt['tool_verdict'], 'usage': parser_receipt.get('usage', {}),
            'parser_receipt': parser_receipt}

