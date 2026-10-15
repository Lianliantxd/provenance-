"""Pinned subscription client; no TLS, proxy, provider or auth-file manipulation."""
from __future__ import annotations
import json
import os
from pathlib import Path
from safe_paths import SafetyError, sha

GATES = ('SAFETY_INTEGRITY_PASS', 'SYNTHETIC_BRIDGE_PASS', 'MODEL_AUTH_CONFIRMED',
         'SUBSCRIPTION_SPEND_CONFIRMED', 'CLOUD_DATA_SCOPE_AUTHORIZED',
         'NEW_RETRY_CALL_BUDGET_AUTHORIZED', 'TLS_VERIFICATION_INTACT', 'OPERATOR_MODE_AUTHORIZED')


def require_authorization(gate: dict) -> dict:
    if any(gate.get(k) is not True for k in GATES):
        raise SafetyError('C13R_OFFLINE_REPAIR_READY_AWAIT_AUTHORIZATION')
    if gate.get('model') != 'gpt-6-luna' or gate.get('auth_mode') != 'SIGN_IN_WITH_CHATGPT':
        raise SafetyError('MODEL_AUTH_OUTSIDE_CONTRACT')
    if gate.get('paid_credits_allowed') is not False or gate.get('auto_recharge_confirmed_off') is not True:
        raise SafetyError('SPEND_GUARD_NOT_CONFIRMED')
    mode = gate.get('operator_mode')
    if mode not in {'direct_current_codex_session', 'independent_terminal'}:
        raise SafetyError('OPERATOR_MODE_NOT_EXPLICITLY_AUTHORIZED')
    if mode == 'independent_terminal' and any(k.startswith('CODEX_') and any(t in k for t in ('SESSION', 'THREAD', 'SANDBOX')) for k in os.environ):
        raise SafetyError('INDEPENDENT_TERMINAL_REQUIRED_DO_NOT_ERASE_MARKERS')
    return gate


def clean_environment() -> dict:
    allowed = ('PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'LANG', 'LC_ALL', 'TERM')
    kept = {k: os.environ[k] for k in allowed if k in os.environ}
    # Preserve host identity markers; never disguise a nested launch as a terminal.
    for k, value in os.environ.items():
        if k.startswith('CODEX_') and any(t in k for t in ('SESSION', 'THREAD', 'SANDBOX')) and not any(t in k for t in ('KEY', 'TOKEN', 'SECRET', 'AUTH')):
            kept[k] = value
    return kept


def worker_argv(client: str, expected_sha256: str, worker: Path, output: Path) -> list[str]:
    if sha(Path(client).read_bytes()) != expected_sha256:
        raise SafetyError('PINNED_CLIENT_BINARY_CHANGED')
    if list(worker.iterdir()):
        raise SafetyError('WORKER_DIRECTORY_NOT_EMPTY')
    argv = [client, 'exec', '--model', 'gpt-6-luna', '--skip-git-repo-check', '--ephemeral',
            '--ignore-user-config', '--strict-config', '--json', '--color', 'never', '--output-last-message', str(output)]
    disabled = ('shell_tool', 'shell_snapshot', 'apps', 'plugins', 'remote_plugin', 'hooks', 'multi_agent',
                'multi_agent_v2', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access',
                'computer_use', 'in_app_browser', 'image_generation', 'view_image', 'skill_search',
                'skill_mcp_dependency_install', 'code_mode_host', 'workspace_dependencies', 'fast_mode',
                'memories', 'goals', 'standalone_web_search', 'daemon_auto_start', 'unbounded_connection_retries',
                'system_proxy_fallback', 'realtime_conversation', 'step_model_switching')
    for feature in disabled:
        argv += ['--disable', feature]
    argv += ['--enable', 'skip_host_skill_discovery']
    fs = {':root': 'deny', ':minimal': 'read', str(worker): 'read', '/opt/homebrew': 'read'}
    profile = 'permissions.c13r_worker={ extends = ":read-only", filesystem = { ' + ', '.join(
        json.dumps(k) + ' = ' + json.dumps(v) for k, v in fs.items()) + ' }, network = { enabled = false } }'
    for config in [profile, 'default_permissions="c13r_worker"', 'model_provider="openai"',
                   'forced_login_method="chatgpt"', 'web_search="disabled"', 'project_doc_max_bytes=0',
                   'approval_policy="never"', 'history.persistence="none"',
                   'projects.' + json.dumps(str(worker)) + '.trust_level="untrusted"']:
        argv += ['--config', config]
    return argv + ['-']

