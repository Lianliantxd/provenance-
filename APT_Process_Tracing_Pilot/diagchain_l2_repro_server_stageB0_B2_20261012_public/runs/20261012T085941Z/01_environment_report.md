# Environment report - 20261012T085941Z

- Host/user: [private-server] / [redacted-user].
- Project root: [private-project-workspace]/APT_Process_Tracing_Pilot/diagchain_l2_repro (new child in user's provenance workspace; not a Git worktree).
- Dedicated environment: [private-project-workspace]/APT_Process_Tracing_Pilot/diagchain_l2_repro/.venv.
- Python: [private-project-workspace]/APT_Process_Tracing_Pilot/diagchain_l2_repro/.venv/bin/python (3.12.4); sys.prefix differs from sys.base_prefix ([preinstalled-python-base]).
- include-system-site-packages = false; every installed distribution is inside this project's .venv.
- pip freeze is empty. No project dependencies were installed; current preparation uses the Python standard library. SciPy is optional and absent.
- System /usr/bin/python3 3.12.3 could not bootstrap venv because ensurepip is absent. No system package was installed. Its incomplete output was preserved at [private-project-workspace]/APT_Process_Tracing_Pilot/diagchain_l2_repro/.venv.failed-system-python3.12-bootstrap; the functional .venv was created from preinstalled [preinstalled-python-base]/bin/python3 3.12.4 without changing that base interpreter.

No system/base interpreter, other project environment, or service was modified.
