# Stage B0-B4 gate report and decision — 20261012T085941Z

## Decision

Status: PARTIAL_CPU_BASELINE_BLOCKED.

B0 server safety, B1 dedicated project environment, and B2 two-case L2 transformation passed. The server input packages are real, complete and hash-frozen. S3 cannot run because no existing deterministic planner implementation was found in the frozen DiagChain release or available DiagChain pilot sources. A server-side file named process_structure_evaluation_v1/src/run_baselines.py exists, but inspection shows it selects paths over a separate frozen DARPA CDM candidate pool and does not consume these DiagChain L2 cards; it is not a compatible baseline. The model/API-oriented controller is not a safe substitute and no new heuristic was invented. No prediction exists, so the official evaluator was not run.

Model status: MODEL_ARM_PENDING_AUTHORIZED_CHANNEL. A fixed, tool-less model handoff prompt and payload manifest are prepared; no model inference occurred.

Replication status: STRICT_OFFICIAL_CONTROLLER_NOT_REPRODUCED. This is an exploratory published-L2 fixed-evidence pilot, not a strict reproduction of the paper's original LLM controller and not a complete APT intent reconstruction task.

## Gate results

| Gate | Status | Evidence |
|---|---|---|
| S0 SERVER_SAFE | PASS | User-owned, non-symlink, non-Git project root; host and resource check in 00_preflight_report.md. |
| S1 PER_PROJECT_VENV | PASS | Project-only .venv; sys.prefix != sys.base_prefix; system site packages disabled; package locations checked in 02_environment_isolation_check.json. |
| S2 INPUT_READY | PASS | 104/104 and 96/96 cards preserved in order and checked; MODIFIED_L2_PROTOCOL documented; runner input hashes in 04_case_input_manifest.json. |
| S3 CPU_BASELINE | BLOCKED | No existing deterministic planner found; both cases are explicitly NOT_RUN in 06_cpu_baseline_runs.csv. |
| S4 EVALUATION | NOT_RUN | No frozen prediction; 07_official_evaluation.csv records this. |
| S5 MESSAGE_BLIND | PENDING | Payload prepared, but no fresh no-tool/no-history model channel was verified. |
| S6 MODEL_ID_BUDGET | PENDING | No provider identity, token usage, or cost verified; no external call made. |

## Work and non-work

Completed: isolated project workspace and venv; exact source transfer; whitelist input transformation; evidence-card preservation checks; separate evaluator-only case map/Gold; leakage marker scan; fixed-bundle and model handoff materials.

Not run: deterministic CPU prediction, official evaluation, model inference, ECRAG/T1, attacks/PoCs, network retrieval, or any server-side install/download.

No system package, system Python, base Anaconda, other project environment, service, network configuration, frozen source tree, or original research directory was modified. The first system-Python venv bootstrap failed because ensurepip is unavailable; its incomplete files were preserved separately. The working venv uses the preinstalled Anaconda3 Python 3.12.4 as base and is otherwise isolated.

Next requirements: identify an already-existing safe deterministic planner or explicitly authorize a new baseline; separately authorize/establish a fresh no-tool model channel and any required paid API budget. Neither condition changes the completed B0-B2 artifacts.
