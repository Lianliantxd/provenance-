# Experiment matrix and budgets

Shared controls: freeze release-L2 input/docs/graph hashes, source commit, retrieval implementation, prompt/schema, transformations and output schema. Do not expose GT/oracle. Keep all event-card evidence; transform wrapper metadata consistently and label MODIFIED_L2_PROTOCOL.

## T1 retrieval-policy track
Arms FIXED_QUERY_4R vs ADAPTIVE_QUERY_4R. Freeze these four generic fixed queries in this order:
1. Identify observed initial access, external requests and exploitation-related activity.
2. Identify observed execution, commands, processes and changes to files or configuration.
3. Identify observed account, privilege, persistence, discovery and lateral-movement activity.
4. Identify observed collection, outbound communication and cleanup activity.
The fixed queries are generic, not derived from support IDs. Adaptive queries may use only prior L4-visible evidence and declared open questions.
Both arms use the same case, docs/graph/corpus hashes, retrieval code, four retrieval operations, Top-K 32 per operation, stable tie order (score then evidence ID), ID-based deduplication, same downstream reconstructor/schema and maximum 128 unique evidence IDs. Empty return consumes an operation. Stop early only after no new IDs in two consecutive rounds or budget exhaustion. No padding.
Current source code verifies a 900-character per-card observation cap (agentic_reconstruction.py and evidence_centric_rag.py). Upper bound is 128×900=115,200 card-body characters; this does not cap full prompts, history, memory, tools or tokens. The aggregate context/token cap and cost are UNKNOWN until a backend is selected and measured before inference. Adaptive planner calls count toward call/token/cost; if total resource parity cannot be measured, classify T1 exploratory and do not claim equal cost. L3 is returned evidence; L4 is exactly what is in each sent model request. Hash full requests.

## T2 fixed-evidence reasoning track
Compare deterministic existing planner with CODEX_ASSISTED_FIXED_EVIDENCE_RECONSTRUCTION. For each case use one Gold-independent canonical bundle containing every evidence card in original source order, unless a deterministic context-limit rule is frozen before inference. Freeze bundle bytes, ID order and hash. Same-case requests must have identical evidence hash, task text, schema and output ceiling. If measured context capacity cannot fit the bundle, stop and redesign before inference. The arms differ in control mechanism, so claim system-level difference only.

## T3 official controller
NOT_AVAILABLE: paper controller identity/configuration not proven. No execution or ranking.

## Logs and stops
Per run save hashes, query/rank/score, pre/post dedup counts, unique IDs, independent operation clusters, full L4 requests and hashes, provider model identity, calls/tokens/cost, latency, retries/errors/truncation/stop reason and prediction hash. Ledger alone is not L4 proof. Three independent sessions per arm/case only if cost and access permit; otherwise single-run exploratory and state cache/session reuse.
Any limit overrun is BUDGET_DEVIATION. Do not tune after Gold. Stage B cannot start until total-context/token/call ceilings and backend metadata collection are concretely frozen.
