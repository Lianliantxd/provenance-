# Stage A gate report

Audit time 2026-10-12 UTC. Repository commit 60e04064f9b3cf59505ee159379cf851956b8394; git status clean (## main...origin/main). Output directory: /Users/tianxd/Documents/DiagChain_Audits/20261012T051607Z_matched_budget_blind_prereg_v1.

| Gate | Result | Evidence/action |
|---|---|---|
| G0 SAFE_STORAGE | PASS | Local APFS /dev/disk3s5, no path symlink observed, not a Git worktree. Sandbox W access was false; reviewed elevated write made this requested audit directory only. No source/server write. |
| G1 INTEGRITY | PASS | Repo, package, prior audit outputs, two pilot cases' L2/docs/graph/GT/oracle and historical frozen contract/prediction/receipt/metrics/ledger hashes verified. No mismatch. |
| G2 BLIND_INPUT | UNKNOWN | No runner was staged. Static scan found wrapper fields disclosing case/annotation framing; transformation is specified but unapplied. |
| G3 ENFORCED_ISOLATION | UNKNOWN, BLOCKING | This session can access repo, audit and Gold. No OS denial test from a runner was possible. |
| G4 EXPERIMENT_FAIRNESS | UNKNOWN | T1/T2 distinct; 4×32 and 900-char/card cap verified. Total token/context/cost ceilings depend on future backend and are not established. |
| G5 MODEL_PROVENANCE | UNKNOWN | Future capture protocol defined; historical served-model ID, exact full prompt trace and cost are unverified. |
| G6 EVALUATOR_BOUNDARY | PASS | Official scores separated from diagnostics; no causality overclaim; units stratified; abstention preserved. |
| G7 STOP_DISCIPLINE | PASS | No inference, retrieval, evaluator, builder, network/API, attack execution or historical modification. |

Package has 1,657 entries. Ten prior audit outputs match prior manifest. Two primary candidates' input/docs/graph/GT/oracle each match package manifest. Historical prediction SHA-256 is bff078c3e4388b678b1644f0f69ffd0409f224be4c53d664d20e6209ab071305 and remains unchanged.

Primary status: BLOCKED_BLIND_ISOLATION. Stage A artifacts and preregistration are delivered; gates are not all passed. Stage B is NO-GO. Required before any run: enforce and test runner/evaluator separation; apply and hash transforms in that restricted environment; fix actual context/token/call/cost limits and full L4 capture; then obtain exact later GO_RUN. Estimated model/API cost: unknown. No model, retrieval, evaluator, builder, attack or network/API call ran.
