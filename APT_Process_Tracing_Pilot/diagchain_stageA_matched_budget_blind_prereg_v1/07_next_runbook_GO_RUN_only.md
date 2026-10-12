# Stage B runbook — later GO_RUN only

This is a manual, not authorization. Stage B is NO-GO until the exact later researcher instruction GO_RUN and all gates below.

## Preflight
1. Establish a fresh runner identity/session. Give it only read-only allowlisted inputs, reviewed prompt/schema and minimal retrieval code. It must not inherit this chat, audit root, source repository, home tree, Gold, oracle outputs or historical predictions.
2. Prove OS-level deny access inside the runner to every blocked path; prove allowlisted reads succeed. Save policy/transcript. Any success or unknown denial means STOP BLOCKED_BLIND_ISOLATION.
3. Apply anonymization/wrapper transform; record input_transform_delta.md, transformed hashes and content scan. Preserve event cards. If any transform depends on Gold or changes event facts, stop.
4. Freeze T1 query templates and T1/T2 settings. Determine backend model ID capture, actual message/token/context limits, calls and cost accounting before any benchmark input. If unknown, strict model/cost comparison is NO-GO.
5. Verify case/index/source hashes. T2 bundle byte/order hashes must match across arms. Disable source-tree imports, arbitrary shell/file access and network unless separately authorized.

## Run
For each case/arm use a fresh session. Persist a pre-run manifest; no more than four retrieval operations, Top-K 32, 900 characters/card and 128 unique IDs. Count adaptive planning calls. Hash complete L4 messages, not just ledgers. T2 uses the exact frozen bundle. Stop for budget overrun, model identity mismatch, unexpected tool/network activity, or isolation failure. No selective rerun after Gold inspection.
Freeze prediction atomically without overwrite and record SHA-256 before evaluation. Schema validation may precede scoring but do not expose GT. Evaluator verifies prediction hash, then scores; keep official evaluator output unchanged and diagnostics separate. Dual human review only when actual independent reviewers are available.
Report hashes, model/backend provenance, cost/calls/tokens, L3/L4, deviations and per-stratum results. No significance or superiority claim from these pilot cases. If any prerequisite is unknown, remain NO-GO.
