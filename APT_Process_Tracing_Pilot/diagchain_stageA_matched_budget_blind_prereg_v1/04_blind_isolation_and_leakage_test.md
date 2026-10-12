# Blind isolation and leakage test

## Status: BLOCKED_BLIND_ISOLATION
This desktop session can read the source repository, audit reports, GT and oracle paths. A separate folder or allowlist is not access control. The sandbox os.access write check on the approved audit root was false; the output directory was created via reviewed elevated write. That does not isolate a runner. No runner_workspace or evaluator_sealed directory was created and no access-denial test is claimed.

## Static input findings
Both primary candidate inputs match the package manifest. Their wrapper includes source/case identity, traceability, input_policy.hidden_targets and required_output schema. These are not the per-step Gold values but disclose case/annotation framing. Mordor additionally contains a Gold-support-card count in sampling metadata. The existing files combine event cards and non-event wrapper fields; passing the full JSON unchanged has not passed a minimal-input whitelist audit. Prior audit reports, GT/oracle files and frozen prediction remain readable in this same user context.
09_runner_allowlist.csv is an audit-side inventory only. Every entry says runner_read_allowed=FALSE because no restricted runner exists. Evaluator read access to GT is a future policy, not a proven OS boundary.

## Required transform before any pilot
Use anonymous case aliases. Preserve event-card bytes and IDs. Remove or replace source IDs, traceability, sampling fields that disclose annotation/support counts, and unneeded hidden-target metadata. Inspect incident_brief and technique_catalog for Gold-derived content; retain only if proven non-Gold. Keep necessary task and output schema. Apply the exact same transformation to all arms; record each field/path and before/after hashes in input_transform_delta.md and label MODIFIED_L2_PROTOCOL. Do not delete commands, URIs, alerts or timestamps merely because they resemble Gold.
No transform has been applied in this Stage A.

## Required enforcement test
Use an OS-enforced sandbox or separate runner principal with a read-only allowlisted mount and a distinct evaluator principal. From inside the runner, verify reads of repository, audit root, home, all GT/oracle/frozen results fail, and allowlisted inputs succeed. Save the policy and denial evidence. If any access is possible or unknown, stop. Prompt instructions and directory separation alone do not count.
No model, retrieval, evaluator, builder, network/API or attack execution occurred.
