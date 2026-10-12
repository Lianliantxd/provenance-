# Model handoff status

Status: MODEL_ARM_PENDING_AUTHORIZED_CHANNEL.

The fixed T2 payloads are present at runner_inputs/case_A.json and runner_inputs/case_B.json. Their exact hashes, card-ID order, byte sizes and rough character/4 estimates are in bundle_sha256_manifest.json. The two payloads contain all 104 and 96 cards respectively, with no Gold-driven selection or truncation. Both payloads share the same task instruction and output schema.

No model call was made. A compliant execution requires a new session with no inherited research/Gold context and no shell, file, browser, repository, retrieval, or external plugin tools. No such channel was verified in this run. No new API cost, model probe, or weight download was authorized. When a compliant channel is authorized, send exactly one case payload with model_reconstruction_prompt.md, retain the exact request/response, record provider-returned model identity and usage, and freeze the prediction hash before evaluation. If model identity is unavailable, label it MODEL_ID_UNVERIFIED.

This is message-level handoff guidance, not an OS isolation claim. The project owner and trusted evaluator can access evaluator_only on the server.
