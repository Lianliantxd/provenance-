# Controller and model identity audit

Static evidence: DiagChain repository commit 60e04064f9b3cf59505ee159379cf851956b8394, clean. Source hashes are in 00_stageA_manifest.json. Relevant files: prompts/chain_reconstruction_prompt.md; agentic_reconstruction.py; run_agentic_reconstruction.py; evidence_centric_rag.py; evaluate_chain_reconstruction.py.
Local agent/retrieval machinery exists, including configurable retrieval kernels, typed/basic action modes and memory options. This proves local code presence only. No independent artifact establishes that the earlier Codex session ran the complete paper Reflection/Memory/Typed Actions/ECRAG controller with the paper configuration. Prior local audit found no paper PDF; exact paper semantics are not independently verified.

Permitted names:
- Historical run: CODEX_ASSISTED_ECRAG_VARIANT, not strict official DiagChain controller reproduction.
- T1: FIXED_QUERY_4R vs ADAPTIVE_QUERY_4R, exploratory released-L2 retrieval-policy comparison.
- T2: DETERMINISTIC_PLANNER vs CODEX_ASSISTED_FIXED_EVIDENCE_RECONSTRUCTION, system-level contrast.
- T3: NOT_AVAILABLE / OFFICIAL_CONTROLLER_NOT_VERIFIED. Do not invent a ranking.

The frozen contract records requested UI label gpt-5.6-luna, but provider-returned served-model ID, immutable snapshot, backend/provider details, full decoding settings, actual token usage and cost are unverified. The freeze receipt hashes prediction and observations; it does not establish provider identity. The exact prompt/message transcript for the old run is not recoverable from the checked artifacts, so do not attribute the published prompt verbatim to every historical call.
Future run metadata must record provider-returned model ID/version, backend, decoding/thinking settings, calls, tokens, cost and full exact L4 request messages with hashes. Unavailable fields remain UNAVAILABLE, never inferred from UI nickname.
