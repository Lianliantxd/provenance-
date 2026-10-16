# C15-S 后验分析合同

这是 C15 成绩已暴露后的固定计划，不是运行前预注册。

```json
{
  "task_id": "DIAGCHAIN_C15S_FIVE_REFLECTION_SNAPSHOT_CLOSEOUT_V1",
  "frozen_utc": "2026-10-16T08:17:46.947560+00:00",
  "analysis_scope": "POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS",
  "exposed_results_before_plan": true,
  "not_preregistration": true,
  "main_units": [
    "C1_R1_ON",
    "C1_R2_ON",
    "C2_R2_ON",
    "C2_R3_ON",
    "C3_R3_ON"
  ],
  "primary_metric": "bestmatch_step_f1",
  "comparison_1": "PRE_REFLECTION_TO_POST_MODEL_RAW",
  "comparison_2": "PRE_REFLECTION_TO_FINAL_FROZEN",
  "postprocessing_check": "POST_MODEL_RAW_TO_FINAL_FROZEN",
  "source_map_sha256": "47fabd421ac606f2799fbe60acdca5ab6641f7221841267443950b364f402ee3",
  "environment_probe_sha256": "223f83c95281eb7487cba2f02adb1bf31d10230bd60c8b6f47c79963e7311c54",
  "environment_python_sha256": "e12637f6c187899280c7f3309c3ade31e80418a9d3fcefb46c347f78aced8b9d",
  "input_policy": "KNOWN_LENGTH_METADATA_REMOVED_V1",
  "new_model_call_limit": 0,
  "score_label": "C15S_POSTHOC_SNAPSHOT_DIAGNOSTIC",
  "numeric_tolerance": 1e-09,
  "ignore_for_semantic_equality": [
    "$.metadata"
  ],
  "no_metadata_inheritance": true,
  "official_metrics": [
    "n_pred_steps",
    "n_gold_steps",
    "bestmatch_matched_steps",
    "bestmatch_step_precision",
    "bestmatch_step_recall",
    "bestmatch_step_f1",
    "ceaf_step_f1",
    "ceaf_aligned_steps",
    "evidence_precision",
    "evidence_recall",
    "evidence_f1",
    "attack_clustering_bcubed_f1",
    "bestmatch_edge_f1",
    "causal_edge_f1_order_aligned",
    "bestmatch_pairwise_order_accuracy",
    "ceaf_pairwise_order_accuracy",
    "aligned_steps"
  ],
  "additional_counts": [
    "n_pred_edges",
    "bestmatch_order_pair_count",
    "ceaf_order_pair_count"
  ],
  "reference_definition": "Official evidence_precision/recall/f1 uses unique canonical step supporting_evidence only; edge citations audited separately, not silently included. Composite case_id+evidence_id keys.",
  "snapshot_schema": "Validate unmodified objects; if invalid do not fabricate. No normalization needed when already valid. Any later normalization must be explicit and versioned.",
  "POST_AUTHOR_ACCEPTED_policy": "Only saved intermediate object; event accepted by absence of discard is not a saved object. Mark SNAPSHOT_UNAVAILABLE if absent.",
  "source_commit": "SOURCE_COMMIT_UNVERIFIABLE_COPY",
  "original_C15": {
    "state": "C15_BATCH_CLOSED_WITH_FAILURES",
    "decision": "HETEROGENEOUS_OR_INCONCLUSIVE",
    "planned": 18,
    "frozen_native_outputs": 12,
    "failed_units": 6,
    "evaluated": 12,
    "model_cli_starts": 121,
    "original_failed_terminal_records_retained": 7,
    "same_original_attempt_completion_reconciled": 1
  },
  "selection_bias": "5 actual accepted reflections from successful ON paths in 3 development-exposed cases; not 5 independent scenarios, not counterfactual OFF",
  "inference": "Descriptive within-run changes only; no cross-case mean, p-value or causal effect; original HETEROGENEOUS_OR_INCONCLUSIVE unchanged",
  "POSTHOC_GOLD_ACCESS": "YES_ON_SERVER_AFTER_FREEZE"
}
```
