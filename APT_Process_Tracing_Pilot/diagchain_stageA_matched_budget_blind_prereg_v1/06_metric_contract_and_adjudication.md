# Metric contract and adjudication

Keep the official evaluator unchanged and preserve its source names, values and output. Static source review only; this audit did not execute it. Source paths below are relative to attack_chain_generation/chain_reconstruction_benchmark.

## Official score fields and calculation contracts

- valid_json and schema_valid are 0/1 format checks, not chain correctness (evaluate_chain_reconstruction.py lines 314–345, 1392–1400).
- input_gold_step_coverage and retrieved_step_coverage: numerator is the count of Gold steps with at least one support evidence ID in the input/selected-ID set; denominator is Gold steps with nonempty support IDs. Empty selected IDs yield null for retrieved coverage. The scorecard field retrieval_step_coverage selects retrieved_step_coverage when available, else input_gold_step_coverage (lines 1023–1049, 1116–1127). It does not prove full L4 visibility or correct per-step attribution.
- attack_clustering_bcubed_precision/recall: for each evidence ID in the attack universe, intersection size of predicted and Gold cluster divided respectively by predicted-cluster size and Gold-cluster size; average item precision/recall, then harmonic F1 (cluster_metrics.py lines 61–77; evaluator selects attack-universe labels around lines 986–1015). Denominator depends on the annotated evidence universe; near-duplicates, cross-step reuse and granularity matter.
- CEAF alignment: first make non-overlapping per-step evidence clusters; repeated refs after first use are counted as duplicate refs and excluded from later clusters. Similarity is evidence-ID intersection size. Find maximum-overlap one-to-one predicted/Gold cluster assignment with no positive-score threshold (evaluate_chain_reconstruction.py lines 725–758, 819–860). CEAF precision is total matched overlap / total predicted cluster evidence mentions; recall divides by total Gold cluster evidence mentions; F1 is harmonic (lines 889–894). Report its denominators, clusters and duplicate-ref counts.
- ceaf_step_precision/recall divide number of aligned matches by predicted steps and Gold steps (lines 896–898). The surfaced grounding_step_evidence_precision/recall/F1 are the average per-match evidence-ID set metrics among aligned matches (lines 928–930; scorecard mapping lines 1133–1136). These are not human-verified correct citations.
- ceaf_pairwise_order_accuracy, surfaced as ordering_pairwise_accuracy: number of correctly ordered pairs among aligned matches / all pairs of aligned matches (n choose 2); when fewer than two matches, code returns 1 for one match and 0 for none (lines 597–609, 923). Always report pair count and matched-step coverage; 1.0 may reflect only one pair.
- causal_edge_f1_order_aligned and best-match edge scores: edges are reduced to source/target step-position pairs; relation name and edge supporting-evidence list are not part of edge_positions comparison (lines 383–391). Precision/recall/F1 are set overlap after step alignment (lines 1320–1340, 1415–1454). Audited references are temporal_after; this topology score does not validate physical/software causality.
- Cited-ID union, such as 5/12, is not per-step correct citation. B-cubed and CEAF are cluster/alignment measures; an evidence ID need not equal an independent action.
- ATT&CK exact label fields do not alone reward a justified unknown; retain abstention diagnostics.

## AUDIT_DIAGNOSTIC_NOT_OFFICIAL

1. L3 returned IDs, L4 actually visible IDs and final cited IDs separately; show per-round truncation/loss.
2. Unique IDs, independently adjudicated operation-cluster coverage, repeated rate and marginal new-ID yield. Gold-support coverage only after freeze by sealed evaluator.
3. Per-Gold-step attribution, missed action, overmerge/oversplit and L2 observability.
4. Claim tier DIRECTLY_OBSERVED / SUPPORTED_INFERENCE / UNVERIFIED / CONTRADICTED / ABSTAINED; measure unsupported mechanism assertions.
5. Temporal sequence and causal relation reviewed separately. No causal F1 absent independent causal labels.
6. Freeze ATT&CK version and send suspected mapping issues to review without silently changing official Gold.

## Evaluation order

Freeze prediction bytes and SHA-256 before evaluator receives case mapping/Gold. Score only that hash. Keep official evaluator output unchanged; place diagnostics in separate files. Subjective diagnostics require two independent reviewers and adjudication; otherwise PENDING_REVIEW. Keep action-unit, alert-node and event-level strata separate. Without L0, scope conclusions to RELEASED_L2_OBSERVABILITY_SCOPE.
