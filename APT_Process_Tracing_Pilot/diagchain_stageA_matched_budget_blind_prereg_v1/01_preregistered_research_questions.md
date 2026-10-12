# Stage A preregistration — frozen before Stage B

Version: matched-budget-blind-prereg-v1. Frozen 2026-10-12 UTC before any Stage B inference. This is an exploratory pilot protocol, not a confirmatory test. All five cases have been inspected by a prior auditor; a fresh runner may reduce direct file leakage but cannot restore an untouched test set.

## Questions and hypotheses
RQ1 / T1 asks whether fixed four-query and adaptive four-round retrieval return different evidence, unique IDs, repeats and independently reviewed action clusters under identical L2, corpus, tool, query-operation cap, Top-K and visible-evidence ceilings. Directional hypothesis only: adaptive queries may find more distinct useful evidence; no result is asserted.
RQ2 / T2 compares the existing deterministic planner and a controlled Codex-assisted reconstructor on byte-identical ordered evidence. This is a system-level difference, not a pure model-weight effect.
RQ3 separates direct observations, supported inference, unverified mechanisms, outcomes, temporal order, causal relations and ATT&CK mapping. Logs may not identify author-level intent or physical causality.

## Units and outcomes
Solr CVE-2017-12629-RCE is DISCOVERY and excluded from new pilot means. The two distinct AutoLabel CVEs are PILOT_ACTION_UNIT, reported case by case; n=2 does not support population effects. ExCyTIn alert-node and Mordor event-level cases are separate exploratory strata, never pooled with action-unit absolute scores. Independent sample means source incident/execution; alternate noise profiles are not independent.
Primary descriptive outcomes retain official metric names. T1 reports L3 returned and L4 actually visible evidence separately. T2 reports fixed-bundle segmentation and citation diagnostics. Extensions are AUDIT_DIAGNOSTIC_NOT_OFFICIAL: action-cluster coverage, duplicate/repeat rate, post-freeze Gold-support coverage, per-step attribution, overmerge/oversplit, claim evidence tier, unsupported mechanism rate, temporal vs causal review, ATT&CK review.
No L0 absence claim from local omission; scope is RELEASED_L2_OBSERVABILITY_SCOPE. Unknown/abstention is allowed where evidence is insufficient. ATT&CK labels are not attack intent. Human diagnostic review needs two independent reviewers and adjudication; otherwise PENDING_REVIEW.

## Analysis and freeze
No p-values or superiority claim for these pilots. Keep step-unit strata separate. Do not compare the historical seven-round Solr run as if it matched a four-round arm. No case is removed after outcomes are seen. Budget violations are marked BUDGET_DEVIATION and excluded from matched-budget contrast unless resolved before inference without Gold access.
Query templates and budgets are frozen in 05_experiment_matrix_and_budgets.md. This protocol SHA-256 is in 10_stageA_SHA256SUMS.txt. No model, retrieval, evaluator, builder, network or attack run occurred. Stage B requires a later exact GO_RUN plus proven isolation and measured context/cost budgets.
