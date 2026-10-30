# Frozen error decomposition

This bundle analyzes existing outputs from the paired ORTHRUS adaptation and retrieval controls. It does not train, tune, or generate new predictions.

- Main findings and limits: analysis-report.md.
- Exact tables: artifacts/PER_PREDICTION_AUDIT.csv, FULL_MODULE_CONTRASTS.csv, BUDGET_SUMMARY.csv, EVENT_CONCENTRATION.csv.
- Statistical limits: stats-appendix.md. One exposed development attack; no independent-attack significance claim.
- Figures and interpretation: figures/ and figure-catalog.md.
- Machine decision: DECISION.json.

Read-only delivery verification:

```sh
python3 -B verify_delivery.py
```

Using already available standard Python, the descriptive table summary can be rechecked against the same artifacts without changing them:

```sh
python3 -B analyze_tables.py --root .
```

audit_frozen.py and audit_candidate_scope.py require authorized existing private artifacts and a fixed reference SHA. They read references only for retrospective diagnosis, not prediction or untouched validation. Use a new output location; never overwrite a frozen run. plot_analysis.py uses an already installed Matplotlib and creates a new figures directory. No dependency installation is included.

Raw logs, model weights, event excerpts, reference identities, credentials and private mappings are excluded from the public bundle. Initial plot layout attempts are preserved privately; only final figures are included here.

See COST_SCOPE_ADDENDUM.md for actual-cost exceptions; matching node hits does not imply universal domination.
