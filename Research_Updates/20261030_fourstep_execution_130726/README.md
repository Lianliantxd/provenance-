# Controlled paired training and event-retrieval pilot

This execution is complete. Read FINAL_MASTER_REPORT.md, DECISION.json and OBSERVED_STATUS.json for actual results and limitations. Do not relaunch jobs against existing output directories.

Use an already available, compatible ORTHRUS Python environment and trusted frozen author artifacts. No dependency installation or dataset download is performed here.

Required configuration for the portable source copies:

```sh
export ORTHRUS_FROZEN_RUN=/path/to/existing/frozen_orthrus_run
export POSTGRES_BIN=/path/to/existing/postgres/bin
export ORTHRUS_DB_USER=existing_database_owner
export ORTHRUS_REFERENCE_FILE=/path/to/authorized/node_reference.csv
```

The private executed source uses registered project paths. CODE_ORIGIN.json maps each public file to its executed source hash; portability changes replace paths/accounts and normalize module names only. The portable full pipeline has not been re-run on a different installation. Pure boundary checks require the existing runtime and, for retrieval checks, NumPy/SciPy:

```sh
python -m unittest -v test_mechanism_checks.py test_paired_boundaries.py test_retrieval_boundaries.py
```

Training/validation history is reset at each epoch start; training precedes validation. The selected post-validation state is carried directly into graph_12 without manufacturing missing days. Q comes from a validation-only threshold and is not forced to contain 16 nodes. All event relevance and causal claims remain scoped to available independent references; unannotated nodes are not confirmed benign. Diffusion values are retrieval scores, not attack probabilities.

after_training.py is a finite same-task sequencer, not a scheduler. For a new execution directory it waits for TRAINING_RESULT/TEST_RESULT and frozen Q, then runs retrieval, freezes predictions, and invokes the reference-reading evaluator. Do not point outputs at a historical frozen run. PostgreSQL extraction uses a private physical copy of a cleanly stopped database, refuses external tablespaces/symlinks, and stops its temporary socket-only process in finally.


最终实际结果以 FINAL_MASTER_REPORT.md、DECISION.json 为准；前期阶段记录不替代终态。


Read-only delivery verification: `python -B verify_delivery.py`.
