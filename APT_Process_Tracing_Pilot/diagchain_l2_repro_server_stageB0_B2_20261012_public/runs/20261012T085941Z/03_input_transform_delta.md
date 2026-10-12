# Input transformation delta

Protocol: MODIFIED_L2_PROTOCOL; these are field-whitelisted derivatives, not byte-identical official inputs.

## Outer fields

Retained unchanged: task_type, task_instruction, incident_brief, required_output. incident_id is replaced with case_A/case_B. Benchmark/source identity, difficulty/profile/noise/length/sampling labels, input_policy, traceability, technique catalog and other outer metadata are removed from runner inputs and retained under evaluator_only.

## Evidence cards

Every card remains in original order. evidence_id, card_type, raw content, line, timestamp and extracted_clues are compared field by field. source_type is generalized from autolabel_log to log_observation; origin is removed from cards and retained in evaluator-only traceability. No card is dropped, shortened, or selected using Gold.

- case_A: 104/104 cards; runner SHA-256 c428651d8f701b819eb4387d854bd089fa2bef5855c558d0ac9975dc060eca83; ordered-ID SHA-256 969212bae19fc8ce3cf766196a843168e34de4625186bda13eb278b8b2b23b85; 108455 bytes; approx. 27114 tokens (characters/4, not tokenizer output).
- case_B: 96/96 cards; runner SHA-256 7c67e347ffc81c7242116592bfe6e6476ee3e6aba6ac8cf1a249c220964f7262; ordered-ID SHA-256 f256cb279d8b9b6ba2e5d182363190dd5e814c655a6aefdcd3532b15b9e72747; 107276 bytes; approx. 26819 tokens (characters/4, not tokenizer output).
