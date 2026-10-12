# L2 content and leakage check

Protocol: MODIFIED_L2_PROTOCOL. Gold was not consulted for selection, ordering, truncation, or transformation.

All source cards are retained in order. Raw content, IDs, card type, line, timestamp, and extracted clues are checked semantically. Source origin is evaluator-only; source_type is normalized to the generic log_observation type. Commands, URLs, IPs and timestamps are retained.

## case_A

- Cards and ordered IDs complete; semantic event fields preserved.
- Exact CVE/case strings in runner payload: none detected. Event facts were never redacted.
- Local absolute path present: False.
- This string/key scan cannot rule out a model inferring case identity from distinctive unmodified event evidence.

## case_B

- Cards and ordered IDs complete; semantic event fields preserved.
- Exact CVE/case strings in runner payload: none detected. Event facts were never redacted.
- Local absolute path present: False.
- This string/key scan cannot rule out a model inferring case identity from distinctive unmodified event evidence.
