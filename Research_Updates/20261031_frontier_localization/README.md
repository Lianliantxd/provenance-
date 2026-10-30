# Frozen frontier localization, input A

This is a completed retrospective diagnostic, not a new ranked attack-reconstruction experiment.

- analysis-report.md: actual findings, cost and claim limits.
- artifacts/CONDITION_PROFILES.csv: all 16 relaxation combinations.
- artifacts/FRONTIER_CASES.csv: 17 anonymous nodes and all minimal sufficient relaxation alternatives.
- witness_group_audit/: anonymous step-level group-barrier checks.
- figures/ and figure-catalog.md: actual charts and interpretation.
- DECISION.json: machine-readable decision.
- NEXT_PILOT_PROTOCOL.json: proposed three-arm development pilot, not executed.

Verify the public delivery read-only:

```sh
python3 -B verify_delivery.py
python3 -B -m unittest -v test_frontier_core
```

frontier_core.py implements finite shared-entity context traversal; it does not infer native causal edges. localize_frontier.py requires authorized existing frozen artifacts and a fixed reference. The baseline must exactly reproduce the old event identity set before interpreting variants. Output must be a new directory.

All core graph traversals run before reference reading. Reference is used only for posthoc counting; this does not turn the previously exposed development instance into a blind test. audit_witness_groups.py validates privately retained saved witnesses and is explicitly a later supplemental audit.

No dependencies are installed. Plotting uses existing Matplotlib. Original event identities, private reference mappings and witness contents remain on the authorized server and are excluded from this bundle.
