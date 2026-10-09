#!/usr/bin/env python3
"""Known-endpoint diagnostic. Run only after T1 artifacts have been sealed."""
import hashlib
import json
from timeline import ROOT, load_timeline, row_ref


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    t1 = ROOT / "outputs/t1_b_only.json"
    assert t1.exists(), "T1 must run first"
    t1_hash_before = sha(t1)
    cfg = json.loads((ROOT / "configs/t2_query.json").read_text())
    poi, groups, times, scanned = load_timeline(cfg["B_event_uuid"])
    a_time = next((ts for ts in times if any(r["event_uuid"] == cfg["A_event_uuid"] for r in groups[ts])), None)
    if a_time is None:
        raise ValueError("A not on observed B-subject timeline")
    times_to_a = [t for t in times if t >= a_time]
    chain = [poi]
    for ts in times_to_a[1:-1]:
        chain.append(groups[ts][0])
    chain.append(next(r for r in groups[a_time] if r["event_uuid"] == cfg["A_event_uuid"]))
    assert all(int(x["timestamp_ns"]) > int(y["timestamp_ns"]) for x, y in zip(chain, chain[1:]))
    assert sha(t1) == t1_hash_before
    output = {
        "T1_output_sha256_before_T2": t1_hash_before,
        "A_event_uuid": cfg["A_event_uuid"], "B_event_uuid": cfg["B_event_uuid"],
        "same_subject": True, "strict_timestamp_steps": len(chain)-1,
        "path_event_count": len(chain),
        "link_types": {"DIRECT_OPERATION_within_endpoint_events":2,"MODEL_POSSIBLE_DEPENDENCY_cross_event":len(chain)-1,"SENSOR_RECORDED_CREATION_OR_EXEC_cross_event":0,"ORDER_UNRESOLVED_on_path":0},
        "direct_only_A_to_B_connected": False,
        "budget_status": {str(b):"PATH_VISIBLE_OBSERVATION_BOUNDARY_NOT_PROVEN_ROOT" if len(chain)<=b else "BUDGET_EXCEEDED" for b in cfg["budgets"]},
        "path_B_to_A": [row_ref(r) for r in chain],
        "limitations": ["Each process timeline hop is a possible dependency, not observed information transfer.","Representative event choice in intermediate equal-time groups is arbitrary; no within-group order inferred.","A/B belong to one observed nginx subject; temporal continuity alone cannot identify an attack root."],
    }
    (ROOT / "outputs/t2_known_endpoints.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({k:v for k,v in output.items() if k != "path_B_to_A"},indent=2))


if __name__ == "__main__":
    main()
