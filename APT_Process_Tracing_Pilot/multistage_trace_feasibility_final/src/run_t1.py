#!/usr/bin/env python3
"""B-only run. Intentionally does not read frozen A or T2 configuration."""
import csv
import json
from pathlib import Path
from timeline import ROOT, load_timeline, path, row_ref


def main():
    cfg = json.loads((ROOT / "configs/t1_query.json").read_text())
    poi, groups, times, scanned = load_timeline(cfg["B_event_uuid"])
    assert poi["event_uuid"] == cfg["B_event_uuid"]
    assert len(times) <= cfg["max_depth_groups"]
    pool = [r for ts in times for r in groups[ts]]
    variants = {"B1-Min": path(groups, times, poi["event_uuid"])}
    for n in (1, 2, 3):
        variants[f"B1-Alt{n}"] = path(groups, times, poi["event_uuid"], n)
    output = {
        "input": "B only from configs/t1_query.json",
        "all_background_event_rows_scanned": scanned,
        "subject_uuid": poi["subject_uuid"],
        "timeline_group_count": len(times),
        "coarse_candidate_pool_count": len(pool),
        "boundary_reached": "earliest observed subject event within the 40-minute window; earlier provenance unknown",
        "all_pool_event_ids": [r["event_uuid"] for r in pool],
        "paths": {name: [row_ref(r) for r in rows] for name, rows in variants.items()},
        "statuses": {},
    }
    for budget in cfg["budgets"]:
        output["statuses"][str(budget)] = {
            "B0_pool_visible": min(len(pool), budget),
            "B0_pool_complete": len(pool) <= budget,
            "B1_path_visible": min(len(times), budget),
            "B1_boundary_reached": len(times) <= budget,
            "reason_if_truncated": "budget below event count" if len(times) > budget else "",
        }
    out = ROOT / "outputs/t1_b_only.json"
    out.write_text(json.dumps(output, indent=2) + "\n")
    with (ROOT / "04_T1_BASELINE_RESULTS.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["method", "budget", "returned_events", "complete_within_budget", "cross_event_link_type", "left_boundary_status"])
        w.writeheader()
        for budget in cfg["budgets"]:
            w.writerow({"method":"B0-all-prior-same-subject-candidates","budget":budget,"returned_events":min(len(pool),budget),"complete_within_budget":len(pool)<=budget,"cross_event_link_type":"MODEL_POSSIBLE_DEPENDENCY","left_boundary_status":"OBSERVATION_BOUNDARY"})
            for name in variants:
                w.writerow({"method":name,"budget":budget,"returned_events":min(len(times),budget),"complete_within_budget":len(times)<=budget,"cross_event_link_type":"MODEL_POSSIBLE_DEPENDENCY","left_boundary_status":"OBSERVATION_BOUNDARY"})
    print(json.dumps({"rows_scanned":scanned,"groups":len(times),"pool":len(pool),"status":output["statuses"]}, indent=2))


if __name__ == "__main__":
    main()
