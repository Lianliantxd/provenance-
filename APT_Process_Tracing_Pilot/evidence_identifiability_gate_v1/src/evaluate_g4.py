#!/usr/bin/env python3
"""Separate prediction from the evaluation-only oracle read."""
import csv
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"outputs"


def predict_without_oracle():
    measurement=json.loads((OUT/"pointer_measurement.json").read_text())
    pointer={r["run_id"]:r["pointer_equal"] for r in measurement["instrumented_untraced"]}
    ids=sorted(p.stem for p in (OUT/"projected_observations").glob("*.json"))
    assert len(ids)==12 and len(pointer)==12
    projections=[json.loads((OUT/"projected_observations"/(i+".json")).read_text()) for i in ids]
    assert all(p==projections[0] for p in projections)
    strategies={}
    for name in ("COARSE_REACHABILITY","ALWAYS_ABSTAIN"):
        strategies[name]={i:"UNDETERMINED" for i in ids}
    for name in ("FIXED_RULE_VALUE_LINEAGE","FIXED_LOW_COST","COLLECT_ALL_VALIDATED_FEASIBLE","RANDOM_SAME_BUDGET","EXHAUSTIVE_SUBSET_REFERENCE"):
        strategies[name]={i:("SUPPORTED_DEPENDENCE" if pointer[i] else "UNDETERMINED") for i in ids}
    return ids,strategies


def evaluate():
    ids,strategies=predict_without_oracle()
    # This oracle is read only after all predictions are fixed in memory.
    oracle=json.loads((OUT/"oracle/cases.json").read_text())
    truth={r["run_id"]:("SUPPORTED_DEPENDENCE" if r["condition"]=="F" else "SUPPORTED_NONDEPENDENCE") for r in oracle}
    assert set(truth)==set(ids)
    rows=[]
    for name,predictions in strategies.items():
        determinate=[i for i in ids if predictions[i]!="UNDETERMINED"]
        correct=sum(predictions[i]==truth[i] for i in determinate)
        errors=len(determinate)-correct
        measured=name in {"FIXED_RULE_VALUE_LINEAGE","FIXED_LOW_COST","COLLECT_ALL_VALIDATED_FEASIBLE","RANDOM_SAME_BUDGET","EXHAUSTIVE_SUBSET_REFERENCE"}
        rows.append({"strategy":name,"Q":"F1_PAYLOAD_TO_OUTPUT_VALUE_DEPENDENCE","histories":len(ids),"correct_determinate":correct,"wrong_determinate":errors,"determinate_assertions":len(determinate),"abstentions":len(ids)-len(determinate),"correct_coverage":f"{correct}/{len(ids)}","wrong_determinate_rate":f"{errors}/{len(determinate)}" if determinate else "NA/0","measurement_bytes_total":64*len(ids) if measured else 0,"deployment":"pre-instrumented application" if measured else "existing metadata only"})
    with (ROOT/"outputs/g4_coverage_risk_cost.csv").open("w",newline="") as h:
        w=csv.DictWriter(h,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(json.dumps(rows,indent=2))


if __name__=="__main__":evaluate()
