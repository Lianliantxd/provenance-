"""Freeze audit candidate classifications without using traceback outputs as labels."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = "/Users/tianxd/Downloads/SimulatedWS12/hw20/anomaly.json"
COMMIT = "434dbe2d0be88bd034c4af0c819aed641d2b3758"
FIELDS = "case_id official_repo_commit official_source_file sheet_cell_or_annotation source_claim_original source_claim_interpretation relation_type source_event_ref target_event_ref source_raw_file target_raw_file source_raw_hash target_raw_hash identity_match_rule time_order_status number_of_candidate_matches reference_status reference_scope is_poi_anchor can_evaluate_pair exclusion_reason review_notes".split()


def main() -> None:
    book = json.loads((ROOT / "outputs/workbook_inventory.json").read_text())
    cells = {c["coordinate"]: c["value"] for c in book["sheets"][0]["cells"]}
    events = json.loads((ROOT / "outputs/key_raw_event_checks.json").read_text())["events"]
    rows = []

    def add(key: str, source_location: str, claim: str, interpretation: str, relation: str, source: str = "", target: str = "", status: str = "PUBLISHED_STEP_ONLY", scope: str = "attack step", reason: str = "STEP_ONLY", notes: str = "", count: str = "NA:not_pair_mapped", poi: bool = False, evaluable: bool = False) -> None:
        a = events.get(source)
        b = events.get(target)
        rows.append(dict(zip(FIELDS, ["NODLINK_WS12", COMMIT, "doc/SimulatedWS12-attack/attack_analysis.xls and attack_annotation" if "A2" in source_location else "doc/SimulatedWS12-attack/attack_analysis.xls; attack_annotation", source_location, claim, interpretation, relation, a["raw_ref"] if a else "", b["raw_ref"] if b else "", RAW if a else "", RAW if b else "", a["raw_sha256"] if a else "", b["raw_sha256"] if b else "", "raw offset+PID+ParentID+MSec; never process key alone" if a and b else "command/path/time only", f"{a['msec']} -> {b['msec']} MSec" if a and b else "NA", count, status, scope, poi, evaluable, reason, notes])))

    add("A1", "Sheet1!C4:D4; A1.txt [pCommand]", cells["D4"], "reconnaissance command/step", "ATTACK_STEP", "a1_cmd", notes="one corresponding cmd start; no event-pair relation")
    add("A2_STEP", "Sheet1!C5:D5; A2.txt [pCommand]", cells["C5"], "compound download and launch command", "ATTACK_STEP", "a2_cmd", "agent_start", scope="published command/intent, not event pair", reason="SOURCE_RELATION_UNCLEAR", notes="published agent OPID differs from later raw Process/Start; no file version or ETW event ID", count="multiple_operations_not_unique", poi=True)
    add("CMD_CERT", "Sheet1!C5:D5; A2.txt [pCommand]", cells["D5"], "A2-associated cmd and certutil starts", "PROCESS_PARENT", "a2_cmd", "certutil_start", "SENSOR_DIRECT_RELATION", "ETW ParentID only; not published event-pair GT", "STEP_ONLY", "certutil ParentID=1996; bounded-window cmd PID=1996", "1_pair_in_frozen_scope", True, True)
    add("CMD_AGENT", "Sheet1!C5:D5; A2.txt [pCommand]", cells["D5"], "later cmd and agent starts", "PROCESS_PARENT", "launch_cmd", "agent_start", "SENSOR_DIRECT_RELATION", "ETW ParentID only; exact published OPID mismatch", "VERSION_MISMATCH", "agent ParentID=4360; bounded-window cmd PID=4360; published OPID does not match later start", "1_pair_in_frozen_scope", True, True)
    add("WRITE_READ", "Sheet1!C5:D5; A2.txt [pCommand]", cells["D5"], "download/launch step does not identify a file version transfer", "FILE_CONTENT_FLOW", "agent_write", "agent_read", "MODEL_INFERRED_ONLY", "same path and time, no byte/version identity", "MODEL_INFERRED_ONLY", "read may use this or another file version", "1_write_1_read_in_frozen_scope")
    add("WRITE_START", "Sheet1!C5:D5; A2.txt [pCommand]", cells["D5"], "download and launch step, no exact write-to-execution pair", "FILE_TO_EXECUTION", "agent_write", "agent_start", "MODEL_INFERRED_ONLY", "path/command similarity, no file object/version match", "MODEL_INFERRED_ONLY", "write predates start but content transfer is unverified", "1_pair_candidate_in_frozen_scope", True)
    add("READ_START", "Sheet1!C5:D5; A2.txt [pCommand]", cells["D5"], "candidate read cannot cause earlier process start", "FILE_TO_EXECUTION", "agent_read", "agent_start", "CONTRADICTED_BY_RECORD", "temporal contradiction", "TIME_CONTRADICTION", "143906.9571 MSec read is later than 143906.2601 MSec start", "1_pair_candidate_in_frozen_scope", True)
    add("OFFICIAL_OPID", "Sheet1!C5; A2.txt [pCommand]", cells["C5"], "published OPID matches earlier stop, not later launch", "EVENT_MATCH", "official_opid_stop", status="PUBLISHED_STEP_ONLY", scope="identifier alignment only", reason="VERSION_MISMATCH", notes="exact published OPID occurs in one Process/Stop and zero Process/Start records in local anomaly.json", count="1_stop_0_starts")
    for name, cell, meaning in [("A3", "D7", "credential attack step"), ("A4", "D6", "persistence step"), ("A5", "D8", "discovery step"), ("A6", "D9", "lateral movement step")]:
        add(name, f"Sheet1!{cell}; {name}.txt", cells[cell], meaning, "ATTACK_STEP", notes="no event-pair relation published; not remapped outside A2 scope")

    dest = ROOT / "02_REFERENCE_PAIR_CANDIDATES.csv"
    with dest.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    freeze = json.loads((ROOT / "outputs/source_freeze.json").read_text())
    freeze["reference_file_sha256"] = hashlib.sha256(dest.read_bytes()).hexdigest()
    freeze["candidate_rows"] = len(rows)
    freeze["qualifying_published_event_pairs"] = sum(r["reference_status"] == "PUBLISHED_PAIR_MATCHED" and r["can_evaluate_pair"] for r in rows)
    (ROOT / "outputs/reference_freeze.json").write_text(json.dumps(freeze, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"rows": len(rows), "sensor_direct_pairs": sum(r["reference_status"] == "SENSOR_DIRECT_RELATION" for r in rows), "published_matched_pairs": freeze["qualifying_published_event_pairs"]}))


if __name__ == "__main__":
    main()
