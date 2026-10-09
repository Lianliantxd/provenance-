#!/usr/bin/env python3
"""Freeze report-selected anchors before any graph search."""
import csv
import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
A_ID = "EBFB7595-F532-54F8-B51B-CE074AAAFE37"
B_ID = "58A15EC1-9BE9-5B97-9C54-1F5746A8AD2E"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    records = {}
    with gzip.open(OUT / "background_events.csv.gz", "rt", newline="") as f:
        for row in csv.DictReader(f):
            if row["event_uuid"] in {A_ID, B_ID}:
                records[row["event_uuid"]] = row
    assert set(records) == {A_ID, B_ID}
    a, b = records[A_ID], records[B_ID]
    assert a["operation"] == "EVENT_CONNECT" and b["operation"] == "EVENT_WRITE"
    assert int(a["timestamp_ns"]) < int(b["timestamp_ns"])
    assert a["subject_uuid"] == b["subject_uuid"]
    artifact = {
        "freeze_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "freeze_phase": "before T1/T2 graph search",
        "report": {
            "path": "/Users/tianxd/Documents/Transparent Computing E3/TC_Ground_Truth_Report_E3_Update.pdf",
            "sha256": sha("/Users/tianxd/Documents/Transparent Computing E3/TC_Ground_Truth_Report_E3_Update.pdf"),
            "section": "3.13 CADETS April 12",
            "page_pdf": "26-28",
            "page_printed": "23-25",
            "timezone": "report clock inferred EDT from independent timestamp correspondence; report itself does not explicitly state zone",
        },
        "source_artifacts": {
            "background_manifest_sha256": sha(OUT / "background_manifest.json"),
            "background_events_sha256": sha(OUT / "background_events.csv.gz"),
            "entity_definitions_sha256": sha(OUT / "entity_definitions.csv.gz"),
            "extractor_sha256": sha(ROOT / "src/extract_background.py"),
        },
        "A_evaluation_only": a,
        "B_query_POI": b,
        "selection": {
            "B_report_step": "14:02 putfile /tmp/tmux-1002, selected before search as uniquely time/path-matched write",
            "A_report_step": "roughly 14:00 Drakon loader connection from webserver, earlier than B",
            "B_time_utc": "2018-04-12T18:02:10.376185722Z",
            "A_time_utc": "2018-04-12T18:00:23.166196193Z",
            "candidate_rank": [
                {"rank": 1, "candidate": "14:02 putfile tmux-1002", "decision": "selected B", "basis": "unique EVENT_WRITE with tmux-1002 path and report-aligned minute"},
                {"rank": 2, "candidate": "14:37 micro scan", "decision": "excluded", "basis": "no EVENT_CONNECT in report-aligned minute to listed target IPs on ports 22/6000"},
                {"rank": 3, "candidate": "execfile /tmp/test", "decision": "excluded", "basis": "four EVENT_EXECUTE records across 18:32-18:35 UTC; report gives no exact minute"},
            ],
        },
        "evaluation": {
            "T1_inputs": "B only; A and report labels withheld from T1 process",
            "T2_inputs": "A and B; diagnostic, no tuning of T1",
            "budgets": [32, 128, 512],
            "boundary": "17:59:00 UTC left edge of one-member 40-minute graph",
            "timeline_rule": "strictly earlier timestamp group of same observed subject; cross-event link is MODEL_POSSIBLE_DEPENDENCY, never direct flow",
            "same_timestamp_rule": "no order inferred within a nanosecond timestamp group",
        },
    }
    target = ROOT / "01_PRESEARCH_FROZEN_ANCHORS.json"
    assert not target.exists(), "freeze is immutable"
    target.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
    configs = ROOT / "configs"
    configs.mkdir(exist_ok=True)
    (configs / "t1_query.json").write_text(json.dumps({
        "B_event_uuid": B_ID,
        "budgets": [32, 128, 512],
        "rule": "strict_prior_subject_timestamp_groups",
        "max_depth_groups": 128,
    }, indent=2) + "\n")
    (configs / "t2_query.json").write_text(json.dumps({
        "A_event_uuid": A_ID,
        "B_event_uuid": B_ID,
        "budgets": [32, 128, 512],
        "rule": "strict_prior_subject_timestamp_groups",
    }, indent=2) + "\n")
    print(target, sha(target))


if __name__ == "__main__":
    main()
