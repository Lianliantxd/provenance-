"""Read-only inventory of the published XLS and bounded WS12 raw refs."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import olefile
import struct
import xlrd
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
LOCAL = PROJECT / "research/repos/nodlink/doc/SimulatedWS12-attack"
RAW = Path("/Users/tianxd/Downloads/SimulatedWS12/hw20/anomaly.json")
COMMIT = "434dbe2d0be88bd034c4af0c819aed641d2b3758"
NAMES = ["attack_analysis.xls"] + [f"attack_annotation/{n}.txt" for n in ("A1", "A2", "A3", "A4", "A5", "A6", "A_alltime")]
OFFSETS = {"a1_cmd": 1270525, "a2_cmd": 1590222, "certutil_start": 1809315, "official_opid_stop": 1807171, "agent_write": 15343712, "launch_cmd": 15345869, "agent_start": 15375641, "agent_read": 15379032}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def redact(s: str) -> str:
    return s.replace("Data123456!", "[REDACTED_CREDENTIAL]").replace("Sangfor123", "[REDACTED_CREDENTIAL]")


def workbook_inventory(path: Path) -> dict:
    book = xlrd.open_workbook(str(path), formatting_info=True)
    sheets = []
    for sheet in book.sheets():
        cells = []
        for row in range(sheet.nrows):
            for col in range(sheet.ncols):
                cell = sheet.cell(row, col)
                if cell.ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK) or not str(cell.value).strip():
                    continue
                raw = str(cell.value)
                cells.append({"coordinate": f"{xlrd.formula.colname(col)}{row+1}", "value": redact(raw), "redacted": raw != redact(raw), "cell_type": cell.ctype})
        sheets.append({"name": sheet.name, "visibility": sheet.visibility, "rows": sheet.nrows, "cols": sheet.ncols, "nonempty_cells": len(cells), "merged_ranges_zero_based": sheet.merged_cells, "note_count": len(sheet.cell_note_map), "hyperlink_count": len(sheet.hyperlink_list), "cells": cells})
    with olefile.OleFileIO(str(path)) as ole:
        streams = [{"name": "/".join(x), "bytes": ole.get_size(x)} for x in ole.listdir(streams=True, storages=False)]
        data = ole.openstream("Workbook").read()
    counts = collections.Counter()
    pos = 0
    while pos + 4 <= len(data):
        record, size = struct.unpack_from("<HH", data, pos)
        if pos + 4 + size > len(data):
            raise ValueError("truncated BIFF record")
        counts[record] += 1
        pos += 4 + size
    if pos != len(data):
        raise ValueError("unparsed BIFF bytes")
    labels = {0x0809: "BOF", 0x0085: "BOUNDSHEET", 0x0006: "FORMULA", 0x001C: "NOTE", 0x005D: "OBJ", 0x00EC: "MSODRAWING", 0x00EB: "MSODRAWINGGROUP", 0x01B6: "TXO"}
    return {"file": str(path), "sha256": digest(path), "format": "OLE2/BIFF .xls", "sheets": sheets, "ole_streams": streams, "biff_selected_record_counts": {label: counts[number] for number, label in labels.items()}, "limitation": "ETExtData OLE extension stream was listed but not semantically decoded"}


def event_at(offset: int) -> dict:
    with RAW.open("rb") as f:
        f.seek(offset)
        raw = f.readline()
    event = json.loads(raw)
    return {"offset": offset, "raw_ref": f"{RAW}@{offset}", "raw_sha256": hashlib.sha256(raw).hexdigest(), "msec": event.get("MSec"), "event_type": event.get("EventName"), "pid": event.get("PID"), "parent_pid": event.get("ParentID"), "process_key": event.get("UniqueProcessKey"), "process_name": event.get("PName"), "file_path": event.get("FileName"), "image_name": event.get("ImageFileName"), "official_opid_present": b"2f9c7075-ec33-4a29-901a-8e383f395763" in raw, "later_opid_present": b"7fa51253-c053-4b44-94eb-5d8a161b429b" in raw}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-download", required=True, type=Path)
    args = parser.parse_args()
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "outputs").mkdir(exist_ok=True)
    versions = {}
    for name in NAMES:
        local, official = LOCAL / name, args.official_download / name
        a, b = digest(local), digest(official)
        if a != b:
            raise ValueError(f"official/local bytes differ: {name}")
        versions[name] = {"local_file": str(local), "sha256": a, "bytes": local.stat().st_size, "official_same_commit_match": True}
    book = workbook_inventory(LOCAL / "attack_analysis.xls")
    events = {name: event_at(offset) for name, offset in OFFSETS.items()}
    assert events["certutil_start"]["parent_pid"] == events["a2_cmd"]["pid"] == "1996"
    assert events["agent_start"]["parent_pid"] == events["launch_cmd"]["pid"] == "4360"
    assert float(events["agent_read"]["msec"]) > float(events["agent_start"]["msec"])
    assert events["a1_cmd"]["process_key"] == events["a2_cmd"]["process_key"] and events["a1_cmd"]["pid"] != events["a2_cmd"]["pid"]
    assert events["official_opid_stop"]["official_opid_present"] and events["official_opid_stop"]["event_type"] == "Process/Stop"
    assert events["agent_start"]["later_opid_present"] and not events["agent_start"]["official_opid_present"]
    raw = {"source": str(RAW), "sha256": digest(RAW), "events": events}
    freeze = {"frozen_utc": datetime.now(timezone.utc).isoformat(), "official_repo": "https://github.com/PKU-ASAL/Simulated-Data", "official_branch": "main", "official_commit": COMMIT, "official_files": versions, "raw_log_sha256": raw["sha256"], "previous_graph_version_sha256": digest(PROJECT / "APT_Process_Tracing_Pilot/identifiability_feasibility_v1/src/run.py"), "previous_candidate_scope_sha256": digest(PROJECT / "APT_Process_Tracing_Pilot/identifiability_feasibility_v1/outputs/ws12_scope.json"), "poi_ids": ["ws12@1809315", "ws12@15375641"], "poi_anchor_msec": ["127919.3304", "143906.2601"], "candidate_scope": "previous anomaly-only Process/Start and agent.exe operations, 117000-145000 MSec", "case_role": "DEVELOPMENT_PRIORLY_INSPECTED"}
    for name, data in [("workbook_inventory", book), ("key_raw_event_checks", raw), ("source_freeze", freeze)]:
        (ROOT / "outputs" / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"official_files_matched": len(versions), "sheets": [s["name"] for s in book["sheets"]], "nonempty_cells": sum(s["nonempty_cells"] for s in book["sheets"]), "raw_refs_checked": len(events)}))


if __name__ == "__main__":
    main()
