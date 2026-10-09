"""Locate two A2 command identifiers without exporting raw command lines."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = Path("/Users/tianxd/Downloads/SimulatedWS12/hw20/anomaly.json")
TERMS = {
    "published": b"2f9c7075-ec33-4a29-901a-8e383f395763",
    "later_raw": b"7fa51253-c053-4b44-94eb-5d8a161b429b",
}


def main() -> None:
    found = {key: [] for key in TERMS}
    with RAW.open("rb") as stream:
        line_number = 0
        while True:
            offset = stream.tell()
            raw = stream.readline()
            if not raw:
                break
            line_number += 1
            matches = [key for key, term in TERMS.items() if term in raw]
            if not matches:
                continue
            event = json.loads(raw)
            item = {
                "raw_offset": offset,
                "raw_line": line_number,
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "msec": event.get("MSec"),
                "event": event.get("EventName"),
                "pid": event.get("PID"),
                "parent_pid": event.get("ParentID"),
                "process_name": event.get("PName"),
                "image_name": event.get("ImageFileName"),
            }
            for key in matches:
                found[key].append(item)
    (ROOT / "outputs/opid_occurrences.json").write_text(
        json.dumps(found, indent=2, ensure_ascii=False) + "\n"
    )
    print(json.dumps({key: len(value) for key, value in found.items()}))


if __name__ == "__main__":
    main()
