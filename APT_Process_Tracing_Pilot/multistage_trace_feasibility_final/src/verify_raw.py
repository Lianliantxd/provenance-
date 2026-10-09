#!/usr/bin/env python3
"""Reopen the original TAR member and verify frozen raw byte offsets and hashes."""
import hashlib
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
freeze = json.loads((ROOT / "01_PRESEARCH_FROZEN_ANCHORS.json").read_text())
refs = {int(freeze[k]["raw_offset"]): freeze[k] for k in ("A_evaluation_only", "B_query_POI")}
archive = Path("/Users/tianxd/Documents/Transparent Computing E3/CADETS/ta1-cadets-e3-official-2.json.tar.gz")
with tarfile.open(archive, "r|gz") as tf:
    member = next(m for m in tf if m.name == "ta1-cadets-e3-official-2.json")
    f = tf.extractfile(member)
    pos, seen = 0, {}
    while f and len(seen) < len(refs):
        line = f.readline()
        if not line: break
        if pos in refs:
            ref = refs[pos]
            assert hashlib.sha256(line).hexdigest() == ref["raw_sha256"]
            assert ref["event_uuid"].encode() in line
            seen[ref["event_uuid"]] = {"offset":pos,"sha256":ref["raw_sha256"],"verified":True}
        pos += len(line)
    assert len(seen) == len(refs)
(ROOT / "outputs/raw_anchor_verification.json").write_text(json.dumps(seen,indent=2)+"\n")
print(json.dumps(seen,indent=2))
