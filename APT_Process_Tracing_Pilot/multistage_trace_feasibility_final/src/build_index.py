#!/usr/bin/env python3
"""Build bounded-memory on-disk indexes for all window events, no label filter."""
import csv
import gzip
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "outputs/background_index.sqlite"


def main():
    if DB.exists():
        raise SystemExit("refusing to overwrite existing index")
    con = sqlite3.connect(DB)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute("CREATE TABLE event(event_uuid TEXT PRIMARY KEY, timestamp_ns INTEGER, subject_uuid TEXT, object_uuid TEXT, operation TEXT, predicate_path TEXT, direction_status TEXT, raw_offset INTEGER, raw_sha256 TEXT)")
    con.execute("CREATE TABLE direct_edge(event_uuid TEXT PRIMARY KEY, src_uuid TEXT, dst_uuid TEXT, operation TEXT)")
    batch, edges, n = [], [], 0
    with gzip.open(ROOT / "outputs/background_events.csv.gz", "rt", newline="") as f:
        for r in csv.DictReader(f):
            batch.append((r["event_uuid"],int(r["timestamp_ns"]),r["subject_uuid"],r["object_uuid"],r["operation"],r["predicate_path"],r["direction_status"],int(r["raw_offset"]),r["raw_sha256"]))
            if r["direction_status"] == "DIRECT_OPERATION":
                edges.append((r["event_uuid"],r["analysis_src_uuid"],r["analysis_dst_uuid"],r["operation"]))
            n += 1
            if len(batch) == 10000:
                con.executemany("INSERT INTO event VALUES (?,?,?,?,?,?,?,?,?)", batch)
                con.executemany("INSERT INTO direct_edge VALUES (?,?,?,?)", edges)
                con.commit(); batch.clear(); edges.clear()
    if batch:
        con.executemany("INSERT INTO event VALUES (?,?,?,?,?,?,?,?,?)", batch)
        con.executemany("INSERT INTO direct_edge VALUES (?,?,?,?)", edges)
    con.execute("CREATE INDEX event_subject_time ON event(subject_uuid,timestamp_ns)")
    con.execute("CREATE INDEX event_object_time ON event(object_uuid,timestamp_ns)")
    con.execute("CREATE INDEX event_time ON event(timestamp_ns)")
    con.commit()
    actual = con.execute("SELECT count(*) FROM event").fetchone()[0]
    direct = con.execute("SELECT count(*) FROM direct_edge").fetchone()[0]
    con.close()
    assert actual == n == 178399 and direct == 50757
    (ROOT / "outputs/index_manifest.json").write_text(json.dumps({"event_rows":actual,"direct_edge_rows":direct,"indexes":["event_uuid primary key","subject_uuid,timestamp_ns","object_uuid,timestamp_ns","timestamp_ns"],"derived_process_links":"queried only as adjacent strict timestamp groups; not materialized all-pairs","labels_used":False},indent=2)+"\n")
    print(actual,direct,DB.stat().st_size)


if __name__ == "__main__":main()
