"""Conservative same-subject timeline diagnostic over the unfiltered event table."""
import csv
import gzip
import sqlite3
import hashlib
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "outputs/background_events.csv.gz"


def index_path():
    local = ROOT / "outputs/background_index.sqlite"
    if local.exists():
        return local
    packed = ROOT / "outputs/background_index.sqlite.gz"
    if not packed.exists():
        raise FileNotFoundError("Build or unpack background index")
    key = hashlib.sha256(packed.read_bytes()).hexdigest()[:16]
    temporary = Path(tempfile.gettempdir()) / f"cadets_0412_index_{key}.sqlite"
    if not temporary.exists():
        with gzip.open(packed,"rb") as src, temporary.open("wb") as dst:
            shutil.copyfileobj(src,dst)
    return temporary


def load_timeline(poi_uuid):
    """Query all-event disk index by POI subject and strictly bounded time."""
    con = sqlite3.connect(index_path())
    con.row_factory = sqlite3.Row
    poi_row = con.execute("SELECT * FROM event WHERE event_uuid=?", (poi_uuid,)).fetchone()
    if poi_row is None:
        raise ValueError("POI absent from full background")
    poi = dict(poi_row)
    poi = {k: str(v) if v is not None else "" for k, v in poi.items()}
    groups = defaultdict(list)
    scanned = con.execute("SELECT count(*) FROM event").fetchone()[0]
    for row in con.execute("SELECT * FROM event WHERE subject_uuid=? AND timestamp_ns<=? ORDER BY timestamp_ns DESC,event_uuid", (poi["subject_uuid"],int(poi["timestamp_ns"]))):
        row = {k: str(v) if v is not None else "" for k,v in dict(row).items()}
        groups[int(row["timestamp_ns"])].append(row)
    con.close()
    for rows in groups.values():
        rows.sort(key=lambda r: r["event_uuid"])
    times = sorted(groups, reverse=True)
    return poi, groups, times, scanned


def path(groups, times, poi_uuid, alternative=0):
    """One event per strict prior timestamp group; equal-time order is unresolved."""
    chain = [next(r for r in groups[times[0]] if r["event_uuid"] == poi_uuid)]
    changed = False
    for i, ts in enumerate(times[1:], 1):
        rows = groups[ts]
        # Alternatives alter the first eligible group selected without label knowledge.
        if alternative and not changed and i >= alternative and len(rows) > 1:
            chain.append(rows[1])
            changed = True
        else:
            chain.append(rows[0])
    return chain


def row_ref(r):
    return {k: r[k] for k in (
        "event_uuid", "timestamp_ns", "subject_uuid", "object_uuid", "operation",
        "predicate_path", "direction_status", "raw_offset", "raw_sha256")}
