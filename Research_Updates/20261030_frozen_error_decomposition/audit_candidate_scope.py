"""Retrospective reference-conditioned error localization, not a predictor."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--reference', type=Path, required=True)
    ap.add_argument('--reference-sha256', required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    start = time.monotonic()
    root = args.root.resolve()
    identities = {}

    def load(n):
        b = (root/n).read_bytes()
        identities[n] = hashlib.sha256(b).hexdigest()
        return json.loads(b)

    b = args.reference.read_bytes()
    assert hashlib.sha256(b).hexdigest() == args.reference_sha256
    ref = {r[0] for r in csv.reader(b.decode().splitlines()) if r}
    mapping = {int(k): v[0] for k, v in load('private_node_uuid_map.json').items()}
    inverse = {v: k for k, v in mapping.items()}
    assert len(mapping) == len(inverse)
    scores = {r['node_uuid'] for r in load('NODE_SCORES.json')}
    q = load('Q.json')
    windows = {w for r in q for w in r['alert_windows']}
    es = load('retrieval_predictions/CANDIDATE_RECORDS_A.json')
    cs = {mapping[n] for e in es for n in (e['u'], e['v'])}
    missing = (ref & scores) - cs
    target_indices = {inverse[x] for x in missing}
    found, found_in_window = set(), set()
    db_path = root/'private_events.sqlite'
    before = db_path.stat()
    digest = hashlib.sha256()
    records = 0
    db = sqlite3.connect('file:'+str(db_path)+'?mode=ro', uri=True)
    try:
        for u, v, t, op, window in db.execute(
                "SELECT src,dst,t,op,window FROM events WHERE split='test' ORDER BY eid"):
            records += 1
            assert records <= 526169, 'Existing compressed development input only'
            digest.update(json.dumps([u,v,t,op,window],separators=(',',':')).encode()+b'\n')
            hit = {u, v} & target_indices
            found.update(hit)
            if window in windows:
                found_in_window.update(hit)
    finally:
        db.close()
    after = db_path.stat()
    assert records == 526169
    assert target_indices == found
    assert (before.st_size,before.st_mtime_ns) == (after.st_size,after.st_mtime_ns)
    result = {'status': 'PASS', 'task': 'retrospective missed-reference location only',
        'reference_nodes': len(ref), 'scored_reference_nodes': len(ref & scores),
        'candidate_reference_nodes': len(ref & cs), 'scored_but_outside_candidates': len(missing),
        'missing_reference_outside_all_Q_alert_windows': len(found-found_in_window),
        'missing_reference_in_Q_alert_windows_but_outside_candidate_frontier': len(found_in_window),
        'selected_database_records_read': records, 'selected_rows_sha256': digest.hexdigest(),
        'sqlite_size_mtime_unchanged': True, 'database_whole_file_sha256': 'NOT_COMPUTED',
        'physical_io_bytes': 'NOT_MEASURED', 'raw_logs_read': 0,
        'new_predictions_generated': 0, 'model_runs': 0,
        'uses_reference_for_posthoc_diagnosis': True,
        'not_valid_for_blind_test_selection': True,
        'input_metadata_sha256': identities, 'wall_seconds': time.monotonic()-start}
    args.out.open('x').write(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
