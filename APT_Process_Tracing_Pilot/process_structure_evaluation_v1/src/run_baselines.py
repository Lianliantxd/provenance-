"""Run the existing path selectors against an unchanged frozen candidate pool.

This module has no label input. Evaluation is done in a separate program.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT.parent
POOL = PILOT/'comparison_v1/outputs/frozen_pool.json'
EVENTS = PILOT/'results/cadets_20180412_q1/events.csv'
PRIOR = PILOT/'identifiability_feasibility_v1/src/run.py'
POI = 'EBFB7595-F532-54F8-B51B-CE074AAAFE37'
BUDGET = 162  # frozen B0 pool size for this previously inspected query


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run() -> dict:
    pool = json.loads(POOL.read_text())
    if pool['event_csv_sha256'] != sha(EVENTS):
        raise ValueError('frozen pool differs from input event table')
    spec = importlib.util.spec_from_file_location('existing_selectors', PRIOR)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load prior selectors')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    candidate = set(pool['searches'][POI]['event_ids'])
    paths = {POI: module.cadets_paths(pool, POI)[:3]}
    with EVENTS.open(newline='') as handle:
        events = {row['native_event_id']: row for row in csv.DictReader(handle)}
    results: dict[str, dict] = {}
    for method in ('B0', 'B1-Min', 'B1-Alternatives'):
        selected_ids, selected_paths, feasibility = module.select_paths(method, paths, candidate, BUDGET)
        if not selected_ids <= candidate:
            raise ValueError('selected output outside frozen candidate pool')
        results[method] = {
            'candidate_event_ids': sorted(candidate),
            'selected_event_ids': sorted(selected_ids),
            'selected_paths': [{'poi': owner, 'event_ids_poi_to_source': path} for owner, path in selected_paths],
            'candidate_count': len(candidate),
            'output_event_count': len(selected_ids),
            'path_count': len(selected_paths),
            'feasibility': feasibility,
            'time_status': 'UNRESOLVED_IF_EQUAL_TIMESTAMP_OR_SAME_LONG_LIVED_ENTITY',
            'raw_ref_hashes': {e: events[e]['raw_record_hash'] for e in sorted(selected_ids)},
        }
    output = {'poi_event_id': POI, 'budget': BUDGET, 'input_events_sha256': sha(EVENTS), 'frozen_pool_sha256': sha(POOL), 'selector_sha256': sha(PRIOR), 'scope': '10-second existing CDM event table, all supported operations, not full attack background', 'results': results}
    dest = ROOT/'outputs/baseline_paths.json'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({m: {'candidate_count': v['candidate_count'], 'output_event_count': v['output_event_count'], 'path_count': v['path_count'], 'feasibility': v['feasibility']} for m, v in results.items()}))
    return output


if __name__ == '__main__':
    run()
