"""Read-only integrity and boundary verification, not scientific proof."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
from frontier_core import minimal_success_masks


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
    r=ap.parse_args().root.resolve()
    manifest=json.loads((r/'SHA256_manifest.json').read_text())
    for n,h in manifest.items():assert hashlib.sha256((r/n).read_bytes()).hexdigest()==h,n
    for n,h in json.loads((r/'IMPLEMENTATION_FREEZE.json').read_text()).items():
        assert hashlib.sha256((r/n).read_bytes()).hexdigest()==h,n
    receipt=json.loads((r/'artifacts/RUN_RECEIPT.json').read_text())
    profiles={int(x['mask']):x for x in csv.DictReader((r/'artifacts/CONDITION_PROFILES.csv').open())}
    cases=list(csv.DictReader((r/'artifacts/FRONTIER_CASES.csv').open()))
    assert set(profiles)==set(range(16)) and len(cases)==receipt['target_reference_nodes']==17
    assert receipt['baseline_exactly_reproduced'] and receipt['model_runs']==receipt['new_ranked_predictions']==0
    assert int(profiles[0]['reachable_events'])==receipt['baseline_candidate_events']==966
    for case in cases:
        masks=json.loads(case['minimal_relaxation_masks'])
        assert masks==minimal_success_masks(set(masks))
        assert all(m&4 for m in masks)
    for mask,row in profiles.items():
        for bit in [1,2,4,8]:
            if not mask&bit:assert int(profiles[mask|bit]['reachable_events'])>=int(row['reachable_events'])
    group=json.loads((r/'witness_group_audit/WITNESS_GROUP_RECEIPT.json').read_text())
    private=json.loads((r/'artifacts/PRIVATE_WITNESS_AUDIT.json').read_text())
    assert group['witness_sha256']==private['private_file_sha256']
    assert group['equal_timestamp_steps']==private['paths_using_equal_timestamp_context_steps']==0
    pilot=json.loads((r/'NEXT_PILOT_PROTOCOL.json').read_text())
    assert pilot['status']=='PROPOSED_NOT_RUN' and not pilot['predictions_generated']
    assert not (r/'artifacts/private').exists(),'Do not publish native witness identities'
    for name in ['figure-01-frontier-coverage-cost','figure-02-node-classes-and-barriers']:
        assert (r/'figures'/(name+'.png')).read_bytes().startswith(b'\x89PNG')
        assert (r/'figures'/(name+'.pdf')).read_bytes().startswith(b'%PDF')
    print(json.dumps({'status':'PASS','files_checked':len(manifest),'profiles':len(profiles),
        'target_reference_nodes':len(cases),'new_predictions':0,'scientific_validity_or_causality_proven':False}))


if __name__=='__main__':main()
