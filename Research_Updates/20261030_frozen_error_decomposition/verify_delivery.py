"""Read-only delivery checks, not a proof of scientific validity."""
from pathlib import Path
import argparse
import csv
import hashlib
import json


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parent)
    root=ap.parse_args().root.resolve()
    manifest=json.loads((root/'SHA256_manifest.json').read_text())
    for name,h in manifest.items():
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==h,name
    decision=json.loads((root/'DECISION.json').read_text())
    coverage=json.loads((root/'artifacts/COVERAGE_PARTITIONS.json').read_text())
    rows=list(csv.DictReader((root/'artifacts/PER_PREDICTION_AUDIT.csv').open()))
    contrasts=list(csv.DictReader((root/'artifacts/FULL_MODULE_CONTRASTS.csv').open()))
    summaries=list(csv.DictReader((root/'artifacts/BUDGET_SUMMARY.csv').open()))
    scope=json.loads((root/'artifacts/CANDIDATE_SCOPE_AUDIT.json').read_text())
    assert len(rows)==148 and len(contrasts)==120 and len(summaries)==12
    for x in rows:
        c=coverage[x['input']]
        assert x['partition_sum_verified']=='True'
        assert sum(int(x[k]) for k in ['reference_hits','miss_outside_scoring',
               'miss_outside_candidates','miss_within_candidates'])==c['reference_total']
    assert decision['candidate_misses_within_Q_alert_windows']==scope['missing_reference_in_Q_alert_windows_but_outside_candidate_frontier']
    assert not decision['original_predictions_modified'] and decision['new_model_runs']==0
    assert all(x['p_value']=='NOT_IDENTIFIABLE' and x['confidence_interval']=='NOT_IDENTIFIABLE'
               for x in summaries)
    for name in ['figure-01-budget-sensitivity','figure-02-loss-and-concentration']:
        assert (root/'figures'/(name+'.png')).read_bytes().startswith(b'\x89PNG')
        assert (root/'figures'/(name+'.pdf')).read_bytes().startswith(b'%PDF')
    print(json.dumps({'status':'PASS','files_checked':len(manifest),
        'prediction_rows':len(rows),'contrast_rows':len(contrasts),'budget_slices':len(summaries),
        'scientific_validity_or_generalization_proven':False}))


if __name__=='__main__':main()
