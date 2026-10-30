"""Read-only artifact boundary verification; not a scientific validity proof."""
from pathlib import Path
import hashlib,json,csv
root=Path(__file__).resolve().parent
manifest=json.loads((root/'SHA256_manifest.json').read_text())
for name,h in manifest.items():
 p=root/name
 assert p.is_file(),name
 assert hashlib.sha256(p.read_bytes()).hexdigest()==h,name
required=['FINAL_MASTER_REPORT.md','DECISION.json','OBSERVED_STATUS.json','CODE_ORIGIN.json']
assert all((root/n).is_file() for n in required)
d=json.loads((root/'DECISION.json').read_text())
e=[json.loads(s) for s in (root/'EPOCHS.jsonl').read_text().splitlines()]
assert len(e)==20 and [r['epoch'] for r in e]==list(range(1,21))
best=min(e,key=lambda x:(x['validation_event_weighted_loss'],x['epoch']))
assert best['epoch']==d['selected_epoch']
assert best['validation_max_event_loss']==d['threshold']
assert d['activity_f1'] is None and d['causal_path_f1'] is None
assert not d['generalization_established'] and not d['automatic_next_stage_authorized']
if (root/'RETRIEVAL_METRICS.csv').exists():
 rows=list(csv.DictReader((root/'RETRIEVAL_METRICS.csv').open()))
 assert len(rows)==d['prediction_files']
 assert len([r for r in rows if r['condition']=='n100_e500' and r['status']=='PREDICTED'])==d['primary_feasible_outputs']
 assert all(r['activity_f1']=='NA' and r['causal_path_f1']=='NA' for r in rows)
print(json.dumps({'status':'PASS','files_checked':len(manifest),'scope':'hashes, epoch selection, states, counts; no scientific proof'}))
