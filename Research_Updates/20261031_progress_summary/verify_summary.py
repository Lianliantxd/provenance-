"""Read-only checks for this descriptive progress summary."""
from pathlib import Path
import json
import hashlib
import re

NAME='2026-10-31--apt-reconstruction--r00--progress-summary.md'
r=Path(__file__).resolve().parent
manifest=json.loads((r/'SHA256_manifest.json').read_text())
for name,h in manifest.items():
    assert hashlib.sha256((r/name).read_bytes()).hexdigest()==h,name
text=(r/NAME).read_text()
assert '@@' not in text
assert text.count('![')==4
assert 'PROPOSED_NOT_RUN' in text and '16.45' in text
assert '38/43不是固定100节点/500事件下的恢复率' in text
assert '不能把它们计为148个独立实验样本' in text
assert '历史' in text and 'UNKNOWN' in text
ledger=json.loads((r/'SOURCE_LEDGER.json').read_text())
assert ledger['source_count']==len(ledger['sources'])==32
assert len({s['id'] for s in ledger['sources']})==32
for s in ledger['sources']:
    assert s['bytes']>0 and len(s['sha256'])==64
status=json.loads((r/'SUMMARY_STATUS.json').read_text())
assert status['paired_epochs']==20 and status['selected_epoch']==19
assert status['Q_count']==18 and status['Q_reference_hits']==13
assert status['retrieval_prediction_files']==148
assert status['frontier_node_partition']==[14,1,2]
assert not status['three_arm_pilot_executed']
assert not status['paper_level_method_superiority_established']
for link in re.findall(r'\]\(([^)]+)\)',text):
    if link.startswith('assets/'):
        assert (r/link).is_file(),link
    elif link.startswith('/'):
        assert Path(link).is_file(),link
for p in r.rglob('*'):
    if p.is_file() and p.suffix in ['.md','.json','.py']:
        b=p.read_bytes()
        private_location=re.compile(rb'/(?:Users|home)/|(?<!\d)10\.\d{1,3}\.\d{1,3}\.')
        assert not private_location.search(b),p.name
print(json.dumps({'status':'PASS','files_verified':len(manifest),
                  'source_items':len(ledger['sources']),'figures':4,
                  'new_experiments_run':0,'scientific_superiority_proven':False}))
