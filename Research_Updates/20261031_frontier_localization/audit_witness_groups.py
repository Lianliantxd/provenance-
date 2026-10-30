"""Posthoc validation of saved context witnesses; returns no raw identities."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import os
import signal
import sqlite3
import time
import collections


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--database',type=Path,required=True)
    ap.add_argument('--witness',type=Path,required=True)
    ap.add_argument('--witness-sha256',required=True)
    ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args();start=time.monotonic();signal.alarm(60)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    data=a.witness.read_bytes();assert hashlib.sha256(data).hexdigest()==a.witness_sha256
    cases=json.loads(data);before=a.database.stat()
    db=sqlite3.connect('file:'+str(a.database)+'?mode=ro',uri=True)
    rows=[];queries=0;logical_rows=0;reasons=collections.Counter()
    try:
        for case in cases:
            for witness in case['witnesses']:
                for step,(left,right) in enumerate(zip(witness['events'],witness['events'][1:]),1):
                    assert left['window']==right['window'] and left['t']!=right['t']
                    channels=[]
                    for entity in sorted({left['u'],left['v']}&{right['u'],right['v']}):
                        queries+=1;assert queries<=128
                        lo,hi=sorted([left['t'],right['t']])
                        groups=dict(db.execute("SELECT t,COUNT(*) FROM events WHERE split='test' AND window=? "
                            "AND t>=? AND t<=? AND (src=? OR dst=?) GROUP BY t ORDER BY t",
                            (left['window'],lo,hi,entity,entity)))
                        logical_rows+=sum(groups.values());assert logical_rows<=2_000_000
                        assert groups.get(left['t'],0)>0 and groups.get(right['t'],0)>0
                        flags=[]
                        if groups[left['t']]>1:flags.append('SOURCE_GROUP_ABSTENTION')
                        if groups[right['t']]>1:flags.append('TARGET_GROUP_BARRIER')
                        if any(count>1 for t,count in groups.items() if lo<t<hi):flags.append('INTERMEDIATE_GROUP_BARRIER')
                        if len(groups)-1>8:flags.append('NEIGHBOR_GROUP_LIMIT')
                        if hi-lo>300_000_000_000:flags.append('TIME_GAP')
                        channels.append(flags)
                    assert channels
                    available=any(not flags for flags in channels)
                    union=sorted({f for channel in channels for f in channel})
                    if not available:reasons.update(union)
                    rows.append({'case_alias':case['alias'],'relaxation_mask':witness['mask'],
                        'step':step,'shared_channels':len(channels),'baseline_relation_available':available,
                        'channel_block_reasons':json.dumps(channels),'equal_timestamp_step':False})
    finally:db.close()
    after=a.database.stat();assert (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
    for case in cases:
        for witness in case['witnesses']:
            subset=[r for r in rows if r['case_alias']==case['alias'] and r['relaxation_mask']==witness['mask']]
            assert any(not r['baseline_relation_available'] for r in subset)
    a.out.mkdir(exist_ok=False)
    with (a.out/'WITNESS_GROUP_STEPS.csv').open('x',newline='') as stream:
        wr=csv.DictWriter(stream,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)
    receipt={'status':'PASS','scope':'posthoc saved context witnesses only',
        'witness_sha256':a.witness_sha256,'context_steps':len(rows),
        'steps_unavailable_under_baseline':sum(not r['baseline_relation_available'] for r in rows),
        'baseline_block_reason_step_counts_overlapping':dict(reasons),
        'equal_timestamp_steps':0,'group_queries':queries,
        'matching_event_rows_aggregated_including_repeats':logical_rows,
        'database_size_mtime_unchanged':True,'physical_io_bytes':'NOT_MEASURED',
        'wall_seconds':time.monotonic()-start,'raw_archive_reads':0,'model_runs':0,
        'interpretation':'reasons overlap; group abstention/barrier checks do not prove attack causality'}
    (a.out/'WITNESS_GROUP_RECEIPT.json').open('x').write(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2));signal.alarm(0)


if __name__=='__main__':main()
