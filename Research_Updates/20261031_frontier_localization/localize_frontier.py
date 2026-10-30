"""Bounded retrospective frontier localization; no predictions are generated."""
from pathlib import Path
import argparse
import collections
import csv
import hashlib
import json
import os
import resource
import signal
import sqlite3
import time
from frontier_core import ContextGraph, mask_names, minimal_success_masks, relaxations


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,required=True)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--reference-sha256',required=True)
    ap.add_argument('--candidate-sha256',required=True)
    ap.add_argument('--selected-rows-sha256',required=True)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args()
    start=time.monotonic()
    os.umask(0o077)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
    signal.alarm(120)
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    inputs={}

    def read(n):
        b=(args.root/n).read_bytes()
        inputs[n]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        return b

    def load(n):return json.loads(read(n))

    freeze=load('PREDICTION_FREEZE.json')
    q=load('Q.json');scores=load('NODE_SCORES.json')
    assert all(inputs[n]['sha256']==freeze[n] for n in ['Q.json','NODE_SCORES.json'])
    original=load('retrieval_predictions/CANDIDATE_RECORDS_A.json')
    assert inputs['retrieval_predictions/CANDIDATE_RECORDS_A.json']['sha256']==args.candidate_sha256
    original_keys={e['key'] for e in original}
    windows={w for row in q for w in row['alert_windows']}
    q_windows={row['index']:set(row['alert_windows']) for row in q}
    db_file=args.root/'private_events.sqlite';stat0=db_file.stat()
    db=sqlite3.connect('file:'+str(db_file)+'?mode=ro',uri=True)
    events=[];scanned=0;rows_digest=hashlib.sha256()
    try:
        for key,u,v,t,op,window in db.execute(
                "SELECT eid,src,dst,t,op,window FROM events WHERE split='test' ORDER BY eid"):
            scanned+=1
            assert scanned<=526169
            rows_digest.update(json.dumps([u,v,t,op,window],separators=(',',':')).encode()+b'\n')
            if window in windows:
                events.append({'key':key,'u':u,'v':v,'t':t,'op':op,'window':window})
                assert len(events)<=30000
    finally:db.close()
    assert scanned==526169 and rows_digest.hexdigest()==args.selected_rows_sha256
    seeds={i for i,e in enumerate(events) if any(
        e['window'] in q_windows[x] for x in {e['u'],e['v']} if x in q_windows)}
    graph=ContextGraph(events)
    distances,parents,graph_rows={},{},[]
    for mask in range(8):
        cfg=relaxations(mask)
        d,p,groups=graph.distances(seeds,cfg['neighbor_group_limit'],cfg['max_gap_ns'],cfg['unordered_ties'])
        distances[mask]=d;parents[mask]=p
        for hop_mask in [0,8]:
            actual_mask=mask|hop_mask;limit=None if hop_mask else 3
            ids={i for i,x in enumerate(d) if x>=0 and (limit is None or x<=limit)}
            graph_rows.append({'mask':actual_mask,'relaxed_conditions':'+'.join(mask_names(actual_mask)) or 'NONE',
                'reachable_events':len(ids),'reachable_nodes':len({n for i in ids for n in (events[i]['u'],events[i]['v'])}),
                'time_groups_enumerated':groups,'context_only':True})
    baseline={e['key'] for i,e in enumerate(events) if 0<=distances[0][i]<=3}
    assert baseline==original_keys,'Independent replay does not match frozen candidate event set'
    # All graph traversals above used only visible events and fixed Q, not the reference.
    mapping={int(k):v[0] for k,v in load('private_node_uuid_map.json').items()}
    ref_bytes=args.reference.read_bytes()
    assert hashlib.sha256(ref_bytes).hexdigest()==args.reference_sha256
    ref={r[0] for r in csv.reader(ref_bytes.decode().splitlines()) if r}
    scored={r['node_uuid'] for r in scores}
    candidate_nodes={mapping[n] for e in original for n in (e['u'],e['v'])}
    target=sorted((ref&scored)-candidate_nodes);assert len(target)==17
    occurrences=collections.defaultdict(list)
    for i,e in enumerate(events):
        for n in {e['u'],e['v']}:
            if mapping[n] in target:occurrences[mapping[n]].append(i)
    public,private=[],[]
    for ordinal,node in enumerate(target,1):
        ids=occurrences[node];assert ids
        minimum={mask:min((distances[mask][i] for i in ids if distances[mask][i]>=0),default=None)
                 for mask in range(8)}
        success=set()
        for mask in range(16):
            d=minimum[mask&7]
            if d is not None and (mask&8 or d<=3):success.add(mask)
        minimal=minimal_success_masks(success)
        classification=('NO_CONTEXT_PATH_WITHIN_FROZEN_WINDOWS' if not minimal else
            'MULTIPLE_ALTERNATIVE_MINIMAL_RELAXATIONS' if len(minimal)>1 else 'UNIQUE_MINIMAL_RELAXATION_SET')
        alias='F%02d'%ordinal
        row={'case_alias':alias,'baseline_unbounded_hops_distance':minimum[0],
            'minimal_relaxation_masks':json.dumps(minimal),
            'minimal_relaxation_names':json.dumps([mask_names(m) for m in minimal]),
            'classification':classification,'unordered_context_is_not_causality':True}
        public.append(row)
        witnesses=[]
        for mask in minimal:
            dlist=distances[mask&7];best=min((i for i in ids if dlist[i]>=0),key=lambda i:(dlist[i],events[i]['key']))
            path=[];i=best
            while i is not None:
                path.append(i);p=parents[mask&7][i];i=p[0] if p else None
            path.reverse()
            assert len(path)-1==dlist[best]
            witnesses.append({'mask':mask,'context_hops':dlist[best],
                'path_truncated':len(path)>64,'events':[events[i] for i in path[:64]],
                'semantics':'shared-entity context witness, not native operation or attack causality'})
        private.append({'alias':alias,'reference_node_uuid':node,'witnesses':witnesses})
    for row in graph_rows:
        cfg=row['mask'];dlist=distances[cfg&7]
        covered={mapping[n] for i,e in enumerate(events) if dlist[i]>=0 and (cfg&8 or dlist[i]<=3)
                 for n in (e['u'],e['v'])}
        row['reference_nodes_reachable']=len(ref&covered)
        row['previously_missing_reference_nodes_reachable']=len(set(target)&covered)
    stat1=db_file.stat()
    assert (stat0.st_size,stat0.st_mtime_ns)==(stat1.st_size,stat1.st_mtime_ns)
    for n,meta in inputs.items():assert hashlib.sha256((args.root/n).read_bytes()).hexdigest()==meta['sha256']
    for name,rows in [('CONDITION_PROFILES.csv',sorted(graph_rows,key=lambda r:r['mask'])),('FRONTIER_CASES.csv',public)]:
        with (out/name).open('x',newline='') as f:
            wr=csv.DictWriter(f,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)
    (out/'private').mkdir(mode=0o700)
    (out/'private/CONTEXT_WITNESSES.json').open('x').write(json.dumps(private,indent=2)+'\n')
    receipt={'status':'PASS','input':'A_author_compressed','selected_records_scanned':scanned,
        'selected_rows_sha256':rows_digest.hexdigest(),'events_in_frozen_alert_windows':len(events),
        'seed_events':len(seeds),'baseline_candidate_events':len(baseline),
        'baseline_exactly_reproduced':True,'target_reference_nodes':len(target),
        'profiles':len(graph_rows),'raw_archive_reads':0,'model_runs':0,'new_ranked_predictions':0,
        'sqlite_size_mtime_unchanged':True,'source_metadata_hashes_unchanged':True,
        'reference_read_after_unlabeled_traversals':True,
        'semantics':'retrospective shared-entity context reachability; no attack causality claims',
        'wall_seconds':time.monotonic()-start,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'CPU_affinity':sorted(os.sched_getaffinity(0)),'address_space_limit_bytes':2*1024**3,
        'time_limit_seconds':120,'physical_io_bytes':'NOT_MEASURED','input_metadata':inputs}
    (out/'RUN_RECEIPT.json').open('x').write(json.dumps(receipt,indent=2)+'\n')
    signal.alarm(0)
    print(json.dumps({'receipt':receipt,'profiles':graph_rows,'cases':public},indent=2))


if __name__=='__main__':main()
