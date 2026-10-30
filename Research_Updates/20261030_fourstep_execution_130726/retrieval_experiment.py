"""Frozen-Q, equal-budget retrieval controls. Standard diffusion, no novelty claim.

Prediction never opens the node reference. Evaluation is a separate command.
"""
from __future__ import annotations
import argparse
import bisect
import collections
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import sqlite3
import time


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical_key(e):
    """Shared A/B facts receive the same sampling priority, regardless of storage ID."""
    uid=e.get('native_uuid',e['key'].split('|',1)[0])
    return '|'.join(map(str,[uid,e['t'],e['op'],e['u'],e['v']]))


def read_windows(root: Path, version: str, split: str):
    name='private_events.sqlite' if version=='A' else 'uncompressed_events.sqlite'
    db=sqlite3.connect('file:'+str(root/name)+'?mode=ro',uri=True)
    names=[r[0] for r in db.execute('SELECT DISTINCT window FROM events WHERE split=? ORDER BY window',(split,))]
    try:
        for window in names:
            if version=='A':
                rows=db.execute('SELECT eid,src,dst,t,op FROM events WHERE split=? AND window=? ORDER BY t,eid',(split,window))
                events=[{'key':r[0],'u':r[1],'v':r[2],'t':r[3],'op':r[4],'window':window} for r in rows]
            else:
                rows=db.execute('SELECT rid,eid,src,dst,t,op FROM events WHERE split=? AND window=? ORDER BY t,eid,rid',(split,window))
                events=[{'key':'dbrow:'+str(r[0]),'native_uuid':r[1],'u':r[2],'v':r[3],'t':r[4],'op':r[5],'window':window} for r in rows]
            yield window,events
    finally:db.close()


class Neighborhood:
    def __init__(self,events):
        self.events=events
        timelines=collections.defaultdict(lambda:collections.defaultdict(list))
        for i,e in enumerate(events):
            for x in {e['u'],e['v']}:timelines[(e['window'],x)][e['t']].append(i)
        self.timelines={k:(sorted(v),v) for k,v in timelines.items()}
        self.cache={}

    def neighbors(self,i):
        if i in self.cache:return self.cache[i]
        e=self.events[i]
        channels={}
        for x in {e['u'],e['v']}:
            times,groups=self.timelines[(e['window'],x)]
            pos=bisect.bisect_left(times,e['t'])
            if len(groups[e['t']])!=1:continue
            neighbors=[]
            for direction in [-1,1]:
                for step in range(1,9):
                    at=pos+direction*step
                    if not 0<=at<len(times):break
                    gap=abs(times[at]-e['t'])
                    if gap>300_000_000_000:break
                    if len(groups[times[at]])!=1:break
                    j=groups[times[at]][0]
                    neighbors.append((j,math.exp(-gap/60_000_000_000)))
            if neighbors:channels[x]=neighbors
        result=[]
        for x,neighbors in sorted(channels.items()):
            z=sum(w for _,w in neighbors)
            result.extend((j,x,w/z/len(channels)) for j,w in neighbors)
        self.cache[i]=result
        return result


def candidates(events,q):
    neighborhood=Neighborhood(events)
    anchor_lists={r['index']:[] for r in q}
    q_windows={r['index']:set(r['alert_windows']) for r in q}
    for i,e in enumerate(events):
        for x in {e['u'],e['v']} & q_windows.keys():
            if e['window'] in q_windows[x]:anchor_lists[x].append(i)
    for x,ids in anchor_lists.items():ids.sort(key=lambda i:(digest(canonical_key(events[i])),events[i]['key']))
    selected=set()
    cursors={x:0 for x in anchor_lists}
    while len(selected)<50000:
        changed=False
        for x,ids in sorted(anchor_lists.items()):
            at=cursors[x]
            if at<len(ids):
                selected.add(ids[at]);cursors[x]+=1;changed=True
                if len(selected)==50000:break
        if not changed:break
    frontier=set(selected)
    for depth in range(3):
        proposals={j for i in frontier for j,x,w in neighborhood.neighbors(i)}-selected
        frontier=set(sorted(proposals,key=lambda i:(digest(canonical_key(events[i])),events[i]['key']))[:50000-len(selected)])
        selected|=frontier
        if not frontier or len(selected)==50000:break
    ids=sorted(selected,key=lambda i:(canonical_key(events[i]),events[i]['key']))
    position={i:k for k,i in enumerate(ids)}
    # Base relations and weights are computed on ORIGINAL timelines, then restricted.
    links=[(position[i],position[j],x,w) for i in ids for j,x,w in neighborhood.neighbors(i) if j in position]
    kept=[events[i] for i in ids]
    import numpy as np
    seed=np.zeros(3*len(kept),dtype=np.float64)
    active=0
    for x,original_ids in anchor_lists.items():
        local=[position[i] for i in original_ids if i in position]
        if local:
            active+=1
            for i in local:seed[3*i]+=1/len(local)
    if active:seed/=active
    report={'full_input_events_in_alert_windows':len(events),'candidate_events':len(ids),
            'candidate_nodes':len({x for e in kept for x in [e['u'],e['v']]}),
            'candidate_limit_reached':len(selected)==50000,'original_context_links_retained':len(links),
            'active_anchor_count':active,'all_Q_count':len(q),'seed_scope':'equal mass per supported Q; unsupported Q retained in node budget',
            'candidate_sha256':digest('\n'.join(e['key'] for e in kept))}
    del neighborhood
    return kept,links,seed,report


class OperationStats:
    def __init__(self,types):
        self.types=types
        self.count=collections.Counter();self.row=collections.Counter()
        self.column=collections.Counter();self.total=collections.Counter()
        self.accepted=0;self.abstained=0;self.vocab=set()

    def signature(self,e,x):return e['op']+':'+('src' if e['u']==x else 'dst')

    def update(self,events):
        timelines=collections.defaultdict(lambda:collections.defaultdict(list))
        for e in events:
            for x in {e['u'],e['v']}:timelines[x][e['t']].append(e)
        for x,groups in timelines.items():
            times=sorted(groups)
            for ta,tb in zip(times,times[1:]):
                if tb-ta>300_000_000_000:continue
                if len(groups[ta])!=1 or len(groups[tb])!=1:
                    self.abstained+=1;continue
                a,b=groups[ta][0],groups[tb][0]
                for source,target,direction in [(a,b,'forward'),(b,a,'backward')]:
                    sa,sb=self.signature(source,x),self.signature(target,x)
                    c=(self.types[x],direction)
                    self.count[c,sa,sb]+=1;self.row[c,sa]+=1
                    self.column[c,sb]+=1;self.total[c]+=1
                    self.vocab.update([sa,sb])
                self.accepted+=1

    def gate(self,a,b,x):
        c=(self.types[x],'forward' if a['t']<b['t'] else 'backward')
        sa,sb=self.signature(a,x),self.signature(b,x)
        ell=0.0
        if self.row[c,sa]>=20:
            m=max(1,len(self.vocab))
            conditional=(self.count[c,sa,sb]+.5)/(self.row[c,sa]+.5*m)
            marginal=(self.column[c,sb]+.5)/(self.total[c]+.5*m)
            ell=max(-3,min(3,math.log(conditional/marginal)))
        return .1+.9/(1+math.exp(-ell))


def transition_matrix(events,links,stats,operation,memory,shuffle_seed=None):
    import numpy as np
    from scipy.sparse import csr_matrix
    n=len(events)
    by_source=collections.defaultdict(list)
    for i,j,x,w in links:by_source[i].append((j,x,w))
    rows,cols,values=[],[],[]
    rng=np.random.default_rng(shuffle_seed)
    for i,e in enumerate(events):
        for h in range(3):
            previous=None if h==0 else e['u'] if h==1 else e['v']
            c,v=[],[]
            for j,x,w in by_source[i]:
                f=events[j]
                gate=stats.gate(e,f,x) if operation else 1.0
                penalty=.25 if memory and previous==x else 1.0
                c.append(3*j+(1 if f['u']==x else 2))
                v.append(w*gate*penalty)
            if shuffle_seed is not None and v:
                v=list(rng.permutation(v))
            if sum(v)>1+1e-10:raise ValueError('Invalid transition row')
            rows.extend([3*i+h]*len(v));cols.extend(c);values.extend(v)
    return csr_matrix((np.asarray(values),(rows,cols)),shape=(3*n,3*n))


def diffuse(matrix,seed,alpha):
    import numpy as np
    r=seed.copy()
    row_mass=np.asarray(matrix.sum(axis=1)).ravel()
    residual=None
    for iteration in range(100):
        returned=float(r @ (1-row_mass))
        nxt=alpha*seed+(1-alpha)*(matrix.T@r+returned*seed)
        if abs(nxt.sum()-1)>1e-8:raise ValueError('Probability mass not conserved')
        residual=float(np.abs(nxt-r).sum())
        r=nxt
        if residual<1e-8:break
    return r.reshape(-1,3).sum(axis=1),{'iterations':iteration+1,'l1_residual':residual,
               'converged':residual<1e-8,'visitation_weighted_restart':float(r @ (1-(1-alpha)*row_mass))}


def decode(events,values,q,bv,be):
    nodes={r['index'] for r in q}
    if len(nodes)>bv:return {'status':'INFEASIBLE_Q_EXCEEDS_NODE_BUDGET','nodes':sorted(nodes),'events':[]}
    selected=[]
    ranked=sorted(range(len(events)),key=lambda i:(-values[i],canonical_key(events[i]),events[i]['key']))
    for i in ranked:
        if not math.isfinite(float(values[i])):continue
        e=events[i];extra={e['u'],e['v']}-nodes
        if len(nodes)+len(extra)>bv:continue
        nodes|={e['u'],e['v']};selected.append(e)
        if len(selected)==be:break
    return {'status':'PREDICTED','nodes':sorted(nodes),'events':selected}


def run(root:Path):
    import numpy as np
    os.umask(0o077)
    os.sched_setaffinity(0,set(sorted(os.sched_getaffinity(0))[:4]))
    if not (root/'PREDICTION_FREEZE.json').is_file():raise ValueError('Q must be frozen')
    if not (root/'COMPRESSION_FACTOR_READY.json').is_file():raise ValueError('Input factor unverified')
    out=root/'retrieval_predictions'
    out.mkdir()
    q=json.loads((root/'Q.json').read_text())
    if not q:
        (out/'STATUS.json').write_text(json.dumps({'status':'NO_ALERTS','methods_run':0}))
        return
    if len(q)>200:
        (out/'STATUS.json').write_text(json.dumps({'status':'ALL_BUDGETS_INFEASIBLE','Q_count':len(q),'methods_run':0,'primary_node_budget':100,'secondary_max_node_budget':200}))
        return
    types={int(k):v[1] for k,v in json.loads((root/'private_node_uuid_map.json').read_text()).items()}
    node_scores={r['index']:r['score'] for r in json.loads((root/'NODE_SCORES.json').read_text())}
    alert_windows={w for r in q for w in r['alert_windows']}
    outputs={};run_rows=[]
    for version in ['A','B']:
        start=time.monotonic()
        stats=OperationStats(types)
        train_n=0
        for window,es in read_windows(root,version,'train'):
            stats.update(es);train_n+=len(es)
        events=[];input_n=0
        for window,es in read_windows(root,version,'test'):
            input_n+=len(es)
            if window in alert_windows:events.extend(es)
        kept,links,seed,report=candidates(events,q)
        report.update(input_version=version,total_test_input_records=input_n,training_input_records=train_n,
                      operation_pairs=stats.accepted,tied_pair_abstentions=stats.abstained)
        (out/('CANDIDATES_'+version+'.json')).write_text(json.dumps(report,indent=2))
        (out/('CANDIDATE_RECORDS_'+version+'.json')).write_text(json.dumps(kept))
        if not kept or not seed.sum():
            run_rows.append({'version':version,'status':'NO_SUPPORTED_ANCHOR_EVENTS'});continue
        seed_times=collections.defaultdict(list)
        for i,e in enumerate(kept):
            if seed[3*i]>0:seed_times[e['window']].append(e['t'])
        for ts in seed_times.values():ts.sort()

        def time_distance(e):
            ts=seed_times[e['window']]
            pos=bisect.bisect_left(ts,e['t'])
            choices=ts[max(0,pos-1):min(len(ts),pos+1)]
            return -min(abs(e['t']-t) for t in choices)/1e9 if choices else -math.inf

        methods=[('frozen_node_anomaly_score',None,None,None),('time_distance',None,None,None),
                 ('first_order_diffusion',False,False,None),('operation_gate_only',True,False,None),
                 ('memory_only',False,True,None),('operation_plus_memory',True,True,None)]
        methods += [('row_mass_shuffle_%d'%i,True,True,i) for i in range(5)]
        budgets=[(100,500),(25,500),(50,500),(200,500),(100,100),(100,2000)]
        for method,op,memory,shuffle in methods:
            mstart=time.monotonic()
            matrix=None
            if method=='frozen_node_anomaly_score':
                values=np.array([max(node_scores.get(e['u'],-math.inf),node_scores.get(e['v'],-math.inf)) for e in kept])
                metrics={}
            elif method=='time_distance':
                values=np.array([time_distance(e) for e in kept]);metrics={}
            else:
                matrix=transition_matrix(kept,links,stats,op,memory,shuffle)
                values,metrics=diffuse(matrix,seed,.2)
                values=np.where(values>0,values,-np.inf)
            ranking_seconds=time.monotonic()-mstart
            for bv,be in budgets:
                decode_started=time.monotonic()
                prediction=decode(kept,values,q,bv,be)
                key='%s__%s__n%d_e%d'%(version,method,bv,be)
                path=out/(key+'.json')
                path.write_text(json.dumps(prediction))
                outputs[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
                run_rows.append({'version':version,'method':method,'node_budget':bv,'event_budget':be,
                     'actual_nodes':len(prediction['nodes']),'actual_events':len(prediction['events']),
                     'unique_native_fact_count':len({(e.get('native_uuid',e['key'].split('|',1)[0]),e['u'],e['v'],e['t'],e['op']) for e in prediction['events']}),
                     'status':prediction['status'],'ranking_seconds':ranking_seconds,'decode_and_save_seconds':time.monotonic()-decode_started,**metrics})
            if method in ['first_order_diffusion','memory_only']:
                for alpha in [.1,.4,.6,.8]:
                    vals,ms=diffuse(matrix,seed,alpha)
                    vals=np.where(vals>0,vals,-np.inf)
                    prediction=decode(kept,vals,q,100,500)
                    key='%s__%s__alpha%.1f'%(version,method,alpha)
                    path=out/(key+'.json');path.write_text(json.dumps(prediction))
                    outputs[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
                    run_rows.append({'version':version,'method':method,'alpha':alpha,'node_budget':100,'event_budget':500,
                         'actual_nodes':len(prediction['nodes']),'actual_events':len(prediction['events']),
                     'unique_native_fact_count':len({(e.get('native_uuid',e['key'].split('|',1)[0]),e['u'],e['v'],e['t'],e['op']) for e in prediction['events']}),**ms})
            print(json.dumps({'version':version,'method':method,'ranking_seconds':time.monotonic()-mstart}),flush=True)
            del matrix;gc.collect()
        run_rows.append({'version':version,'total_seconds':time.monotonic()-start})
    (out/'PREDICTION_FREEZE.json').write_text(json.dumps(outputs,indent=2))
    (out/'RUNS.json').write_text(json.dumps(run_rows,indent=2))
    (out/'STATUS.json').write_text(json.dumps({'status':'FROZEN_BEFORE_EVALUATION','prediction_files':len(outputs),
            'labels_read':False,'rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    run(p.parse_args().out.resolve())
