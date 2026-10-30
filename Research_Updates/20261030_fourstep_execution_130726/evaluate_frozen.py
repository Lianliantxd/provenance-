"""Post-freeze, reference-reading evaluator. Never changes any prediction."""
from __future__ import annotations
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path


def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(2**20),b''):h.update(block)
    return h.hexdigest()


def fact(e):
    return (e.get('native_uuid',e['key'].split('|',1)[0]),e['u'],e['v'],e['t'],e['op'])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--reference-sha256',required=True)
    args=parser.parse_args();root=args.out.resolve()
    if not (root/'TEST_RESULT.json').is_file():raise ValueError('Test must complete before evaluation')
    freeze=json.loads((root/'PREDICTION_FREEZE.json').read_text())
    for name,h in freeze.items():
        if sha(root/name)!=h:raise ValueError('Frozen model/Q/score identity mismatch: '+name)
    epochs=[json.loads(s) for s in (root/'EPOCHS.jsonl').read_text().splitlines()]
    if len(epochs)!=20 or [r['epoch'] for r in epochs]!=list(range(1,21)):
        raise ValueError('Twenty complete epochs required')
    selected=min(epochs,key=lambda r:(r['validation_event_weighted_loss'],r['epoch']))
    selection=json.loads((root/'SELECTION.json').read_text())
    if selected['epoch']!=selection['epoch'] or selected['validation_max_event_loss']!=selection['threshold']:
        raise ValueError('Validation-only checkpoint/threshold rule violated')
    if sha(args.reference)!=args.reference_sha256:raise ValueError('Fixed reference bytes changed')
    reference={r[0] for r in csv.reader(args.reference.open()) if r}
    if len(reference)!=43:raise ValueError('Fixed reference identity/count mismatch')
    q=json.loads((root/'Q.json').read_text())
    qids={r['node_uuid'] for r in q}
    scores=json.loads((root/'NODE_SCORES.json').read_text())
    scored={r['node_uuid'] for r in scores}
    metrics={'reference_sha256':sha(args.reference),'reference_nodes':len(reference),
        'reference_nodes_in_scored_universe':len(reference&scored),'scored_nodes':len(scored),
        'Q_count':len(qids),'Q_annotation_hits':len(qids&reference),
        'Q_recall43':len(qids&reference)/43,
        'Q_reference_overlap_fraction':len(qids&reference)/len(qids) if qids else None,
        'unannotated_Q_nodes':len(qids-reference),'unannotated_semantics':'UNKNOWN, not verified benign',
        'true_attack_precision':None,'activity_membership_f1':None,'causal_edge_f1':None,'causal_path_f1':None,
        'claim_scope':'controlled adaptation, exposed development case, validation-only checkpoint/threshold selection'}
    (root/'DEVELOPMENT_DETECTION_METRICS.json').open('x').write(json.dumps(metrics,indent=2))
    pred=root/'retrieval_predictions'
    if not pred.exists():
        print(json.dumps(metrics,indent=2));return
    status=json.loads((pred/'STATUS.json').read_text())
    if status['status']!='FROZEN_BEFORE_EVALUATION':
        (root/'RETRIEVAL_EVALUATION_STATUS.json').write_text(json.dumps({'status':status['status'],'no_retrieval_accuracy_generated':True},indent=2))
        print(json.dumps({'detection':metrics,'retrieval':status},indent=2));return
    manifest=json.loads((pred/'PREDICTION_FREEZE.json').read_text())
    if not manifest:
        (root/'RETRIEVAL_EVALUATION_STATUS.json').write_text(json.dumps({'status':'NO_SUPPORTED_CANDIDATES','no_retrieval_accuracy_generated':True}))
        print(json.dumps({'detection':metrics,'retrieval':'NO_SUPPORTED_CANDIDATES'},indent=2));return
    for name,h in manifest.items():
        if sha(pred/name)!=h:raise ValueError('Retrieval prediction changed before evaluation')
    mapping={int(k):v[0] for k,v in json.loads((root/'private_node_uuid_map.json').read_text()).items()}
    targets=json.loads((root/'EVALUATION_ONLY_EVENT_TARGETS.json').read_text())
    target_facts={(x['native_uuid'],x['u'],x['v'],x['t'],x['op']) for x in targets}
    runs=json.loads((pred/'RUNS.json').read_text())
    rows=[]
    for name in sorted(manifest):
        output=json.loads((pred/name).read_text())
        nodes={mapping[n] for n in output['nodes']}
        facts={fact(e) for e in output['events']}
        parts=name[:-5].split('__')
        valid=output['status']=='PREDICTED'
        rows.append({'file':name,'input':parts[0],'method':parts[1],'condition':parts[2],
            'status':output['status'],'returned_nodes':len(nodes),'returned_events':len(output['events']),
            'unique_native_facts':len(facts),'annotation_hits':len(nodes&reference) if valid else None,
            'new_annotation_hits':len((nodes-qids)&reference) if valid else None,'recall43':len(nodes&reference)/43 if valid else None,
            'reference_overlap_fraction':len(nodes&reference)/len(nodes) if nodes and valid else None,
            'unannotated_nodes':len(nodes-reference) if valid else None,'limited_event_targets_hit':len(facts&target_facts) if valid else None,
            'limited_event_targets_total':len(target_facts),'true_precision':'NA','activity_f1':'NA','causal_path_f1':'NA'})
    with (root/'RETRIEVAL_METRICS.csv').open('x',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=list(rows[0]));wr.writeheader();wr.writerows(rows)
    ceilings=[]
    for version in ['A','B']:
        es=json.loads((pred/('CANDIDATE_RECORDS_'+version+'.json')).read_text())
        candidate_nodes={mapping[n] for e in es for n in (e['u'],e['v'])}
        candidate_facts={fact(e) for e in es}
        ceilings.append({'input':version,'candidate_node_annotation_hits':len(candidate_nodes&reference),
             'candidate_node_recall43_ceiling':len(candidate_nodes&reference)/43,
             'limited_event_targets_in_candidates':len(candidate_facts&target_facts)})
    (root/'CANDIDATE_REFERENCE_CEILINGS.json').write_text(json.dumps(ceilings,indent=2))
    # Recheck after reading references. This is integrity evidence, not a scientific proof.
    assert all(sha(pred/name)==h for name,h in manifest.items())
    (root/'RETRIEVAL_EVALUATION_STATUS.json').write_text(json.dumps({'status':'POST_FREEZE_EVALUATION_COMPLETE',
        'predictions_checked':len(manifest),'predictions_unchanged':True,'reference_scope':'43 positive nodes + 3 limited development event targets; no confirmed negative event reference',
        'independent_attack_count':1,'random_seeds_are_not_independent_attacks':True},indent=2))
    primary=[r for r in rows if r['condition']=='n100_e500']
    print(json.dumps({'detection':metrics,'primary_retrieval':primary,'ceilings':ceilings},indent=2))


if __name__=='__main__':main()
