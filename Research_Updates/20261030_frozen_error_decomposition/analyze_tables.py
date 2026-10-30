"""Descriptive summaries only: routing seeds are not independent attacks."""
from pathlib import Path
import csv
import json
import statistics
import argparse


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--root',type=Path,required=True)
    root=ap.parse_args().root.resolve()
    rows=list(csv.DictReader((root/'artifacts/RETRIEVAL_METRICS.csv').open()))
    contrasts=list(csv.DictReader((root/'artifacts/FULL_MODULE_CONTRASTS.csv').open()))
    conditions=['n25_e500','n50_e500','n100_e500','n200_e500','n100_e100','n100_e2000']
    summary=[]
    for v in ['A','B']:
        for condition in conditions:
            selected=[x for x in rows if x['input']==v and x['condition']==condition]
            by_method={x['method']:x for x in selected}
            shuffled=[int(x['annotation_hits']) for x in selected if x['method'].startswith('row_mass_shuffle_')]
            assert len(shuffled)==5
            full=int(by_method['operation_plus_memory']['annotation_hits'])
            plain=int(by_method['first_order_diffusion']['annotation_hits'])
            summary.append({'input':v,'condition':condition,'full_hits':full,'plain_hits':plain,
                'full_minus_plain_hits':full-plain,'full_minus_plain_recall_percentage_points':100*(full-plain)/43,
                'operation_only_hits':int(by_method['operation_gate_only']['annotation_hits']),
                'memory_only_hits':int(by_method['memory_only']['annotation_hits']),
                'shuffle_n_routing_seeds':len(shuffled),'shuffle_mean_hits':statistics.mean(shuffled),
                'shuffle_sample_sd_hits':statistics.stdev(shuffled),
                'shuffle_min_hits':min(shuffled),'shuffle_max_hits':max(shuffled),
                'shuffle_seeds_at_least_full':sum(x>=full for x in shuffled),
                'independent_attacks':1,'confidence_interval':'NOT_IDENTIFIABLE',
                'p_value':'NOT_IDENTIFIABLE'})
    if not (root/'artifacts/BUDGET_SUMMARY.csv').exists():
        with (root/'artifacts/BUDGET_SUMMARY.csv').open('x',newline='') as stream:
            wr=csv.DictWriter(stream,fieldnames=list(summary[0]));wr.writeheader();wr.writerows(summary)
    else:
        existing=list(csv.DictReader((root/'artifacts/BUDGET_SUMMARY.csv').open()))
        assert existing==[{k:str(v) for k,v in x.items()} for x in summary]
    receipt=json.loads((root/'artifacts/AUDIT_RECEIPT.json').read_text())
    scope=json.loads((root/'artifacts/CANDIDATE_SCOPE_AUDIT.json').read_text())
    assert receipt['predictions_unchanged'] and scope['sqlite_size_mtime_unchanged']
    assert scope['missing_reference_in_Q_alert_windows_but_outside_candidate_frontier']==17
    coverage=json.loads((root/'artifacts/COVERAGE_PARTITIONS.json').read_text())['A']
    primary=next(x for x in rows if x['input']=='A' and x['method']=='operation_plus_memory'
                 and x['condition']=='n100_e500')
    full_hits=int(primary['annotation_hits'])
    total=coverage['reference_total']
    outside=coverage['reference_outside_scored_universe']
    frontier=coverage['reference_scored_but_outside_candidates']
    concentration=list(csv.DictReader((root/'artifacts/EVENT_CONCENTRATION.csv').open()))
    b_anomaly=next(x for x in concentration if x['input']=='B' and x['method']=='frozen_node_anomaly_score')
    decision={'status':'FRONTIER_COVERAGE_AND_EVENT_CONCENTRATION_IDENTIFIED',
        'original_predictions_modified':False,'new_model_runs':0,'independent_attacks':1,
        'full_primary_reference_hits':full_hits,'primary_misses':total-full_hits,
        'miss_outside_scored_input':outside,'miss_outside_frontier':frontier,
        'miss_within_frontier':coverage['reference_in_candidates']-full_hits,
        'pre_ranking_fraction_of_primary_misses':(outside+frontier)/(total-full_hits),
        'candidate_misses_within_Q_alert_windows':scope['missing_reference_in_Q_alert_windows_but_outside_candidate_frontier'],
        'B_anomaly_largest_pair_fraction':float(b_anomaly['largest_pair_fraction']),
        'low_budget_full_minus_plain_gains':[
            {'input':x['input'],'condition':x['condition'],'gain':x['full_minus_plain_hits']}
            for x in summary if x['full_minus_plain_hits']>0],
        'all_slices_joint_hits_equal_single_modules':all(
            x['full_hits']==x['operation_only_hits']==x['memory_only_hits'] for x in summary),
        'all_shuffle_seeds_match_or_exceed_full_in_each_slice':all(
            x['shuffle_seeds_at_least_full']==5 for x in summary),
        'joint_mechanism_value_established':False,'activity_or_causal_reconstruction_established':False,
        'next_priority':'LOCALIZE_EXISTING_FRONTIER_EXCLUSION_BEFORE_NEW_RANKER',
        'next_priority_scope':'Existing frozen events only; distinguish hop, time, tie-abstention and missing native relations',
        'posthoc_reference_use':'Diagnostic only; may not be reused as untouched validation',
        'automatic_next_stage_started':False}
    payload=json.dumps(decision,indent=2)+'\n'
    path=root/'DECISION.json'
    if path.exists():assert path.read_text()==payload
    else:path.open('x').write(payload)
    # Internal data-boundary checks, not additional attack experiments.
    assert len(rows)==148 and len(contrasts)==120 and len(summary)==12
    assert all(x['partition_sum_verified']=='True' for x in csv.DictReader(
        (root/'artifacts/PER_PREDICTION_AUDIT.csv').open()))
    assert decision['all_slices_joint_hits_equal_single_modules']
    assert decision['all_shuffle_seeds_match_or_exceed_full_in_each_slice']
    print(json.dumps({'summary_rows':len(summary),'decision':decision},indent=2))


if __name__=='__main__':main()
