"""Summarize fixed reachability profiles; no ranking or model execution."""
from pathlib import Path
import argparse
import csv
import hashlib
import json


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True)
    root=ap.parse_args().root.resolve()
    rows=list(csv.DictReader((root/'artifacts/CONDITION_PROFILES.csv').open()))
    cases=list(csv.DictReader((root/'artifacts/FRONTIER_CASES.csv').open()))
    profiles={int(x['mask']):x for x in rows}
    assert set(profiles)==set(range(16)) and len(cases)==17
    classified={'tie_context_alone':0,'tie_context_plus_another_relaxation':0,'no_context_path':0}
    for case in cases:
        masks=json.loads(case['minimal_relaxation_masks'])
        if not masks:classified['no_context_path']+=1
        elif masks==[4]:classified['tie_context_alone']+=1
        else:
            assert all(m&4 for m in masks)
            classified['tie_context_plus_another_relaxation']+=1
    assert sum(classified.values())==len(cases)
    assert all(case['baseline_unbounded_hops_distance']=='' for case in cases)
    for mask in range(16):
        x=profiles[mask]
        assert int(x['reference_nodes_reachable'])==24+int(x['previously_missing_reference_nodes_reachable'])
        if not mask&4:assert int(x['previously_missing_reference_nodes_reachable'])==0
        for bit in [1,2,4,8]:
            if not mask&bit:
                assert int(profiles[mask|bit]['reachable_events'])>=int(x['reachable_events'])
    witness=json.loads((root/'artifacts/PRIVATE_WITNESS_AUDIT.json').read_text())
    steps=json.loads((root/'witness_group_audit/WITNESS_GROUP_RECEIPT.json').read_text())
    assert witness['private_file_sha256']==steps['witness_sha256']
    receipt=json.loads((root/'artifacts/RUN_RECEIPT.json').read_text())
    assert receipt['baseline_exactly_reproduced'] and receipt['model_runs']==0
    decision={'status':'TIE_GROUP_ABSTENTION_AND_BARRIERS_LOCALIZED_IN_INPUT_A',
        'input_scope':'existing author-compressed A, one exposed development attack',
        'target_reference_nodes':len(cases),'mutually_exclusive_node_classes':classified,
        'strict_context_unreachable_target_nodes_even_without_hop_cap':len(cases),
        'any_profile_without_tie_relaxation_recovers_targets':any(
            int(profiles[m]['previously_missing_reference_nodes_reachable'])>0
            for m in range(16) if not m&4),
        'tie_only_candidate_reference_nodes':int(profiles[4]['reference_nodes_reachable']),
        'tie_only_candidate_events':int(profiles[4]['reachable_events']),
        'tie_only_candidate_event_expansion':int(profiles[4]['reachable_events'])/int(profiles[0]['reachable_events']),
        'fully_relaxed_same_window_reference_nodes':int(profiles[15]['reference_nodes_reachable']),
        'witness_paths':witness['context_witness_paths'],
        'witness_paths_with_equal_timestamp_steps':witness['paths_using_equal_timestamp_context_steps'],
        'blocked_witness_steps':steps['steps_unavailable_under_baseline'],
        'overlapping_block_reasons':steps['baseline_block_reason_step_counts_overlapping'],
        'candidate_potential_is_not_budgeted_recovery':True,
        'attack_causality_established':False,'activity_membership_established':False,
        'new_ranked_predictions':0,'model_runs':0,'reference_is_posthoc_development_only':True,
        'next_priority':'THREE_ARM_CANDIDATE_POLICY_PILOT_WITH_FROZEN_RANKER',
        'pilot_executed':False,'new_heldout_qualification':False}
    (root/'DECISION.json').open('x').write(json.dumps(decision,indent=2)+'\n')
    supplemental={'file':'audit_witness_groups.py','sha256':hashlib.sha256((root/'audit_witness_groups.py').read_bytes()).hexdigest(),
        'timing':'recorded after supplemental diagnostic execution; not a preregistration',
        'purpose':'validate saved context witness group barriers without generating predictions'}
    (root/'SUPPLEMENTAL_CODE_RECORD.json').open('x').write(json.dumps(supplemental,indent=2)+'\n')
    print(json.dumps(decision,indent=2))


if __name__=='__main__':main()
