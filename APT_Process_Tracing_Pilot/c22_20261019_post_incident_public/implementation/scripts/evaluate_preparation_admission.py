"""Independent process: eligibility audit of preparation, no answer read while incomplete.
A semantic reference evaluation is deliberately deferred to completed-data frozen trial.
"""
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    out=R/'candidate_output/preparation'
    for name in ['CANDIDATE_FREEZE.json','BASELINE_FREEZE.json']:
        d=json.loads((out/name).read_text())
        for rel,h in d['outputs'].items():assert sha(R/rel)==h
    audit=json.loads((out/'GENERATION_AUDIT.json').read_text());b=json.loads((out/'BASELINE_RESULT_PRIVATE.json').read_text());assert audit['raw_missing']>0
    d={'task_id':'C22_POST_INCIDENT_SOURCE_TRACING_EVALUATION_ADMISSION_V1','status':'C22_NATIVE_READ_AUTHORIZATION_PENDING','phase':'PREPARATION_ONLY','GO_NO_GO':'NO_GO_PENDING_NEW_READ','B_level':'B2_POSTHOC_MAPPED_EVENT_INHERITED_UNCHANGED','A_reference_level':'A2_REMOTE_EXECUTION_SESSION_INHERITED_UNCHANGED_NOT_REEVALUATED','correct_A_in_universe':'NOT_EVALUATED_REFERENCE_DEFERRED','correct_A_posthoc_identifiable':'INHERITED_C20_POSTHOC_REFERENCE_ONLY','A_historical_origin_grade':'HISTORICAL_ORIGIN_TIME_UNRESOLVED','candidate_universe_status':'PARTIAL_UNIVERSE','candidate_count':audit['candidate_count'],'complete_identity_count':audit['complete_identity_count'],'post_incident_identity_eligibility':'OBSERVED_CONTEXTS_ONLY_NOT_COMPLETE_UNIVERSE','historical_causal_eligibility':False,'raw_coverage_complete':False,'raw_available':audit['raw_available'],'raw_missing':audit['raw_missing'],'index_native_time_recall_proven_complete':False,'reference_leakage':False,'reference_read_this_stage':False,'historical_supervisor_exposure':True,'strict_blind_claim':False,'temporal_causality_leakage':False,'direct_parent_baseline_result':b['evaluation_state'],'legal_identity_match_count':b['identity_join_match_count'],'posthoc_diagnostic_match_count':b['posthoc_diagnostic_match_count'],'posthoc_diagnostic_is_source_success':False,'nontriviality_established':False,'source_ranking_ready':False,'path_F1_ready':False,'future_causal_edges_created':0,'ZIP_member_reads':0,'next_minimum_action':'Obtain the single C22-specific human approval bound to missing target set and frozen code; then one bounded sequential member read. No reference-based rule changes.','additional_admission_limit':'Completing288 raw records does not itself prove index retrieval covers every native historical session or resolve missing timezone/order. Retain NO_GO if those gates remain.'}
    p=R/'05_EVALUATION_ADMISSION_AND_DIFFICULTY.json'
    with p.open('x') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(d,ensure_ascii=False))
if __name__=='__main__':main()
