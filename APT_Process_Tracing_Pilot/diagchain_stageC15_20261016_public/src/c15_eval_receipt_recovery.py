"""Post-seal CPU evaluation receipt repair; original evaluator stays byte-identical."""
from __future__ import annotations
import os,sys,json,time,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from c15_common import *
import c15_server_protocol as original

def evaluate(root:Path)->dict:
    batch=evaluation_gate(ROOT);c=original.attempt_contract(root);original.unit_by_attempt(root);original.verify_sources(c)
    unit=next(t for t in batch['units'] if t['run_unit_id']==c['run_unit_id'])
    if unit['status']!='FROZEN' or unit['attempt_id']!=c['attempt_id'] or not (root/'mac_freeze_attestation.json').exists():raise SafetyError('ONLY_ATTESTED_FROZEN_OUTPUT_EVALUABLE')
    frozen=read(root/'prediction_trace_freeze.json')
    def verify():
        for x in frozen['files']:
            if sha(safe_path(root,x['path']).read_bytes())!=x['sha256']:raise SafetyError('FROZEN_OUTPUT_CHANGED')
    verify();out=ROOT/'evaluation'/c['run_unit_id'];full=out/'official_evaluation.json';complete=out/'evaluation_complete.json'
    if complete.exists():
        cached=read(complete);raw=full.read_text()
        if sha(raw)!=cached['official_result_sha256']:raise SafetyError('EVALUATED_RESULT_HASH_CHANGED')
        return {**cached,'official_result_utf8':raw}
    out.mkdir(mode=0o700,parents=True,exist_ok=True)
    started=out/'evaluation_started.json';batch_hash=sha((ROOT/'09_batch_terminal_freeze.json').read_bytes())
    if started.exists():
        if read(started)['batch_freeze_sha256']!=batch_hash:raise SafetyError('PARTIAL_EVALUATION_BATCH_VERSION_CHANGED')
    else:atomic_create(out,'evaluation_started.json',{'utc':utc(),'first_C15_Gold_semantic_read_after_entire_batch_seal':True,'batch_freeze_sha256':batch_hash})
    for key in ['input','ground_truth']:
        item=c['case_paths'][key]
        if sha(Path(item['path']).read_bytes())!=item['sha256']:raise SafetyError('EVALUATION_INPUT_OR_GOLD_VERSION_CHANGED')
    os.environ.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(ROOT/'tmp'),XDG_CACHE_HOME=str(ROOT/'cache'))
    def timeout(*unused):raise SafetyError('EVALUATOR_CPU_TIMEOUT')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(180)
    sys.path.insert(0,str(ROOT/'author_tree/benchmark'));import evaluate_chain_reconstruction as official
    fresh=official.evaluate(read(root/'prediction.json'),strict_json(Path(c['case_paths']['ground_truth']['path']).read_text()),strict_json(Path(c['case_paths']['input']['path']).read_text()))
    retained_partial=full.exists()
    if retained_partial:
        if read(full)!=fresh:raise SafetyError('FRESH_OFFICIAL_EVALUATION_DIFFERS_FROM_THIS_ROUND_PARTIAL_RESULT')
    else:atomic_create(out,'official_evaluation.json',fresh)
    verify();signal.alarm(0)
    metrics={k:v for k,v in fresh['metrics'].items() if isinstance(v,(int,float,bool)) or v is None}
    for name,key in [('bestmatch_order_pair_count','best_matches'),('ceaf_order_pair_count','ceaf_matches')]:metrics[name]=len(fresh[key])*(len(fresh[key])-1)//2
    receipt={'state':'OFFICIAL_EVALUATED','run_unit_id':c['run_unit_id'],'metrics':metrics,'prediction_sha256':sha((root/'prediction.json').read_bytes()),'trace_sha256':sha((root/'trace.json').read_bytes()),
        'evaluator_sha256':sha((ROOT/'author_tree/benchmark/evaluate_chain_reconstruction.py').read_bytes()),'Gold_exposed_to_worker':False,'official_result_sha256':sha(full.read_bytes()),
        'receipt_adapter':'C15_EVALUATOR_PATH_HASH_RECEIPT_FIX_V1','existing_this_round_partial_result_retained_and_recomputed_equal':retained_partial,'new_model_calls':0}
    atomic_create(out,'evaluation_complete.json',receipt);return {**receipt,'official_result_utf8':full.read_text()}

if __name__=='__main__':
    os.umask(0o077)
    try:
        if sys.argv[2]!='evaluate' or strict_json(sys.stdin.read(10000))!={}:raise SafetyError('ONLY_FROZEN_OFFICIAL_EVALUATION_SUPPORTED')
        print(json.dumps(evaluate(Path(sys.argv[1])),ensure_ascii=False))
    except Exception as e:print(json.dumps({'state':'EVALUATION_RECEIPT_REJECTED','reason':str(e)[:500]}),file=sys.stderr);raise SystemExit(3)
