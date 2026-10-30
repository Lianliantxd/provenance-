"""Finite same-task continuation: wait for frozen Q, run controls, then evaluate."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
import subprocess
import time
import traceback


def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(2**20),b''):h.update(block)
    return h.hexdigest()


def main():
    args=argparse.ArgumentParser();args.add_argument('--out',type=Path,required=True)
    args.add_argument('--reference-sha256',required=True)
    cfg=args.parse_args();root=cfg.out.resolve()
    def status(stage,**kw):
        v={'stage':stage,**kw};tmp=root/'AFTER_TRAINING_STATUS.tmp'
        tmp.write_text(json.dumps(v,indent=2));tmp.replace(root/'AFTER_TRAINING_STATUS.json')
        print(json.dumps(v),flush=True)
    files=['retrieval_experiment.py','evaluate_frozen.py','EVALUATION_ONLY_EVENT_TARGETS.json','PHASE2_DECISION.json']
    expected={n:sha(root/n) for n in files}
    (root/'PILOT_RUN_FREEZE.json').open('x').write(json.dumps({'files':expected,
        'parameters':{'alpha_primary':.2,'rho':.25,'tau_seconds':60,'min_count':20,'smoothing':.5,
          'operation_gate_floor':.1,'operation_log_ratio_clip':[-3,3],'iterations':100,'tolerance':1e-8,
          'input_versions':['A','B'],'primary_node_budget':100,'primary_event_budget':500},
        'new_model_predictions_seen_when_code_frozen':(root/'TEST_RESULT.json').exists(),
        'scope':'development retrieval experiment only; no activity disentanglement or causality claim'},indent=2))
    try:
        review=json.loads((root/'PHASE2_DECISION.json').read_text())
        if review['limited_relevance_targets']<1:
            raise ValueError('No independently corroborated limited retrieval target; do not start mechanism experiment')
        if json.loads((root/'RETRIEVAL_TEST_RECEIPT.json').read_text())['exit_code']!=0:
            raise ValueError('Boundary tests did not pass')
        status('WAITING_FOR_TWENTY_EPOCH_TRAINING_AND_FROZEN_Q')
        pid=json.loads((root/'LAUNCH.json').read_text())['pid']
        while not (root/'TEST_RESULT.json').is_file():
            if (root/'FAILURE_all.json').is_file():raise RuntimeError('Paired runner failed; preserve failure receipt')
            if not Path('/proc/%d'%pid).exists():raise RuntimeError('Paired runner stopped without a frozen test result')
            time.sleep(15)
        if not (root/'COMPRESSION_FACTOR_READY.json').is_file():raise ValueError('A/B equivalence proof unavailable')
        for n,v in expected.items():
            if sha(root/n)!=v:raise ValueError('Pilot code/reference changed after freeze')
        cpus=json.loads((root/'CPU_AFFINITY_ADJUSTMENT.json').read_text())['new_cpus']
        os.sched_setaffinity(0,set(cpus))
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',CUDA_VISIBLE_DEVICES='',OPENBLAS_NUM_THREADS='4',OMP_NUM_THREADS='4')
        python=sys.executable
        status('RUNNING_COMMON_INPUT_RETRIEVAL_CONTROLS')
        with (root/'retrieval_run.log').open('xb') as f:
            r=subprocess.run([python,'-u','-B',str(root/'retrieval_experiment.py'),'--out',str(root)],
                 cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT)
        if r.returncode:raise RuntimeError('Retrieval worker exit code '+str(r.returncode))
        status('EVALUATING_FROZEN_PREDICTIONS_ONLY')
        reference=os.environ['ORTHRUS_REFERENCE_FILE']
        with (root/'evaluation_run.log').open('xb') as f:
            r=subprocess.run([python,'-u','-B',str(root/'evaluate_frozen.py'),'--out',str(root),
                    '--reference',reference,'--reference-sha256',cfg.reference_sha256],cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT)
        if r.returncode:raise RuntimeError('Independent evaluator exit code '+str(r.returncode))
        status('EXPERIMENTS_COMPLETE_READY_FOR_FINAL_SCIENTIFIC_DECISION',retrieval_exit_code=0,evaluation_exit_code=0)
    except Exception as exc:
        status('POST_TRAINING_BLOCKED_OR_FAILED',error_type=type(exc).__name__,message=str(exc))
        (root/'AFTER_TRAINING_FAILURE.json').write_text(json.dumps({'traceback':traceback.format_exc()},indent=2))
        raise


if __name__=='__main__':main()
