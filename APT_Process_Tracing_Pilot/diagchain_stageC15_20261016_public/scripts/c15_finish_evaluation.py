"""No model path: resume official CPU evaluation after receipt-only Path hash bug."""
from __future__ import annotations
import os,subprocess,shlex,time
from pathlib import Path
from c15_common import *
import c15_resume_mux as mux
import c15_postrun_finalize as post
import c15_evaluate_and_report as stage
import c15_reporting_addendum as disclosure
from ssh_ack_transport import exchange

def evaluation_rpc(plan:dict,attempt:str,mode:str,payload:dict,*,deadline:float,evaluator:bool=False,timeout:float=60)->dict:
    if mode!='evaluate':return mux.rpc(plan,attempt,mode,payload,deadline=deadline,evaluator=evaluator,timeout=timeout)
    def send(m:str,p:dict,left:float)->dict:
        remote=Path(plan['server_root']);argv=['ssh','-i',plan['ssh_identity_file'],'-o','BatchMode=yes','-o','ConnectTimeout=30','-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+mux.SOCKET,plan['server'],shlex.join([plan['evaluator_python'],'-B',str(remote/'src/c15_eval_receipt_recovery.py'),str(remote/'private_recovery_attempts'/attempt),m])]
        v=subprocess.run(argv,cwd=ROOT,input=json.dumps(p),text=True,capture_output=True,timeout=left,shell=False)
        if v.returncode==255:raise ConnectionError('EVALUATION_SSH_TRANSPORT_FAILURE')
        if v.returncode:
            atomic_create(ROOT/'logs','evaluation_receipt_failure_'+str(time.time_ns())+'.json',{'stderr':v.stderr,'exit':v.returncode})
            raise SafetyError('EVALUATION_RECEIPT_ADAPTER_REJECTED')
        return strict_json(v.stdout)
    return exchange(mode,payload,send,deadline=deadline,rpc_limit=timeout)

if __name__=='__main__':
    os.umask(0o077);frozen_check(ROOT);evaluation_gate(ROOT)
    for x in read(ROOT/'27_evaluation_receipt_repair_freeze.json')['files']:
        if sha(safe_path(ROOT,x['path']).read_bytes())!=x['sha256']:raise SafetyError('EVALUATION_RECEIPT_REPAIR_SOURCE_CHANGED')
    before=len(list((ROOT/'runs').glob('*/exchange_*/cli_start_receipt.json')));post.install_resolution_reader();stage.rpc=evaluation_rpc
    stage.evaluate(ROOT);stage.reports(ROOT);disclosure.render(ROOT);gate=read(ROOT/'reports/16_final_gate.json');common=post.common;common.progress(ROOT,gate['state'])
    if len(list((ROOT/'runs').glob('*/exchange_*/cli_start_receipt.json')))!=before:raise SafetyError('MODEL_CALL_AFTER_BATCH_SEAL')
    print(json.dumps({'state':gate['state'],'decision':gate['decision'],'evaluated':gate['evaluated_primary_metric'],'model_cli_starts':before,'new_model_calls_during_evaluation':0}))
