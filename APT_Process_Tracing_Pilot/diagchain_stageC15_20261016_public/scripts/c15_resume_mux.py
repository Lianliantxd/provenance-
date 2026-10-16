"""Temporary same-host SSH connection reuse around the frozen ACK transport."""
from __future__ import annotations
import argparse,os,shlex,subprocess,time
from pathlib import Path
from c15_common import *
from ssh_ack_transport import exchange
import c15_resume_compat as compat
import c15_run_batch as native_batch

VERSION='C15_SSH_MUX_V1'
SOCKET='tmp/c15_mux_v1.sock'

def rpc(plan:dict,attempt:str,mode:str,payload:dict,*,deadline:float,evaluator:bool=False,timeout:float=60)->dict:
    safe_path(ROOT,SOCKET)
    remote=Path(plan['server_root']);py=plan['evaluator_python' if evaluator else 'controller_python']
    def send(m:str,p:dict,left:float)->dict:
        argv=['ssh','-i',plan['ssh_identity_file'],'-o','BatchMode=yes','-o','ConnectTimeout=30',
              '-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+SOCKET,
              plan['server'],shlex.join([py,'-B',str(remote/'src/c15_server_protocol.py'),str(remote/'private_recovery_attempts'/attempt),m])]
        v=subprocess.run(argv,cwd=ROOT,input=json.dumps(p,ensure_ascii=False),text=True,capture_output=True,timeout=left,shell=False)
        if v.returncode==255:raise ConnectionError('SSH_TRANSPORT_FAILURE:'+sha(v.stderr))
        if v.returncode:raise SafetyError('C15_IPC_REJECTED:'+m+':'+sha(v.stderr))
        return strict_json(v.stdout)
    return exchange(mode,payload,send,deadline=deadline,rpc_limit=timeout)

def verify(root:Path)->dict:
    compat.verify_continuation(root)
    a=read(root/'authorization/CONTINUATION_02.json');f=root/'19_ssh_mux_freeze.json'
    if a.get('state')!='USER_CONTINUATION_MINIMAL_SSH_REUSE' or not a.get('direct_user_message_locator'):
        raise SafetyError('SSH_REUSE_CONTINUATION_MISSING')
    if a.get('freeze_sha256')!=sha(f.read_bytes()) or a.get('original_limits')!=LIMITS:
        raise SafetyError('SSH_REUSE_CONTINUATION_CHANGED')
    for x in read(f)['files']:
        if sha(safe_path(root,x['path']).read_bytes())!=x['sha256']:raise SafetyError('SSH_REUSE_FROZEN_FILE_CHANGED')
    return a

def run(root:Path,quota:Path)->dict:
    a=verify(root);native_batch.rpc=rpc;original=native_batch.run_one
    versions=root/'ssh_transport_versions';versions.mkdir(mode=0o700,exist_ok=True)
    def versioned(root:Path,unit:dict,gate:dict,plan:dict)->dict:
        if unit['run_unit_id'] not in a['remaining_unit_ids']:raise SafetyError('SSH_REUSE_ONLY_REMAINING_ORIGINAL_UNITS')
        atomic_create(versions,unit['run_unit_id']+'.json',{'version':VERSION,'run_unit_id':unit['run_unit_id'],'freeze_sha256':a['freeze_sha256'],'utc':utc()})
        return original(root,unit,gate,plan)
    native_batch.run_one=versioned
    return compat.run(root,quota)

if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');p.add_argument('--quota-receipt',type=Path);a=p.parse_args()
    try:
        if a.check:verify(ROOT);result={'state':'SSH_MUX_CONTINUATION_CHECK_PASS','new_model_calls':0}
        elif a.quota_receipt:result=run(ROOT,a.quota_receipt)
        else:raise SafetyError('CURRENT_QUOTA_RECEIPT_REQUIRED')
        print(json.dumps(result,ensure_ascii=False))
    except SafetyError as error:
        print(json.dumps({'state':str(error),'new_model_calls_from_gate_failure':0}));raise SystemExit(3)
