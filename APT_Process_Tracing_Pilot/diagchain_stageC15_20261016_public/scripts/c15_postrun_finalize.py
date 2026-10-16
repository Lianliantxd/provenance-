"""Reconcile an already-frozen same attempt; no model/restart path exists here."""
from __future__ import annotations
import argparse,os,time,json,datetime
from pathlib import Path
import c15_common as common
from c15_common import *
import c15_resume_mux as mux
import c15_evaluate_and_report as official_stage
import c15_reporting_addendum as disclosure

UNIT='C1_R3_OFF'
ORIGINAL_READ=common.read

def effective_read(path:Path)->dict:
    path=Path(path)
    if path.name=='terminal.json' and path.parent.parent==ROOT/'runs' and path.parent.name==UNIT:
        resolved=path.with_name('terminal_resolution.json')
        if resolved.exists():
            old=ORIGINAL_READ(path);new=ORIGINAL_READ(resolved)
            if (new['original_failed_terminal_sha256']!=sha(path.read_bytes()) or
                (new['attempt_id'],new['run_unit_id'])!=(old['attempt_id'],old['run_unit_id']) or
                new['resolution_kind']!='SAME_ATTEMPT_ALREADY_FROZEN_OUTPUT_TRANSFER' or
                new['status']!='FROZEN' or new['new_model_calls_for_resolution']!=0):
                raise SafetyError('TERMINAL_RESOLUTION_BINDING_FAILED')
            proof=path.parent/'same_attempt_completion_proof.json'
            if sha(proof.read_bytes())!=new['resolution_proof_sha256']:raise SafetyError('RESOLUTION_PROOF_CHANGED')
            return new
    return ORIGINAL_READ(path)

def install_resolution_reader()->None:
    common.read=effective_read;official_stage.read=effective_read;disclosure.read=effective_read

def recover(root:Path)->dict:
    mux.verify(root);d=root/'runs'/UNIT;old=ORIGINAL_READ(d/'terminal.json')
    if (d/'terminal_resolution.json').exists():return effective_read(d/'terminal.json')
    if old['status']!='FAILED' or not old['reason'].startswith('SafetyError:C15_IPC_REJECTED:get:'):
        raise SafetyError('ONLY_OBSERVED_STATUS_GET_COMPLETION_RACE_CAN_BE_RESOLVED')
    plan=read(root/'configs/study_private.json');unit=next(u for u in read(root/'configs/run_units_private.json')['units'] if u['run_unit_id']==UNIT)
    started=time.monotonic();status=mux.rpc(plan,old['attempt_id'],'status',{},deadline=time.time()+60)
    if status.get('state')!='PREDICTION_FROZEN' or status['attempt_id']!=old['attempt_id']:raise SafetyError('NATIVE_COMPLETION_NOT_CONFIRMED')
    packet=mux.rpc(plan,old['attempt_id'],'artifacts',{},deadline=time.time()+60)
    dest=d/'server_artifacts'
    for name,data in packet['files'].items():
        f=safe_path(dest,name);f.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        if f.exists():
            if f.read_text()!=data:raise SafetyError('RECOVERY_ARTIFACT_CONFLICT')
        else:atomic_create(dest,name,data)
    frozen=read(dest/'prediction_trace_freeze.json')
    if frozen['attempt_id']!=old['attempt_id'] or frozen['model_messages']!=old['actual_cli_starts']:raise SafetyError('RECOVERY_MESSAGE_COUNT_BINDING')
    for row in frozen['files']:
        if sha(safe_path(dest,row['path']).read_bytes())!=row['sha256']:raise SafetyError('RECOVERY_NATIVE_FREEZE_HASH')
    checks=[]
    for seq in range(1,frozen['model_messages']+1):
        x=d/f'exchange_{seq:04d}';q=read(x/'request.json');response=read(x/'response.json')
        rq=read(dest/f'exchange/REQUEST_{seq:04d}.json');rs=read(dest/f'exchange/RESPONSE_{seq:04d}.json');consumed=read(dest/f'exchange/CONSUMED_{seq:04d}.json')
        if q!=rq or response!=rs:raise SafetyError('RECOVERY_ENVELOPE_BYTE_BINDING')
        if (q['run_id'],q['attempt_id'],q['case_id'],q['seq'])!=(unit['run_id'],old['attempt_id'],unit['case_id'],seq):raise SafetyError('RECOVERY_CROSS_UNIT_OR_ATTEMPT')
        if sha(q['prompt_utf8'])!=q['prompt_sha256'] or sha((x/'final_reply_utf8.txt').read_bytes())!=response['reply_sha256']:raise SafetyError('RECOVERY_PROMPT_OR_REPLY_BYTES')
        for key in ['attempt_id','seq','phase','prompt_sha256','reply_sha256','source']:
            if consumed[key]!=response[key]:raise SafetyError('RECOVERY_CONSUMED_ACK_BINDING')
        if read(x/'parser_receipt.json')['status']!='CANONICAL_FINAL_VERIFIED' or not (x/'server_ack.json').exists():raise SafetyError('RECOVERY_CANONICAL_OR_ACK_MISSING')
        checks.append({'seq':seq,'prompt_sha256':q['prompt_sha256'],'reply_sha256':response['reply_sha256'],'same_original_attempt_server_consumed':True})
    if frozen['phase_counts']['reflection']!=0:raise SafetyError('OFF_REFLECTION_PROTOCOL_VIOLATION')
    proof={'state':'SAME_ATTEMPT_NATIVE_COMPLETION_VERIFIED_ZERO_NEW_MODEL_CALLS','run_unit_id':UNIT,'attempt_id':old['attempt_id'],
        'original_failed_terminal_sha256':sha((d/'terminal.json').read_bytes()),'server_freeze_sha256':sha((dest/'prediction_trace_freeze.json').read_bytes()),
        'checks':checks,'new_model_calls':0,'new_attempts':0,'prediction_sha256':sha((dest/'prediction.json').read_bytes()),'trace_sha256':sha((dest/'trace.json').read_bytes())}
    atomic_create(d,'same_attempt_completion_proof.json',proof)
    files=[{'path':p.relative_to(d).as_posix(),'sha256':sha(p.read_bytes())} for p in sorted(d.rglob('*')) if p.is_file()]
    manifest={'state':'MAC_FROZEN_BEFORE_GOLD','attempt_id':old['attempt_id'],'case_id':unit['case_id'],'run_unit_id':UNIT,
        'model_messages':frozen['model_messages'],'server_freeze_sha256':proof['server_freeze_sha256'],'files':files,
        'bridge_failure_record_retained':True,'same_attempt_transfer_reconciliation':True}
    mp=atomic_create(d,'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json',manifest)
    ack=mux.rpc(plan,old['attempt_id'],'freeze_ack',{'manifest':manifest,'manifest_sha256':sha(mp.read_bytes())},deadline=time.time()+60);atomic_create(d,'freeze_ack.json',ack)
    trace=read(dest/'trace.json');new={**old,'status':'FROZEN','bridge_original_status':'FAILED','bridge_original_reason':old['reason'],
        'reason':'SAME_ATTEMPT_ALREADY_COMPLETED_RECONCILED_NO_REGENERATION','resolution_kind':'SAME_ATTEMPT_ALREADY_FROZEN_OUTPUT_TRANSFER',
        'original_failed_terminal_sha256':proof['original_failed_terminal_sha256'],'resolution_proof_sha256':sha((d/'same_attempt_completion_proof.json').read_bytes()),
        'resolved_utc':utc(),'resolution_transfer_seconds':time.monotonic()-started,'new_model_calls_for_resolution':0,
        'model_phase_counts':frozen['phase_counts'],'reflection_calls':0,'reflection_invoked':False,'revision_accepted':[],'discard_reasons':[],
        'termination_reason':trace['final_metadata'].get('termination_reason','UNAVAILABLE'),'mac_manifest_path':mp.relative_to(root).as_posix(),
        'mac_manifest_sha256':sha(mp.read_bytes()),'prediction_sha256':proof['prediction_sha256'],'trace_sha256':proof['trace_sha256'],'official_evaluated':False}
    atomic_create(d,'terminal_resolution.json',new);return new

def seal(root:Path)->dict:
    mux.verify(root);units=read(root/'configs/run_units_private.json')['units'];terminals=[]
    for u in units:
        p=root/'runs'/u['run_unit_id']/'terminal.json';t=effective_read(p)
        if t['status'] not in ('FROZEN','FAILED'):raise SafetyError('ALL_18_TERMINALS_REQUIRED')
        actual=p.with_name('terminal_resolution.json') if t.get('resolution_kind') else p
        t={**t,'terminal_sha256':sha(actual.read_bytes()),'terminal_record_path':actual.relative_to(root).as_posix()};terminals.append(t)
        if t['status']=='FROZEN':official_stage.verify_local_frozen_unit(root,t)
    raw_failures=sum(ORIGINAL_READ(root/'runs'/u['run_unit_id']/'terminal.json')['status']=='FAILED' for u in units)
    f={'state':'BATCH_PREDICTIONS_SEALED','utc':utc(),'units':terminals,'protocol_sha256':sha((root/'08_preregistration_and_code_freeze.json').read_bytes()),
        'Gold_semantics_read_by_C15_before_seal':False,'original_bridge_failure_records_retained':raw_failures,
        'same_original_attempt_reconciled':sum(bool(t.get('resolution_kind')) for t in terminals),'new_model_calls_for_reconciliation':0}
    atomic_create(root,'09_batch_terminal_freeze.json',f);return f

if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--recover-same-attempt',action='store_true');p.add_argument('--seal',action='store_true');p.add_argument('--evaluate',action='store_true');p.add_argument('--report',action='store_true');a=p.parse_args()
    frozen_check(ROOT)
    f=read(ROOT/'25_postrun_reporting_freeze.json')
    for x in f['files']:
        if sha(safe_path(ROOT,x['path']).read_bytes())!=x['sha256']:raise SafetyError('POSTRUN_REPORTING_FREEZE_CHANGED')
    install_resolution_reader()
    if a.recover_same_attempt:
        t=recover(ROOT);print(json.dumps({'resolved_unit':t['run_unit_id'],'status':t['status'],'new_model_calls':0}))
    if a.seal:
        f=seal(ROOT);print(json.dumps({'batch_state':f['state'],'frozen':sum(t['status']=='FROZEN' for t in f['units']),'failed':sum(t['status']=='FAILED' for t in f['units']),'Gold_read':False}))
    if a.evaluate:
        official_stage.rpc=mux.rpc;official_stage.evaluate(ROOT);print(json.dumps({'state':'OFFICIAL_EVALUATION_COMPLETE'}))
    if a.report:
        official_stage.reports(ROOT);disclosure.render(ROOT);gate=read(ROOT/'reports/16_final_gate.json');common.progress(ROOT,gate['state']);print(json.dumps(gate))
