"""One frozen paired block at a time; uses C13-R V2 worker/parser/ACK unchanged."""
from __future__ import annotations
import argparse,json,os,shlex,subprocess,sys,time,uuid
from pathlib import Path
from c15_common import *
from bridge_state_machine import ExchangeState
from recovery_runner import run_new_exchange
import recovery_runner as frozen_worker
from strict_exchange_validator import validate_request,validate_response
from ssh_ack_transport import exchange
from safe_paths import ExclusiveLease

def rpc(plan:dict,attempt:str,mode:str,payload:dict,*,deadline:float,evaluator:bool=False,timeout:float=60) -> dict:
 py=plan['evaluator_python' if evaluator else 'controller_python'];remote=Path(plan['server_root'])
 def send(m: str,p: dict,left: float) -> dict:
  argv=['ssh','-i',plan['ssh_identity_file'],'-o','BatchMode=yes','-o','ConnectTimeout=30',plan['server'],shlex.join([py,'-B',str(remote/'src/c15_server_protocol.py'),str(remote/'private_recovery_attempts'/attempt),m])]
  v=subprocess.run(argv,input=json.dumps(p,ensure_ascii=False),text=True,capture_output=True,timeout=left,shell=False)
  if v.returncode==255:raise ConnectionError('SSH_TRANSPORT_FAILURE:'+sha(v.stderr))
  if v.returncode:raise SafetyError('C15_IPC_REJECTED:'+m+':'+sha(v.stderr))
  return strict_json(v.stdout)
 return exchange(mode,payload,send,deadline=deadline,rpc_limit=timeout)

def freeze_one(root:Path,unit:dict,plan:dict,attempt:str,states:list,deadline:float) -> dict:
 local=root/'runs'/unit['run_unit_id'];packet=rpc(plan,attempt,'artifacts',{},deadline=deadline)
 for name,data in packet['files'].items():
  target=safe_path(local/'server_artifacts',name)
  if not target.parent.exists():private_dir(local/'server_artifacts',str(target.parent.relative_to(local/'server_artifacts')))
  atomic_create(local/'server_artifacts',name,data)
 freeze=read(local/'server_artifacts/prediction_trace_freeze.json')
 for item in freeze['files']:
  if sha(safe_path(local/'server_artifacts',item['path']).read_bytes())!=item['sha256']:raise SafetyError('TRANSFER_FROZEN_HASH_MISMATCH')
 for state in states:state.transition('PREDICTION_FROZEN',{'server_freeze_verified':True})
 files=[{'path':p.relative_to(local).as_posix(),'sha256':sha(p.read_bytes())} for p in sorted(local.rglob('*')) if p.is_file()]
 m={'state':'MAC_FROZEN_BEFORE_GOLD','attempt_id':attempt,'case_id':unit['case_id'],'run_unit_id':unit['run_unit_id'],'model_messages':freeze['model_messages'],'server_freeze_sha256':sha((local/'server_artifacts/prediction_trace_freeze.json').read_bytes()),'files':files};mp=atomic_create(local,'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json',m)
 ack=rpc(plan,attempt,'freeze_ack',{'manifest':m,'manifest_sha256':sha(mp.read_bytes())},deadline=deadline);atomic_create(local,'freeze_ack.json',ack)
 trace=read(local/'server_artifacts/trace.json');events=trace['reflection_events'];calls=freeze['phase_counts']['reflection']
 if unit['assigned_arm']=='OFF' and calls:raise SafetyError('OFF_REFLECTION_PROTOCOL_VIOLATION')
 revision_accepted=[not (x.get('parse_error') or x.get('empty_revision_discarded') or x.get('shrinking_revision_discarded')) for x in events]
 return {'status':'FROZEN','run_unit_id':unit['run_unit_id'],'attempt_id':attempt,'assigned_arm':unit['assigned_arm'],'reflection_calls':calls,'reflection_invoked':calls>0,'revision_accepted':revision_accepted,'discard_reasons':[{k:v for k,v in x.items() if k in ['parse_error','empty_revision_discarded','shrinking_revision_discarded']} for x in events],'model_phase_counts':freeze['phase_counts'],'termination_reason':trace['final_metadata'].get('termination_reason','UNAVAILABLE'),'mac_manifest_path':mp.relative_to(root).as_posix(),'mac_manifest_sha256':sha(mp.read_bytes()),'prediction_sha256':sha((local/'server_artifacts/prediction.json').read_bytes()),'trace_sha256':sha((local/'server_artifacts/trace.json').read_bytes()),'official_evaluated':False}

def run_one(root:Path,unit:dict,gate:dict,plan:dict) -> dict:
 local=private_dir(root/'runs',unit['run_unit_id']);private_dir(local,'server_artifacts');budget=BatchBudget(root,unit);budget.begin_case(unit['case_id']);attempt='a'+uuid.uuid4().hex;worker=private_dir(root/'worker_sessions',uuid.uuid4().hex)
 deadline=time.time()+min(1800,LIMITS['batch_active_seconds']-budget.completed_total());c={**unit,'attempt_id':attempt,'model':'gpt-6-luna','source_files':plan['source_files'],'budgets':{'case_wall_seconds':1800,'worker_timeout_seconds':360},'case_deadline_epoch':deadline,'historical_root':str(Path(plan['server_root'])/'NO_CROSS_RUN_HISTORY')};atomic_create(local,'contract.json',c);states=[];seq=1;server_started=False
 try:
  started=rpc(plan,attempt,'start',{'contract':c,'authorization':gate},deadline=deadline);server_started=True;atomic_create(local,'server_start_receipt.json',started);progress(root,'C15_RUNNING_OR_PAUSED_FOR_INCLUDED_QUOTA')
  while True:
   budget.wait_seconds(unit['case_id']);status=rpc(plan,attempt,'status',{},deadline=deadline)
   if status['state']=='FAILED_AND_SEALED':
    atomic_create(local,'server_abort_status.json',status);raise SafetyError('EXTERNAL_OR_NATIVE_CONTROLLER_ABORT:'+str(status.get('reason','UNKNOWN')))
   if status['state']=='PREDICTION_FROZEN':break
   packet=rpc(plan,attempt,'get',{'seq':seq},deadline=deadline)
   if packet['state']=='WAIT':time.sleep(.2);continue
   q=packet['request'];validate_request(q)
   if (q['run_id'],q['attempt_id'],q['case_id'],q['seq'])!=(unit['run_id'],attempt,unit['case_id'],seq):raise SafetyError('CROSS_UNIT_REQUEST_OR_REPLY')
   if unit['assigned_arm']=='OFF' and q['phase']=='reflection':raise SafetyError('OFF_REFLECTION_PROTOCOL_VIOLATION')
   # Exact author prompt only; no historical replies or C14 content is supplied.
   x=private_dir(local,f'exchange_{seq:04d}');state=ExchangeState(x/'state',q);states.append(state);atomic_create(x,'input_metadata_audit.json',audit_metadata_prompt(q))
   response=run_new_exchange(q,x,worker,state,budget,gate,plan['client'],[]);validate_response(q,response)
   ack=rpc(plan,attempt,'put',{'seq':seq,'response':response},deadline=deadline);atomic_create(x,'server_ack.json',ack);state.transition('SERVER_ACCEPTED',ack)
   while True:
    budget.wait_seconds(unit['case_id']);continued=rpc(plan,attempt,'consumed',{'seq':seq},deadline=deadline)
    if continued['state']=='CONTROLLER_CONTINUED':state.transition('CONTROLLER_CONTINUED',continued);break
    status=rpc(plan,attempt,'status',{},deadline=deadline)
    if status['state']=='FAILED_AND_SEALED':raise SafetyError('CONTROLLER_ABORT_AFTER_ACK')
    time.sleep(.2)
   seq+=1
  terminal=freeze_one(root,unit,plan,attempt,states,deadline)
 except Exception as e:
  for state in states:
   if state.state not in ('FAILED_AND_SEALED','OFFICIAL_EVALUATED'):state.transition('FAILED_AND_SEALED',{'reason':str(e)[:300]})
  reason=type(e).__name__+':'+str(e);terminal={'status':'FAILED','run_unit_id':unit['run_unit_id'],'attempt_id':attempt,'assigned_arm':unit['assigned_arm'],'reason':reason,'failure_class':'EXTERNAL_BUDGET_OR_TRANSPORT_ABORT','remote_completion':'UNKNOWN_UNLESS_FROZEN_ACK_PRESENT','auto_new_model_retry':False}
  if server_started:
   try:atomic_create(local,'stop_ack.json',rpc(plan,attempt,'stop',{},deadline=time.time()+12,timeout=10))
   except Exception as stop_error:terminal['stop_status']='UNRESOLVED:'+type(stop_error).__name__
 terminal['generated_phase_requests_observed']={phase:sum(x.request['phase']==phase for x in states) for phase in ['controller','repair','synthesis','reflection']}
 terminal['actual_reflection_cli_starts']=sum((p.parent/'cli_start_receipt.json').exists() and read(p).get('phase')=='reflection' for p in local.glob('exchange_*/request.json'))
 terminal.update(utc=utc(),active_elapsed_seconds=budget.active_seconds(),new_cli_reservations=sum(read(p)['run_unit_id']==unit['run_unit_id'] for p in (root/'budget').glob('*_reservation.json')),actual_cli_starts=len(list(local.glob('exchange_*/cli_start_receipt.json'))),replays=0)
 atomic_create(local,'terminal.json',terminal);progress(root,'C15_RUNNING_OR_PAUSED_FOR_INCLUDED_QUOTA');return terminal

def seal_batch(root:Path) -> dict:
 units=read(root/'configs/run_units_private.json')['units'];terminals=[]
 for u in units:
  p=root/'runs'/u['run_unit_id']/'terminal.json'
  if not p.exists():raise SafetyError('BATCH_HAS_PENDING_UNITS_NO_EVALUATION')
  t=read(p);t.update(terminal_sha256=sha(p.read_bytes()));terminals.append(t)
 f={'state':'BATCH_PREDICTIONS_SEALED','utc':utc(),'units':terminals,'protocol_sha256':sha((root/'08_preregistration_and_code_freeze.json').read_bytes()),'Gold_semantics_read_by_C15_before_seal':False};atomic_create(root,'09_batch_terminal_freeze.json',f);return f

def install_worker_environment(root:Path) -> None:
 original=frozen_worker.clean_environment
 if getattr(original,'_c15_wrapped',False):return
 def isolated_environment():
  env=original();env.update(TMPDIR=str(root/'tmp'),XDG_CACHE_HOME=str(root/'cache'));return env
 isolated_environment._c15_wrapped=True;frozen_worker.clean_environment=isolated_environment

def run_block(root:Path,quota_path:Path) -> dict:
 frozen_check(root);approval=root/'authorization/BATCH_APPROVAL.json'
 if not approval.exists():raise SafetyError('C15_PREPARED_AWAITING_BATCH_AUTHORIZATION')
 gate=read(approval);require_batch_authorization(root,gate);configure_case_scope(root);require_quota(read(quota_path),gate);install_worker_environment(root)
 plan=read(root/'configs/study_private.json');units=read(root/'configs/run_units_private.json')['units']
 # An orphaned started unit is not silently re-started or given a fresh time budget.
 for u in units:
  d=root/'runs'/u['run_unit_id']
  if (d/'active_start.json').exists() and not (d/'terminal.json').exists():raise SafetyError('ORPHAN_RUN_REQUIRES_READ_ONLY_SAME_RUN_RECONCILIATION_NO_MODEL_RESEND')
 pending=[u for u in units if not (root/'runs'/u['run_unit_id']/'terminal.json').exists()]
 if not pending:return progress(root,'AWAITING_BATCH_SEAL')
 block=pending[0]['block'];results=[]
 for u in pending:
  if u['block']!=block:break
  result=run_one(root,u,gate,plan);results.append(result)
  if result['status']=='FAILED':
   progress(root,'C15_RUNNING_OR_PAUSED_FOR_INCLUDED_QUOTA','SAFETY_PAUSE_AFTER_FAILURE:'+result['reason']);return {'state':'PAUSED_AFTER_FAILURE_NO_AUTORETRY','results':results}
 return {'state':'PAIRED_BLOCK_COMPLETE_REQUIRES_CURRENT_QUOTA_CHECK_BEFORE_NEXT_BLOCK','block':block,'results':results}

if __name__=='__main__':
 os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('--check-preparation',action='store_true');p.add_argument('--run-next-block',action='store_true');p.add_argument('--quota-receipt',type=Path);p.add_argument('--seal-batch',action='store_true');a=p.parse_args()
 try:
  if a.check_preparation:frozen_check(ROOT);result={'state':'FROZEN_PREPARATION_INTEGRITY_PASS','new_model_calls':0}
  elif a.run_next_block:
   if not a.quota_receipt:raise SafetyError('CURRENT_QUOTA_REQUIRED')
   with ExclusiveLease(ROOT,'BATCH_EXECUTION_LOCK'):result=run_block(ROOT,a.quota_receipt)
  elif a.seal_batch:result=seal_batch(ROOT)
  else:raise SafetyError('SELECT_AN_ACTION')
  print(json.dumps(result,ensure_ascii=False))
 except SafetyError as e:print(json.dumps({'state':str(e),'new_model_calls_from_gate_failure':0}));raise SystemExit(3)
