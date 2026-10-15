"""Sequential bounded recovery. Never imported by offline tests to start a model."""
from __future__ import annotations
import json,shlex,subprocess,time,uuid
from pathlib import Path
from bridge_state_machine import Budget,ExchangeState,utc
from codex_worker_config import require_authorization
from safe_paths import *
from strict_exchange_validator import validate_request,validate_response
from replay_and_resume import verified_replay

def rpc(plan,attempt,mode,payload,*,evaluator=False,timeout=60):
 from ssh_ack_transport import exchange
 py=plan['evaluator_python' if evaluator else 'controller_python'];server=Path(plan['server_root'])
 if '_transport_deadline_epoch' not in plan:raise SafetyError('SHARED_TRANSPORT_DEADLINE_REQUIRED')
 def send(selected_mode,selected_payload,remaining_seconds):
  argv=['ssh','-i',plan['ssh_identity_file'],'-o','BatchMode=yes','-o','ConnectTimeout=30',plan['server'],shlex.join([py,'-B',str(server/'src/server_protocol.py'),str(server/'private_recovery_attempts'/attempt),selected_mode])]
  p=subprocess.run(argv,input=json.dumps(selected_payload,ensure_ascii=False),text=True,capture_output=True,timeout=remaining_seconds,shell=False)
  if p.returncode==255:raise ConnectionError('SSH_TRANSPORT_FAILURE:'+sha(p.stderr))
  if p.returncode!=0:raise SafetyError('SERVER_IPC_LOGIC_REJECTED:'+selected_mode+':'+sha(p.stderr))
  return strict_json(p.stdout)
 return exchange(mode,payload,send,deadline=plan['_transport_deadline_epoch'],rpc_limit=timeout)

def verify_frozen_package(root):
 receipt=strict_json((root/'11_frozen_bridge_version_receipt.json').read_text())
 if receipt['state']!='C13R_TRANSPORT_FIX_SYNTHETIC_FROZEN':raise SafetyError('SOURCE_NOT_FROZEN')
 for item in receipt['files']:
  if sha(safe_path(root,item['path']).read_bytes())!=item['sha256']:raise SafetyError('FROZEN_CODE_OR_PROTOCOL_CHANGED')

def checked_budgets(gate,plan):
 b=gate['approved_budgets'];proposal=plan['proposed_budgets']
 for key in proposal:
  if type(b.get(key)) is not int or not 1<=b[key]<=proposal[key]:raise SafetyError('APPROVED_BUDGET_OUT_OF_RANGE')
 if b['per_case_new_cli_calls']>b['total_new_cli_calls'] or b['concurrency']!=1:raise SafetyError('BUDGET_OR_CONCURRENCY_SCOPE')
 return b

def run_two_cases(root,gate):
 require_authorization(gate);verify_frozen_package(root)
 if gate.get("approved_frozen_bridge_receipt_sha256")!=sha((root/"11_frozen_bridge_version_receipt.json").read_bytes()):raise SafetyError("AUTHORIZATION_NOT_BOUND_TO_FROZEN_VERSION")
 plan=strict_json((root/'recovery_plan_DRAFT.json').read_text());b=checked_budgets(gate,plan)
 from recovery_runner import run_new_exchange
 with ExclusiveLease(root):
  budget=Budget(root/'private_recovery_attempts'/'NEW_CALL_BUDGET',total_limit=b['total_new_cli_calls'],per_case_limit=b['per_case_new_cli_calls'],total_wall=b['total_wall_seconds'],case_wall=b['case_wall_seconds'],worker_wait=b['worker_timeout_seconds'])
  summaries=[]
  for index,case in enumerate(plan['cases'],1):
   budget.begin_case(case['case_id']);attempt='C13R_'+str(index)+'_'+uuid.uuid4().hex
   local=private_dir(root/'private_recovery_attempts',attempt);private_dir(local,'server_artifacts');worker=private_dir(local,'worker')
   deadline=time.time()+min(b['case_wall_seconds'],b['total_wall_seconds']-(time.monotonic()-budget.started))
   plan['_transport_deadline_epoch']=deadline
   c={**case,'attempt_id':attempt,'model':'gpt-6-luna','source_files':plan['source_files'],'budgets':b,'case_deadline_epoch':deadline}
   atomic_create(local,'contract.json',c);states=[];seq=1;started=False
   try:
    reply=rpc(plan,attempt,'start',{'contract':c,'authorization':gate});started=True;atomic_create(local,'server_start_receipt.json',reply)
    while True:
     budget.wait_seconds(case['case_id']);status=rpc(plan,attempt,'status',{})
     if status['state']=='FAILED_AND_SEALED':raise SafetyError('NATIVE_CONTROLLER_ABORTED')
     if status['state']=='PREDICTION_FROZEN':break
     packet=rpc(plan,attempt,'get',{'seq':seq})
     if packet['state']=='WAIT':time.sleep(.2);continue
     q=packet['request'];validate_request(q)
     if (q['attempt_id'],q['run_id'],q['case_id'],q['seq'])!=(attempt,case['run_id'],case['case_id'],seq):raise SafetyError('SERVER_REQUEST_IDENTITY')
     x=private_dir(local,'exchange_'+str(seq).zfill(4));s=ExchangeState(x/'state',q);states.append(s)
     pair=packet.get('historical_pair');res=None
     if pair:
      # A different regenerated prompt is not replayable; never force the historical answer.
      if all(pair[0].get(k)==q[k] for k in ['run_id','case_id','seq','phase','prompt_sha256']):
       res=verified_replay(q,*pair,q['prompt_utf8'].encode(),old_controller_alive=False,new_attempt_is_fresh=True)
       atomic_create(x,'request.json',q);atomic_create(x,'response.json',res);s.transition('RESPONSE_RECEIVED',{'source':'VERIFIED_REPLAY','new_cli_calls':0});s.transition('RESPONSE_VALIDATED',{'reply_sha256':res['reply_sha256']})
     if res is None:res=run_new_exchange(q,x,worker,s,budget,gate,plan['client'],plan['unknown_history'])
     validate_response(q,res)
     ack=rpc(plan,attempt,'put',{'seq':seq,'response':res});atomic_create(x,'server_ack.json',ack);s.transition('SERVER_ACCEPTED',ack)
     while True:
      budget.wait_seconds(case['case_id']);consumed=rpc(plan,attempt,'consumed',{'seq':seq})
      if consumed['state']=='CONTROLLER_CONTINUED':s.transition('CONTROLLER_CONTINUED',consumed);break
      status=rpc(plan,attempt,'status',{})
      if status['state']=='FAILED_AND_SEALED':raise SafetyError('NATIVE_ABORT_AFTER_ACK')
      time.sleep(.2)
     seq+=1
    packet=rpc(plan,attempt,'artifacts',{},timeout=60)
    for name,data in packet['files'].items():
     path=safe_path(local/'server_artifacts',name)
     if not path.parent.exists():private_dir(local/'server_artifacts',str(path.parent.relative_to(local/'server_artifacts')))
     atomic_create(local/'server_artifacts',name,data)
    freeze=strict_json((local/'server_artifacts/prediction_trace_freeze.json').read_text())
    for item in freeze['files']:
     if sha(safe_path(local/'server_artifacts',item['path']).read_bytes())!=item['sha256']:raise SafetyError('SERVER_ARTIFACT_TRANSFER_CHANGED')
    for state in states:state.transition('PREDICTION_FROZEN',{'server_freeze_verified':True})
    files=[{'path':str(p.relative_to(local)),'sha256':sha(p.read_bytes())} for p in sorted(local.rglob('*')) if p.is_file()]
    m={'state':'MAC_FROZEN_BEFORE_GOLD','attempt_id':attempt,'case_id':case['case_id'],'model_messages':freeze['model_messages'],'server_freeze_sha256':sha((local/'server_artifacts/prediction_trace_freeze.json').read_bytes()),'files':files}
    mp=atomic_create(local,'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json',m)
    ack=rpc(plan,attempt,'freeze_ack',{'manifest':m,'manifest_sha256':sha(mp.read_bytes())});atomic_create(local,'freeze_ack.json',ack)
    budget.wait_seconds(case['case_id']);evaluation=rpc(plan,attempt,'evaluate',{},evaluator=True,timeout=min(190,budget.wait_seconds(case['case_id'])))
    atomic_create(local,'official_metrics_only.json',evaluation)
    for state in states:state.transition('OFFICIAL_EVALUATED',{'evaluation_summary_sha256':sha(json.dumps(evaluation,sort_keys=True))})
    summaries.append({'case_id':case['case_id'],'attempt_id':attempt,'state':'OFFICIAL_EVALUATED','new_actual_cli_starts':sum(1 for p in local.glob('exchange_*/cli_start_receipt.json')),'model_messages':freeze['model_messages'],'metrics':evaluation['metrics']})
   except Exception as exc:
    for s in states:
     if s.state not in {'OFFICIAL_EVALUATED','FAILED_AND_SEALED'}:s.transition('FAILED_AND_SEALED',{'reason':type(exc).__name__+':'+str(exc)[:300]})
    failure={'utc':utc(),'state':'FAILED_AND_SEALED','case_id':case['case_id'],'attempt_id':attempt,'reason':type(exc).__name__+':'+str(exc)[:400],'auto_retry':False}
    atomic_create(local,'FAILURE_SEALED.json',failure)
    if started:
     try:atomic_create(local,'stop_ack.json',rpc(plan,attempt,'stop',{}))
     except Exception:pass
    summaries.append(failure)
    # An unknown send halts the whole recovery; no subsequent real request starts.
    atomic_create(root/'private_recovery_attempts','RECOVERY_STOPPED_NO_AUTORETRY.json',{'summaries':summaries});raise
  atomic_create(root/'private_recovery_attempts','TWO_CASE_RESULT_SUMMARY.json',{'summaries':summaries,'historical_cli_starts':17,'new_cli_reservations':len(budget.reservations),'replays_are_new_calls':False})
