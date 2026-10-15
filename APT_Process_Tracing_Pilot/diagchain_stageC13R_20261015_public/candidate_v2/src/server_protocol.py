"""Fixed server IPC; only new C13-R attempt namespaces may be written."""
from __future__ import annotations
import json,os,subprocess,sys,time
from pathlib import Path
from safe_paths import *
from bridge_state_machine import utc
from codex_worker_config import GATES
from strict_exchange_validator import validate_response
from server_native_controller import PACKAGE,attempt_contract,alive,verify_sources

def current_attempt(root):
 c=attempt_contract(root)
 if not alive(root):raise SafetyError('EXITED_CONTROLLER_NO_BACKFILL')
 return c

def accept_response(root,seq,res):
 c=current_attempt(root)
 if not 1<=seq<=47:raise SafetyError('SEQUENCE_SCOPE')
 q=strict_json(safe_path(root,f'exchange/REQUEST_{seq:04d}.json').read_text())
 validate_response(q,res)
 p=safe_path(root,f'exchange/RESPONSE_{seq:04d}.json')
 if p.exists():
  if strict_json(p.read_text())!=res:raise SafetyError('CONFLICTING_DUPLICATE_RESPONSE')
  return {'state':'ALREADY_ACCEPTED_IDENTICAL','seq':seq,'reply_sha256':res['reply_sha256']}
 waiting=strict_json((root/f'exchange/WAITING_{seq:04d}.json').read_text())
 if waiting['attempt_id']!=c['attempt_id'] or waiting['pid']!=strict_json((root/'controller_started.json').read_text())['pid']:raise SafetyError('WAITING_IDENTITY')
 atomic_create(root,f'exchange/RESPONSE_{seq:04d}.json',res)
 return {'state':'SERVER_ACCEPTED','seq':seq,'reply_sha256':res['reply_sha256']}

def start(root,payload):
 if root.parent!=PACKAGE/'private_recovery_attempts':raise SafetyError('ATTEMPT_SCOPE')
 safe_path(PACKAGE,str(root.relative_to(PACKAGE)))
 g=payload['authorization'];plan=strict_json((PACKAGE/'recovery_plan_DRAFT.json').read_text())
 if any(g.get(k) is not True for k in GATES) or g['model']!='gpt-6-luna' or g['auth_mode']!='SIGN_IN_WITH_CHATGPT' or g['paid_credits_allowed'] is not False or g['auto_recharge_confirmed_off'] is not True:raise SafetyError('AUTHORIZATION_INCOMPLETE')
 c=payload['contract'];entry=next(x for x in plan['cases'] if x['case_id']==c['case_id'])
 for k in ['run_id','case_id','historical_root','case_paths','native_config','research_profile']:
  if c[k]!=entry[k]:raise SafetyError('FROZEN_PLAN_CHANGED:'+k)
 if c['attempt_id']!=root.name or c['source_files']!=plan['source_files']:raise SafetyError('CONTRACT_BINDING')
 if c['budgets']!=g['approved_budgets']:raise SafetyError('BUDGET_BINDING')
 if not time.time()<c['case_deadline_epoch']<=time.time()+c['budgets']['case_wall_seconds']+2:raise SafetyError('CASE_DEADLINE')
 for p in (PACKAGE/'private_recovery_attempts').iterdir():
  if p.is_dir() and alive(p):raise SafetyError('OTHER_CONTROLLER_ACTIVE')
 old=Path(c['historical_root'])
 if not (old/'controller_aborted.json').exists() and not (old/'controller_complete.json').exists():raise SafetyError('HISTORICAL_EXIT_NOT_CONFIRMED')
 verify_sources(c);private_dir(root.parent,root.name);private_dir(root,'exchange');private_dir(root,'logs')
 atomic_create(root,'contract.json',c);atomic_create(root,'authorization.json',g)
 env={k:os.environ[k] for k in ['PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR'] if k in os.environ};env.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='')
 with (root/'logs/controller.stdout').open('xb') as out,(root/'logs/controller.stderr').open('xb') as err:
  p=subprocess.Popen([plan['controller_python'],'-B',str(PACKAGE/'src/server_native_controller.py'),'--attempt',str(root)],cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,shell=False,start_new_session=True)
 atomic_create(root,'launch.json',{'utc':utc(),'pid':p.pid,'attempt_id':c['attempt_id']})
 return {'state':'CONTROLLER_STARTED','pid':p.pid}

def evaluate(root):
 c=attempt_contract(root);verify_sources(c)
 if not (root/'controller_complete.json').exists() or not (root/'mac_freeze_attestation.json').exists():raise SafetyError('BOTH_FREEZES_REQUIRED')
 if time.time()>=c['case_deadline_epoch']:raise SafetyError('EVALUATION_CASE_BUDGET_EXHAUSTED')
 import signal
 def timeout(*args):raise SafetyError('EVALUATION_TIMEOUT')
 signal.signal(signal.SIGALRM,timeout);signal.alarm(max(1,int(min(180,c['case_deadline_epoch']-time.time()))))
 frozen=strict_json((root/'prediction_trace_freeze.json').read_text())
 def verify():
  for x in frozen['files']:
   if sha(safe_path(root,x['path']).read_bytes())!=x['sha256']:raise SafetyError('FROZEN_OUTPUT_CHANGED')
 verify();item=c['case_paths']['ground_truth'];gp=Path(item['path']);safe_path(gp.parent,gp.name);raw=gp.read_bytes()
 if sha(raw)!=item['sha256']:raise SafetyError('GOLD_VERSION_MISMATCH')
 atomic_create(root,'evaluation_started.json',{'utc':utc(),'Gold_first_semantic_read_after_both_freezes':True,'freeze_sha256':sha((root/'prediction_trace_freeze.json').read_bytes())})
 sys.path.insert(0,str(PACKAGE/'author_tree/benchmark'))
 import evaluate_chain_reconstruction as official
 result=official.evaluate(strict_json((root/'prediction.json').read_text()),strict_json(raw.decode()),strict_json(Path(c['case_paths']['input']['path']).read_text()))
 atomic_create(root,'official_evaluation.json',result);verify()
 summary={k:v for k,v in result.get('metrics',{}).items() if isinstance(v,(int,float,bool)) or v is None}
 r={'state':'OFFICIAL_EVALUATED','utc':utc(),'attempt_id':c['attempt_id'],'metrics':summary,'prediction_sha256':sha((root/'prediction.json').read_bytes()),'trace_sha256':sha((root/'trace.json').read_bytes()),'Gold_exposed_to_worker':False}
 atomic_create(root,'evaluation_complete.json',r);signal.alarm(0);return r

def dispatch(root,mode,payload):
 if mode=='start':return start(root,payload)
 c=attempt_contract(root)
 if mode=='status':
  for n in ['controller_aborted.json','evaluation_complete.json','controller_complete.json']:
   if (root/n).exists():return strict_json((root/n).read_text())
  return {'state':'RUNNING' if alive(root) else 'EXITED_OR_STARTING'}
 if mode=='get':
  current_attempt(root);seq=payload['seq'];p=safe_path(root,f'exchange/REQUEST_{seq:04d}.json')
  if not p.exists():return {'state':'WAIT'}
  q=strict_json(p.read_text());from replay_and_resume import historical_pair
  pair=historical_pair(Path(c['historical_root']),seq)
  return {'state':'REQUEST','request':q,'historical_pair':list(pair) if pair else None}
 if mode=='put':return accept_response(root,payload['seq'],payload['response'])
 if mode=='consumed':
  p=safe_path(root,f'exchange/CONSUMED_{payload["seq"]:04d}.json');return {'state':'CONTROLLER_CONTINUED','receipt':strict_json(p.read_text())} if p.exists() else {'state':'WAIT'}
 if mode=='stop':
  if alive(root) and not (root/'STOP.json').exists():atomic_create(root,'STOP.json',{'utc':utc(),'reason':'MAC_BRIDGE_SEALED_NO_RESEND'})
  return {'state':'STOP_REQUESTED_ONLY_OWN_ATTEMPT'}
 if mode=='artifacts':
  if not (root/'controller_complete.json').exists():raise SafetyError('PREDICTION_NOT_FROZEN')
  f=strict_json((root/'prediction_trace_freeze.json').read_text());names=['prediction_trace_freeze.json','controller_complete.json']+[x['path'] for x in f['files']]
  return {'state':'SERVER_FROZEN','files':{n:safe_path(root,n).read_text() for n in names}}
 if mode=='freeze_ack':
  if not (root/'controller_complete.json').exists():raise SafetyError('SERVER_FREEZE_REQUIRED')
  m=payload['manifest']
  if m['attempt_id']!=c['attempt_id'] or m['state']!='MAC_FROZEN_BEFORE_GOLD' or sha((json.dumps(m,ensure_ascii=False,indent=2)+'\n').encode())!=payload['manifest_sha256']:raise SafetyError('MAC_FREEZE_BINDING')
  f=strict_json((root/'prediction_trace_freeze.json').read_text())
  if m['model_messages']!=f['model_messages'] or m['server_freeze_sha256']!=sha((root/'prediction_trace_freeze.json').read_bytes()):raise SafetyError('FREEZE_COUNT_OR_HASH')
  atomic_create(root,'mac_freeze_attestation.json',payload);return {'state':'MAC_FREEZE_ACCEPTED'}
 if mode=='evaluate':return evaluate(root)
 raise SafetyError('UNKNOWN_IPC_MODE')
if __name__=='__main__':
 os.umask(0o077)
 try:
  r=dispatch(Path(sys.argv[1]),sys.argv[2],strict_json(sys.stdin.read(12000000)));print(json.dumps(r,ensure_ascii=False))
 except Exception as e:
  print(json.dumps({'state':'IPC_REJECTED','error_type':type(e).__name__,'reason':str(e)[:300]}),file=sys.stderr);raise SystemExit(3)
