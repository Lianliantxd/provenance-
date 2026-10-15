"""C15 namespace/config and batch-evaluation gate around the frozen V2 mailbox IPC."""
from __future__ import annotations
import sys,os,json,subprocess,time,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from c15_common import *
import server_protocol as v2
from server_native_controller import alive,attempt_contract,verify_sources

def unit_by_attempt(root:Path) -> dict:
 c=attempt_contract(root);units=read(ROOT/'configs/run_units_private.json')['units'];u=next(x for x in units if x['run_unit_id']==c['run_unit_id'])
 for k in ['run_id','case_id','native_config','case_paths','assigned_arm','input_policy']:
  if c[k]!=u[k]:raise SafetyError('C15_RUN_UNIT_CONFIG_CHANGED:'+k)
 return u

def start(root:Path,payload:dict) -> dict:
 frozen_check(ROOT);g=payload['authorization'];require_batch_authorization(ROOT,g);plan=read(ROOT/'configs/study_private.json');c=payload['contract'];u=next(x for x in read(ROOT/'configs/run_units_private.json')['units'] if x['run_unit_id']==c['run_unit_id'])
 if root.parent!=ROOT/'private_recovery_attempts' or c['attempt_id']!=root.name:raise SafetyError('C15_ATTEMPT_SCOPE')
 for k in ['run_id','case_id','case_paths','native_config','assigned_arm','input_policy']:
  if c[k]!=u[k]:raise SafetyError('C15_FROZEN_RUN_CONFIG_CHANGED:'+k)
 if c['source_files']!=plan['source_files'] or c['model']!='gpt-6-luna':raise SafetyError('C15_SOURCE_OR_MODEL_CHANGED')
 if c['budgets']!={'case_wall_seconds':1800,'worker_timeout_seconds':360}:raise SafetyError('C15_NATIVE_WAIT_BUDGET_CHANGED')
 if not time.time()<c['case_deadline_epoch']<=time.time()+1802:raise SafetyError('C15_CASE_DEADLINE')
 parent=ROOT/'private_recovery_attempts';parent.mkdir(mode=0o700,exist_ok=True)
 if any(alive(x) for x in parent.iterdir() if x.is_dir()):raise SafetyError('C15_CONCURRENCY_ONE')
 verify_sources(c);private_dir(parent,root.name);private_dir(root,'exchange');private_dir(root,'logs');atomic_create(root,'contract.json',c);atomic_create(root,'authorization.json',g)
 env={k:os.environ[k] for k in ['PATH','HOME','USER','LOGNAME','LANG','LC_ALL'] if k in os.environ};env.update(PYTHONDONTWRITEBYTECODE='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='',TMPDIR=str(ROOT/'tmp'),XDG_CACHE_HOME=str(ROOT/'cache'))
 with (root/'logs/controller.stdout').open('xb') as out,(root/'logs/controller.stderr').open('xb') as err:
  proc=subprocess.Popen([plan['controller_python'],'-B',str(ROOT/'src/c15_server_native_controller.py'),'--attempt',str(root)],cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,shell=False,start_new_session=True)
 atomic_create(root,'launch.json',{'utc':utc(),'pid':proc.pid,'attempt_id':root.name});return {'state':'CONTROLLER_STARTED','pid':proc.pid}

def evaluate_batch(root:Path) -> dict:
 batch=evaluation_gate(ROOT);c=attempt_contract(root);unit_by_attempt(root);verify_sources(c)
 unit=next(x for x in batch['units'] if x['run_unit_id']==c['run_unit_id'])
 if unit['status']!='FROZEN' or unit['attempt_id']!=c['attempt_id']:raise SafetyError('ONLY_FROZEN_COMPLETED_RUN_EVALUABLE')
 if not (root/'mac_freeze_attestation.json').exists():raise SafetyError('MAC_FREEZE_REQUIRED')
 frozen=read(root/'prediction_trace_freeze.json')
 def verify():
  for x in frozen['files']:
   if sha(safe_path(root,x['path']).read_bytes())!=x['sha256']:raise SafetyError('FROZEN_RUN_CHANGED')
 verify();out=ROOT/'evaluation'/c['run_unit_id']
 if (out/'evaluation_complete.json').exists():
  cached=read(out/'evaluation_complete.json');cached['official_result_utf8']=(out/'official_evaluation.json').read_text();verify();return cached
 private_dir(out.parent,out.name)
 # This is the first semantic Gold read, gated by the entire terminal batch seal.
 gold=c['case_paths']['ground_truth'];raw=Path(gold['path']).read_bytes()
 if sha(raw)!=gold['sha256']:raise SafetyError('GOLD_VERSION_MISMATCH')
 ip=c['case_paths']['input'];ib=Path(ip['path']).read_bytes()
 if sha(ib)!=ip['sha256']:raise SafetyError('DERIVED_INPUT_CHANGED')
 atomic_create(out,'evaluation_started.json',{'utc':utc(),'first_C15_Gold_semantic_read_after_entire_batch_seal':True,'batch_freeze_sha256':sha((ROOT/'09_batch_terminal_freeze.json').read_bytes())})
 def timeout(*unused):raise SafetyError('C15_EVALUATOR_TIMEOUT')
 signal.signal(signal.SIGALRM,timeout);signal.alarm(180)
 sys.path.insert(0,str(ROOT/'author_tree/benchmark'));import evaluate_chain_reconstruction as official
 result=official.evaluate(read(root/'prediction.json'),strict_json(raw.decode()),strict_json(ib.decode()));atomic_create(out,'official_evaluation.json',result);verify();signal.alarm(0)
 summary={k:v for k,v in result['metrics'].items() if isinstance(v,(int,float,bool)) or v is None};summary['bestmatch_order_pair_count']=len(result['best_matches'])*(len(result['best_matches'])-1)//2;summary['ceaf_order_pair_count']=len(result['ceaf_matches'])*(len(result['ceaf_matches'])-1)//2
 receipt={'state':'OFFICIAL_EVALUATED','run_unit_id':c['run_unit_id'],'metrics':summary,'prediction_sha256':sha((root/'prediction.json').read_bytes()),'trace_sha256':sha((root/'trace.json').read_bytes()),'evaluator_sha256':sha(ROOT/'author_tree/benchmark/evaluate_chain_reconstruction.py'),'Gold_exposed_to_worker':False,'official_result_sha256':sha((out/'official_evaluation.json').read_bytes())};atomic_create(out,'evaluation_complete.json',receipt);return {**receipt,'official_result_utf8':(out/'official_evaluation.json').read_text()}

def dispatch(root:Path,mode:str,payload:dict) -> dict:
 configure_case_scope(ROOT)
 if mode=='install_batch_freeze':
  frozen_check(ROOT);f=payload['freeze'];expected={x['run_unit_id'] for x in read(ROOT/'configs/run_units_private.json')['units']}
  if f.get('state') not in ('BATCH_PREDICTIONS_SEALED','PARTIAL_BATCH_CLOSED') or {x['run_unit_id'] for x in f['units']}!=expected:raise SafetyError('WHOLE_BATCH_TERMINALS_REQUIRED')
  if f['state']=='PARTIAL_BATCH_CLOSED' and not f.get('direct_user_termination_locator'):raise SafetyError('EXPLICIT_PARTIAL_TERMINATION_REQUIRED')
  for t in f['units']:
   if t['status'] not in (('FROZEN','FAILED','NOT_STARTED_CLOSED') if f['state']=='PARTIAL_BATCH_CLOSED' else ('FROZEN','FAILED')):raise SafetyError('BATCH_NONTERMINAL')
   if t['status']=='FROZEN' and sha(safe_path(ROOT,t['mac_manifest_path']).read_bytes())!=t['mac_manifest_sha256']:raise SafetyError('MAC_MANIFEST_NOT_MIRRORED')
  target=ROOT/'09_batch_terminal_freeze.json'
  if target.exists():
   if read(target)!=f:raise SafetyError('BATCH_FREEZE_CONFLICT')
  else:atomic_create(ROOT,target.name,f)
  return {'state':f['state'],'sha256':sha(target.read_bytes())}
 if mode=='start':return start(root,payload)
 if mode=='evaluate':return evaluate_batch(root)
 if mode=='get':
  v2.current_attempt(root);unit_by_attempt(root);seq=payload['seq'];p=safe_path(root,f'exchange/REQUEST_{seq:04d}.json')
  return {'state':'REQUEST','request':read(p),'historical_pair':None} if p.exists() else {'state':'WAIT'}
 if mode=='freeze_ack':
  ack=v2.dispatch(root,mode,payload);c=attempt_contract(root);target=ROOT/'runs'/c['run_unit_id'];target.mkdir(parents=True,exist_ok=True,mode=0o700)
  atomic_create(target,'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json',payload['manifest']);return ack
 if mode=='put':
  unit_by_attempt(root)
  if payload['response']['source']=='VERIFIED_REPLAY':raise SafetyError('C15_NO_CROSS_RUN_OR_HISTORICAL_REPLAY')
 # Identical-envelope ACK recovery uses the original V2 accept_response unchanged.
 return v2.dispatch(root,mode,payload)

if __name__=='__main__':
 os.umask(0o077)
 try:print(json.dumps(dispatch(Path(sys.argv[1]),sys.argv[2],strict_json(sys.stdin.read(12000000))),ensure_ascii=False))
 except Exception as e:print(json.dumps({'state':'IPC_REJECTED','reason':str(e)[:400]}),file=sys.stderr);raise SystemExit(3)
