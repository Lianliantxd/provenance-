"""New attempt only. Unmodified native CPU Controller with a text mailbox."""
from __future__ import annotations
import argparse,json,os,re,signal,sys,time
from pathlib import Path
from safe_paths import SafetyError,atomic_create,safe_path,sha,strict_json
from strict_exchange_validator import phase_of,validate_request,validate_response
from bridge_state_machine import utc
PACKAGE=Path(__file__).resolve().parents[1]
class BridgeHalt(BaseException):pass

def attempt_contract(root):
 root=Path(root)
 if root.parent!=PACKAGE/'private_recovery_attempts':raise SafetyError('ATTEMPT_ROOT_SCOPE')
 safe_path(PACKAGE,str(root.relative_to(PACKAGE)))
 c=strict_json((root/'contract.json').read_text())
 if c['attempt_id']!=root.name or c['model']!='gpt-6-luna':raise SafetyError('ATTEMPT_BINDING')
 return c

def verify_sources(c):
 for item in c['source_files']:
  if sha(safe_path(PACKAGE/'author_tree/benchmark',item['relative']).read_bytes())!=item['sha256']:raise SafetyError('AUTHOR_SOURCE_CHANGED')
 for name in ['.env.local','author_tree/.env.local']:
  if safe_path(PACKAGE,name).exists():raise SafetyError('UNEXPECTED_ENV_FILE')

def alive(root):
 if (root/'controller_aborted.json').exists() or (root/'controller_complete.json').exists():return False
 p=root/'controller_started.json'
 if not p.exists():return False
 s=strict_json(p.read_text());pid=s['pid']
 try:
  os.kill(pid,0)
  cmd=Path('/proc')/str(pid)/'cmdline'
  return str(root).encode() in cmd.read_bytes() and b'server_native_controller.py' in cmd.read_bytes()
 except (OSError,ValueError):return False

class Mailbox:
 def __init__(self,root,c):self.root,self.c,self.calls,self.turn=root,c,0,0;self.counts=dict.fromkeys(['controller','repair','synthesis','reflection'],0)
 def __call__(self,prompt,**unused):
  try:return self.exchange(prompt)
  except Exception as e:raise BridgeHalt(type(e).__name__+':'+str(e)) from e
 def exchange(self,prompt):
  if self.calls>=47:raise SafetyError('NATIVE_MAX_PHASE_MESSAGES')
  self.calls+=1;phase=phase_of(prompt);self.counts[phase]+=1
  if phase=='controller':
   m=re.search(r'current turn is (\d+)',prompt)
   if m is None:raise SafetyError('MISSING_NATIVE_TURN')
   self.turn=int(m.group(1))
  q=dict(run_id=self.c['run_id'],attempt_id=self.c['attempt_id'],case_id=self.c['case_id'],seq=self.calls,phase=phase,controller_turn=self.turn,prompt_utf8=prompt,prompt_sha256=sha(prompt),created_utc=utc())
  validate_request(q)
  atomic_create(self.root,f'exchange/REQUEST_{self.calls:04d}.json',q)
  atomic_create(self.root,f'exchange/WAITING_{self.calls:04d}.json',{'pid':os.getpid(),'attempt_id':self.c['attempt_id'],'seq':self.calls})
  target=self.root/f'exchange/RESPONSE_{self.calls:04d}.json';deadline=min(time.time()+self.c['budgets']['worker_timeout_seconds']+30,self.c['case_deadline_epoch'])
  while not target.exists():
   if (self.root/'STOP.json').exists() or time.time()>=deadline:raise SafetyError('RESPONSE_WAIT_OR_CASE_TIMEOUT')
   time.sleep(.2)
  res=strict_json(target.read_text());raw=validate_response(q,res)
  if res['source']=='VERIFIED_REPLAY':
   from replay_and_resume import historical_pair,verified_replay
   pair=historical_pair(Path(self.c['historical_root']),self.calls)
   if pair is None:raise SafetyError('NO_HISTORICAL_REPLY_ON_SERVER')
   checked=verified_replay(q,*pair,prompt.encode(),old_controller_alive=False,new_attempt_is_fresh=True)
   if checked['reply_sha256']!=res['reply_sha256']:raise SafetyError('REPLAY_SERVER_HASH_MISMATCH')
  atomic_create(self.root,f'exchange/CONSUMED_{self.calls:04d}.json',{k:res[k] for k in ['seq','phase','prompt_sha256','reply_sha256','source','attempt_id']})
  import run_chain_reconstruction_paper_systems as systems
  usage=res.get('usage',{}) if res['source']!='VERIFIED_REPLAY' else {}
  systems.LAST_MODEL_CALL_TELEMETRY={'provider':'codex_chatgpt_text_bridge','model':'gpt-6-luna','response_model':'UNVERIFIED','prompt_tokens':usage.get('input_tokens'),'output_tokens':usage.get('output_tokens'),'prompt_chars':len(prompt),'output_chars':len(raw),'request_sha256':q['prompt_sha256'],'finish_reason':'VERIFIED_REPLAY' if res['source']=='VERIFIED_REPLAY' else 'CLI_TURN_COMPLETED'}
  return raw

def main(root):
 os.umask(0o077);c=attempt_contract(root);verify_sources(c)
 atomic_create(root,'controller_started.json',{'utc':utc(),'pid':os.getpid(),'attempt_id':c['attempt_id']})
 def stop(*unused):raise BridgeHalt('CASE_WALL_TIME_EXHAUSTED')
 if time.time()>=c['case_deadline_epoch']:raise SafetyError('CASE_DEADLINE_EXPIRED')
 signal.signal(signal.SIGALRM,stop);signal.alarm(max(1,int(c['case_deadline_epoch']-time.time())))
 os.nice(10)
 for key in ['input','retrieval_docs','input_graph']:
  p=Path(c['case_paths'][key]['path']);safe_path(p.parent,p.name)
  if sha(p.read_bytes())!=c['case_paths'][key]['sha256']:raise SafetyError('INPUT_HASH_CHANGED')
 sys.path.insert(0,str(PACKAGE/'author_tree/benchmark'))
 import agentic_reconstruction as native
 import run_chain_reconstruction_paper_systems as systems
 import socket
 def reject(*unused,**kwargs):raise BridgeHalt('SERVER_NETWORK_OR_MODEL_FORBIDDEN')
 socket.socket.connect=reject;socket.create_connection=reject;systems.call_model=reject
 mailbox=Mailbox(root,c);native.call_model=mailbox
 state=systems.build_state(*(Path(c['case_paths'][k]['path']) for k in ['input','retrieval_docs','input_graph']))
 fields={k:v for k,v in c['native_config'].items() if k in native.AgenticRunConfig.__dataclass_fields__};fields.update(provider='codex_chatgpt_text_bridge',model='gpt-6-luna',timeout=c['budgets']['worker_timeout_seconds'])
 cfg=native.AgenticRunConfig(**fields);kernel=native.PaperRetrievalKernel('ECRAG',state,top_k=32,max_observation_chars=cfg.max_observation_chars)
 prediction,trace=native.AgenticController(state,kernel,cfg).run()
 atomic_create(root,'prediction.json',prediction);atomic_create(root,'trace.json',trace)
 files=[{'path':str(p.relative_to(root)),'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(root.glob('exchange/*.json'))]+[{'path':n,'sha256':sha((root/n).read_bytes()),'bytes':(root/n).stat().st_size} for n in ['prediction.json','trace.json']]
 atomic_create(root,'prediction_trace_freeze.json',{'utc':utc(),'attempt_id':c['attempt_id'],'files':files,'model_messages':mailbox.calls,'phase_counts':mailbox.counts,'Gold_semantics_read':False})
 atomic_create(root,'controller_complete.json',{'state':'PREDICTION_FROZEN','attempt_id':c['attempt_id'],'model_messages':mailbox.calls});signal.alarm(0)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--attempt',required=True);root=Path(parser.parse_args().attempt)
 try:main(root)
 except BaseException as e:
  try:atomic_create(root,'controller_aborted.json',{'utc':utc(),'state':'FAILED_AND_SEALED','error_type':type(e).__name__,'reason':str(e)[:500]})
  except BaseException:pass
  raise SystemExit(3)
