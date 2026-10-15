import copy,json,os,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from safe_paths import *
from jsonl_final_message_parser import *
from strict_exchange_validator import *
from bridge_state_machine import *
from replay_and_resume import *
from codex_worker_config import *
from recovery_runner import run_fake_exchange,capture_process

def stream(raw='{}',earlier=None,extra=None):
 e=[{'type':'thread.started','thread_id':'synthetic-thread'},{'type':'turn.started'}]
 if extra:e+=extra
 if earlier is not None:e.append({'type':'item.completed','item':{'type':'agent_message','id':'a','text':earlier}})
 e += [{'type':'item.completed','item':{'type':'agent_message','id':'b','text':raw}},{'type':'turn.completed','usage':{'input_tokens':1,'output_tokens':2}}]
 return ('\n'.join(json.dumps(x,ensure_ascii=False) for x in e)+'\n').encode()
def request(case='SYNTHETIC_A',seq=1,phase='controller'):
 return dict(run_id='SYNTHETIC_RUN',attempt_id='fresh',case_id=case,seq=seq,phase=phase,controller_turn=1,prompt_utf8='SYNTHETIC data $(touch nope); `false` 中文',prompt_sha256=sha('SYNTHETIC data $(touch nope); `false` 中文'),data_class='SYNTHETIC_ONLY')
def budget(p,**kw):
 return Budget(p,total_limit=kw.get('total',46),per_case_limit=kw.get('each',23),total_wall=kw.get('total_wall',3600),case_wall=kw.get('case_wall',1800),worker_wait=kw.get('wait',2),synthetic=True)
class Tests(unittest.TestCase):
 def setUp(self):
  self.root=private_dir(ROOT/'synthetic_exchange','test_'+uuid.uuid4().hex)
 def expect(self,code,func,*a,**kw):
  with self.assertRaisesRegex((SafetyError,FileExistsError),code):func(*a,**kw)
 def test_single(self):self.assertEqual(parse_final(stream(),b'{}',0)['completed_message_count'],1)
 def test_multiple_distinct_messages(self):
  r=parse_final(stream('{"x":2}',earlier='commentary'),b'{"x":2}',0);self.assertEqual(r['completed_message_count'],2);self.assertFalse(r['messages_concatenated'])
 def test_utf8_physical_chunks(self):
  p=JsonlParser()
  for b in stream('{"值":"中"}'):p.feed(bytes([b]))
  self.assertEqual(p.finish('{"值":"中"}'.encode(),0)['author_json_status'],'OBJECT')
 def test_no_unconditional_concatenation(self):self.expect('OUTPUT_FILE_MISMATCH',parse_final,stream('{}',earlier='x'),b'x{}',0)
 def test_unknown_fragments(self):
  e=[{'type':'item.completed','item':{'type':'agent_message','id':'x','content':[{'text':'{}'}]}}]
  self.expect('UNVERIFIED_FRAGMENT_SCHEMA',parse_final,stream(extra=e),b'{}',0)
 def test_tool_event(self):self.expect('TOOL_OR_UNSUPPORTED',parse_final,stream(extra=[{'type':'item.started','item':{'type':'command_execution','id':'c','command':'SYNTHETIC'}}]),b'{}',0)
 def test_stderr_not_model(self):
  r=self.fake({'stderr':'DEBUG synthetic warning\n'});self.assertEqual(r['raw_reply_utf8'],'{}')
 def test_debug_stdout_rejected(self):self.expect('INVALID_OR_TRUNCATED_JSONL',parse_final,b'debug\n'+stream(),b'{}',0)
 def test_truncated_event(self):self.expect('INVALID_OR_TRUNCATED_JSONL',parse_final,stream()+b'{"type":',b'{}',0)
 def test_empty(self):self.expect('EMPTY_OR_OVERSIZED',parse_final,stream(''),b'',0)
 def test_invalid_author_json_preserved(self):self.assertEqual(parse_final(stream('{broken'),b'{broken',0)['author_json_status'],'INVALID_OR_TRUNCATED_AUTHOR_JSON')
 def test_root_type_preserved(self):self.assertEqual(parse_final(stream('[]'),b'[]',0)['author_json_status'],'JSON_ROOT_NOT_OBJECT')
 def test_duplicate_final(self):
  e={'type':'item.completed','item':{'type':'agent_message','id':'b','text':'{}'}}
  self.expect('DUPLICATE_FINAL_EVENT',parse_final,stream(extra=[e]),b'{}',0)
 def test_duplicate_turn(self):self.expect('EVENT_AFTER_TURN_COMPLETION',parse_final,stream()+b'{"type":"turn.completed"}\n',b'{}',0)
 def test_file_mismatch(self):self.expect('OUTPUT_FILE_MISMATCH',parse_final,stream(),b'{"x":1}',0)
 def test_nonzero_exit(self):self.expect('CLI_EXIT_ABNORMAL',parse_final,stream(),b'{}',1)
 def test_partial_exit(self):self.expect('CLI_EXIT_ABNORMAL',parse_final,b'{"type":"thread.started"}\n',b'partial',2)
 def test_bounded_tls_then_complete(self):
  for msg in ['stream disconnected before completion: tls handshake eof','request timed out','Connection failed: error sending request']:
   r=parse_final(stream(extra=[{'type':'error','message':'Reconnecting... 2/5 ('+msg+')'}]),b'{}',0);self.assertEqual(len(r['transport_events']),1)
 def test_tls_counter_reset(self):
  e=[{'type':'error','message':f'Reconnecting... {n}/5 (stream disconnected before completion: tls handshake eof)'} for n in (4,5,1)]
  self.expect('TRANSPORT_RETRY_STATE_UNKNOWN',parse_final,stream(extra=e),b'{}',0)
 def test_certificate_error_stop(self):self.expect('UNRECOGNIZED',parse_final,stream(extra=[{'type':'error','message':'certificate validation failed'}]),b'{}',0)
 def test_pre_turn_failure(self):self.expect('UNRECOGNIZED_OR_PRE_TURN',parse_final,b'{"type":"error","message":"connection failed"}\n',b'',1)
 def test_missing_completion(self):self.expect('REMOTE_COMPLETION_UNKNOWN',parse_final,b'{"type":"thread.started"}\n{"type":"turn.started"}\n',b'{}',0)
 def test_repeated_finish(self):
  p=JsonlParser();p.feed(stream());p.finish(b'{}',0);self.expect('ALREADY_FINISHED',p.finish,b'{}',0)
 def test_reply_hash_binding(self):
  q=request();r=make_response(q,'{}',source='FAKE_WORKER',parser_receipt=parse_final(stream(),b'{}',0));r['reply_sha256']='0'*64;self.expect('REPLY_BYTES',validate_response,q,r,synthetic=True)
 def test_prompt_hash_binding(self):
  q=request();q['prompt_sha256']='0'*64;self.expect('PROMPT_BYTES',validate_request,q,synthetic=True)
 def test_run_seq_phase_binding(self):
  q=request();r=make_response(q,'{}',source='FAKE_WORKER',parser_receipt=parse_final(stream(),b'{}',0))
  for k,v in [('run_id','other'),('seq',2),('phase','repair'),('attempt_id','other'),('case_id','SYNTHETIC_B')]:
   wrong={**r,k:v};self.expect('RESPONSE_BINDING',validate_response,q,wrong,synthetic=True)
 def test_valid_replay_zero_calls(self):
  q=request();old={**q,'attempt_id':'old'};r=make_response(old,'{}',source='FAKE_WORKER',parser_receipt=parse_final(stream(),b'{}',0))
  res=verified_replay(q,old,r,q['prompt_utf8'].encode(),old_controller_alive=False,new_attempt_is_fresh=True,synthetic=True);self.assertEqual(res['replay_provenance']['new_cli_invocations'],0)
 def test_replay_inconsistent_prompt(self):
  q=request();old={**q,'attempt_id':'old'};r=make_response(old,'{}',source='FAKE_WORKER',parser_receipt=parse_final(stream(),b'{}',0));self.expect('REGENERATED_PROMPT',verified_replay,q,old,r,b'different',old_controller_alive=False,new_attempt_is_fresh=True,synthetic=True)
 def test_exited_backfill_refused(self):
  q=request();self.expect('EXITED_ATTEMPT_BACKFILL',verified_replay,q,q,{},q['prompt_utf8'].encode(),old_controller_alive=False,new_attempt_is_fresh=True,synthetic=True)
 def test_unknown_no_resend(self):
  q=request();self.expect('NO_AUTOMATIC_RESEND',reject_unknown_resend,q,[q],{});reject_unknown_resend(q,[q],{'explicit_unknown_completion_reissue':[{**q,'approved':True}]})
 def test_all_phases_budget(self):
  b=budget(self.root/'budget',each=4,total=4);b.begin_case('SYNTHETIC_A')
  for i,phase in enumerate(['controller','repair','synthesis','reflection'],1):b.reserve(request(seq=i,phase=phase))
  self.expect('NEW_CLI_BUDGET',b.reserve,request(seq=5))
 def test_duplicate_request(self):
  b=budget(self.root/'budget');b.begin_case('SYNTHETIC_A');b.reserve(request());self.expect('DUPLICATE_CLI',b.reserve,request())
 def test_case_isolation_and_per_case_cap(self):
  b=budget(self.root/'budget',each=1,total=2);b.begin_case('SYNTHETIC_A');b.begin_case('SYNTHETIC_B');b.reserve(request());self.expect('NEW_CLI_BUDGET',b.reserve,request(seq=2));b.reserve({**request('SYNTHETIC_B'),'attempt_id':'freshB'});self.assertEqual(len(b.reservations),2)
 def test_wall_budget(self):
  b=budget(self.root/'budget',case_wall=.01);b.begin_case('SYNTHETIC_A');time.sleep(.02);self.expect('WALL_TIME',b.reserve,request())
 def test_budget_limits(self):self.expect('EXCEEDS',budget,self.root/'b',total=47)
 def test_no_budget_restart(self):
  b=budget(self.root/'b');b.begin_case('SYNTHETIC_A');self.expect('CASE_ALREADY_STARTED',b.begin_case,'SYNTHETIC_A')
 def test_state_machine_unknown_terminal(self):
  s=ExchangeState(self.root/'journal',request());s.transition('REQUEST_SENT');s.transition('REMOTE_COMPLETION_UNKNOWN');self.expect('INVALID_STATE',s.transition,'REQUEST_SENT');s.transition('FAILED_AND_SEALED')
 def test_prediction_before_evaluation(self):
  s=ExchangeState(self.root/'journal',request());self.expect('INVALID_STATE',s.transition,'OFFICIAL_EVALUATED')
 def test_atomic_private_nonoverwriting(self):
  p=atomic_create(self.root,'x',b'first');self.assertEqual(p.stat().st_mode&0o777,0o600);self.expect('File exists',atomic_create,self.root,'x',b'second');self.assertEqual(p.read_bytes(),b'first')
 def test_traversal(self):
  for p in ['../x','/tmp/x']:self.expect('PATH_OUTSIDE',atomic_create,self.root,p,b'bad')
 def test_symlink(self):
  (self.root/'link').symlink_to(self.root,target_is_directory=True);self.expect('SYMLINK',atomic_create,self.root,'link/x',b'bad');self.expect('SYMLINK',ExchangeState,self.root/'link/journal',request())
 def test_parallel_lease(self):
  with ExclusiveLease(self.root):self.expect('File exists',ExclusiveLease(self.root).__enter__)
 def test_gate_before_real_execution(self):self.expect('AWAIT_AUTHORIZATION',require_authorization,{})
 def test_paid_spend_rejected(self):
  g={**dict.fromkeys(GATES,True),'model':'gpt-6-luna','auth_mode':'SIGN_IN_WITH_CHATGPT','paid_credits_allowed':True};self.expect('SPEND_GUARD',require_authorization,g)
 def test_environment_no_credentials(self):
  os.environ['C13R_UNTRUSTED']='$(false)';self.assertNotIn('C13R_UNTRUSTED',clean_environment());self.assertEqual(clean_environment().get('HOME'),os.environ.get('HOME'))
 def test_fake_rejects_real_case(self):
  q=request('excytin-incident-34.alert-evidence');self.expect('FAKE_WORKER_REJECTS',run_fake_exchange,q,self.root,self.root,None,None,Path('x'),Path('x'))
 def fake(self,changes=None,timeout=2):
  f={'data_class':'SYNTHETIC_ONLY','canonical':'{}','stdout_chunks':[stream().decode()]};f.update(changes or {})
  fixture=atomic_create(self.root,'fixture.json',f);q=request();state=ExchangeState(self.root/'journal',q);b=budget(self.root/'budget',wait=timeout);b.begin_case(q['case_id']);w=private_dir(self.root,'worker')
  return run_fake_exchange(q,self.root,w,state,b,ROOT/'tests/fake_worker.py',fixture)
 def test_fake_delayed_reply(self):self.assertEqual(self.fake({'delay_before':.03})['source'],'FAKE_WORKER')
 def test_fake_timeout_unknown(self):
  self.expect('CLI_PROCESS_TIMEOUT',self.fake,{'delay_before':.3},.03);states=[p.name for p in (self.root/'journal').glob('*.json')];self.assertTrue(any('REMOTE_COMPLETION_UNKNOWN' in n for n in states))
 def test_fake_nonzero_partial(self):self.expect('CLI_EXIT_ABNORMAL',self.fake,{'exit_code':2})
 def test_fake_pre_send_spawn_failure(self):
  q=request();s=ExchangeState(self.root/'journal',q)
  with self.assertRaises(FileNotFoundError):capture_process(['/synthetic-missing-executable',str(self.root/'final_reply_utf8.txt')],q,self.root,self.root,1,s,synthetic=True)
  self.assertEqual(s.state,'FAILED_AND_SEALED')
if __name__=='__main__':
 os.umask(0o077);unittest.main(verbosity=2)
