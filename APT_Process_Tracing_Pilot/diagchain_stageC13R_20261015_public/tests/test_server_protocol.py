import sys,unittest,uuid,json
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from safe_paths import *
from server_protocol import accept_response,current_attempt
from native_recovery_orchestrator import checked_budgets
from codex_worker_config import clean_environment
import os
class ServerTests(unittest.TestCase):
 def setUp(self):
  self.root=private_dir(ROOT/'synthetic_exchange','ipc_'+uuid.uuid4().hex);private_dir(self.root,'exchange')
  atomic_create(self.root,'controller_started.json',{'pid':123,'attempt_id':'SYNTHETIC_ATTEMPT'})
  atomic_create(self.root,'exchange/REQUEST_0001.json',{'data_class':'SYNTHETIC_ONLY'})
  atomic_create(self.root,'exchange/WAITING_0001.json',{'pid':123,'attempt_id':'SYNTHETIC_ATTEMPT'})
  self.c={'attempt_id':'SYNTHETIC_ATTEMPT'};self.r={'reply_sha256':sha('SYNTHETIC'),'data_class':'SYNTHETIC_ONLY'}
 def test_identical_ack_idempotent(self):
  with patch('server_protocol.current_attempt',return_value=self.c),patch('server_protocol.validate_response'):
   self.assertEqual(accept_response(self.root,1,self.r)['state'],'SERVER_ACCEPTED')
   self.assertEqual(accept_response(self.root,1,self.r)['state'],'ALREADY_ACCEPTED_IDENTICAL')
 def test_conflict_not_overwritten(self):
  with patch('server_protocol.current_attempt',return_value=self.c),patch('server_protocol.validate_response'):
   accept_response(self.root,1,self.r)
   with self.assertRaisesRegex(SafetyError,'CONFLICTING_DUPLICATE'):accept_response(self.root,1,{**self.r,'reply_sha256':sha('other')})
 def test_exited_controller_no_put(self):
  with patch('server_protocol.attempt_contract',return_value=self.c),patch('server_protocol.alive',return_value=False):
   with self.assertRaisesRegex(SafetyError,'EXITED_CONTROLLER'):accept_response(self.root,1,self.r)
 def test_waiting_mismatch(self):
  with patch('server_protocol.current_attempt',return_value={'attempt_id':'OTHER'}),patch('server_protocol.validate_response'):
   with self.assertRaisesRegex(SafetyError,'WAITING_IDENTITY'):accept_response(self.root,1,self.r)
 def test_budget_proposal_and_smaller_approval(self):
  b={'total_new_cli_calls':46,'per_case_new_cli_calls':23,'worker_timeout_seconds':360,'case_wall_seconds':1800,'total_wall_seconds':3600,'concurrency':1}
  self.assertEqual(checked_budgets({'approved_budgets':b},{'proposed_budgets':b}),b)
  smaller={**b,'total_new_cli_calls':4,'per_case_new_cli_calls':2};self.assertEqual(checked_budgets({'approved_budgets':smaller},{'proposed_budgets':b}),smaller)
  with self.assertRaises(SafetyError):checked_budgets({'approved_budgets':{**b,'total_new_cli_calls':47}},{'proposed_budgets':b})
 def test_nested_markers_preserved(self):
  with patch.dict(os.environ,{'CODEX_SESSION_ID':'SYNTHETIC_MARKER','OPENAI_API_KEY':'SYNTHETIC_NOT_REAL'}):
   env=clean_environment();self.assertEqual(env['CODEX_SESSION_ID'],'SYNTHETIC_MARKER');self.assertNotIn('OPENAI_API_KEY',env)
if __name__=='__main__':unittest.main()

class AdditionalTests(unittest.TestCase):
 def test_native_errors_not_swallowed_as_json_repair(self):
  from server_native_controller import BridgeHalt
  self.assertFalse(issubclass(BridgeHalt,Exception))
 def test_all_python_syntax_and_no_untrusted_execution_apis(self):
  import ast
  for p in (ROOT/'src').glob('*.py'):
   tree=ast.parse(p.read_text(),feature_version=(3,9))
   for n in ast.walk(tree):
    if isinstance(n,ast.Call):
     self.assertFalse(isinstance(n.func,ast.Name) and n.func.id in ['eval','exec'])
     self.assertFalse(isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='os' and n.func.attr=='system')
     for keyword in n.keywords:
      if keyword.arg=='shell':self.assertIs(keyword.value.value,False)
 def test_all_native_sources_remain_byte_identical(self):
  c=json.loads((ROOT/'private_history_audit/task_context.json').read_text())
  for item in c['source_files']:self.assertEqual(sha((ROOT/'author_tree/benchmark'/item['relative']).read_bytes()),item['sha256'])

class FallbackTests(unittest.TestCase):
 def test_actual_https_fallback_then_retry_reset_stops(self):
  from test_transport import stream
  from jsonl_final_message_parser import parse_final,ParseFailure
  e=[{'type':'error','message':'Reconnecting... 5/5 (stream disconnected before completion: tls handshake eof)'}, {'type':'item.completed','item':{'type':'error','message':'Falling back from WebSockets to HTTPS transport. stream disconnected before completion: tls handshake eof'}},{'type':'error','message':'Reconnecting... 1/5 (Connection failed: error sending request)'}]
  with self.assertRaisesRegex(ParseFailure,'TRANSPORT_RETRY_STATE_UNKNOWN'):parse_final(stream(extra=e),b'{}',0)
 def test_known_https_fallback_completed_without_reset(self):
  from test_transport import stream
  from jsonl_final_message_parser import parse_final
  e=[{'type':'error','message':'Reconnecting... 2/5 (stream disconnected before completion: tls handshake eof)'},{'type':'item.completed','item':{'type':'error','message':'Falling back from WebSockets to HTTPS transport. stream disconnected before completion: tls handshake eof'}}]
  self.assertTrue(parse_final(stream(extra=e),b'{}',0)['https_fallback_observed'])
