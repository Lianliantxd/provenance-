import json,sys,time,unittest,subprocess
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from native_recovery_orchestrator import rpc
from safe_paths import SafetyError
class Tests(unittest.TestCase):
 def plan(self):return {'server_root':'/SYNTHETIC_ROOT','controller_python':'/SYNTHETIC_PYTHON','evaluator_python':'/SYNTHETIC_EVALUATOR','ssh_identity_file':'/SYNTHETIC_KEY_PATH_ONLY','server':'SYNTHETIC_SERVER','_transport_deadline_epoch':time.time()+5}
 def test_rpc_read_retry_with_one_absolute_deadline(self):
  with patch('native_recovery_orchestrator.subprocess.run',side_effect=[subprocess.TimeoutExpired(['SYNTHETIC'],1),subprocess.CompletedProcess([],0,'{"state":"WAIT"}','')]) as run:
   self.assertEqual(rpc(self.plan(),'SYNTHETIC_ATTEMPT','get',{'seq':1})['state'],'WAIT');self.assertEqual(run.call_count,2)
   for call in run.call_args_list:self.assertLessEqual(call.kwargs['timeout'],5);self.assertIn('ConnectTimeout=30',call.args[0]);self.assertIs(call.kwargs['shell'],False)
 def test_missing_shared_deadline_stops(self):
  p=self.plan();del p['_transport_deadline_epoch']
  with patch('native_recovery_orchestrator.subprocess.run') as run:
   with self.assertRaisesRegex(SafetyError,'SHARED_TRANSPORT_DEADLINE'):rpc(p,'SYNTHETIC','get',{})
   run.assert_not_called()
 def test_logic_reject_does_not_retry(self):
  with patch('native_recovery_orchestrator.subprocess.run',return_value=subprocess.CompletedProcess([],3,'','SYNTHETIC_REJECT')) as run:
   with self.assertRaisesRegex(SafetyError,'LOGIC_REJECTED'):rpc(self.plan(),'SYNTHETIC','put',{})
   self.assertEqual(run.call_count,1)
