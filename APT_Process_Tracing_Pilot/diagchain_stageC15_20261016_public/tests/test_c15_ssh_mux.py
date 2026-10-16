import sys,time,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import c15_resume_mux as mux
from ssh_ack_transport import TransportStop

PLAN={'server_root':'/synthetic/study','controller_python':'/synthetic/python','evaluator_python':'/synthetic/evaluator','ssh_identity_file':'/synthetic/key','server':'synthetic@host'}
class SshMuxTests(unittest.TestCase):
    def test_only_temporary_mux_options_change_and_payload_stays_data(self):
        with patch.object(mux.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='{"state":"WAIT"}',stderr='')) as call:
            self.assertEqual(mux.rpc(PLAN,'synthetic_attempt','get',{'seq':1},deadline=time.time()+30),{'state':'WAIT'})
        args,kwargs=call.call_args;argv=args[0]
        self.assertIn('ControlMaster=auto',argv);self.assertIn('ControlPersist=600',argv);self.assertIn('ControlPath='+mux.SOCKET,argv)
        self.assertEqual(kwargs['cwd'],mux.ROOT);self.assertFalse(kwargs['shell']);self.assertEqual(json.loads(kwargs['input']),{'seq':1});self.assertLessEqual(kwargs['timeout'],30)
    def test_readonly_failure_has_only_original_single_retry(self):
        with patch.object(mux.subprocess,'run',return_value=SimpleNamespace(returncode=255,stdout='',stderr='synthetic disconnect')) as call:
            with self.assertRaises(TransportStop):mux.rpc(PLAN,'synthetic_attempt','status',{},deadline=time.time()+30)
            self.assertEqual(call.call_count,2)
    def test_start_failure_is_never_retried(self):
        with patch.object(mux.subprocess,'run',return_value=SimpleNamespace(returncode=255,stdout='',stderr='synthetic disconnect')) as call:
            with self.assertRaises(TransportStop):mux.rpc(PLAN,'synthetic_attempt','start',{},deadline=time.time()+30)
            self.assertEqual(call.call_count,1)
    def test_expired_deadline_never_launches_ssh(self):
        with patch.object(mux.subprocess,'run') as call:
            with self.assertRaises(TransportStop):mux.rpc(PLAN,'synthetic_attempt','status',{},deadline=time.time()-1)
            call.assert_not_called()
    def test_unknown_server_reply_stays_rejected(self):
        with patch.object(mux.subprocess,'run',return_value=SimpleNamespace(returncode=3,stdout='',stderr='synthetic server rejection')):
            with self.assertRaises(mux.SafetyError):mux.rpc(PLAN,'synthetic_attempt','get',{'seq':1},deadline=time.time()+30)

if __name__=='__main__':unittest.main()
