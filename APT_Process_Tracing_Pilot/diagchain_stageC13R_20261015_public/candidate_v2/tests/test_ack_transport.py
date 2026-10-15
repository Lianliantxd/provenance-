import unittest,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from ssh_ack_transport import *
class Sim:
 def __init__(self,outcomes):self.outcomes=list(outcomes);self.calls=[]
 def __call__(self,m,p,t):
  self.calls.append((m,p,t));v=self.outcomes.pop(0)
  if isinstance(v,BaseException):raise v
  return v

def timeout():return subprocess.TimeoutExpired(['SYNTHETIC_SSH'],30)
def response():return {'run_id':'SYNTHETIC_RUN','attempt_id':'SYNTHETIC_NEW_ATTEMPT','case_id':'SYNTHETIC_CASE','seq':2,'phase':'controller','prompt_sha256':'a'*64,'reply_sha256':'b'*64,'source':'VERIFIED_REPLAY'}
def payload():return {'seq':2,'response':response()}
def receipt():return {'state':'CONTROLLER_CONTINUED','receipt':{k:response()[k] for k in ['attempt_id','seq','phase','prompt_sha256','reply_sha256','source']}}
def run(m,s,p=None,**kw):return exchange(m,p or {},s,deadline=100,clock=lambda:0,**kw)
class Tests(unittest.TestCase):
 def test_normal_ack(self):
  s=Sim([{'state':'SERVER_ACCEPTED'}]);self.assertEqual(run('put',s,payload())['state'],'SERVER_ACCEPTED');self.assertEqual(len(s.calls),1)
 def test_read_retry_once(self):
  for mode in READ_ONLY:
   s=Sim([timeout(),{'state':'WAIT'}]);self.assertEqual(run(mode,s)['state'],'WAIT');self.assertEqual(len(s.calls),2)
 def test_read_retry_bounded(self):
  s=Sim([timeout(),timeout(),{'state':'SHOULD_NOT_RUN'}])
  with self.assertRaises(TransportStop):run('get',s)
  self.assertEqual(len(s.calls),2)
 def test_no_start_evaluate_stop_or_model_retry(self):
  for mode in ['start','evaluate','stop','model']:
   s=Sim([timeout(),{'state':'SHOULD_NOT_RUN'}])
   with self.assertRaisesRegex(TransportStop,'NO_MUTATING_RETRY'):run(mode,s)
   self.assertEqual(len(s.calls),1)
 def test_put_resolved_by_consumed_receipt_no_resend(self):
  s=Sim([timeout(),receipt()]);r=run('put',s,payload());self.assertEqual(r['reconciled_by'],'EXACT_CONSUMED_RECEIPT');self.assertEqual([x[0] for x in s.calls],['put','consumed'])
 def test_consumed_bad_sha_stops(self):
  c=receipt();c['receipt']['reply_sha256']='c'*64;s=Sim([timeout(),c])
  with self.assertRaisesRegex(TransportStop,'BINDING_MISMATCH'):run('put',s,payload())
  self.assertEqual(len(s.calls),2)
 def test_pending_live_request_identical_resend(self):
  s=Sim([timeout(),{'state':'WAIT'},{'state':'REQUEST','request':response()},{'state':'ALREADY_ACCEPTED_IDENTICAL'}]);r=run('put',s,payload());self.assertEqual(r['state'],'ALREADY_ACCEPTED_IDENTICAL');self.assertEqual(s.calls[0][1],s.calls[3][1])
 def test_exited_controller_no_backfill(self):
  s=Sim([timeout(),{'state':'WAIT'},{'state':'FAILED_AND_SEALED'}])
  with self.assertRaisesRegex(TransportStop,'LIVE_REQUEST_NOT_CONFIRMED'):run('put',s,payload())
 def test_wrong_attempt_no_backfill(self):
  q={**response(),'attempt_id':'OTHER'};s=Sim([timeout(),{'state':'WAIT'},{'state':'REQUEST','request':q}])
  with self.assertRaisesRegex(TransportStop,'LIVE_REQUEST_BINDING'):run('put',s,payload())
 def test_second_put_timeout_no_third_send(self):
  s=Sim([timeout(),{'state':'WAIT'},{'state':'REQUEST','request':response()},timeout(),{'state':'SHOULD_NOT_RUN'}])
  with self.assertRaisesRegex(TransportStop,'UNRESOLVED_NO_MORE_RETRY'):run('put',s,payload())
  self.assertEqual(len(s.calls),4)
 def test_shared_deadline(self):
  times=iter([0,101]);s=Sim([timeout(),{'state':'SHOULD_NOT_RUN'}])
  with self.assertRaisesRegex(TransportStop,'DEADLINE'):exchange('get',{},s,deadline=100,clock=lambda:next(times))
  self.assertEqual(len(s.calls),1)
 def test_timeout_reduced_to_remaining(self):
  s=Sim([{'state':'WAIT'}]);exchange('get',{},s,deadline=8,clock=lambda:5);self.assertEqual(s.calls[0][2],3)
 def test_no_logic_rejection_retry(self):
  s=Sim([ValueError('SYNTHETIC_IPC_REJECTED'),{'state':'SHOULD_NOT_RUN'}])
  with self.assertRaises(ValueError):run('put',s,payload())
  self.assertEqual(len(s.calls),1)
 def test_untrusted_text_not_executed(self):
  p=payload();p['response']['raw_reply_utf8']='SYNTHETIC $(touch invalid); `false`';s=Sim([timeout(),{'state':'WAIT'},{'state':'REQUEST','request':response()},{'state':'SERVER_ACCEPTED'}]);run('put',s,p);self.assertEqual(s.calls[-1][1],p)
if __name__=='__main__':unittest.main()
