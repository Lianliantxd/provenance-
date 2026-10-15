"""C13-R candidate only: bounded SSH retries never re-launch a model worker."""
from __future__ import annotations
import json,subprocess,time
from typing import Callable
class TransportStop(RuntimeError):pass
READ_ONLY={'status','get','consumed'}
BINDINGS=('run_id','attempt_id','case_id','seq','phase','prompt_sha256','reply_sha256')

def remaining(deadline:float,limit:float,clock:Callable[[],float])->float:
 left=min(limit,deadline-clock())
 if left<=0:raise TransportStop('CASE_OR_TOTAL_DEADLINE_EXHAUSTED')
 return left

def exchange(mode:str,payload:dict,send:Callable,*,deadline:float,clock=time.time,
             rpc_limit:float=60,read_retries:int=1)->dict:
 """send is a fixed trusted SSH argv function. Every retry shares one deadline.

 Never retry start/evaluate/stop/model. A put timeout may only read the receipt
 or resend the *same envelope* after a same-live-attempt get confirms identity.
 """
 if read_retries not in (0,1) or not 0<rpc_limit<=190:raise TransportStop('TRANSPORT_PROPOSAL_LIMIT')
 def once(m,p):return send(m,p,remaining(deadline,rpc_limit,clock))
 def read(m,p):
  try:return once(m,p)
  except (subprocess.TimeoutExpired,ConnectionError):
   if not read_retries:raise
   return once(m,p)
 try:return read(mode,payload) if mode in READ_ONLY else once(mode,payload)
 except (subprocess.TimeoutExpired,ConnectionError) as cause:
  if mode!='put':raise TransportStop('AMBIGUOUS_SSH_NO_MUTATING_RETRY:'+mode) from cause
 expected=payload['response'];seq=payload['seq']
 try:
  consumed=read('consumed',{'seq':seq})
  if consumed.get('state')=='CONTROLLER_CONTINUED':
   receipt=consumed.get('receipt',{})
   for key in ('attempt_id','seq','phase','prompt_sha256','reply_sha256','source'):
    if type(receipt.get(key)) is not type(expected[key]) or receipt.get(key)!=expected[key]:raise TransportStop('CONSUMED_RECEIPT_BINDING_MISMATCH')
   return {'state':'SERVER_ACCEPTED','seq':seq,'reply_sha256':expected['reply_sha256'],'reconciled_by':'EXACT_CONSUMED_RECEIPT','new_model_calls':0}
  if consumed.get('state')!='WAIT':raise TransportStop('UNKNOWN_CONSUMED_STATE')
  # server get refuses an exited/aborted controller; never backfill an old run.
  q=read('get',{'seq':seq})
  if q.get('state')!='REQUEST':raise TransportStop('LIVE_REQUEST_NOT_CONFIRMED')
  actual=q.get('request',{})
  for key in BINDINGS[:-1]:
   if type(actual.get(key)) is not type(expected[key]) or actual.get(key)!=expected[key]:raise TransportStop('LIVE_REQUEST_BINDING_MISMATCH')
  return once('put',payload)  # one exact idempotent envelope; never a model call.
 except (subprocess.TimeoutExpired,ConnectionError) as cause:
  raise TransportStop('ACK_RECONCILIATION_UNRESOLVED_NO_MORE_RETRY') from cause
