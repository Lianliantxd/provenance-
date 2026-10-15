"""Small C15 input/config/schedule, authorization and persistent batch-budget adapters."""
from __future__ import annotations
import csv,copy,datetime,hashlib,json,os,random,re,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT/'src'))
from safe_paths import SafetyError,atomic_create,private_dir,safe_path,sha,strict_json
LIMITS={'planned':18,'per_run_new_cli':46,'total_new_cli':828,'cli_wait_seconds':360,'run_active_seconds':1800,'batch_active_seconds':32400,'concurrency':1}
POLICY='KNOWN_LENGTH_METADATA_REMOVED_V1'
SEED='C15_REFLECTION_SWITCH_V1'

def utc() -> str:return datetime.datetime.now(datetime.timezone.utc).isoformat()
def read(path:Path) -> dict:return strict_json(path.read_text())
def write_state(path:Path,value:dict) -> None:
 safe_path(path.parent,path.name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 tmp=path.with_name('.state-'+uuid.uuid4().hex);tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');tmp.chmod(0o600);os.replace(tmp,path)

def transform_input(original:dict) -> tuple[dict,list[dict]]:
 derived=copy.deepcopy(original);delta=[]
 for key in ('length_bucket','length_bucket_label'):
  if key in derived:delta.append({'op':'remove','json_path':'$.'+key,'old_value':derived.pop(key)})
 expected={k:v for k,v in original.items() if k not in ('length_bucket','length_bucket_label')}
 if derived!=expected or derived.get('evidence_cards')!=original.get('evidence_cards'):raise SafetyError('UNAUTHORIZED_INPUT_CHANGE')
 return derived,delta

def schedule() -> list[dict]:
 rng=random.Random(SEED);first_by_case={c:([True,True,False] if i<2 else [True,False,False]) for i,c in enumerate(['C1','C2','C3'])}
 for a in first_by_case.values():rng.shuffle(a)
 rows=[];block=0
 for repeat in range(1,4):
  cases=['C1','C2','C3'];rng.shuffle(cases)
  for case in cases:
   block+=1;first=first_by_case[case][repeat-1]
   for arm in (['ON','OFF'] if first else ['OFF','ON']):rows.append({'execution_order':len(rows)+1,'block':block,'case_alias':case,'repeat_id':'R'+str(repeat),'assigned_arm':arm,'run_unit_id':case+'_R'+str(repeat)+'_'+arm,'agent_method':'reflection' if arm=='ON' else 'plain'})
 assert len({x['run_unit_id'] for x in rows})==18
 assert sum(x['assigned_arm']=='ON' for x in rows[::2])==5
 return rows

def configure_case_scope(root:Path) -> None:
 # New batch's fixed three-case allowlist, not a relaxation of identity/byte checks.
 import strict_exchange_validator as validator
 cases={c['case_id'] for c in read(root/'configs/study_private.json')['cases']}
 if len(cases)!=3:raise SafetyError('C15_REQUIRES_EXACTLY_THREE_FIXED_CASES')
 validator.CASES=frozenset(cases)

def audit_metadata_prompt(q:dict) -> dict:
 if q['phase']=='repair':return {'policy':POLICY,'status':'NATIVE_REPAIR_HAS_NO_CASE_STUB; raw model reply not rewritten','prompt_sha256':q['prompt_sha256']}
 marker='Incident metadata without full evidence:\n';text=q['prompt_utf8']
 if marker not in text:raise SafetyError('C15_METADATA_STUB_BOUNDARY_MISSING')
 start=text.index(marker)+len(marker)
 try:stub,n=json.JSONDecoder().raw_decode(text[start:])
 except ValueError as e:raise SafetyError('C15_METADATA_STUB_UNPARSEABLE') from e
 def visit(obj):
  if isinstance(obj,dict):
   if any(k in obj for k in ('length_bucket','length_bucket_label')):raise SafetyError('C15_KNOWN_LENGTH_METADATA_REINJECTED')
   for v in obj.values():visit(v)
  elif isinstance(obj,list):
   for v in obj:visit(v)
 visit(stub)
 return {'policy':POLICY,'status':'KNOWN_STRUCTURED_LENGTH_KEYS_ABSENT','stub_char_span':[start,start+n],'stub_sha256':sha(text[start:start+n]),'prompt_sha256':q['prompt_sha256'],'logs_not_globally_rewritten':True}

def frozen_check(root:Path) -> dict:
 f=read(root/'08_preregistration_and_code_freeze.json')
 for row in f['files']:
  if sha(safe_path(root,row['path']).read_bytes())!=row['sha256']:raise SafetyError('C15_FROZEN_PREPARATION_CHANGED:'+row['path'])
 return f

def require_batch_authorization(root:Path,gate:dict) -> None:
 if gate.get('state')!='USER_APPROVED_C15_18_RUN_BATCH' or gate.get('direct_user_message_locator') in (None,'','PENDING'):raise SafetyError('C15_PREPARED_AWAITING_BATCH_AUTHORIZATION')
 if gate.get('approved_protocol_sha256')!=sha((root/'08_preregistration_and_code_freeze.json').read_bytes()):raise SafetyError('C15_AUTHORIZATION_VERSION_MISMATCH')
 if gate.get('limits')!=LIMITS or gate.get('model')!='gpt-6-luna' or gate.get('auth_mode')!='SIGN_IN_WITH_CHATGPT':raise SafetyError('C15_AUTHORIZATION_SCOPE_MISMATCH')
 if gate.get('auto_recharge_confirmed_off') is not True or gate.get('paid_credits_allowed') is not False or gate.get('operator_mode')!='direct_current_codex_session':raise SafetyError('C15_SPEND_OR_OPERATOR_AUTHORIZATION_MISSING')
 expected={x['run_unit_id'] for x in schedule()}
 if set(gate.get('approved_run_unit_ids',[]))!=expected:raise SafetyError('C15_NOT_ALL_18_UNITS_APPROVED')
 # The receipt is recorded by the engineering Agent only AFTER a direct human reply.
 # Boolean values are assertions of that trust boundary, never a substitute for it.

def require_quota(receipt:dict,gate:dict,*,now:float|None=None) -> None:
 now=time.time() if now is None else now
 if receipt.get('source')!='get_usage_limits' or now-receipt.get('checked_epoch',0)>900 or receipt.get('checked_epoch',0)>now+30:raise SafetyError('CURRENT_QUOTA_RECEIPT_REQUIRED')
 if receipt.get('ordinaryUsageAllowed') is not True or receipt.get('included_exhausted') is not False:raise SafetyError('PAUSED_FOR_INCLUDED_QUOTA')
 credits=receipt.get('credits',{})
 if credits.get('hasCredits') is not False or str(credits.get('balance')) not in ('0','0.0') or credits.get('unlimited') is not False:raise SafetyError('ONLY_INCLUDED_SPEND_CONTROL_UNVERIFIED')
 if gate.get('auto_recharge_confirmed_off') is not True:raise SafetyError('AUTOMATIC_RELOAD_UNVERIFIED')

def evaluation_gate(root:Path) -> dict:
 fpath=root/'09_batch_terminal_freeze.json'
 if not fpath.exists():raise SafetyError('BATCH_NOT_SEALED_NO_GOLD_READ')
 f=read(fpath)
 if f['state'] not in ('BATCH_PREDICTIONS_SEALED','PARTIAL_BATCH_CLOSED'):raise SafetyError('BATCH_NOT_CLOSED_NO_GOLD_READ')
 if f['state']=='PARTIAL_BATCH_CLOSED' and not f.get('direct_user_termination_locator'):raise SafetyError('EXPLICIT_PARTIAL_TERMINATION_REQUIRED')
 if f['state']=='BATCH_PREDICTIONS_SEALED' and (len(f['units'])!=18 or any(x['status'] not in ('FROZEN','FAILED') for x in f['units'])):raise SafetyError('BATCH_TERMINALS_INCOMPLETE')
 for x in f['units']:
  if x.get('mac_manifest_path') and sha(safe_path(root,x['mac_manifest_path']).read_bytes())!=x['mac_manifest_sha256']:raise SafetyError('BATCH_MANIFEST_CHANGED')
 return f

class BatchBudget:
 """Reservations persist before Popen; active elapsed cannot reset across blocks."""
 def __init__(self,root:Path,unit:dict,*,clock=time.time,limits:dict|None=None):
  self.root,self.unit,self.clock=root,unit,clock;self.limits=limits or LIMITS;self.journal=root/'budget';self.journal.mkdir(mode=0o700,exist_ok=True)
  self.start_file=root/'runs'/unit['run_unit_id']/'active_start.json';self.elapsed_clock=time.monotonic if clock is time.time else clock;self.active_clock_start=None
 def begin_case(self,case_id:str) -> None:
  if case_id!=self.unit['case_id']:raise SafetyError('BUDGET_CASE_IDENTITY')
  self.start_file.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  if self.start_file.exists():raise SafetyError('RUN_ALREADY_STARTED_NO_TIME_RESET')
  self.active_clock_start=self.elapsed_clock()
  atomic_create(self.start_file.parent,self.start_file.name,{'start_epoch':self.clock(),'run_unit_id':self.unit['run_unit_id'],'case_id':case_id,'utc':utc()})
 def active_seconds(self) -> float:
  return max(0,self.elapsed_clock()-self.active_clock_start) if self.active_clock_start is not None else max(0,self.clock()-read(self.start_file)['start_epoch'])
 def completed_total(self) -> float:
  return sum(float(read(p).get('active_elapsed_seconds',0)) for p in (self.root/'runs').glob('*/terminal.json') if p.parent.name!=self.unit['run_unit_id'])
 def wait_seconds(self,case_id:str) -> float:
  if case_id!=self.unit['case_id']:raise SafetyError('BUDGET_CROSS_UNIT_CASE')
  active=self.active_seconds();remaining=min(self.limits['cli_wait_seconds'],self.limits['run_active_seconds']-active,self.limits['batch_active_seconds']-self.completed_total()-active)
  if remaining<=0:raise SafetyError('C15_ACTIVE_WALL_BUDGET_EXHAUSTED')
  return remaining
 def reserve(self,q:dict) -> None:
  self.wait_seconds(q['case_id'])
  if q['run_id']!=self.unit['run_id'] or q['case_id']!=self.unit['case_id']:raise SafetyError('CROSS_ARM_REPEAT_OR_CASE_REPLAY_FORBIDDEN')
  rows=[read(p) for p in sorted(self.journal.glob('*_reservation.json'))]
  if any((x['attempt_id'],x['seq'])==(q['attempt_id'],q['seq']) for x in rows):raise SafetyError('DUPLICATE_CLI_RESERVATION')
  if len(rows)>=self.limits['total_new_cli'] or sum(x['run_unit_id']==self.unit['run_unit_id'] for x in rows)>=self.limits['per_run_new_cli']:raise SafetyError('C15_CLI_BUDGET_EXHAUSTED')
  value={k:q[k] for k in ('case_id','run_id','attempt_id','seq','phase','prompt_sha256')};value.update(run_unit_id=self.unit['run_unit_id'],utc=utc(),state='LAUNCH_RESERVED_NOT_REFUNDABLE_ON_AMBIGUITY')
  atomic_create(self.journal,f'{len(rows)+1:04d}_reservation.json',value)

def progress(root:Path,state:str,reason:str|None=None) -> dict:
 units=read(root/'configs/run_units_private.json')['units'];statuses=[]
 for u in units:
  t=root/'runs'/u['run_unit_id']/'terminal.json';started=(root/'runs'/u['run_unit_id']/'active_start.json').exists()
  statuses.append(read(t)['status'] if t.exists() else 'RUNNING' if started else 'PENDING')
 counts={k:statuses.count(v) for k,v in [('running','RUNNING'),('frozen_valid','FROZEN'),('terminal_failed','FAILED'),('pending','PENDING')]}
 assert sum(counts.values())==18
 result={'state':state,'planned':18,'started':18-counts['pending'],**counts,'evaluated':len(list((root/'evaluation').glob('*/official_evaluation.json'))),'cumulative_cli_reservations':len(list((root/'budget').glob('*_reservation.json'))),'actual_cli_starts':len(list((root/'runs').glob('*/exchange_*/cli_start_receipt.json'))),'cumulative_terminal_active_seconds':sum(read(p).get('active_elapsed_seconds',0) for p in (root/'runs').glob('*/terminal.json')),'pause_reason':reason,'utc':utc()};write_state(root/'batch_progress.json',result);return result
