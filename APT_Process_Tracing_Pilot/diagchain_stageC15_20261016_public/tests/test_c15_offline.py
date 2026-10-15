import copy,json,os,socket,sys,tempfile,unittest,dataclasses
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src'),str(ROOT/'author_tree/benchmark')]
from c15_common import *
import agentic_reconstruction as native
import run_chain_reconstruction_paper_systems as systems
from strict_exchange_validator import phase_of
from c15_run_batch import run_block,seal_batch

class PrepTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'tmp');self.r=Path(self.tmp.name);(self.r/'runs').mkdir();self.unit={'run_unit_id':'SYNTHETIC_C1_R1_ON','run_id':'SYNTHETIC_run_unique','case_id':'SYNTHETIC_CASE'};self.now=[1000.]
 def tearDown(self):self.tmp.cleanup()
 def test_transform_only_two_root_paths(self):
  original={'length_bucket':'from-label','length_bucket_label':'derived','evidence_cards':[{'content':'length_bucket must stay as literal log text','extracted_clues':{'x':[1,2]}}],'other':{'n':3}}
  new,delta=transform_input(original);self.assertEqual(new['evidence_cards'],original['evidence_cards']);self.assertEqual(new['other'],original['other']);self.assertEqual(len(delta),2);self.assertIn('length_bucket',original)
 def test_derived_inputs_exact_and_graph_docs_original_hashes(self):
  p=read(ROOT/'00_preflight_source_runtime.json')
  for x in p['deltas']:self.assertTrue(x['evidence_cards_and_order_equal'] and x['all_other_fields_equal'] and x['Docs_and_Graph_unchanged'])
  for d in p['derived']:
   self.assertEqual(sha((ROOT/d['input']['relative']).read_bytes()),d['input']['sha256']);obj=read(ROOT/d['input']['relative']);self.assertNotIn('length_bucket',obj);self.assertNotIn('length_bucket_label',obj)
 def test_schedule_counterbalanced_unique_new_states(self):
  a=schedule();self.assertEqual(a,schedule());
  with (ROOT/'05_run_schedule.csv').open() as f:self.assertEqual(list(csv.DictReader(f)),[{k:str(v) for k,v in x.items()} for x in a]);self.assertEqual(len(a),18);self.assertEqual(len({x['run_unit_id'] for x in a}),18);self.assertEqual(sum(x['assigned_arm']=='ON' for x in a[::2]),5)
  for c in ['C1','C2','C3']:self.assertIn(sum(x['case_alias']==c and x['assigned_arm']=='ON' for x in a[::2]),[1,2])
  units=read(ROOT/'configs/run_units_private.json')['units'];self.assertEqual(len({x['run_id'] for x in units}),18)
 def test_46_and_828_reservations_include_failures(self):
  limits={**LIMITS};budget=BatchBudget(self.r,self.unit,clock=lambda:self.now[0],limits=limits);budget.begin_case('SYNTHETIC_CASE')
  q={**self.unit,'attempt_id':'SYNTHETIC_ATTEMPT','seq':1,'phase':'controller','prompt_sha256':'a'*64}
  for seq in range(1,47):budget.reserve({**q,'seq':seq})
  with self.assertRaisesRegex(SafetyError,'CLI_BUDGET'):budget.reserve({**q,'seq':47})
  # Failed starts remain reservations and a later Budget object sees the same journal.
  other={**self.unit,'run_unit_id':'SYNTHETIC_OTHER_UNIT','run_id':'SYNTHETIC_OTHER_RUN'};limits={**LIMITS,'total_new_cli':46};second=BatchBudget(self.r,other,clock=lambda:self.now[0],limits=limits);second.begin_case(other['case_id'])
  with self.assertRaisesRegex(SafetyError,'CLI_BUDGET'):second.reserve({**q,'run_id':other['run_id'],'attempt_id':'OTHER'})
  # Exercise the actual production 828 guard with persistent synthetic journals.
  for seq in range(47,829):atomic_create(self.r/'budget',f'{seq:04d}_reservation.json',{**q,'seq':seq,'run_unit_id':'SYNTHETIC_HISTORICAL_OTHER'})
  third=BatchBudget(self.r,other,clock=lambda:self.now[0]);
  with self.assertRaisesRegex(SafetyError,'CLI_BUDGET'):third.reserve({**q,'run_id':other['run_id'],'attempt_id':'OTHER'})
 def test_wall_and_wait_and_no_reset(self):
  b=BatchBudget(self.r,self.unit,clock=lambda:self.now[0]);b.begin_case(self.unit['case_id']);self.assertEqual(b.wait_seconds(self.unit['case_id']),360)
  self.now[0]=2799.;self.assertEqual(b.wait_seconds(self.unit['case_id']),1)
  self.now[0]=2800.
  with self.assertRaisesRegex(SafetyError,'ACTIVE_WALL'):b.wait_seconds(self.unit['case_id'])
  with self.assertRaisesRegex(SafetyError,'NO_TIME_RESET'):b.begin_case(self.unit['case_id'])
 def test_real_active_clock_uses_monotonic_not_mutable_epoch(self):
  b=BatchBudget(self.r,self.unit);self.assertIs(b.elapsed_clock,time.monotonic);b.begin_case(self.unit['case_id']);write_state(b.start_file,{'start_epoch':1});self.assertLess(b.active_seconds(),1)
 def test_32400_batch_active_ceiling(self):
  d=self.r/'runs/finished';d.mkdir();write_state(d/'terminal.json',{'active_elapsed_seconds':32399});b=BatchBudget(self.r,self.unit,clock=lambda:self.now[0]);b.begin_case(self.unit['case_id']);self.assertEqual(b.wait_seconds(self.unit['case_id']),1);self.now[0]+=1
  with self.assertRaisesRegex(SafetyError,'ACTIVE_WALL'):b.wait_seconds(self.unit['case_id'])
 def test_cross_run_reply_and_duplicate_request_denied(self):
  b=BatchBudget(self.r,self.unit,clock=lambda:self.now[0]);b.begin_case(self.unit['case_id']);q={**self.unit,'attempt_id':'A','seq':1,'phase':'controller','prompt_sha256':'a'*64};b.reserve(q)
  with self.assertRaisesRegex(SafetyError,'DUPLICATE'):b.reserve(q)
  with self.assertRaisesRegex(SafetyError,'CROSS_ARM'):b.reserve({**q,'run_id':'different_arm'})
 def test_quota_positive_credits_stale_or_exhausted_denied(self):
  q={'source':'get_usage_limits','checked_epoch':1000.,'ordinaryUsageAllowed':True,'included_exhausted':False,'credits':{'hasCredits':False,'balance':'0','unlimited':False}};g={'auto_recharge_confirmed_off':True};require_quota(q,g,now=1001.)
  for changed in [{**q,'credits':{'hasCredits':True,'balance':'10','unlimited':False}},{**q,'included_exhausted':True},{**q,'checked_epoch':0}]:
   with self.assertRaises(SafetyError):require_quota(changed,g,now=1001.)
 def test_three_case_scope_adapter_and_unknown_denial(self):
  import strict_exchange_validator as validator
  from unittest.mock import patch
  with patch.object(validator,'CASES',set(validator.CASES)):
   configure_case_scope(ROOT);self.assertEqual(len(validator.CASES),3);self.assertIn('CVE-2023-25157.mixed-log',validator.CASES)
   self.assertNotIn('UNAPPROVED_FOURTH_CASE',validator.CASES)
   prompt='You are operating in AGENTIC attack-chain reconstruction mode. SYNTHETIC_ONLY'
   q={'run_id':'synthetic','attempt_id':'synthetic','case_id':'CVE-2023-25157.mixed-log','seq':1,'phase':'controller','controller_turn':1,'prompt_utf8':prompt,'prompt_sha256':sha(prompt)};validator.validate_request(q)
   with self.assertRaisesRegex(SafetyError,'CASE_NOT_AUTHORIZED'):validator.validate_request({**q,'case_id':'UNAPPROVED_FOURTH_CASE'})
 def test_runtime_stub_audit_does_not_edit_log_strings(self):
  text='Incident metadata without full evidence:\n'+json.dumps({'log_literal':'length_bucket remains literal'})+'\nRetrieved evidence memory:\nSYNTHETIC'
  q={'phase':'controller','prompt_utf8':text,'prompt_sha256':sha(text)};self.assertEqual(audit_metadata_prompt(q)['status'],'KNOWN_STRUCTURED_LENGTH_KEYS_ABSENT');self.assertEqual(q['prompt_utf8'],text)
  bad='Incident metadata without full evidence:\n'+json.dumps({'length_bucket':'derived'})
  with self.assertRaisesRegex(SafetyError,'REINJECTED'):audit_metadata_prompt({**q,'prompt_utf8':bad,'prompt_sha256':sha(bad)})
 def test_auth_template_is_not_authorization(self):
  with self.assertRaisesRegex(SafetyError,'AWAITING_BATCH_AUTHORIZATION'):require_batch_authorization(ROOT,read(ROOT/'06_budget_and_authorization.json'))
 def test_no_gold_read_before_full_batch_seal(self):
  with self.assertRaisesRegex(SafetyError,'BATCH_NOT_SEALED'):evaluation_gate(self.r)
  with self.assertRaisesRegex(SafetyError,'PENDING_UNITS'):seal_batch(ROOT)
 def test_summary_missing_values_not_zero_or_independent_events(self):
  from c15_evaluate_and_report import summary
  s=summary([None,.5,None]);self.assertEqual(s['valid_count'],1);self.assertEqual(s['missing_count'],2);self.assertEqual(s['mean'],.5);self.assertEqual(s['sample_sd'],'NOT_ESTIMABLE');self.assertIsNone(summary([None,None,None])['mean'])
 def test_server_evaluator_rejects_before_gold_or_attempt_read(self):
  import c15_server_protocol as server
  with patch.object(server,'attempt_contract',side_effect=AssertionError('MUST_NOT_REACH_ATTEMPT_OR_GOLD')):
   with self.assertRaisesRegex(SafetyError,'BATCH_NOT_SEALED'):server.evaluate_batch(Path('SYNTHETIC_UNSTARTED'))
 def test_partial_closure_needs_direct_user_termination(self):
  write_state(self.r/'09_batch_terminal_freeze.json',{'state':'PARTIAL_BATCH_CLOSED','units':[]})
  with self.assertRaisesRegex(SafetyError,'EXPLICIT_PARTIAL'):evaluation_gate(self.r)
 def test_full_evaluator_bytes_and_summary_distinct_and_hash_verified(self):
  from c15_evaluate_and_report import save_official_result
  raw=json.dumps({'metrics':{'bestmatch_step_f1':.25},'synthetic_pair_details':['SYNTHETIC']})+'\n';result={'metrics':{'bestmatch_step_f1':.25},'official_result_utf8':raw,'official_result_sha256':sha(raw)};save_official_result(self.r/'eval',result)
  self.assertEqual((self.r/'eval/official_evaluation.json').read_text(),raw);self.assertNotIn('official_result_utf8',read(self.r/'eval/official_metrics_summary.json'))
  with self.assertRaisesRegex(SafetyError,'TRANSFER_HASH'):save_official_result(self.r/'other',{**result,'official_result_sha256':'0'*64})
 def test_local_frozen_unit_tamper_caught(self):
  from c15_evaluate_and_report import verify_local_frozen_unit
  local=self.r/'unit';local.mkdir();(local/'synthetic.txt').write_text('frozen');write_state(local/'manifest.json',{'files':[{'path':'synthetic.txt','sha256':sha('frozen')}]});t={'mac_manifest_path':'unit/manifest.json','mac_manifest_sha256':sha((local/'manifest.json').read_bytes())};verify_local_frozen_unit(self.r,t);(local/'synthetic.txt').write_text('changed')
  with self.assertRaisesRegex(SafetyError,'FROZEN_UNIT_CHANGED'):verify_local_frozen_unit(self.r,t)
 def test_safe_paths_and_nonoverwrite(self):
  with self.assertRaises(SafetyError):safe_path(self.r,'../outside')
  atomic_create(self.r,'once.json',{})
  with self.assertRaises(FileExistsError):atomic_create(self.r,'once.json',{})
  (self.r/'link').symlink_to(self.r)
  with self.assertRaises(SafetyError):safe_path(self.r,'link/x')

class NativeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'tmp');self.r=Path(self.tmp.name)
  self.inc={'incident_id':'SYNTHETIC_CASE','incident_brief':'Synthetic process file observation','evidence_cards':[{'evidence_id':'E1','card_type':'log','source_type':'synthetic','timestamp':'2024-01-01T00:00:00Z','content':json.dumps({'Image':'synthetic.exe','TargetFilename':'synthetic.txt','EventID':11}),'extracted_clues':{'processes':['synthetic.exe'],'files':['synthetic.txt']}}]}
  (self.r/'input.json').write_text(json.dumps(self.inc));(self.r/'docs.jsonl').write_text(json.dumps({'doc_id':'E1','text':'synthetic.exe creates synthetic.txt process file write'})+'\n');(self.r/'graph.json').write_text(json.dumps({'nodes':[{'id':'E1','node_type':'event'}],'edges':[]}))
 def tearDown(self):self.tmp.cleanup()
 def state(self):return systems.build_state(self.r/'input.json',self.r/'docs.jsonl',self.r/'graph.json')
 def chain(self,n=1):return {'incident_summary':'Synthetic only','attack_chain':[{'step_id':'S'+str(i+1),'order':i+1,'attack_step':'Create synthetic file','step_description':'synthetic.exe creates synthetic.txt','tactic':'execution','technique_id':'unknown','technique_name':'unknown','entities':{'processes':['synthetic.exe'],'files':['synthetic.txt']},'supporting_evidence':['E1'],'confidence':'low'} for i in range(n)],'causal_edges':[]}
 def config(self,arm):
  c=read(ROOT/'configs/ON.json' if arm=='ON' else ROOT/'configs/OFF.json');return native.AgenticRunConfig(**c)
 def controller(self,arm):
  st=self.state();cfg=self.config(arm);return native.AgenticController(st,native.PaperRetrievalKernel('ECRAG',st,top_k=32,max_observation_chars=cfg.max_observation_chars),cfg)
 def run_native(self,arm,replies):
  controller=self.controller(arm);messages=[];answers=iter(replies)
  def fake(prompt,**kwargs):messages.append(prompt);return next(answers)
  with patch.object(native,'call_model',side_effect=fake),patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK_IN_FAKE')):
   pred,trace=controller.run()
  return pred,trace,messages
 def test_same_native_prefix_prompts_retrieval_and_one_reflection(self):
  query=json.dumps({'thought':'synthetic','action':'query_evidence','query_intent':'synthetic process file','working_chain':native.empty_chain()});submit=json.dumps({'thought':'synthetic','action':'submit','query_intent':'','working_chain':self.chain()});reflection=json.dumps({'reflection':{'issues':[],'changes':[],'confidence':'low'},'working_chain':self.chain()})
  on=self.run_native('ON',[query,submit,reflection]);off=self.run_native('OFF',[query,submit]);self.assertEqual(on[2][:-1],off[2]);self.assertEqual(len(on[1]['reflection_events']),1);self.assertEqual(len(off[1]['reflection_events']),0);self.assertEqual([x['selected_evidence_ids'] for x in on[1]['observations']],[x['selected_evidence_ids'] for x in off[1]['observations']]);self.assertEqual(on[0]['attack_chain'],off[0]['attack_chain'])
 def test_native_empty_and_shrinking_revision_rejected(self):
  c=self.controller('ON');obs=[c.kernel.query('synthetic process',turn=1,working_chain=native.empty_chain())]
  for revised,flag in [(native.empty_chain(),'empty_revision_discarded'),(self.chain(1),'shrinking_revision_discarded')]:
   with patch.object(native,'call_model',return_value=json.dumps({'reflection':{},'working_chain':revised})):
    result,event=c._reflect_and_revise(self.chain(4),obs,turn=2)
   self.assertTrue(event[flag]);self.assertEqual(len(result['attack_chain']),4)
 def test_on_give_up_or_parse_error_no_forced_reflection(self):
  for replies in [[json.dumps({'action':'give_up','thought':'synthetic','working_chain':native.empty_chain()})],['not JSON','not JSON','not JSON']]:
   pred,trace,messages=self.run_native('ON',replies);self.assertEqual(len(trace['reflection_events']),0)
 def test_grounding_both_arms_and_derived_metadata_every_entry(self):
  for arm in ['ON','OFF']:
   c=self.controller(arm);stale=self.chain();stale['attack_chain'][0]['supporting_evidence']=['UNOBSERVED'];result=c._apply_grounding_check(stale,['E1']);self.assertTrue(result['enabled']);self.assertEqual(stale['attack_chain'],[])
   prompts=[c._build_controller_prompt(1,native.empty_chain(),[],''),c._build_reflection_prompt(self.chain(),[],[]),c._build_synthesis_prompt(self.chain(),[],[]),c._build_json_repair_prompt('SYNTHETIC invalid','SYNTHETIC parse')]
   for p in prompts:self.assertNotIn('"length_bucket"',p);self.assertNotIn('"length_bucket_label"',p)
 def test_external_budget_halt_not_native_fallback(self):
  from server_native_controller import BridgeHalt
  c=self.controller('ON')
  with patch.object(native,'call_model',side_effect=BridgeHalt('SYNTHETIC_EXTERNAL_HALT')):
   with self.assertRaises(BridgeHalt):c.run()
 def test_actual_derived_stubs_and_four_prompt_entrypoints_no_metadata_reinjection(self):
  for case in read(ROOT/'configs/study_private.json')['cases']:
   data=read(ROOT/('prepared_inputs/'+case['case_alias']+'.input.json'));st=self.state();st.incident_input=data;c=native.AgenticController(st,native.PaperRetrievalKernel('ECRAG',st,top_k=32),self.config('ON'))
   for p in [c._build_controller_prompt(1,native.empty_chain(),[],''),c._build_reflection_prompt(native.empty_chain(),[],[]),c._build_synthesis_prompt(native.empty_chain(),[],[]),c._build_json_repair_prompt('SYNTHETIC invalid','SYNTHETIC parse')]:
    self.assertNotIn('"length_bucket"',p);self.assertNotIn('"length_bucket_label"',p)
if __name__=='__main__':unittest.main()
