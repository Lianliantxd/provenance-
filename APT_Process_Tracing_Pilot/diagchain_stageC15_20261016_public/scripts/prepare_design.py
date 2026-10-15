from pathlib import Path
import sys,json,dataclasses,csv,hashlib
from c15_common import *
r=ROOT
if (r/'08_preregistration_and_code_freeze.json').exists():raise SafetyError('PREPARATION_ALREADY_FROZEN_DO_NOT_REGENERATE_DESIGN')
p=read(r/'configs/study_private.json');pre=read(r/'00_preflight_source_runtime.json');p['source_files'].append({'relative':'run_agentic_reconstruction.py','sha256':pre['run_entry_sha256'],'bytes':(r/'author_tree/benchmark/run_agentic_reconstruction.py').stat().st_size});p['native_common']=pre['resolved_native_config'];p['cases']=[{**c,'derived_case_paths':{k:d[k] for k in ['input','retrieval_docs','input_graph','ground_truth']}} for c,d in zip(p['cases'],pre['derived'])];p['limits']=LIMITS;write_state(r/'configs/study_private.json',p)
write_state(r/'03_input_transform_delta.json',{'policy':POLICY,'cases':pre['deltas'],'no_global_string_replacement':True,'source_files_unchanged':True,'Gold_semantics_read':False})
write_state(r/'04_derived_input_manifest.json',{'policy':POLICY,'cases':pre['derived'],'Docs_Graph_policy':'SHARED_READ_ONLY_SAME_HASH_BOTH_ARMS','original_card_values_and_order_unchanged':True})
on={**p['native_common'],'agent_method':'reflection'};off={**p['native_common'],'agent_method':'plain'};diff={k:{'ON':on[k],'OFF':off[k]} for k in on if on[k]!=off[k]};assert list(diff)==['agent_method'];write_state(r/'02_config_diff_on_off.json',{'planned_method_differences':diff,'source_agent_method_control_branches':[660,688,766],'earlier_prompt_path_difference':'TO_BE_TESTED_WITH_NATIVE_FAKE_PATH','final_metadata_difference_expected':True,'backend_output_context_limits':{'num_predict':None,'max_tokens':None,'num_ctx':None,'reasoning_effort':None,'temperature_request':0,'backend_temperature_honored':'UNVERIFIED','backend_snapshot':'UNVERIFIED'},'ignored_old_non_dataclass_field':'json_mode=native Ollama format=json was not applied by the Codex text bridge; not a C15 schema change'})
write_state(r/'configs/ON.json',on);write_state(r/'configs/OFF.json',off)
rows=schedule()
with (r/'05_run_schedule.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
units=[]
for row in rows:
 c=next(c for c in p['cases'] if c['case_alias']==row['case_alias']);u={**row,'run_id':'c15_'+uuid.uuid4().hex,'case_id':c['case_id'],'case_paths':c['derived_case_paths'],'native_config':on if row['assigned_arm']=='ON' else off,'input_policy':POLICY,'research_profile':'DEVELOPMENT_EXPOSED_EXPLORATORY_COMPONENT_ABLATION','model':'gpt-6-luna'};write_state(r/'configs'/('run_'+row['run_unit_id']+'.json'),u);units.append(u)
write_state(r/'configs/run_units_private.json',{'units':units,'seed':SEED,'model_noise_seed':'UNCONTROLLED','cross_run_replay':False})
write_state(r/'06_budget_and_authorization.json',{'state':'C15_PREPARED_AWAITING_BATCH_AUTHORIZATION','authorization_granted':False,'reason':'User provided a preparation contract and an authorization request TEMPLATE, not direct approval of 18 runs / 828 starts','direct_user_message_locator':'PENDING','model':'gpt-6-luna','limits':LIMITS,'paid_credits_allowed':False,'auto_recharge_confirmed_off':'PENDING_CURRENT_CONFIRMATION','current_credits_balance':'0 (preparation tool snapshot; refresh before execution)','account_ordinary_usage_available':True,'no_real_smoke':True})
progress(r,'C15_PREPARATION_IN_PROGRESS','Batch human authorization not yet obtained')
print('SCHEDULE_CONFIG_READY',len(units),'units',sum(x['assigned_arm']=='ON' for x in rows[::2]),'ON-first blocks')
