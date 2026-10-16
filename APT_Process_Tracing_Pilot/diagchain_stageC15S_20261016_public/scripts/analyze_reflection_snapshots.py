#!/usr/bin/env python3
"""C15-S: offline extraction and official scoring of immutable Reflection snapshots.
No controller, model client, subprocess, network, or semantic repair is called here.
Configuration contains private source paths; public exports must exclude it.
"""
from __future__ import annotations
import argparse,csv,datetime,hashlib,importlib,json,math,os,sys,time
from pathlib import Path
from typing import Any

UNITS=['C1_R1_ON','C1_R2_ON','C2_R2_ON','C2_R3_ON','C3_R3_ON']
STAGES=['PRE_REFLECTION','POST_MODEL_RAW','FINAL_FROZEN']
CONTRASTS=[('POST_MODEL_RAW','PRE_REFLECTION'),('FINAL_FROZEN','PRE_REFLECTION'),('FINAL_FROZEN','POST_MODEL_RAW')]
MARKER='Current working_chain before reflection:\n'
END='\n\nRetrieved evidence memory:\n'
METRICS=['n_pred_steps','n_gold_steps','bestmatch_matched_steps','bestmatch_step_precision','bestmatch_step_recall','bestmatch_step_f1','ceaf_step_f1','ceaf_aligned_steps','evidence_precision','evidence_recall','evidence_f1','attack_clustering_bcubed_f1','bestmatch_edge_f1','causal_edge_f1_order_aligned','bestmatch_pairwise_order_accuracy','ceaf_pairwise_order_accuracy','aligned_steps']
TOL=1e-9

def utc()->str:return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(b:bytes|str)->str:return hashlib.sha256(b.encode('utf-8') if isinstance(b,str) else b).hexdigest()
def sha(p:Path)->str:return digest(p.read_bytes())
def pairs(items:list)->dict:
 d={}
 for k,v in items:
  if k in d:raise ValueError('DUPLICATE_JSON_KEY')
  d[k]=v
 return d
def loads(s:str)->Any:return json.loads(s,object_pairs_hook=pairs,parse_constant=lambda v:(_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
def read(p:Path)->Any:return loads(p.read_text(encoding='utf-8'))
def canon(v:Any)->str:return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def objhash(v:Any)->str:return digest(canon(v))
def safe(p:Path)->Path:
 if '..' in p.parts:raise ValueError('PATH_TRAVERSAL')
 for q in [p,*p.parents]:
  if q.is_symlink():raise ValueError('SYMLINK_PATH')
 return p
def write(root:Path,name:str,v:Any)->None:
 p=safe(root/name)
 if not p.is_relative_to(root):raise ValueError('OUTPUT_ESCAPE')
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 b=(v if isinstance(v,str) else json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode('utf-8')
 if p.exists():
  if p.read_bytes()==b:return
  raise ValueError('NO_OVERWRITE:'+name)
 with p.open('xb') as f:f.write(b)
 p.chmod(0o600)
def table(root:Path,name:str,rows:list[dict])->None:
 import io
 s=io.StringIO(newline='');fields=list(dict.fromkeys(k for row in rows for k in row));w=csv.DictWriter(s,fieldnames=fields,lineterminator='\n');w.writeheader()
 for row in rows:w.writerow({k:canon(v) if isinstance(v,(dict,list)) else ('NA' if v is None else v) for k,v in row.items()})
 write(root,name,s.getvalue())
def verify(checks:list[dict],prefix:Path|None=None)->list[dict]:
 out=[]
 for x in checks:
  p=safe(prefix/x['relative'] if prefix is not None else Path(x['path']));h=sha(p)
  if h!=x['sha256']:raise ValueError('SOURCE_HASH_MISMATCH:'+str(p))
  out.append({'path':str(p),'sha256':h,'matches':True})
 return out

def extract_pre(t:str)->tuple[dict,dict]:
 # Adapted from C14 extract_section: unique marker + strict raw_decode;
 # require terminal memory boundary and independently verify UTF-8 slice.
 if t.count(MARKER)!=1:raise ValueError('AMBIGUOUS_SNAPSHOT_MARKER')
 start=t.index(MARKER)+len(MARKER);start+=len(t[start:])-len(t[start:].lstrip())
 value,n=json.JSONDecoder(object_pairs_hook=pairs).raw_decode(t[start:]);end=start+n
 if not isinstance(value,dict) or not t[end:].startswith(END):raise ValueError('SNAPSHOT_BOUNDARY')
 bs=len(t[:start].encode('utf-8'));be=len(t[:end].encode('utf-8'))
 if loads(t.encode('utf-8')[bs:be].decode('utf-8'))!=value:raise ValueError('UTF8_SLICE')
 return value,{'char_span':[start,end],'utf8_span':[bs,be],'slice_sha256':digest(t[start:end]),'json_path':'$.prompt_utf8 -> unique Current working_chain before reflection'}

def extract_post(raw:str)->tuple[dict,dict]:
 # Only a single complete JSON object; optional JSON fence with no other text.
 t=raw.strip();offset=raw.index(t) if t else 0
 if t.startswith('```json\n') and t.endswith('\n```'):offset+=8;t=t[8:-4]
 obj,n=json.JSONDecoder(object_pairs_hook=pairs).raw_decode(t)
 if t[n:].strip() or not isinstance(obj,dict):raise ValueError('POST_NOT_SINGLE_COMPLETE_OBJECT')
 if 'working_chain' not in obj or not isinstance(obj['working_chain'],dict):raise ValueError('POST_WORKING_CHAIN_UNAVAILABLE')
 return obj['working_chain'],{'json_path':'$.working_chain','root_char_span':[offset,offset+n],'root_utf8_span':[len(raw[:offset].encode()),len(raw[:offset+n].encode())]}

def citation_ids(chain:dict|None,edges:bool=False,case_id:str='')->set[tuple[str,str]]|None:
 if chain is None:return None
 return {(case_id,str(e)) for s in chain.get('causal_edges' if edges else 'attack_chain',[]) for e in s.get('supporting_evidence',[])}
def semantic(chain:dict)->dict:
 # Metadata is the only ignored root key. Preserve all other fields including unknown keys.
 return {k:v for k,v in chain.items() if k!='metadata'}
def fields_diff(a:Any,b:Any,path:str='$')->list[dict]:
 if type(a)!=type(b):return [{'path':path,'before':a,'after':b}]
 if isinstance(a,dict):
  out=[]
  for k in sorted(a.keys()|b.keys()):
   if k not in a:out.append({'path':path+'.'+k,'change':'ADDED','after':b[k]})
   elif k not in b:out.append({'path':path+'.'+k,'change':'REMOVED','before':a[k]})
   else:out+=fields_diff(a[k],b[k],path+'.'+k)
  return out
 if isinstance(a,list):
  if len(a)!=len(b):return [{'path':path,'change':'LIST_CONTENT_OR_LENGTH_CHANGED','before':a,'after':b}]
  return [x for i,(v,w) in enumerate(zip(a,b)) for x in fields_diff(v,w,path+f'[{i}]')]
 return [] if a==b else [{'path':path,'before':a,'after':b}]

def chain_mapping(before:dict|None,after:dict|None)->dict:
 # C14 conservative exact text / overlapping reference candidate rule.
 if before is None or after is None:return {'status':'SNAPSHOT_UNAVAILABLE'}
 out=[]
 for i,a in enumerate(before.get('attack_chain',[])):
  candidates=[]
  for j,b in enumerate(after.get('attack_chain',[])):
   overlap=set(a.get('supporting_evidence',[]))&set(b.get('supporting_evidence',[]));text_equal=(a.get('attack_step'),a.get('step_description'))==(b.get('attack_step'),b.get('step_description'))
   exact_ignoring_number={k:v for k,v in a.items() if k not in ['step_id','order']}=={k:v for k,v in b.items() if k not in ['step_id','order']}
   if overlap or text_equal or exact_ignoring_number:candidates.append({'after_index':j,'after_id':b.get('step_id'),'evidence_overlap':sorted(overlap),'action_text_equal':text_equal,'entities_equal':a.get('entities')==b.get('entities'),'exact_ignoring_step_id_and_order':exact_ignoring_number})
  out.append({'before_index':i,'before_id':a.get('step_id'),'candidates':candidates,'status':'NO_IDENTITY_CANDIDATE' if not candidates else 'UNIQUE_CANDIDATE_NOT_SEMANTIC_PROOF' if len(candidates)==1 else 'AMBIGUOUS_MAPPING'})
 return {'status':'CANDIDATE_MAPPING','rows':out}

def probe(root:Path,cfg:dict)->None:
 checks=verify(cfg['server_dependencies']);py=Path(sys.executable)
 import importlib.metadata
 packages={}
 for name in ['numpy','scipy','scikit-learn']:
  try:packages[name]=importlib.metadata.version(name)
  except importlib.metadata.PackageNotFoundError:packages[name]='NOT_INSTALLED'
 write(root,'logs/server_preanalysis_probe.json',{'utc':utc(),'dependencies':checks,'python':str(py),'python_sha256':sha(py),'python_version':sys.version,'package_versions':packages,'source_commit':cfg['source_commit'],'analysis_script_sha256':sha(Path(__file__)),'new_model_calls':0,'Gold_content_read':False,'Gold_file_hash_read':True})
 print(canon({'state':'PROBE_PASS','checked':len(checks)}))

def freeze(root:Path,cfg:dict)->None:
 probe_record=read(root/'logs/server_preanalysis_probe.json')
 contract={'task_id':cfg['task_id'],'frozen_utc':utc(),'analysis_scope':'POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS','exposed_results_before_plan':True,'not_preregistration':True,'main_units':UNITS,'primary_metric':'bestmatch_step_f1','comparison_1':'PRE_REFLECTION_TO_POST_MODEL_RAW','comparison_2':'PRE_REFLECTION_TO_FINAL_FROZEN','postprocessing_check':'POST_MODEL_RAW_TO_FINAL_FROZEN','source_map_sha256':sha(root/'00_source_map_and_scope.json'),'environment_probe_sha256':sha(root/'logs/server_preanalysis_probe.json'),'environment_python_sha256':probe_record['python_sha256'],'input_policy':cfg['input_policy'],'new_model_call_limit':0,'score_label':'C15S_POSTHOC_SNAPSHOT_DIAGNOSTIC','numeric_tolerance':TOL,'ignore_for_semantic_equality':['$.metadata'],'no_metadata_inheritance':True,'official_metrics':METRICS,'additional_counts':['n_pred_edges','bestmatch_order_pair_count','ceaf_order_pair_count'],'reference_definition':'Official evidence_precision/recall/f1 uses unique canonical step supporting_evidence only; edge citations audited separately, not silently included. Composite case_id+evidence_id keys.','snapshot_schema':'Validate unmodified objects; if invalid do not fabricate. No normalization needed when already valid. Any later normalization must be explicit and versioned.','POST_AUTHOR_ACCEPTED_policy':'Only saved intermediate object; event accepted by absence of discard is not a saved object. Mark SNAPSHOT_UNAVAILABLE if absent.','source_commit':cfg['source_commit'],'original_C15':cfg['original_end_to_end'],'selection_bias':'5 actual accepted reflections from successful ON paths in 3 development-exposed cases; not 5 independent scenarios, not counterfactual OFF','inference':'Descriptive within-run changes only; no cross-case mean, p-value or causal effect; original HETEROGENEOUS_OR_INCONCLUSIVE unchanged','POSTHOC_GOLD_ACCESS':'YES_ON_SERVER_AFTER_FREEZE'}
 write(root,'02_snapshot_analysis_contract.json',contract)
 write(root,'02_snapshot_analysis_contract.md','# C15-S 后验分析合同\n\n这是 C15 成绩已暴露后的固定计划，不是运行前预注册。\n\n```json\n'+json.dumps(contract,ensure_ascii=False,indent=2)+'\n```\n')
 write(root,'logs/analysis_contract_freeze.json',{'utc':utc(),'contract_sha256':sha(root/'02_snapshot_analysis_contract.json'),'contract_markdown_sha256':sha(root/'02_snapshot_analysis_contract.md'),'analysis_script_sha256':sha(Path(__file__)),'new_snapshot_scores_read':False,'new_model_calls':0})

def verify_exchange(u:dict,q:dict,v:dict,raw:str,pr:dict,ack:dict,cons:dict)->None:
 for k in ['run_id','attempt_id','case_id','seq']:
  if q.get(k)!=v.get(k) or q.get(k)!=u.get(k):raise ValueError('EXCHANGE_IDENTITY:'+k)
 if q.get('phase')!=v.get('phase') or q.get('phase')!=cons.get('phase') or q.get('phase')!='reflection':raise ValueError('WRONG_PHASE')
 if not (q['prompt_sha256']==digest(q['prompt_utf8'])==v['prompt_sha256']==cons['prompt_sha256']):raise ValueError('PROMPT_BINDING')
 if v.get('raw_reply_utf8')!=raw or not (digest(raw)==v['reply_sha256']==pr['reply_sha256']==ack['reply_sha256']==cons['reply_sha256']):raise ValueError('CANONICAL_REPLY_BINDING')
 if cons.get('attempt_id')!=u['attempt_id']:raise ValueError('CONSUMED_ATTEMPT')
 if pr.get('messages_concatenated') is not False or pr.get('status')!='CANONICAL_FINAL_VERIFIED' or pr.get('selection')!='EXACT_LAST_COMPLETED_MESSAGE_MATCHES_CANONICAL_FILE':raise ValueError('CANONICAL_SELECTION')
 if ack.get('state')!='SERVER_ACCEPTED':raise ValueError('ACK_NOT_ACCEPTED')

def extract(root:Path,cfg:dict)->None:
 verify(cfg['local_dependencies'],Path(cfg['old_mac_root']));old=Path(cfg['old_mac_root']);selection=[];provenance=[];costs=[]
 batch=read(old/'09_batch_terminal_freeze.json');actual=sorted(x['run_unit_id'] for x in batch['units'] if x.get('reflection_calls')==1 and x.get('revision_accepted')==[True]);assert actual==sorted(UNITS)
 for u in cfg['units']:
  uid=u['run_unit_id'];d=old/'runs'/uid;ex=old/u['exchange'];q=read(ex/'request.json');v=read(ex/'response.json');raw=(ex/'final_reply_utf8.txt').read_text();pr=read(ex/'parser_receipt.json');ack=read(ex/'server_ack.json');cons=read(d/f"server_artifacts/exchange/CONSUMED_{u['seq']:04d}.json");trace=read(d/'server_artifacts/trace.json');final=read(d/'server_artifacts/prediction.json')
  verify_exchange(u,q,v,raw,pr,ack,cons)
  events=[e for e in trace['reflection_events'] if e.get('raw')==raw];assert len(events)==1;event=events[0]
  assert event['parse_error'] is None and not event.get('empty_revision_discarded') and not event.get('shrinking_revision_discarded');assert event['turn']==q['controller_turn']
  rp=[z for z in trace['raw_responses'] if z.get('phase')=='reflection'];assert len(rp)==1 and rp[0]['raw']==raw
  selection.append({'run_unit_id':uid,'case_id':u['case_id'],'actual_phase':'reflection','seq':u['seq'],'controller_turn':q['controller_turn'],'reflection_called':True,'revision_accepted':True,'selection_basis':'ALL_ACTUAL_ACCEPTED_REFLECTIONS_NOT_SCORE','source_final_f1':read(old/u['existing_official_result'])['metrics']['bestmatch_step_f1']})
  snapshots={'FINAL_FROZEN':(final,{'json_path':'$','source_path':str(d/'server_artifacts/prediction.json'),'source_sha256':sha(d/'server_artifacts/prediction.json')})}
  for label,fn,src in [('PRE_REFLECTION',lambda:extract_pre(q['prompt_utf8']),ex/'request.json'),('POST_MODEL_RAW',lambda:extract_post(raw),ex/'final_reply_utf8.txt')]:
   try:
    snap,prov=fn();snapshots[label]=(snap,{**prov,'source_path':str(src),'source_sha256':sha(src),'logical_payload_sha256':q['prompt_sha256'] if label=='PRE_REFLECTION' else digest(raw)})
   except (ValueError,TypeError,KeyError) as err:
    write(root,f'private_snapshots/{uid}/{label}_GAP.json',{'state':'SNAPSHOT_UNAVAILABLE_OR_AMBIGUOUS','reason':str(err)})
  for label,(snap,prov) in snapshots.items():
   write(root,f'private_snapshots/{uid}/{label}.json',snap);write(root,f'private_snapshots/{uid}/{label}_provenance.json',{**prov,'snapshot_object_sha256':objhash(snap),'snapshot_file_sha256':sha(root/f'private_snapshots/{uid}/{label}.json'),'semantic_object_sha256':objhash(semantic(snap)),'run_unit_id':uid,'run_id':u['run_id'],'attempt_id':u['attempt_id'],'case_id':u['case_id'],'seq':u['seq'],'selected_message_id':pr['selected_message_id'] if label=='POST_MODEL_RAW' else None,'canonical_file_consumed_ACK_verified':True})
  # No trace object stores the accepted intermediate chain (raw+event are saved only).
  write(root,f'private_snapshots/{uid}/POST_AUTHOR_ACCEPTED_status.json',{'state':'SNAPSHOT_UNAVAILABLE','reason':'Trace reflection event stores raw reply and latency, not a separate accepted working_chain object; do not reconstruct it.','acceptance_control_flow_and_terminal_verified':True,'trace_reflection_event_keys':list(event)})
  pre=snapshots.get('PRE_REFLECTION',(None,))[0];post=snapshots.get('POST_MODEL_RAW',(None,))[0];equal=post is not None and semantic(post)==semantic(final)
  write(root,f'private_snapshots/{uid}/postprocessing_field_differences.json',{'POST_RAW_TO_FINAL':fields_diff(post,final) if post is not None else None,'semantic_equal_ignoring_only_root_metadata':equal,'POSTPROCESSING_CAUSE':'ONLY_FINAL_METADATA_ADDITION' if equal and 'metadata' not in post else 'NO_DIFFERENCE' if post==final else 'POSTPROCESSING_CAUSE_UNKNOWN','normalized_snapshot':'NOT_APPLIED_RAW_OBJECTS_FIRST','POST_ACCEPTED':'SNAPSHOT_UNAVAILABLE'})
  provenance.append({'run_unit_id':uid,'seq':u['seq'],'PRE_status':'EXTRACTED' if pre is not None else 'SNAPSHOT_GAP','POST_RAW_status':'EXTRACTED' if post is not None else 'SNAPSHOT_GAP','FINAL_status':'FROZEN_SOURCE_HASH_VERIFIED','POST_AUTHOR_ACCEPTED':'SNAPSHOT_UNAVAILABLE','CAN_COMPARE_MODEL_REVISION':pre is not None and post is not None,'CAN_COMPARE_FINAL_CHANGE':pre is not None,'reason':'Actual same-run request/current chain and consumed final response; schema and final scores checked separately','post_final_semantic_equal':equal,'postprocessing_evidence':'Only metadata addition' if equal else 'POSTPROCESSING_CAUSE_UNKNOWN','metadata_dependent_comparison':'METADATA_DEPENDENT_NOT_COMPARABLE','PRE_sha256':objhash(pre) if pre is not None else None,'POST_RAW_sha256':objhash(post) if post is not None else None,'FINAL_sha256':objhash(final)})
  exit_record=read(ex/'cli_exit_receipt.json');costs.append({'run_unit_id':uid,'reflection_seq':u['seq'],'author_reflection_latency_sec':event['latency_sec'],'cli_elapsed_seconds':exit_record['elapsed_seconds'],'whole_ON_CLI_starts':u['terminal']['actual_cli_starts'],'whole_ON_phase_counts':u['terminal']['model_phase_counts'],'reflection_input_tokens':pr['usage'].get('input_tokens'),'reflection_cached_input_tokens':pr['usage'].get('cached_input_tokens'),'reflection_output_tokens':pr['usage'].get('output_tokens'),'reflection_reasoning_output_tokens':pr['usage'].get('reasoning_output_tokens'),'usage_source':'Existing canonical parser receipt; not a new account/billing check','model_snapshot':'UNVERIFIED','sampling':'UNVERIFIED','exact_billing':'UNVERIFIED','new_model_calls':0})
 table(root,'01_five_reflection_selection.csv',selection);table(root,'03_snapshot_provenance_and_comparability.csv',provenance);table(root,'08_existing_reflection_costs.csv',costs)
 write(root,'logs/extraction_complete.json',{'utc':utc(),'units':len(selection),'new_model_calls':0,'sources_rechecked':len(cfg['local_dependencies'])})
 print(canon({'state':'EXTRACTED','units':len(selection),'post_final_semantic_equal':[x['post_final_semantic_equal'] for x in provenance]}))

def scalar_equal(a:Any,b:Any)->bool:
 if isinstance(a,(int,float)) and isinstance(b,(int,float)):return math.isfinite(a) and math.isfinite(b) and abs(a-b)<=TOL
 return a==b

def evaluate(root:Path,cfg:dict)->None:
 os.environ.update(OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='',PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(root/'tmp'),XDG_CACHE_HOME=str(root/'cache'));sys.dont_write_bytecode=True
 contract=read(root/'02_snapshot_analysis_contract.json');f=read(root/'logs/analysis_contract_freeze.json');assert sha(root/'02_snapshot_analysis_contract.json')==f['contract_sha256']
 probe_record=read(root/'logs/server_preanalysis_probe.json');assert sha(Path(sys.executable))==probe_record['python_sha256'];assert sys.version==probe_record['python_version']
 verify(cfg['server_dependencies']);old=Path(cfg['old_server_root']);source=old/'author_tree/benchmark';sys.path.insert(0,str(source));ev=importlib.import_module('evaluate_chain_reconstruction')
 allmetrics=[];repro=[];refs={};timer=time.monotonic()
 for u in cfg['units']:
  uid=u['run_unit_id'];case=u['case_id'];d=root/'private_snapshots'/uid;inp=read(Path(u['paths']['input']['path']));gold=read(Path(u['paths']['ground_truth']['path']));gold_ids={(case,e) for s in ev.sorted_steps(gold) for e in ev.canonical_evidence_ids(s)};refs[uid]=sorted(gold_ids)
  # Run FINAL first; then score real PRE and raw POST without injecting metadata.
  for label in ['FINAL_FROZEN','PRE_REFLECTION','POST_MODEL_RAW']:
   p=d/(label+'.json');resultfile=f'private_snapshots/{uid}/{label}_official_evaluation.json'
   if not p.exists():continue
   snap=read(p);errors=ev.validate_prediction_schema(snap)
   if errors:
    write(root,f'private_snapshots/{uid}/{label}_schema_gap.json',{'state':'SNAPSHOT_NOT_SCORABLE','errors':errors});continue
   begin=time.monotonic()
   if (root/resultfile).exists():result=read(root/resultfile);cpu=None
   else:
    result=ev.evaluate(snap,gold,inp);cpu=time.monotonic()-begin;write(root,resultfile,result);write(root,f'private_snapshots/{uid}/{label}_cpu_receipt.json',{'utc':utc(),'elapsed_seconds':cpu,'python':sys.executable,'evaluator_sha256':sha(source/'evaluate_chain_reconstruction.py'),'cluster_metrics_sha256':sha(source/'cluster_metrics.py'),'snapshot_file_sha256':sha(p),'input_sha256':sha(Path(u['paths']['input']['path'])),'Gold_sha256':sha(Path(u['paths']['ground_truth']['path'])),'score_label':'C15S_POSTHOC_SNAPSHOT_DIAGNOSTIC','new_model_calls':0,'POSTHOC_GOLD_ACCESS':'YES','metadata_inherited':False,'normalization_applied':False})
   m=result['metrics'];row={'run_unit_id':uid,'case_id':case,'stage':label,'score_label':'C15S_POSTHOC_SNAPSHOT_DIAGNOSTIC',**{k:m.get(k) for k in METRICS},'n_pred_edges':len(snap['causal_edges']),'n_pred_edges_source':'len(snapshot.causal_edges)','bestmatch_order_pair_count':len(result['best_matches'])*(len(result['best_matches'])-1)//2,'ceaf_order_pair_count':len(result['ceaf_matches'])*(len(result['ceaf_matches'])-1)//2,'bestmatch_order_status':'NO_COMPARABLE_PAIRS' if len(result['best_matches'])<2 else 'AVAILABLE','ceaf_order_status':'NO_COMPARABLE_PAIRS' if len(result['ceaf_matches'])<2 else 'AVAILABLE','metadata_dependent_metrics':'METADATA_DEPENDENT_NOT_COMPARABLE','CPU_elapsed_seconds':read(root/f'private_snapshots/{uid}/{label}_cpu_receipt.json')['elapsed_seconds']}
   allmetrics.append(row)
   if label=='FINAL_FROZEN':
    oldeval=read(old/u['existing_official_result']);om=oldeval['metrics'];differences=[{'field':k,'old':om.get(k),'new':m.get(k)} for k in om.keys()|m.keys() if not scalar_equal(om.get(k),m.get(k))];full_equal=oldeval==result
    repro.append({'run_unit_id':uid,'status':'PASS' if not differences else 'FINAL_SCORE_REPRODUCTION_MISMATCH','numeric_tolerance':TOL,'official_metric_fields_compared':len(om.keys()|m.keys()),'metric_differences':differences,'full_official_result_exact_equal':full_equal,'old_final_F1':om['bestmatch_step_f1'],'new_final_F1':m['bestmatch_step_f1'],'prediction_source_sha256':u['terminal']['prediction_sha256'],'evaluator_sha256':sha(source/'evaluate_chain_reconstruction.py'),'input_sha256':sha(Path(u['paths']['input']['path']))})
   stepids=citation_ids(snap,False,case);edgeids=citation_ids(snap,True,case);allids=stepids|edgeids
   write(root,f'private_snapshots/{uid}/{label}_citation_sets.json',{'Gold_step_support_unique':sorted(gold_ids),'step_references_unique':sorted(stepids),'edge_references_unique':sorted(edgeids),'all_step_edge_references_unique':sorted(allids),'official_evidence_metric_pred_set':sorted(stepids),'official_reference_intersection':sorted(stepids&gold_ids),'step_nonreference':sorted(stepids-gold_ids),'edge_only':sorted(edgeids-stepids),'evaluator_reference_definition':'evaluate(): all_pred_ev and all_gold_ev union canonical_evidence_ids over steps ONLY; attribution/exposure metadata metrics not compared'})
  table(root,f'private_snapshots/{uid}/metrics_checkpoint.csv',[x for x in allmetrics if x['run_unit_id']==uid])
 table(root,'04_final_score_reproduction.csv',repro);table(root,'05_snapshot_metrics.csv',allmetrics)
 write(root,'logs/official_reference_sets_private.json',refs)
 post=verify(cfg['server_dependencies']);write(root,'logs/server_postanalysis_integrity.json',{'utc':utc(),'checks':post,'new_model_calls':0,'new_CPU_evaluation_elapsed_seconds':time.monotonic()-timer,'original_C15':cfg['original_end_to_end']})
 print(canon({'state':'EVALUATED','snapshots':len(allmetrics),'final_reproduction':[x['status'] for x in repro],'CPU_seconds':time.monotonic()-timer}))

def report_data(root:Path,cfg:dict)->None:
 with (root/'05_snapshot_metrics.csv').open() as f:rows=list(csv.DictReader(f))
 idx={(x['run_unit_id'],x['stage']):x for x in rows};deltas=[];changes=[]
 for u in cfg['units']:
  uid=u['run_unit_id'];case=u['case_id'];d=root/'private_snapshots'/uid
  for after,before in CONTRASTS:
   a,b=idx.get((uid,after)),idx.get((uid,before));contrast=after+'_MINUS_'+before
   if a is None or b is None:
    deltas.append({'run_unit_id':uid,'contrast':contrast,'status':'SNAPSHOT_NOT_SCORABLE_OR_UNAVAILABLE'});continue
   delta={}
   for k in METRICS+['n_pred_edges','bestmatch_order_pair_count','ceaf_order_pair_count']:
    try:delta[k]=float(a[k])-float(b[k])
    except (ValueError,TypeError):delta[k]=None
   deltas.append({'run_unit_id':uid,'contrast':contrast,'status':'AVAILABLE_SAME_INPUT_EVALUATOR_RAW_OBJECTS',**delta})
   ca,cb=read(d/(after+'.json')),read(d/(before+'.json'));sa,sb=citation_ids(ca,False,case),citation_ids(cb,False,case);ea,eb=citation_ids(ca,True,case),citation_ids(cb,True,case);ga=set(tuple(x) for x in read(d/(after+'_citation_sets.json'))['Gold_step_support_unique']);mapping=chain_mapping(cb,ca)
   change={'run_unit_id':uid,'case_id':case,'contrast':contrast,'pred_steps_before':len(cb['attack_chain']),'pred_steps_after':len(ca['attack_chain']),'pred_edges_before':len(cb['causal_edges']),'pred_edges_after':len(ca['causal_edges']),'step_citations_before':len(sb),'step_citations_after':len(sa),'step_citations_added':len(sa-sb),'step_citations_removed':len(sb-sa),'edge_citations_added':len(ea-eb),'edge_citations_removed':len(eb-ea),'all_citations_added':len((sa|ea)-(sb|eb)),'all_citations_removed':len((sb|eb)-(sa|ea)),'official_reference_citations_before':len(sb&ga),'official_reference_citations_after':len(sa&ga),'official_reference_added':len((sa-sb)&ga),'official_reference_removed':len((sb-sa)&ga),'step_list_exact_equal':cb['attack_chain']==ca['attack_chain'],'edge_list_exact_equal':cb['causal_edges']==ca['causal_edges'],'incident_summary_equal':cb.get('incident_summary')==ca.get('incident_summary'),'mapping_ambiguous_before_steps':sum(x['status']=='AMBIGUOUS_MAPPING' for x in mapping['rows']),'mapping_no_candidate_before_steps':sum(x['status']=='NO_IDENTITY_CANDIDATE' for x in mapping['rows']),'nonreference_citation_interpretation':'NOT_AUTOMATICALLY_IRRELEVANT','semantic_truth':'NOT_IDENTIFIABLE'}
   changes.append(change);write(root,f'private_snapshots/{uid}/{contrast}_structure_private.json',{'aggregate':change,'step_citation_ids_added':sorted(sa-sb),'step_citation_ids_removed':sorted(sb-sa),'edge_citation_ids_added':sorted(ea-eb),'edge_citation_ids_removed':sorted(eb-ea),'all_reference_ids_added':sorted(((sa|ea)-(sb|eb))&ga),'all_reference_ids_removed':sorted(((sb|eb)-(sa|ea))&ga),'step_mapping':mapping,'semantic_field_differences':fields_diff(semantic(cb),semantic(ca))})
 table(root,'06_within_run_deltas.csv',deltas);table(root,'07_structural_and_citation_changes.csv',changes)
 write(root,'logs/mac_postanalysis_integrity.json',{'utc':utc(),'checks':verify(cfg['local_dependencies'],Path(cfg['old_mac_root'])),'new_model_calls':0})
 print(canon({'state':'DIFFS_COMPLETE','contrasts':len(deltas)}))

def main()->None:
 p=argparse.ArgumentParser();p.add_argument('action',choices=['probe','freeze','extract','evaluate','report-data']);p.add_argument('--root',type=Path,required=True);a=p.parse_args();root=safe(a.root);os.umask(0o077);sys.dont_write_bytecode=True;cfg=read(root/'00_source_map_and_scope.json')
 {'probe':probe,'freeze':freeze,'extract':extract,'evaluate':evaluate,'report-data':report_data}[a.action](root,cfg)
if __name__=='__main__':main()
