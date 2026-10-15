"""Entire terminal batch first, unchanged official metrics second, casewise summaries last."""
from __future__ import annotations
import argparse,csv,json,statistics,time
from pathlib import Path
from c15_common import *
from c15_run_batch import rpc

def table(path:Path,rows:list[dict]) -> None:
 if not rows:return
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 with path.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for x in rows for k in x)),lineterminator='\n');w.writeheader()
  for x in rows:w.writerow({k:json.dumps(v) if isinstance(v,(list,dict)) else ('NA' if v is None else v) for k,v in x.items()})
 path.chmod(0o600)
def summary(values:list) -> dict:
 v=[x for x in values if isinstance(x,(int,float))]
 return {'raw_R1_R2_R3':values,'valid_count':len(v),'missing_count':len(values)-len(v),'mean':statistics.mean(v) if v else None,'median':statistics.median(v) if v else None,'sample_sd':statistics.stdev(v) if len(v)>1 else 'NOT_ESTIMABLE','min':min(v) if v else None,'max':max(v) if v else None}

def verify_local_frozen_unit(root:Path,t:dict) -> None:
 manifest=safe_path(root,t['mac_manifest_path'])
 if sha(manifest.read_bytes())!=t['mac_manifest_sha256']:raise SafetyError('LOCAL_UNIT_MANIFEST_CHANGED')
 m=read(manifest);local=manifest.parent
 for x in m['files']:
  if sha(safe_path(local,x['path']).read_bytes())!=x['sha256']:raise SafetyError('LOCAL_FROZEN_UNIT_CHANGED')

def save_official_result(directory:Path,result:dict) -> None:
 raw=result['official_result_utf8']
 if sha(raw)!=result['official_result_sha256']:raise SafetyError('OFFICIAL_RESULT_TRANSFER_HASH')
 directory.mkdir(mode=0o700,parents=True,exist_ok=True)
 for name,data in [('official_evaluation.json',raw),('official_metrics_summary.json',{k:v for k,v in result.items() if k!='official_result_utf8'})]:
  target=directory/name
  if target.exists():
   if (target.read_text()!=data if isinstance(data,str) else read(target)!=data):raise SafetyError('OFFICIAL_RESULT_LOCAL_CONFLICT')
  else:atomic_create(directory,name,data)

def evaluate(root:Path) -> None:
 frozen_check(root);batch=evaluation_gate(root);plan=read(root/'configs/study_private.json');anchor=next((x for x in batch['units'] if x['status']=='FROZEN'),None)
 if anchor is None:return
 rpc(plan,anchor['attempt_id'],'install_batch_freeze',{'freeze':batch},deadline=time.time()+90)
 for t in batch['units']:
  if t['status']!='FROZEN':continue
  verify_local_frozen_unit(root,t)
  target=root/'evaluation'/t['run_unit_id']/'official_metrics_summary.json'
  if target.exists():continue
  before=time.monotonic();result=rpc(plan,t['attempt_id'],'evaluate',{},deadline=time.time()+200,evaluator=True,timeout=190);result['Mac_evaluation_transfer_wall_seconds']=time.monotonic()-before
  save_official_result(target.parent,result);verify_local_frozen_unit(root,t)
 progress(root,'C15_OFFICIAL_EVALUATION_COMPLETE')

def reports(root:Path) -> None:
 batch=evaluation_gate(root);units=read(root/'configs/run_units_private.json')['units'];rows=[];cost=[]
 for u in units:
  d=root/'runs'/u['run_unit_id'];t=read(d/'terminal.json') if (d/'terminal.json').exists() else {'status':'NOT_STARTED_CLOSED','active_elapsed_seconds':None,'actual_cli_starts':0,'new_cli_reservations':0};f=root/'evaluation'/u['run_unit_id']/'official_metrics_summary.json';evaluation=read(f) if f.exists() else None;m=evaluation['metrics'] if evaluation else {};reflection=t.get('model_phase_counts',{});usages=[read(p).get('usage',{}) for p in d.glob('exchange_*/parser_receipt.json')]
  token={key:sum(x[key] for x in usages) if usages and all(isinstance(x.get(key),int) for x in usages) else 'UNAVAILABLE' for key in ['input_tokens','cached_input_tokens','output_tokens','reasoning_output_tokens']}
  phase={key:reflection.get(key,'UNAVAILABLE') for key in ['controller','reflection','repair','synthesis']}
  row={k:u[k] for k in ['case_alias','repeat_id','assigned_arm','run_unit_id','execution_order','block']};row.update(terminal_status=t['status'],failure_reason=t.get('reason'),actual_reflection_calls=t.get('reflection_calls','UNAVAILABLE'),revision_accepted=t.get('revision_accepted','UNAVAILABLE'),active_elapsed_seconds=t['active_elapsed_seconds'],actual_cli_starts=t['actual_cli_starts'],reserved_cli_starts=t['new_cli_reservations'],**token,**m)
  row['bestmatch_step_f1']=m.get('bestmatch_step_f1');row['bestmatch_order_status']='NO_COMPARABLE_PAIRS' if m.get('bestmatch_order_pair_count')==0 else 'AVAILABLE' if evaluation else 'UNAVAILABLE';row['ceaf_order_status']='NO_COMPARABLE_PAIRS' if m.get('ceaf_order_pair_count')==0 else 'AVAILABLE' if evaluation else 'UNAVAILABLE';rows.append(row);cost.append({k:row[k] for k in ['case_alias','repeat_id','assigned_arm','run_unit_id','terminal_status','actual_reflection_calls','revision_accepted','active_elapsed_seconds','actual_cli_starts','reserved_cli_starts',*token]}|phase)
 casewise=[];pairs=[]
 for case in ['C1','C2','C3']:
  for arm in ['ON','OFF']:
   vals=[next(x for x in rows if x['case_alias']==case and x['assigned_arm']==arm and x['repeat_id']=='R'+str(rep)) for rep in range(1,4)]
   for metric in ['bestmatch_step_f1','evidence_f1','ceaf_step_f1','bestmatch_edge_f1','causal_edge_f1_order_aligned','actual_cli_starts','active_elapsed_seconds']:
    casewise.append({'case_alias':case,'assigned_arm':arm,'metric':metric,**summary([x.get(metric) for x in vals]),'completed_frozen_count':sum(x['terminal_status']=='FROZEN' for x in vals),'denominator_planned':3})
  for rep in range(1,4):
   on=next(x for x in rows if x['case_alias']==case and x['repeat_id']=='R'+str(rep) and x['assigned_arm']=='ON');off=next(x for x in rows if x['case_alias']==case and x['repeat_id']=='R'+str(rep) and x['assigned_arm']=='OFF');a,b=on['bestmatch_step_f1'],off['bestmatch_step_f1'];pairs.append({'case_alias':case,'repeat_id':'R'+str(rep),'F1_ON':a,'F1_OFF':b,'delta_ON_minus_OFF':a-b if isinstance(a,(int,float)) and isinstance(b,(int,float)) else None,'missing_pair':not (isinstance(a,(int,float)) and isinstance(b,(int,float))),'not_independent_attack_scenario':True})
 table(root/'reports/10_all_18_runs.csv',rows);table(root/'reports/11_casewise_on_off_summary.csv',casewise);table(root/'reports/12_paired_differences_and_missingness.csv',pairs);table(root/'reports/13_cost_and_realized_reflection.csv',cost)
 complete=all(x['bestmatch_step_f1'] is not None for x in rows);decision='HETEROGENEOUS_OR_INCONCLUSIVE'
 if not complete:decision='HETEROGENEOUS_OR_INCONCLUSIVE'
 else:
  bycase=[[x['delta_ON_minus_OFF'] for x in pairs if x['case_alias']==c] for c in ['C1','C2','C3']]
  if all(all(d>=0 for d in ds) and any(d>0 for d in ds) for ds in bycase):decision='KEEP_NATIVE_REFLECTION'
  elif all(all(d<=0 for d in ds) and any(d<0 for d in ds) for ds in bycase) and all(statistics.mean(x['actual_cli_starts'] for x in rows if x['case_alias']==c and x['assigned_arm']=='OFF')<=statistics.mean(x['actual_cli_starts'] for x in rows if x['case_alias']==c and x['assigned_arm']=='ON') for c in ['C1','C2','C3']):decision='PREFER_PLAIN_FOR_CURRENT_BACKEND_EXPLORATORY'
 if any(any(marker in str(x.get('failure_reason','')) for marker in ['PROTOCOL_VIOLATION','CROSS_UNIT','MODEL_OR_TOOL','UNAUTHORIZED','OFF_REFLECTION']) for x in rows):decision='ABLATION_INVALID_OR_INCOMPLETE'
 if batch['state']=='PARTIAL_BATCH_CLOSED':decision='ABLATION_INVALID_OR_INCOMPLETE'
 state='C15_PARTIAL_BATCH_CLOSED' if batch['state']=='PARTIAL_BATCH_CLOSED' else 'C15_18_RUNS_FROZEN_EVALUATED' if complete and all(x['terminal_status']=='FROZEN' for x in rows) else 'C15_BATCH_CLOSED_WITH_FAILURES'
 write_state(root/'reports/16_final_gate.json',{'state':state,'decision':decision,'primary_metric':'bestmatch_step_f1','planned':18,'evaluated_primary_metric':sum(x['bestmatch_step_f1'] is not None for x in rows),'assigned_arm_analysis':True,'SEMANTIC_TRUTH_NOT_INDEPENDENTLY_VALIDATED':True,'NOVELTY_UNVERIFIED':True,'no_cross_case_F1_average':True})
 text='本轮是三个开发案例的组件对照，结论：'+decision+'。失败保留NA，不把18次运行当18个独立场景。Reflection额外成本见成本表；保留ON的决定只适用于当前预算/后端，不证明收益成本比普遍合理。\n\n'
 for c in ['C1','C2','C3']:
  text+=c+'：\n\n'
  for x in casewise:
   if x['case_alias']==c and x['metric']=='bestmatch_step_f1':text+=x['assigned_arm']+' '+json.dumps(x,ensure_ascii=False)+'\n\n'
 text+='ON实际触发次数与接纳情况见13表，OFF必须零次。旧C13/C14成绩未并入。请求模型gpt-6-luna、客户端版本见00/合同，服务端snapshot、temperature实际采用及精确计费UNVERIFIED；没有独立人工语义真值，不报告实际幻觉率。无下一算法或自动追加试验。\n';(root/'reports/15_plain_language_conclusion_zh.md').write_text(text)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--evaluate',action='store_true');p.add_argument('--report',action='store_true');a=p.parse_args()
 if a.evaluate:evaluate(ROOT)
 if a.report:reports(ROOT)
