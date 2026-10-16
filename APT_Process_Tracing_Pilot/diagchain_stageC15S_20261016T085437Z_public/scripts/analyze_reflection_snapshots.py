#!/usr/bin/env python3
"""Offline C15-S snapshot closeout. No controller, model or transport invocation.

Trusted author evaluator and the reviewed C14 extract_section/chain_mapping helpers
are imported read-only. Historical prompts and replies are parsed as JSON data.
"""
from __future__ import annotations
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import sys
import time
import traceback

VERSION='C15S_OFFLINE_V1'
UNITS=['C1_R1_ON','C1_R2_ON','C2_R2_ON','C2_R3_ON','C3_R3_ON']
EVALUATOR_SHA='8543ca870b64f6cbc36727df32f5b6e9bdc51dca6b111545b33c50d31bfaaf09'
CLUSTER_SHA='eabcb12c30b2dfc19c25ae36aadaa63358a5ce9f77e767a4fc3c37a79850744b'
C14_SHA='442dabf005581ff309e973e251b2f1dd7daf89eec964b58fa6f708f0b9ca6c82'
METRICS=['n_pred_steps','n_gold_steps','bestmatch_matched_steps','bestmatch_step_precision','bestmatch_step_recall','bestmatch_step_f1',
 'ceaf_step_f1','ceaf_aligned_steps','evidence_precision','evidence_recall','evidence_f1','attack_clustering_bcubed_f1',
 'bestmatch_edge_f1','causal_edge_f1_order_aligned','bestmatch_pairwise_order_accuracy','bestmatch_order_pair_count',
 'ceaf_pairwise_order_accuracy','ceaf_order_pair_count']
STAGES=['PRE_REFLECTION','POST_MODEL_RAW','FINAL_FROZEN']
TOL=1e-9

def utc()->str:return datetime.now(timezone.utc).isoformat()
def digest(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def sha(path:Path)->str:return digest(path.read_bytes())
def canon(obj:object)->bytes:return json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def strict_pairs(items:list)->dict:
    d={}
    for k,v in items:
        if k in d:raise ValueError('DUPLICATE_JSON_KEY:'+k)
        d[k]=v
    return d
def loads(s:str)->object:return json.loads(s,object_pairs_hook=strict_pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
def read(path:Path)->object:return loads(path.read_text())
def no_symlinks(p:Path)->None:
    if any(q.is_symlink() for q in [p,*p.parents]):raise ValueError('SYMLINK_PATH:'+str(p))
def safe(root:Path,name:str)->Path:
    rel=PurePosixPath(name)
    if rel.is_absolute() or '..' in rel.parts:raise ValueError('PATH_OUTSIDE_ROOT')
    p=root/name;no_symlinks(p)
    if not p.resolve().is_relative_to(root.resolve()):raise ValueError('PATH_OUTSIDE_ROOT')
    return p
def save(root:Path,name:str,obj:object,exclusive:bool=False)->None:
    p=safe(root,name);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    text=obj if isinstance(obj,str) else json.dumps(obj,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    with p.open('x' if exclusive else 'w') as f:f.write(text)
    p.chmod(0o600)
def table(root:Path,name:str,rows:list[dict])->None:
    p=safe(root,name);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fields=list(dict.fromkeys(k for row in rows for k in row)) or ['status']
    with p.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader()
        for row in rows:w.writerow({k:json.dumps(v,ensure_ascii=False,sort_keys=True) if isinstance(v,(dict,list,tuple)) else 'NA' if v is None else v for k,v in row.items()})
    p.chmod(0o600)
def tree_diff(a:object,b:object,path:str='$')->list[dict]:
    if type(a)!=type(b):return [{'path':path,'before':a,'after':b}]
    if isinstance(a,dict):
        out=[]
        for k in sorted(set(a)|set(b)):
            if k not in a or k not in b:out.append({'path':path+'.'+k,'before':a.get(k),'after':b.get(k),'key_presence_changed':True})
            else:out.extend(tree_diff(a[k],b[k],path+'.'+k))
        return out
    if isinstance(a,list):
        if len(a)!=len(b):return [{'path':path,'before':a,'after':b,'list_length_changed':True}]
        return [x for i,(av,bv) in enumerate(zip(a,b)) for x in tree_diff(av,bv,path+f'[{i}]')]
    return [] if a==b else [{'path':path,'before':a,'after':b}]
def semantic(chain:dict)->dict:
    # Only known runtime metadata may be ignored; preserve all other root fields.
    return {k:v for k,v in chain.items() if k!='metadata'}
def phase_request_paths(unit:Path)->list[Path]:
    return [p for p in sorted(unit.glob('exchange_*/request.json')) if read(p).get('phase')=='reflection']
def dependencies(cfg:dict,root:Path)->tuple[object,object]:
    sys.dont_write_bytecode=True
    os.environ['TMPDIR']=str(root/'tmp');os.environ['XDG_CACHE_HOME']=str(root/'cache')
    for n in ['tmp','cache']:safe(root,n).mkdir(exist_ok=True,mode=0o700)
    source=Path(cfg['author_source']);c14=Path(cfg['c14_helpers'])
    assert sha(source/'evaluate_chain_reconstruction.py')==EVALUATOR_SHA
    assert sha(source/'cluster_metrics.py')==CLUSTER_SHA
    assert sha(c14/'analyze_frozen_runs.py')==C14_SHA
    sys.path.insert(0,str(source));ev=importlib.import_module('evaluate_chain_reconstruction')
    sys.path.insert(0,str(c14));old=importlib.import_module('analyze_frozen_runs')
    return ev,old

def prepare(cfg:dict,root:Path)->None:
    hist=Path(cfg['historical_root']);no_symlinks(hist)
    manifest=read(hist/'artifacts_manifest.json');expected={x['path']:x for x in manifest['files']}
    closure=read(hist/'sync_receipts/FINAL_C15_CLOSURE_SYNC.json')
    assert sha(hist/'artifacts_manifest.json')==closure['main_manifest_sha256']
    assert sha(hist/'09_batch_terminal_freeze.json')==closure['batch_freeze_sha256']
    batch=read(hist/'09_batch_terminal_freeze.json');gate=read(hist/'reports/16_final_gate.json')
    assert gate['model_cli_starts']==121 and gate['evaluated']==12 and gate['terminal_failed']==6
    assert gate['decision']=='HETEROGENEOUS_OR_INCONCLUSIVE'
    ev,old=dependencies(cfg,root)
    files=[];selection=[];actual=[]
    def check(p:Path,exp:str,role:str)->None:
        no_symlinks(p);got=sha(p)
        if got!=exp:raise ValueError('SOURCE_SHA256_MISMATCH:'+str(p))
        files.append({'path':str(p),'sha256':got,'bytes':p.stat().st_size,'role':role})
    for n in ['04_derived_input_manifest.json','09_batch_terminal_freeze.json','reports/16_final_gate.json','reports/10_all_18_runs.csv',
              'reports/12_paired_differences_and_missingness.csv','reports/22_transport_versions_and_cost_coverage.csv']:
        check(safe(hist,n),expected[n]['sha256'],'ORIGINAL_C15_BOUNDARY')
    for u in batch['units']:
        if u.get('actual_reflection_cli_starts',0)>0 and any(u.get('revision_accepted',[])):actual.append(u['run_unit_id'])
    assert set(actual)==set(UNITS),('EXPECTED_ACTUAL_SELECTION_CONFLICT',UNITS,actual)
    for name in UNITS:
        d=hist/'runs'/name;unit=next(x for x in batch['units'] if x['run_unit_id']==name)
        unitmanifest=read(d/'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json')
        check(d/'MAC_ARTIFACTS_FROZEN_BEFORE_GOLD.json',unit['mac_manifest_sha256'],'UNIT_FREEZE')
        unitindex={x['path']:x for x in unitmanifest['files']}
        def unitcheck(p:Path,role:str)->None:
            rel=str(p.relative_to(d))
            # Terminal records are sealed later than the per-unit artifact receipt.
            # Use the already frozen batch-wide manifest, never a newly guessed hash.
            exp=(unitindex[rel] if rel in unitindex else expected[str(p.relative_to(hist))])['sha256']
            check(p,exp,role)
        for n in ['contract.json','terminal.json','server_artifacts/trace.json','server_artifacts/prediction.json','server_artifacts/prediction_trace_freeze.json']:
            unitcheck(d/n,n)
        qs=phase_request_paths(d);assert len(qs)==1
        qp=qs[0];q=read(qp);contract=read(d/'contract.json');terminal=read(d/'terminal.json')
        assert q['attempt_id']==contract['attempt_id']==terminal['attempt_id']==unit['attempt_id']
        assert q['run_id']==contract['run_id'] and q['case_id']==contract['case_id']
        assert terminal['reflection_calls']==1 and terminal['revision_accepted']==[True]
        for n in ['request.json','response.json','final_reply_utf8.txt','parser_receipt.json','server_ack.json','cli_start_receipt.json','cli_exit_receipt.json']:
            unitcheck(qp.parent/n,'REFLECTION_'+n)
        seq=q['seq']
        for n in [f'REQUEST_{seq:04d}.json',f'RESPONSE_{seq:04d}.json',f'CONSUMED_{seq:04d}.json']:
            unitcheck(d/'server_artifacts/exchange'/n,'AUTHOR_EXCHANGE')
        for key in ['input','ground_truth']:
            x=contract['case_paths'][key];check(Path(x['path']),x['sha256'],name+'_'+key)
        inp=read(Path(contract['case_paths']['input']['path']))
        assert 'length_bucket' not in inp and 'length_bucket_label' not in inp
        for n in ['official_evaluation.json','official_metrics_summary.json']:
            rel='evaluation/'+name+'/'+n;check(hist/rel,expected[rel]['sha256'],'ORIGINAL_OFFICIAL_RESULT')
        selection.append({'run_unit_id':name,'case_id':q['case_id'],'attempt_id':q['attempt_id'],'phase':'reflection','request_seq':seq,
                'actual_reflection_calls':1,'revision_accepted':True,'selection_basis':'ALL_ACTUAL_CALLED_AND_ACCEPTED_NOT_SCORE_SELECTED',
                'request_path':str(qp),'canonical_final_path':str(qp.parent/'final_reply_utf8.txt')})
    for folder,n in [(Path(cfg['author_source']),'evaluate_chain_reconstruction.py'),(Path(cfg['author_source']),'cluster_metrics.py'),
                     (Path(cfg['author_source']),'agentic_reconstruction.py'),(Path(cfg['c14_helpers']),'analyze_frozen_runs.py'),
                     (Path(cfg['c14_helpers']),'prompt_card_span_index_v2.py')]:
        p=folder/n;files.append({'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size,'role':'TRUSTED_OFFLINE_DEPENDENCY'})
    import scipy
    import numpy
    env={'python_executable':sys.executable,'python_version':sys.version,'python_binary_sha256':sha(Path(sys.executable).resolve()),
        'scipy':scipy.__version__,'numpy':numpy.__version__,'scipy_optimize_available':ev.linear_sum_assignment is not None,
        'scipy_module_sha256':sha(Path(scipy.__file__)),'numpy_module_sha256':sha(Path(numpy.__file__)),
        'evaluator_path':str(Path(ev.__file__)),'evaluator_sha256':EVALUATOR_SHA,'cluster_metrics_sha256':CLUSTER_SHA,
        'bytecode_writes_disabled':sys.dont_write_bytecode,'project_environment_reused':True}
    scope={'analysis_scope':'POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS','version':VERSION,'frozen_utc':utc(),'config':cfg,
        'source_commit':'SOURCE_COMMIT_UNVERIFIABLE_COPY','new_model_call_limit':0,'POSTHOC_GOLD_ACCESS':'YES',
        'main_units':UNITS,'actual_units':actual,'environment':env,'dependencies':files,
        'original_boundary':{k:gate[k] for k in ['state','decision','planned','evaluated','terminal_failed','model_cli_starts']},
        'new_endpoint_samples':0,'metric_tolerance':TOL,'historical_manifests_read_only':True}
    save(root,'00_source_map_and_scope.json',scope,exclusive=True)
    table(root,'01_five_reflection_selection.csv',selection)
    save(root,'02_snapshot_analysis_contract.md',f'''# C15-S 后验分析合同

冻结时间：{scope['frozen_utc']}。结果已暴露后的分析计划，不是 C15 运行前预注册。

- analysis_scope=POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS
- new_model_call_limit=0；POSTHOC_GOLD_ACCESS=YES
- main_units={','.join(UNITS)}；筛选依据为全部实际调用且接纳 Reflection。
- primary_metric=bestmatch_step_f1
- comparison_1=PRE_REFLECTION_TO_POST_MODEL_RAW
- comparison_2=PRE_REFLECTION_TO_FINAL_FROZEN
- postprocessing_check=POST_MODEL_RAW_TO_FINAL_FROZEN
- PRE 只取真实请求 Current working_chain before reflection；POST 只取作者已消费最终消息；FINAL 只取原冻结 Prediction。
- 可选 POST_AUTHOR_ACCEPTED 无实际保存对象即 SNAPSHOT_UNAVAILABLE，accepted=true 不产生新快照。
- 同 run、同 C15 去除 length_bucket/length_bucket_label 的派生 Input、同 Gold、同评价器与现有环境。
- FINAL 先以原指标复核，容差 {TOL}；完整性哈希必须精确一致。关键成绩不符则阻断该单元新旧合并解释。
- 不补 metadata；retrieval/attribution/exposure 等依赖缺失元数据的指标不进入主比较。
- 原对象缺必需语义字段即不评分，不修补；原始快照保留。必要规范化需记录逐字段变化，本轮优先直接按真实对象评分。
- 步骤重编号不等于删除；只用精确结构/引用集合候选；歧义保留。证据引用使用 case_id+evidence_id 复合键。
- 全部指标方向完整报告，不跨案例平均、不显著性检验、不把 PRE 当 OFF，不改变 18终态/12评价/6NA/121历史CLI。
- 仍保持 HETEROGENEOUS_OR_INCONCLUSIVE；局部修订差异不是随机关闭反思的完整反事实。
''',exclusive=True)
    print(json.dumps({'state':'CONTRACT_FROZEN_BEFORE_NEW_SCORES','units':len(selection),'dependencies_checked':len(files),'new_model_calls':0}),flush=True)

def extract_pre(prompt:str,c14:object)->tuple[dict,dict]:
    marker='Current working_chain before reflection:\n'
    obj,span=c14.extract_section(prompt,marker)
    if obj is None or not isinstance(obj,dict) or span is None:raise ValueError('AMBIGUOUS_OR_UNAVAILABLE_PRE_SNAPSHOT')
    tail=prompt[span[1]:]
    if not tail.startswith('\n\nRetrieved evidence memory:\n'):raise ValueError('PRE_JSON_BOUNDARY_NOT_VERIFIED')
    a,b=span;bs,be=len(prompt[:a].encode()),len(prompt[:b].encode())
    assert loads(prompt.encode()[bs:be].decode())==obj
    return obj,{'json_path':'$.prompt_utf8::<Current working_chain before reflection>','char_span':[a,b],'utf8_byte_span':[bs,be],
                'span_scope':'Decoded request.prompt_utf8, not byte offsets in JSON-escaped request file','json_slice_sha256':digest(prompt.encode()[bs:be])}

def exact_post(raw:str)->tuple[dict,dict]:
    # Never concatenate multiple messages or salvage prefixes.
    text=raw.strip();prefix=len(raw)-len(raw.lstrip())
    if text.startswith('```json\n') and text.endswith('```'):
        start=prefix+len('```json\n');end=len(raw.rstrip())-3;text=raw[start:end].strip()
    outer=loads(text)
    if not isinstance(outer,dict) or not isinstance(outer.get('working_chain'),dict):raise ValueError('POST_WORKING_CHAIN_UNAVAILABLE')
    return outer['working_chain'],{'json_path':'$.working_chain','full_message_sha256':digest(raw.encode()),'complete_strict_json':True,
                                  'messages_concatenated':False,'normalization':'NONE'}

def verify_message_identity(q:dict,response:dict,sr:dict,sq:dict,raw:str,parser:dict,ack:dict,consumed:dict)->None:
    assert q==sq
    assert q['phase']=='reflection' and digest(q['prompt_utf8'].encode())==q['prompt_sha256']
    for obj in [response,sr]:
        for k in ['run_id','attempt_id','case_id','seq','phase','prompt_sha256']:assert obj[k]==q[k]
        assert obj['raw_reply_utf8']==raw and obj['reply_sha256']==digest(raw.encode())
    assert parser['reply_sha256']==ack['reply_sha256']==consumed['reply_sha256']==digest(raw.encode())
    assert ack['seq']==consumed['seq']==q['seq']
    assert consumed['phase']=='reflection' and consumed['attempt_id']==q['attempt_id'] and consumed['prompt_sha256']==q['prompt_sha256']
    assert not parser['messages_concatenated'] and parser['raw_reply_modified'] is False
    assert parser.get('selected_message_id') and parser.get('completed_message_count',0)>=1

def reference_sets(chain:dict,ev:object,cid:str)->dict:
    step={(cid,str(e)) for s in chain.get('attack_chain',[]) for e in ev.canonical_evidence_ids(s)}
    edge={(cid,str(e)) for s in chain.get('causal_edges',[]) for e in ev.canonical_evidence_ids(s)}
    # Author evidence_precision/recall/f1 use step evidence only, not the union.
    return {'step':step,'edge':edge,'union':step|edge,'official':step}

def structural(before:dict,after:dict,cid:str,c14:object,ev:object)->dict:
    b=reference_sets(before,ev,cid);a=reference_sets(after,ev,cid)
    old_steps=before.get('attack_chain',[]);new_steps=after.get('attack_chain',[])
    mapping=c14.chain_mapping(before,after)
    def stable(s:dict)->str:return digest(canon({k:v for k,v in s.items() if k not in ['step_id','order']}))
    old_sig=Counter(stable(s) for s in old_steps);new_sig=Counter(stable(s) for s in new_steps)
    return {'step_count_before':len(old_steps),'step_count_after':len(new_steps),'step_count_delta':len(new_steps)-len(old_steps),
         'edge_count_before':len(before.get('causal_edges',[])),'edge_count_after':len(after.get('causal_edges',[])),
         'edge_count_delta':len(after.get('causal_edges',[]))-len(before.get('causal_edges',[])),
         'step_citation_ids_added':sorted(a['step']-b['step']),'step_citation_ids_removed':sorted(b['step']-a['step']),
         'edge_citation_ids_added':sorted(a['edge']-b['edge']),'edge_citation_ids_removed':sorted(b['edge']-a['edge']),
         'same_step_content_ignoring_id_order':old_sig==new_sig,'step_id_or_order_changed':[(s.get('step_id'),s.get('order')) for s in old_steps]!=[(s.get('step_id'),s.get('order')) for s in new_steps],
         'incident_summary_changed':before.get('incident_summary')!=after.get('incident_summary'),
         'attack_chain_exact_equal':old_steps==new_steps,'causal_edges_exact_equal':before.get('causal_edges')==after.get('causal_edges'),
         'candidate_mapping':mapping,'mapping_is_semantic_ground_truth':False,
         'text_changed':[(s.get('attack_step'),s.get('step_description')) for s in old_steps]!=[(s.get('attack_step'),s.get('step_description')) for s in new_steps]}

def analyze(cfg:dict,root:Path)->None:
    scope=read(root/'00_source_map_and_scope.json');hist=Path(cfg['historical_root']);ev,c14=dependencies(cfg,root)
    for f in scope['dependencies']:assert sha(Path(f['path']))==f['sha256']
    metric_rows=[];comparison_rows=[];deltas=[];structures=[];costs=[];reproduction=[];outcomes=[]
    source_index={x['path']:x for x in scope['dependencies']}
    for unit in UNITS:
        if (root/f'private_snapshots/{unit}/unit_complete.json').exists():
            outcome=read(root/f'private_snapshots/{unit}/unit_complete.json')
            for key,target in [('metrics',metric_rows),('comparison',comparison_rows),('deltas',deltas),('structures',structures),('costs',costs),('reproduction',reproduction)]:target.extend(outcome[key])
            outcomes.append(outcome);continue
        started=time.perf_counter();d=hist/'runs'/unit;prefix='private_snapshots/'+unit+'/'
        result={'unit':unit,'metrics':[],'comparison':[],'deltas':[],'structures':[],'costs':[],'reproduction':[]}
        try:
            qpath=phase_request_paths(d)[0];q=read(qpath);x=qpath.parent;response=read(x/'response.json')
            raw=(x/'final_reply_utf8.txt').read_text();parser=read(x/'parser_receipt.json');ack=read(x/'server_ack.json')
            consumed=read(d/f"server_artifacts/exchange/CONSUMED_{q['seq']:04d}.json")
            sr=read(d/f"server_artifacts/exchange/RESPONSE_{q['seq']:04d}.json")
            sq=read(d/f"server_artifacts/exchange/REQUEST_{q['seq']:04d}.json")
            trace=read(d/'server_artifacts/trace.json');contract=read(d/'contract.json');cid=contract['case_id']
            verify_message_identity(q,response,sr,sq,raw,parser,ack,consumed)
            matching=[e for e in trace['reflection_events'] if e.get('turn')==q['controller_turn'] and e.get('raw')==raw]
            assert len(matching)==1
            event=matching[0];assert event.get('parse_error') is None and not event.get('empty_revision_discarded') and not event.get('shrinking_revision_discarded')
            final=read(d/'server_artifacts/prediction.json');pre=post=None;pre_source=post_source={};gaps=[]
            try:pre,pre_source=extract_pre(q['prompt_utf8'],c14)
            except (ValueError,TypeError) as exc:gaps.append('PRE:'+str(exc))
            try:post,post_source=exact_post(raw)
            except (ValueError,TypeError) as exc:gaps.append('POST:'+str(exc))
            snapshots={'PRE_REFLECTION':pre,'POST_MODEL_RAW':post,'FINAL_FROZEN':final}
            sources={'request_file_sha256':sha(qpath),'response_file_sha256':sha(x/'response.json'),'trace_sha256':sha(d/'server_artifacts/trace.json'),
                 'prediction_sha256':sha(d/'server_artifacts/prediction.json'),'request_seq':q['seq'],'prompt_sha256':q['prompt_sha256'],
                 'selected_message_id':parser['selected_message_id'],'completed_message_count':parser['completed_message_count'],
                 'earlier_message_hashes':parser.get('earlier_message_hashes',[]),'final_message_file_sha256':sha(x/'final_reply_utf8.txt'),
                 'PRE_source':pre_source,'POST_source':post_source,'POST_AUTHOR_ACCEPTED':'SNAPSHOT_UNAVAILABLE',
                 'accepted_record_is_not_intermediate_snapshot':True,'all_identity_checks_passed':True,'gaps':gaps,
                 'raw_normalization':'NONE; original complete objects scored without additions',
                 'canonical_final_selection':parser.get('selection'),'server_consumption_hash_verified':True}
            for label,obj in snapshots.items():
                if obj is not None:save(root,prefix+label+'.json',obj)
            semdiff=tree_diff(semantic(post),semantic(final)) if post is not None else None
            sources['POST_RAW_FINAL_semantic_equal']=semdiff==[] if semdiff is not None else None
            sources['POST_RAW_FINAL_full_equal']=post==final if post is not None else None
            sources['POST_RAW_FINAL_differences']=semdiff
            sources['field_hashes']={label:{k:digest(canon(v)) for k,v in obj.items()} for label,obj in snapshots.items() if obj is not None}
            sources['canonical_object_hashes']={label:digest(canon(obj)) for label,obj in snapshots.items() if obj is not None}
            sources['postprocessing_trace']={'grounding_check_note':trace['final_metadata'].get('grounding_check_note'),
                    'support_gate_events':trace.get('support_gate_events',[])}
            sources['postprocessing_cause']='NO_SEMANTIC_CHANGE_METADATA_ADDED_ONLY' if semdiff==[] else 'POSTPROCESSING_CAUSE_UNKNOWN'
            save(root,prefix+'snapshot_provenance.json',sources)
            cp=contract['case_paths'];inp=read(Path(cp['input']['path']));gt=read(Path(cp['ground_truth']['path']))
            gold=reference_sets(gt,ev,cid)['step']
            old=read(hist/'evaluation'/unit/'official_evaluation.json')
            fresh=ev.evaluate(final,gt,inp);save(root,prefix+'FINAL_FROZEN_evaluation.json',fresh)
            mismatches=[]
            for metric,want in old['metrics'].items():
                got=fresh['metrics'].get(metric)
                same=got==want or isinstance(got,(int,float)) and isinstance(want,(int,float)) and abs(got-want)<=TOL
                if not same:mismatches.append(metric)
                result['reproduction'].append({'run_unit_id':unit,'metric':metric,'EXPECTED_original_C15':want,'ACTUAL_C15S':got,
                       'tolerance':TOL,'status':'MATCH' if same else 'FINAL_SCORE_REPRODUCTION_MISMATCH'})
            key_scores=['n_pred_steps','n_gold_steps','bestmatch_matched_steps','bestmatch_step_f1','evidence_f1','bestmatch_edge_f1','causal_edge_f1_order_aligned']
            final_ok=not any(x in mismatches for x in key_scores)
            stages={};evaluations={}
            for label,obj in snapshots.items():
                if obj is None:
                    result['metrics'].append({'run_unit_id':unit,'stage':label,'status':'SNAPSHOT_UNAVAILABLE'});continue
                errors=ev.validate_prediction_schema(obj)
                if errors:
                    result['metrics'].append({'run_unit_id':unit,'stage':label,'status':'SNAPSHOT_NOT_SCORABLE','schema_errors':errors});continue
                e=fresh if label=='FINAL_FROZEN' else ev.evaluate(obj,gt,inp)
                if label!='FINAL_FROZEN':save(root,prefix+label+'_evaluation.json',e)
                evaluations[label]=e;ms=e['metrics'];refs=reference_sets(obj,ev,cid)
                row={'run_unit_id':unit,'case_id':cid,'stage':label,'status':'C15S_POSTHOC_SNAPSHOT_DIAGNOSTIC',
                     **{k:ms.get(k) for k in METRICS},'n_pred_edges':len(obj.get('causal_edges',[])),
                     'n_pred_edges_source':'direct_snapshot_causal_edges_list_length',
                     'bestmatch_order_pair_count_actual':len(e['best_matches'])*(len(e['best_matches'])-1)//2,
                     'ceaf_order_pair_count_actual':len(e['ceaf_matches'])*(len(e['ceaf_matches'])-1)//2,
                     'bestmatch_order_status':'NO_COMPARABLE_PAIRS' if len(e['best_matches'])<2 else 'AVAILABLE',
                     'ceaf_order_status':'NO_COMPARABLE_PAIRS' if len(e['ceaf_matches'])<2 else 'AVAILABLE',
                     'step_unique_reference_ids':len(refs['step']),'edge_unique_reference_ids':len(refs['edge']),
                     'official_citation_unique_ids':len(refs['official']),'step_and_edge_union_unique_ids':len(refs['union']),
                     'gold_unique_support_ids':len(gold),'official_cited_gold_ids':len(refs['official']&gold),
                     'official_cited_nonreference_ids':len(refs['official']-gold),
                     'input_sha256':cp['input']['sha256'],'gold_sha256':cp['ground_truth']['sha256'],'evaluator_sha256':EVALUATOR_SHA,
                     'metadata_status':'ORIGINAL_FROZEN_METADATA_RETAINED' if label=='FINAL_FROZEN' else 'METADATA_DEPENDENT_NOT_COMPARABLE',
                     'metadata_copied_from_final':False}
                # Preserve original metric names/values. Actual pair counts are separate derived fields.
                stages[label]=row;result['metrics'].append(row)
                save(root,prefix+label+'_reference_sets_private.json',{k:sorted(v) for k,v in refs.items()}|{'gold_step_support':sorted(gold)})
            for before,after,label in [('PRE_REFLECTION','POST_MODEL_RAW','POST_MINUS_PRE'),('PRE_REFLECTION','FINAL_FROZEN','FINAL_MINUS_PRE'),('POST_MODEL_RAW','FINAL_FROZEN','FINAL_MINUS_POST')]:
                comparable=before in stages and after in stages and final_ok
                row={'run_unit_id':unit,'comparison':label,'status':'COMPARABLE' if comparable else 'NOT_COMPARABLE',
                     'reason':'same input, source and environment; no metadata copied' if comparable else 'SNAPSHOT_OR_FINAL_REPRODUCTION_GAP'}
                if comparable:
                    for metric in METRICS+['n_pred_edges','official_cited_gold_ids','official_cited_nonreference_ids']:
                        av,bv=stages[after].get(metric),stages[before].get(metric)
                        row[metric+'_delta']=av-bv if isinstance(av,(int,float)) and isinstance(bv,(int,float)) else None
                result['deltas'].append(row)
                if snapshots[before] is not None and snapshots[after] is not None:
                    diff=structural(snapshots[before],snapshots[after],cid,c14,ev)
                    save(root,prefix+label+'_structural_diff_private.json',diff)
                    result['structures'].append({'run_unit_id':unit,'comparison':label,**{k:v for k,v in diff.items() if k!='candidate_mapping'},
                        'ambiguous_mapping_rows':sum(x['status']=='AMBIGUOUS_MAPPING' for x in diff['candidate_mapping'].get('rows',[])),
                        'candidate_mapping_file':prefix+label+'_structural_diff_private.json'})
            result['comparison'].append({'run_unit_id':unit,'request_seq':q['seq'],'phase':'reflection','actual_acceptance':True,
                'PRE_status':'ARTIFACT_VERIFIED' if pre is not None else 'SNAPSHOT_UNAVAILABLE','POST_RAW_status':'ARTIFACT_VERIFIED' if post is not None else 'SNAPSHOT_UNAVAILABLE',
                'POST_AUTHOR_ACCEPTED':'SNAPSHOT_UNAVAILABLE','FINAL_status':'ARTIFACT_VERIFIED',
                'POST_RAW_equals_FINAL_semantic':sources['POST_RAW_FINAL_semantic_equal'],
                'CAN_COMPARE_MODEL_REVISION':all(s in stages for s in ['PRE_REFLECTION','POST_MODEL_RAW']) and final_ok,
                'CAN_COMPARE_FINAL_CHANGE':all(s in stages for s in ['PRE_REFLECTION','FINAL_FROZEN']) and final_ok,
                'FINAL_SCORE_REPRODUCTION':'MATCH' if final_ok else 'FINAL_SCORE_REPRODUCTION_MISMATCH','all_metric_mismatch_count':len(mismatches),
                'postprocessing_cause':sources['postprocessing_cause'],'source_provenance_file':prefix+'snapshot_provenance.json',
                'missing_metadata_policy':'METADATA_DEPENDENT_NOT_COMPARABLE; no copying','gaps':gaps})
            cli=read(x/'cli_exit_receipt.json');terminal=read(d/'terminal.json')
            result['costs'].append({'run_unit_id':unit,'request_seq':q['seq'],'phase':'reflection','reflection_call_latency_sec':event.get('latency_sec'),
                 'cli_wall_seconds':cli.get('wall_seconds',cli.get('elapsed_seconds')),'saved_usage':parser.get('usage'),
                 'saved_model_call_telemetry':event.get('model_call'),'whole_ON_cli_starts':terminal['actual_cli_starts'],
                 'whole_ON_phase_counts':terminal['model_phase_counts'],'cost_completeness':'SAVED_FIELDS_ONLY_NO_ACCOUNT_LOOKUP',
                 'model_snapshot':'UNVERIFIED','sampling_runtime':'UNVERIFIED','billing':'UNVERIFIED','new_model_calls':0})
            result['status']='EVALUATED' if final_ok and all(s in stages for s in STAGES) else 'GAPS_OR_SCORE_MISMATCH'
        except Exception as exc:
            result['status']='SOURCE_OR_SNAPSHOT_GAP';result['error']=str(exc)
            result['comparison'].append({'run_unit_id':unit,'status':'SOURCE_OR_SNAPSHOT_GAP','reason':str(exc),'CAN_COMPARE_MODEL_REVISION':False,'CAN_COMPARE_FINAL_CHANGE':False})
            save(root,'logs/'+unit+'_error.txt',traceback.format_exc())
        result['cpu_analysis_elapsed_seconds']=time.perf_counter()-started
        save(root,prefix+'unit_complete.json',result)
        for key,target in [('metrics',metric_rows),('comparison',comparison_rows),('deltas',deltas),('structures',structures),('costs',costs),('reproduction',reproduction)]:target.extend(result[key])
        outcomes.append(result)
        save(root,'logs/progress.json',{'completed_units':[x['unit'] for x in outcomes],'new_model_calls':0,'utc':utc()})
        print(unit,result['status'],flush=True)
    table(root,'03_snapshot_provenance_and_comparability.csv',comparison_rows)
    table(root,'04_final_score_reproduction.csv',reproduction)
    table(root,'05_snapshot_metrics.csv',metric_rows)
    table(root,'06_within_run_deltas.csv',deltas)
    table(root,'07_structural_and_citation_changes.csv',structures)
    table(root,'08_existing_reflection_costs.csv',costs)
    # Verify original required files again, including inputs, Gold, request and response.
    unchanged=[{'path':x['path'],'sha256':sha(Path(x['path'])),'unchanged':sha(Path(x['path']))==x['sha256']} for x in scope['dependencies']]
    save(root,'logs/original_source_integrity_after.json',unchanged)
    assert all(x['unchanged'] for x in unchanged)
    save(root,'logs/analysis_execution_receipt.json',{'version':VERSION,'utc':utc(),'new_model_calls':0,'POSTHOC_GOLD_ACCESS':'YES',
         'unit_statuses':{x['unit']:x['status'] for x in outcomes},'original_sources_unchanged':True,
         'cpu_elapsed_seconds':sum(x['cpu_analysis_elapsed_seconds'] for x in outcomes),
         'analysis_code_sha256':sha(Path(__file__)),'new_endpoint_samples':0,'environment':scope['environment']})

def finalize(cfg:dict,root:Path)->None:
    """Report saved scores only; deliberately does not call evaluate again."""
    scope=read(root/'00_source_map_and_scope.json')
    outcomes=[read(root/f'private_snapshots/{u}/unit_complete.json') for u in UNITS]
    rows=[r for x in outcomes for r in x['metrics']]
    by={(r['run_unit_id'],r['stage']):r for r in rows}
    reproductions=[r for x in outcomes for r in x['reproduction']]
    comparisons=[r for x in outcomes for r in x['comparison']]
    assert all(x['status']=='EVALUATED' for x in outcomes)
    assert all(r['status']=='MATCH' for r in reproductions)
    assert all(r['CAN_COMPARE_MODEL_REVISION'] and r['CAN_COMPARE_FINAL_CHANGE'] for r in comparisons)
    def fmt(v:object)->str:return f'{v:.6f}' if isinstance(v,float) else str(v)
    def tri(u:str,k:str)->str:return ' → '.join(fmt(by[u,s][k]) for s in STAGES)
    table1=['|运行单元|预测步数 PRE→RAW→FINAL|匹配数 PRE→RAW→FINAL|Step F1 PRE→RAW→FINAL|Evidence F1 PRE→RAW→FINAL|',
            '|---|---|---|---|---|']
    table2=['|运行单元|Bestmatch Edge F1 PRE→RAW→FINAL|Order-aligned Edge F1 PRE→RAW→FINAL|POST与FINAL|来源／可比性|',
            '|---|---|---|---|---|']
    for u in UNITS:
        table1.append('|'+u+'|'+tri(u,'n_pred_steps')+'|'+tri(u,'bestmatch_matched_steps')+'|'+tri(u,'bestmatch_step_f1')+'|'+tri(u,'evidence_f1')+'|')
        table2.append('|'+u+'|'+tri(u,'bestmatch_edge_f1')+'|'+tri(u,'causal_edge_f1_order_aligned')+'|三项链字段相同；完整对象不同|ARTIFACT_VERIFIED／可比较|')
    descriptions={
      'C1_R1_ON':'原有 MapPreview、WFS SQL-like 请求、WCS 请求被重新组织，补入多个普通 web 请求并扩展时间边。匹配仍为原 WFS 相关参考位点；不能将其余未匹配请求判作幻觉。',
      'C1_R2_ON':'从一个 WFS SQL 表达式探测扩展为 web 界面、MapPreview、WCS 等七步，并降低/移除部分不确定 ATT&CK 映射；唯一匹配位点仍是原探测步骤。',
      'C2_R2_ON':'将 PowerShell、任务创建及 RunOnce 等按警报节点进一步拆分/重述，仍保留下载文件相关组合行为。参考匹配不是简单新增三步：见匹配集合的新增与丢失计数。',
      'C2_R3_ON':'保留前七步的主体结构、修改描述/LDAP技术解释，新增五个主机任务警报步骤；新的匹配主要出现在 RunOnce 参考位置，新增警报不自动等于新的正确动作。',
      'C3_R3_ON':'保留原六个步骤并改写图像解码执行描述，新增两个 working.zip 删除步骤；两处既有匹配位置未增加。'}
    match_changes=[];costrows=[];sourceextras=[]
    paragraphs=[]
    for out in outcomes:
        u=out['unit'];pre=by[u,'PRE_REFLECTION'];post=by[u,'POST_MODEL_RAW'];d=root/'private_snapshots'/u
        before=read(d/'PRE_REFLECTION_evaluation.json');after=read(d/'POST_MODEL_RAW_evaluation.json')
        old={x['gold_index'] for x in before['best_matches']};new={x['gold_index'] for x in after['best_matches']}
        detail={'run_unit_id':u,'gold_indices_added':sorted(new-old),'gold_indices_lost':sorted(old-new),
            'before_matches':before['best_matches'],'after_matches':after['best_matches'],
            'matching_is_official_evaluator_not_independent_behavior_truth':True}
        save(root,f'private_snapshots/{u}/gold_matching_changes_private.json',detail)
        match_changes.append({'run_unit_id':u,'new_gold_positions_matched':len(new-old),'old_gold_positions_no_longer_matched':len(old-new),
                'matching_count_net_change':len(new)-len(old)})
        structural_change=read(d/'POST_MINUS_PRE_structural_diff_private.json')
        paragraphs.append(f"### {u}\n\n**ARTIFACT_VERIFIED**：预测步数 {pre['n_pred_steps']}→{post['n_pred_steps']}；参考匹配 {pre['bestmatch_matched_steps']}→{post['bestmatch_matched_steps']}，净变化 {post['bestmatch_matched_steps']-pre['bestmatch_matched_steps']:+d}。新增匹配参考位置 {len(new-old)}、丢失 {len(old-new)}。{descriptions[u]}\n\n"
            +f"引用方面：步骤唯一引用新增 {len(structural_change['step_citation_ids_added'])}、移除 {len(structural_change['step_citation_ids_removed'])}；边引用新增 {len(structural_change['edge_citation_ids_added'])}、移除 {len(structural_change['edge_citation_ids_removed'])}。边数 {structural_change['edge_count_before']}→{structural_change['edge_count_after']}。Evidence Precision {pre['evidence_precision']:.6f}→{post['evidence_precision']:.6f}，Recall {pre['evidence_recall']:.6f}→{post['evidence_recall']:.6f}。\n\n"
            +f"**POSTHOC_INTERPRETATION**：Step F1 的变化对应预测分母 {pre['n_pred_steps']}→{post['n_pred_steps']}、匹配分子 {pre['bestmatch_matched_steps']}→{post['bestmatch_matched_steps']}；Gold 步数固定为 {pre['n_gold_steps']}。描述、置信度、引用和编号/顺序变化详见私有逐字段/候选映射文件，不能据新增步骤数推断真实行为准确率。\n")
        sources=read(d/'snapshot_provenance.json');final=read(d/'FINAL_FROZEN.json');metadata=final.get('metadata',{})
        save(root,f'private_snapshots/{u}/POST_FINAL_full_object_field_diff_private.json',tree_diff(read(d/'POST_MODEL_RAW.json'),final))
        sourceextras.append({'run_unit_id':u,'POST_RAW_FINAL_three_chain_objects_equal':all(read(d/'POST_MODEL_RAW.json').get(k)==final.get(k) for k in ['incident_summary','attack_chain','causal_edges']),
            'full_object_equal':False,'final_only_metadata_keys':list(metadata),
            'metadata_includes_retrieval_and_observation_ids':True,
            'metadata_is_not_filled_into_PRE_or_POST':True,'grounding_check_note':sources['postprocessing_trace']['grounding_check_note']})
        c=out['costs'][0];usage=c.get('saved_usage') or {}
        costrows.append({**c,**{k:usage.get(k) for k in ['input_tokens','cached_input_tokens','output_tokens','reasoning_output_tokens']}})
    table(root,'08_existing_reflection_costs.csv',costrows)
    table(root,'private_snapshots/gold_matching_change_counts.csv',match_changes)
    save(root,'private_snapshots/POST_FINAL_metadata_inventory.json',sourceextras)
    up=sum(by[u,'POST_MODEL_RAW']['bestmatch_step_f1']>by[u,'PRE_REFLECTION']['bestmatch_step_f1']+TOL for u in UNITS)
    down=sum(by[u,'POST_MODEL_RAW']['bestmatch_step_f1']<by[u,'PRE_REFLECTION']['bestmatch_step_f1']-TOL for u in UNITS)
    report='''五次真实反思均增加输出步骤：两次参考匹配增加，三次不变；Step F1两升三降。C2_R2_ON从反思前5个匹配、F1=0.5882升至8个、0.8000。五次链字段均与终局相同。本补充不改变C15原不确定性结论。

# 表1：真实快照的步骤与参考指标

以下均为同一运行内 PRE_REFLECTION→POST_MODEL_RAW→FINAL_FROZEN；不是 OFF→ON。数值变化基于未四舍五入原值。

'''+ '\n'.join(table1)+ '\n\n# 表2：两类边指标与可比性\n\n'+'\n'.join(table2)+'''

五个 FINAL 的所有官方 metrics 均同版复核一致（容差1e-9；输入、预测与源码哈希要求精确一致）。15个快照均满足原评价器入口，无补字段或规范化。五个可选 POST_AUTHOR_ACCEPTED 均未单独保存，所以为 SNAPSHOT_UNAVAILABLE；这不影响已验证的 PRE/RAW/FINAL 三阶段比较。未拼接多条模型消息。

# 每次反思改变了什么

'''+ '\n'.join(paragraphs)+'''
# C2_R2_ON：不能把0.8差额全归终局反思

**ARTIFACT_VERIFIED**：反思前已输出6步，其中5步匹配，Step F1=0.5882352941；反思后9步、8步匹配，F1=0.8000000000，局部净增3个匹配、F1增加0.2117647059。匹配集合有4个新参考位点、1个旧位点不再匹配，而非只追加三项独立正确事实。Evidence F1反而从0.666667降至0.592593，Precision从0.562500降至0.500000，Recall从0.818182降至0.727273。

**POSTHOC_INTERPRETATION**：较多匹配在反思前已经形成；真实这次修订进一步改善了作者Step指标，但引用指标并未同步上升。ON有10次Controller、3次Repair、1次Reflection；另一路OFF仅2次Controller、1次Repair并以give_up终止。不能将OFF的合法0分当成这个ON的PRE，不能把端到端0.8全部归给最后一次Reflection。

**NOT_IDENTIFIABLE**：如果关闭反思但保留完全相同其他路径会怎样，未执行且不可从本快照识别；也不能据作者匹配分数证明新增动作的真实安全语义。

# RAW与FINAL、证据引用及边的边界

**ARTIFACT_VERIFIED**：五次 incident_summary、attack_chain、causal_edges 逐字段相同，包括描述、实体、引用和顺序。完整对象不同：FINAL增加 metadata，含运行统计、检索及观察引用等；完整差异已保存，没有将这些字段悄悄忽略成“全对象相同”，也没有复制到PRE/RAW以补指标。Trace的grounding记录均为0个移除步骤、0个移除边、0个过滤引用。因此没有观察到链语义后处理变化，不能据此证明所有反思后处理一般都无作用。

作者 evidence_precision/recall/f1 的实际引用集合是**步骤引用唯一ID集合**；边引用另行统计，两者并集也另存，不能把并集当官方Evidence F1分母。所有ID比较以case_id+evidence_id隔离。非参考引用不等于无关证据，未匹配步骤不等于幻觉，正确ID不等于动作/对象/结果正确。

边指标只按作者定义比较映射端点或链位置；不验证真实因果、关系文字或边的引用正确性。两类边F1不能互换。排序比较对少于2匹配步骤时标NO_COMPARABLE_PAIRS，保留官方数值，不解释为完美排序。各阶段CEAF、聚类、两种顺序指标及实际对数均在05表。

# 成本、原批次与同步

**ARTIFACT_VERIFIED**：本轮新增研究模型调用0，没有Worker、API模型或Smoke请求，没有补跑失败单元/第19次端到端，也没有重启Controller。原18终态、12个已评价运行、6个NA、121次历史CLI，以及原terminal/terminal_resolution区别均保持不变。原67次ON对54次OFF的差额不能全部算Reflection成本。

08表只使用既有Reflection耗时和token字段；服务端模型快照、实际采样及账务继续UNVERIFIED。本轮CPU分析耗时另见执行回执，不冒充模型耗时。

Mac与服务器私有新目录保存快照、原文跨度、逐字段/参考匹配差异及完整指标；完整Prompt/回复/Gold仍以原地哈希引用，不额外复制。GitHub仅发布不含原文、证据映射、个人路径和凭据的聚合指标、通用代码、限制与公共manifest。真实同步结果见独立sync_receipts；分析完成与同步完成分开记录。

# 结论上限

**POSTHOC_INTERPRETATION**：只在这5次已成功且触发并接纳Reflection的条件子集中，观察到“扩写未必增加匹配”，也观察到一次较明显和一次小幅Step F1提升。不是5个独立场景，不是9个ON的无偏替代，不计算跨家族均值/显著性，不多数投票选择开关。

**NOT_IDENTIFIABLE**：普遍有益/有害、总体因果效应、真实幻觉率、行为准确率及算法创新有效性。主结论继续为HETEROGENEOUS_OR_INCONCLUSIVE。保留作者原生配置是基线定义选择，不是本轮证明其最优。完成即停止，不自动启动C16。
'''
    save(root,'09_plain_language_closeout_zh.md',report)
    limitations='''# C15-S 限制与原C15边界

- 本轮为 POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS。POSTHOC_GOLD_ACCESS=YES，结果已暴露后的冻结计划，不冒充预注册。
- 5次来自3个已暴露案例，且是成功并触发接纳反思的条件子集；不代表5个独立攻击、不代表原全部ON。
- PRE是当前ON真实请求中的working_chain，不是OFF分支，不填补原失败/缺失配对。
- C15_BATCH_CLOSED_WITH_FAILURES：18终态、12评价、6NA、121历史CLI；原7FAILED记录有1同attempt消歧完成，terminal与terminal_resolution区别不改。
- 主结论 HETEROGENEOUS_OR_INCONCLUSIVE 保留，无跨案例F1平均、显著性、普遍因果效应或行为真值声明。
- 所有已提取快照均完整可评分，无JSON修复、字段补造或FINAL metadata继承；5个单独作者接纳后中间链未保存。
- 参考匹配仅为作者评价器的操作化定义，非独立人工语义真值；未匹配不等于幻觉。
- 官方Evidence F1仅以步骤引用唯一ID计算，边引用和并集另计；证据键按case_id隔离，重复引用不算独立事实。
- 边拓扑分数不验证因果关系；NO_COMPARABLE_PAIRS不解释为排序完美。
- 源码为 SOURCE_COMMIT_UNVERIFIABLE_COPY。逐文件SHA-256已核验，不能将Git blob SHA冒充文件SHA-256。
- 模型快照、采样实际采用与账务UNVERIFIED；本轮没有访问额度账号或新模型。
- 新研究模型调用0，未修改旧实验。同步状态在独立回执中记录，不能以发布成功替代分析完成。
'''
    save(root,'10_limitations_and_original_C15_boundary.md',limitations)
    gate={'state':'C15S_FIVE_REFLECTION_SNAPSHOTS_EVALUATED_CLOSEOUT_COMPLETE','analysis_scope':'POSTHOC_WITHIN_RUN_REFLECTION_SNAPSHOTS',
        'utc':utc(),'G0':'PASS_111_REQUIRED_SOURCE_HASH_CHECKS_AND_ALL_FINAL_METRICS_MATCH',
        'G1':'PASS_ALL_FIVE_ACTUAL_CALLED_AND_ACCEPTED_REFLECTIONS_RETAINED',
        'G2':'PASS_PRE_REQUEST_POST_CANONICAL_CONSUMED_REPLY_FINAL_FROZEN_DISTINCT; OPTIONAL_ACCEPTED_UNAVAILABLE',
        'G3':'PASS_SAME_DERIVED_INPUT_GOLD_EVALUATOR_ENVIRONMENT_NO_METADATA_INHERITANCE',
        'G4':'PASS_ZERO_NEW_MODEL_CALLS_NO_CONTROLLER_OR_FAILURE_REPLAY_OLD_FILES_UNCHANGED',
        'G5':'PASS_HETEROGENEOUS_OR_INCONCLUSIVE_RETAINED_PRE_NOT_OFF',
        'G6':'SEE_INDEPENDENT_SYNC_RECEIPTS_FOR_ACTUAL_SERVER_AND_GITHUB_STATUS',
        'analysis_completed':True,'new_model_calls':0,'POSTHOC_GOLD_ACCESS':'YES','snapshot_scores':15,
        'new_endpoint_samples':0,'original_end_to_end_evaluated_runs':12,'original_failed_NA':6,'original_model_cli_starts':121,
        'source_commit':'SOURCE_COMMIT_UNVERIFIABLE_COPY','post_raw_final_three_chain_objects_equal':5,
        'full_object_equal':0,'optional_post_author_accepted_missing':5,'score_reproduction_mismatch_count':0,
        'within_five_step_f1_direction':{'up':up,'down':down,'equal':5-up-down,'incomparable':0},
        'main_conclusion':'HETEROGENEOUS_OR_INCONCLUSIVE','causal_effect':'NOT_IDENTIFIABLE','SEMANTIC_TRUTH_NOT_INDEPENDENTLY_VALIDATED':True}
    save(root,'11_final_gate.json',gate)
    # Narrow export: no snapshots, reference-ID lists, raw text, source-map paths or account data.
    public=root/'public_export'
    for name in ['09_plain_language_closeout_zh.md','10_limitations_and_original_C15_boundary.md','11_final_gate.json']:
        save(public,name,(root/name).read_text())
    clean_metrics=[]
    allowed=['run_unit_id','case_id','stage','status',*METRICS,'n_pred_edges','n_pred_edges_source','bestmatch_order_pair_count_actual','ceaf_order_pair_count_actual',
             'bestmatch_order_status','ceaf_order_status','step_unique_reference_ids','edge_unique_reference_ids','official_citation_unique_ids','step_and_edge_union_unique_ids',
             'gold_unique_support_ids','official_cited_gold_ids','official_cited_nonreference_ids','metadata_status','metadata_copied_from_final']
    for r in rows:clean_metrics.append({k:r.get(k) for k in allowed})
    table(public,'05_snapshot_metrics.csv',clean_metrics)
    table(public,'06_within_run_deltas.csv',[r for x in outcomes for r in x['deltas']])
    simple_struct=[]
    for o in outcomes:
        for r in o['structures']:
            simple_struct.append({k:v for k,v in r.items() if k not in ['step_citation_ids_added','step_citation_ids_removed','edge_citation_ids_added','edge_citation_ids_removed','candidate_mapping_file']}|
                  {k+'_count':len(r[k]) for k in ['step_citation_ids_added','step_citation_ids_removed','edge_citation_ids_added','edge_citation_ids_removed']})
    table(public,'07_structural_and_citation_change_counts.csv',simple_struct)
    table(public,'reference_matching_change_counts.csv',match_changes)
    # Some evaluator metrics carry exposure/reference-ID lists. Keep their complete
    # reconciliation private; publish only the explicitly selected score/count fields.
    table(public,'04_final_score_reproduction.csv',[r for x in outcomes for r in x['reproduction'] if r['metric'] in METRICS])
    table(public,'08_existing_reflection_costs.csv',[{k:r.get(k) for k in ['run_unit_id','request_seq','phase','reflection_call_latency_sec','cli_wall_seconds',
          'input_tokens','cached_input_tokens','output_tokens','reasoning_output_tokens','whole_ON_cli_starts','whole_ON_phase_counts','model_snapshot','sampling_runtime','billing','new_model_calls']} for r in costrows])
    save(public,'scripts/analyze_reflection_snapshots.py',Path(__file__).read_text())
    save(public,'README.md','''# C15-S: five actual Reflection snapshot closeout

Posthoc, within-run, offline diagnostics. Zero new research model calls. The historical C15 result remains HETEROGENEOUS_OR_INCONCLUSIVE: 18 terminal units, 12 evaluated outputs, 6 failed NA, 121 CLI starts.

Read 09_plain_language_closeout_zh.md for the five-row comparisons and 10_limitations_and_original_C15_boundary.md for interpretation limits. PRE is not OFF. No statistical or general causal effect is claimed.

This export contains aggregate metrics and payload-free generic analysis code only. No prompts, replies, snapshots, Gold, evidence-ID mappings, personal paths or credentials. Private source configuration is intentionally excluded. The generic program needs authorized private artifacts and the frozen author's evaluator; it never invokes a controller or model.

Original C15 public source commit: 5306e1c77e881773e302ed6d7f146ba262ac3ce6. Independent synchronization receipts are retained privately.
''')
    save(root,'logs/finalization_receipt.json',{'utc':utc(),'report_only_no_reevaluation':True,'new_model_calls':0,'analysis_script_final_sha256':sha(Path(__file__)),
         'metric_files_unchanged':True,'public_export_requires_content_review_before_publish':True})
    print(json.dumps({'state':gate['state'],'step_f1_up':up,'step_f1_down':down,'final_all_metrics_match':True,'new_model_calls':0}),flush=True)

def main()->None:
    os.umask(0o077);sys.dont_write_bytecode=True
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--prepare',action='store_true');p.add_argument('--analyze',action='store_true');p.add_argument('--finalize',action='store_true');a=p.parse_args()
    root=a.out;no_symlinks(root);assert root.is_dir() and (root.stat().st_mode&0o777)==0o700
    cfg=read(a.config)
    if a.prepare:prepare(cfg,root)
    if a.analyze:analyze(cfg,root)
    if a.finalize:finalize(cfg,root)

if __name__=='__main__':main()
