#!/usr/bin/env python3
"""Offline diagnosis of immutable requests, replies and chain snapshots. No model calls.
Inputs are explicit private configuration; output is a fresh, private directory.
"""
from __future__ import annotations
import argparse, collections, csv, hashlib, importlib, json, os, re, sys
from pathlib import Path
from prompt_card_span_index_v2 import card_blocks, json_leaves, LexicalJSON

VERSION='c14-offline-v1.1-source-prefix-correction'
ROLE_FIELDS={'alert_name','alert_type','description','compromised_entity','display_name','EventID','Image','CommandLine','ParentImage','ParentCommandLine','TargetFilename','TargetObject','Details','SourceImage','TargetImage','DestinationIp','DestinationPort','ScriptBlockText','ScriptBlockId','ProcessGuid','ProcessId','ParentProcessGuid','ParentProcessId','User','AccountName','SourceName','Hostname','Channel','TaskName','ObjectName','ServiceName','EventType','Hashes','SourceIp','SourcePort','TargetUserName','TargetDomainName','LogonType','IpAddress','WorkstationName','Payload','Message'}
HEADER_FIELDS={'@timestamp','AccountName','Channel','Domain','EventID','EventTime','Hostname','SourceName','UtcTime'}
ACTION_FIELDS=ROLE_FIELDS-{'AccountName','SourceName','Hostname','Channel','EventID','ProcessGuid','ProcessId','ParentProcessGuid','ParentProcessId','User','ScriptBlockId','Hashes'}

def digest(x):return hashlib.sha256(x if isinstance(x,bytes) else x.encode()).hexdigest()
def sha(p):return digest(Path(p).read_bytes())
def strict_pairs(items):
 d={}
 for k,v in items:
  if k in d:raise ValueError('DUPLICATE_JSON_KEY')
  d[k]=v
 return d
def loads(s):return json.loads(s,object_pairs_hook=strict_pairs,parse_constant=lambda v:(_ for _ in ()).throw(ValueError(v)))
def read(p):return loads(Path(p).read_text())
def save(root,name,value):
 p=root/name
 if p.is_symlink() or any(q.is_symlink() for q in [p.parent,*p.parents]):raise ValueError('SYMLINK_OUTPUT')
 p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
 s=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
 p.write_text(s);p.chmod(0o600)
def table(root,name,rows):
 if not rows:return
 fields=list(dict.fromkeys(k for x in rows for k in x));p=root/name
 if p.is_symlink():raise ValueError('SYMLINK_OUTPUT')
 with p.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader()
  for row in rows:w.writerow({k:json.dumps(v,ensure_ascii=False,sort_keys=True) if isinstance(v,(dict,list,set,tuple)) else v for k,v in row.items()})
 p.chmod(0o600)
def ids(chain,edges=False):
 if chain is None:return None
 items=chain.get('causal_edges',[]) if edges else chain.get('attack_chain',[])
 return {str(e) for s in items if isinstance(s,dict) for e in s.get('supporting_evidence',[]) if isinstance(e,(str,int))}
def union_ids(chain):
 if chain is None:return None
 return ids(chain)|ids(chain,True)
def extract_section(t,marker):
 if t.count(marker)!=1:return None,None
 start=t.index(marker)+len(marker);start+=len(t[start:])-len(t[start:].lstrip())
 try:
  value,n=json.JSONDecoder(object_pairs_hook=strict_pairs).raw_decode(t[start:]);return value,(start,start+n)
 except (ValueError,TypeError):return None,None

def candidate(raw):
 """Complete JSON first; otherwise only complete step objects, marked prefix-only."""
 t=raw.strip()
 if t.startswith('```'):t=re.sub(r'^```(?:json)?\s*','',t);t=re.sub(r'\s*```$','',t)
 try:
  d=loads(t);return (d.get('working_chain',d),'COMPLETE_OBJECT') if isinstance(d,dict) else (None,'NON_OBJECT')
 except (ValueError,TypeError):pass
 m=re.search(r'"working_chain"\s*:\s*\{',t)
 if not m:return None,'UNPARSEABLE'
 a=re.search(r'"attack_chain"\s*:\s*\[',t[m.end():])
 if not a:return None,'UNPARSEABLE'
 pos=m.end()+a.end();steps=[]
 while pos<len(t):
  while pos<len(t) and t[pos] in ' \n\r\t,':pos+=1
  if pos>=len(t) or t[pos]!='{':break
  try:s,n=json.JSONDecoder(object_pairs_hook=strict_pairs).raw_decode(t[pos:])
  except (ValueError,TypeError):break
  if not isinstance(s,dict):break
  steps.append(s);pos+=n
 return ({'attack_chain':steps,'causal_edges':[]} if steps else None),'COMPLETE_STEP_PREFIX_ONLY'

def source_parse_status(content):
 try:loads(content);return 'COMPLETE_JSON'
 except (ValueError,TypeError):return 'SOURCE_JSON_INCOMPLETE_OR_NONJSON'

def field_leaves(content):
 if source_parse_status(content)=='COMPLETE_JSON':return json_leaves(content,0)
 # Reuse lexical scanner, retain only independently decodable complete prefix leaves.
 # Never complete a cut string or infer the missing tail.
 lex=LexicalJSON(content,0)
 try:lex.value()
 except (ValueError,IndexError,TypeError):pass
 out=[];seen=set()
 for leaf in lex.leaves:
  path=leaf['field_path']
  if path in seen:return []
  seen.add(path)
  try:valid=loads(content[leaf['start']:leaf['end']])==leaf['value']
  except (ValueError,TypeError):valid=False
  if valid:out.append(leaf)
 return out

def visibility(prompt,blocks,eid,card,required):
 b=blocks.get(eid,[]);allfields=field_leaves(str(card.get('content','')));found={};boundaries=[]
 for block in b:
  if block['form']!='FULL_CARD':continue
  t=block['text'];m=re.search(r'(?m)^content: ',t)
  if not m:continue
  start=block['start']+m.end();end=prompt.find('\nclues:',start)
  if end<0 or end>block['end']:continue
  rendered=prompt[start:end];lex=LexicalJSON(rendered,start)
  try:lex.value()
  except (ValueError,IndexError,TypeError):pass
  # Only complete leaves whose exact lexical slice independently decodes.
  for leaf in lex.leaves:
   try:verified=loads(prompt[leaf['start']:leaf['end']])==leaf['value']
   except (ValueError,TypeError):verified=False
   if verified:
    cp=leaf['field_path'];expected=next((x for x in allfields if x['field_path']==cp),None)
    if expected and expected['value']==leaf['value']:
     bs=len(prompt[:leaf['start']].encode());be=len(prompt[:leaf['end']].encode())
     assert prompt.encode()[bs:be].decode()==prompt[leaf['start']:leaf['end']]
     found[cp]={'char_span':[leaf['start'],leaf['end']],'utf8_byte_span':[bs,be],'value_sha256':digest(json.dumps(leaf['value'],ensure_ascii=False,sort_keys=True))}
  boundaries.append({'char_span':[block['start'],block['end']],'form':block['form'],'content_complete':rendered==str(card.get('content','')),'content_chars':len(rendered),'source_content_chars':len(str(card.get('content','')))})
 full_all=any(x['content_complete'] for x in boundaries)
 necessary_complete=bool(required) and all(x in found for x in required)
 if necessary_complete:state='CARD_FIELD_COMPLETE'
 elif b:state='CARD_FIELD_PARTIAL'
 elif re.search(r'(?<![A-Za-z0-9_])'+re.escape(eid)+r'(?![A-Za-z0-9_])',prompt):state='OTHER_PROMPT_MENTION'
 else:state='NOT_FOUND_IN_AVAILABLE_REQUEST'
 return {'visibility':state,'necessary_complete':necessary_complete,'whole_content_complete':full_all,'source_parse_status':source_parse_status(str(card.get('content',''))),'source_leaf_count':len(allfields),'complete_leaf_count':len(found),'required_fields':required,'missing_required':[x for x in required if x not in found],'field_spans':found,'card_boundaries':boundaries,'scope':'exact same-ID card boundaries in terminal Retrieved evidence memory; other mention is ID-only, not equivalent-content proof'}

def chain_mapping(before,after):
 if before is None or after is None:return {'status':'SNAPSHOT_UNAVAILABLE'}
 out=[]
 for a in before.get('attack_chain',[]):
  candidates=[]
  for b in after.get('attack_chain',[]):
   overlap=set(a.get('supporting_evidence',[]))&set(b.get('supporting_evidence',[]))
   text_equal=(a.get('attack_step'),a.get('step_description'))==(b.get('attack_step'),b.get('step_description'))
   if overlap or text_equal:candidates.append({'after':b.get('step_id'),'evidence_overlap':sorted(overlap),'action_text_equal':text_equal,'entities_equal':a.get('entities')==b.get('entities')})
  out.append({'before':a.get('step_id'),'candidates':candidates,'status':'NO_IDENTITY_CANDIDATE' if not candidates else 'UNIQUE_CANDIDATE_NOT_SEMANTIC_PROOF' if len(candidates)==1 else 'AMBIGUOUS_MAPPING'})
 return {'status':'CANDIDATE_MAPPING','rows':out}

def classify(eid,snapshots,raw_cited,exposures,reflection_seq):
 accepted=[s for s in snapshots if s['chain'] is not None]
 transitions=[]
 for prev,nxt in zip(accepted,accepted[1:]):
  if eid in union_ids(prev['chain']) and eid not in union_ids(nxt['chain']):
   transitions.append({'from':prev['label'],'to':nxt['label'],'transition_seq':prev.get('producer_seq'),'to_seq':nxt.get('producer_seq'),'source_sha256':prev['source_sha256'],'target_sha256':nxt['source_sha256']})
 ever=any(eid in union_ids(s['chain']) for s in accepted)
 if transitions:
  last=transitions[-1];f='USED_THEN_REMOVED_BY_REFLECTION' if last['from']=='reflection_pre' and last['to']=='final' else 'USED_THEN_REMOVED_BY_OTHER_UPDATE'
 elif ever:f='TRACE_INCOMPLETE_OR_UNRESOLVED'
 elif raw_cited:f='MODEL_PROPOSED_BUT_CONTROLLER_NOT_RETAINED'
 elif any(e['necessary_complete'] for e in exposures):f='NEVER_USED_WITH_COMPLETE_FIELD_EXPOSURE'
 else:f='NEVER_USED_WITH_PARTIAL_OR_UNVERIFIED_EXPOSURE'
 return f,transitions,ever

def run(cfg,root):
 root=root.resolve();os.umask(0o077)
 if root.is_symlink():raise ValueError('SYMLINK_ROOT')
 source=Path(cfg['source_dir'])
 for x in cfg['source_files']:assert sha(source/x['relative'])==x['sha256']
 sys.path.insert(0,str(source));ev=importlib.import_module('evaluate_chain_reconstruction')
 frozen={};ledger=[];life=[];missing=[];summary=[];alignment=[];reflection_rows=[];snapshot_metrics=[];reconciliation=[];edges=[];fieldchecks=[]
 transport={(x['case_id'],x['seq']):x for x in read(root/'logical_transport_metadata_private.json')}
 for case in cfg['cases']:
  cid=case['case_id'];a=Path(cfg['server_root'])/'private_recovery_attempts'/case['attempt_id'];paths=case['case_paths'];inp=read(paths['input']['path']);gt=read(paths['ground_truth']['path']);pred=read(a/'prediction.json');trace=read(a/'trace.json');official=read(a/'official_evaluation.json')
  for kind,row in paths.items():assert sha(row['path'])==row['sha256']
  assert sha(a/'prediction.json')==case['prediction_sha256'];assert sha(a/'trace.json')==case['trace_sha256']
  frozen[cid]={'prediction_sha256':sha(a/'prediction.json'),'trace_sha256':sha(a/'trace.json'),'official_evaluation_sha256':sha(a/'official_evaluation.json'),'gold_sha256':paths['ground_truth']['sha256'],'input_sha256':paths['input']['sha256']}
  cards={x['evidence_id']:x for x in inp['evidence_cards']};gs=ev.sorted_steps(gt);ps=ev.sorted_steps(pred)
  G={e for s in gs for e in ev.canonical_evidence_ids(s)};O=ev.selected_evidence_ids(pred);CS=ids(pred);CE=ids(pred,True);CO=CS|CE;D=(G&O)-CO
  sets={'G':sorted(G),'O':sorted(O),'C_step':sorted(CS),'C_edge':sorted(CE),'C_official':sorted(CO),'D':sorted(D),'G_minus_O':sorted(G-O)}
  save(root,'private_evidence_excerpts/'+cid+'_set_index.json',sets)
  requests=[];snapshots=[];raw_uses=collections.defaultdict(list);observations=trace['observations'];obsunion=set().union(*(set(x['selected_evidence_ids']) for x in observations));assert obsunion==O
  firstturn={e:min(x['turn'] for x in observations if e in x['selected_evidence_ids']) for e in O};blocks_by_seq={}
  raw_trace=trace['raw_responses']
  for seq in range(1,len(raw_trace)+1):
   qpath=a/'exchange'/f'REQUEST_{seq:04d}.json';vpath=a/'exchange'/f'RESPONSE_{seq:04d}.json';q=read(qpath);v=read(vpath);cons=read(a/'exchange'/f'CONSUMED_{seq:04d}.json');t=q['prompt_utf8'];raw=v['raw_reply_utf8'];meta=transport[cid,seq]
   assert digest(t)==q['prompt_sha256']==meta['prompt_sha256'];assert digest(raw)==v['reply_sha256']==meta['reply_sha256']==cons['reply_sha256'];assert raw_trace[seq-1]['raw']==raw
   phase=q['phase'];turn=q['controller_turn'];before_ids=set().union(*(set(x['selected_evidence_ids']) for x in observations if x['turn']<turn)) if phase!='reflection' else O.copy()
   # Exact prompt metadata / IDs are retained separately; repairs carry no invented cards.
   blocks=card_blocks(t);blocks_by_seq[seq]=blocks
   for e in blocks:assert e in before_ids,'FUTURE_EVIDENCE_IN_PROMPT'
   marker='Current working_chain before reflection:\n' if phase=='reflection' else 'Current working_chain:\n'
   before,span=extract_section(t,marker) if phase in ('controller','reflection') else (None,None)
   if before is not None:
    assert isinstance(before,dict);snapshots.append({'label':'reflection_pre' if phase=='reflection' else f'before_request_{seq}','producer_seq':seq,'chain':before,'source_sha256':sha(qpath),'prompt_sha256':digest(t),'json_char_span':span})
   cand,status=candidate(raw)
   if cand is not None:
    for e in union_ids(cand):raw_uses[e].append({'seq':seq,'phase':phase,'candidate_status':status,'reply_sha256':digest(raw)})
   returned=set().union(*(set(x['selected_evidence_ids']) for x in observations if x['turn']==turn)) if phase=='controller' else set()
   record={'case_id':cid,'logical_seq':seq,'logical_run_id':q['run_id'],'successful_attempt':case['attempt_id'],'origin_attempt':meta['origin_attempt'],'phase':phase,'controller_turn':turn,'prompt_sha256':digest(t),'reply_sha256':digest(raw),'request_file_sha256':sha(qpath),'response_file_sha256':sha(vpath),'new_cli_or_replay':'NEW_CLI' if meta['actual_new_cli_start'] else 'VERIFIED_REPLAY','replay_provenance':meta['replay_provenance'],'server_consumed':True,'observed_ids_before_request':sorted(before_ids),'query_action':next((x['action'] for x in trace['turns'] if x['turn']==turn),'UNKNOWN') if phase=='controller' else phase,'returned_ids_after_controller_turn':sorted(returned),'retrieval_payload_snapshot':'NOT_SAVED_IN_TRACE; actual rendered payload checked per request','actual_full_card_ids':sorted(e for e,b in blocks.items() if any(x['form']=='FULL_CARD' for x in b)),'actual_summary_card_ids':sorted(e for e,b in blocks.items() if any(x['form']=='SUMMARY_CARD' for x in b)),'working_chain_before_ids':sorted(union_ids(before)) if before is not None else 'SNAPSHOT_UNAVAILABLE','raw_candidate_ids':sorted(union_ids(cand)) if cand is not None else 'UNPARSEABLE','parse_status':status,'working_chain_after':'RESOLVED_BY_NEXT_ACTUAL_CONTROLLER_OR_REFLECTION_REQUEST','normalization_or_filter_event':'See accepted transition and trace.json_repair_events; no simulated controller','canonical_reply_verification':meta['canonical_final_file_exact'],'snapshot_json_char_span':span or 'SNAPSHOT_UNAVAILABLE'}
   ledger.append(record);requests.append({'q':q,'raw':raw,'candidate':cand,'before':before,'q_sha256':sha(qpath),'v_sha256':sha(vpath),'record':record})
  refl=next(x for x in requests if x['q']['phase']=='reflection');rseq=refl['q']['seq'];pre=refl['before'];post=refl['candidate'];assert post is not None and refl['record']['parse_status']=='COMPLETE_OBJECT'
  snapshots.append({'label':'final','producer_seq':rseq,'chain':pred,'source_sha256':sha(a/'prediction.json')})
  # Accepted state after a request is observed at the next non-repair request.
  for req in requests:
   seq=req['q']['seq'];nxt=next((s for s in snapshots if s['producer_seq']>seq),None)
   req['record']['working_chain_after']=sorted(union_ids(nxt['chain'])) if nxt else sorted(CO)
   req['record']['working_chain_after_snapshot_source']=nxt['source_sha256'] if nxt else sha(a/'prediction.json')
  save(root,'private_evidence_excerpts/'+cid+'_reflection_states.json',{'case_id':cid,'pre':pre,'raw_post':post,'accepted_final_without_metadata':{k:v for k,v in pred.items() if k!='metadata'},'reflection_seq':rseq,'pre_source':{'request_sha256':refl['q_sha256'],'prompt_sha256':refl['q']['prompt_sha256'],'span':next(x['json_char_span'] for x in snapshots if x['label']=='reflection_pre')},'raw_post_response_sha256':refl['v_sha256'],'mapping':chain_mapping(pre,post),'controller_postprocessing_semantic_equal':post=={k:v for k,v in pred.items() if k!='metadata'}})
  preids=union_ids(pre);postids=union_ids(post)
  change_rows=[]
  for mapping_row in chain_mapping(pre,post).get('rows',[]):
   old=next(s for s in pre['attack_chain'] if s['step_id']==mapping_row['before'])
   for m in mapping_row['candidates']:
    new=next(s for s in post['attack_chain'] if s['step_id']==m['after'])
    change_rows.append({'case_id':cid,'seq':rseq,'before_step':old['step_id'],'after_candidate':new['step_id'],'mapping_status':mapping_row['status'],'citation_set_equal':set(old['supporting_evidence'])==set(new['supporting_evidence']),'citation_overlap':m['evidence_overlap'],'title_equal':old.get('attack_step')==new.get('attack_step'),'description_equal':old.get('step_description')==new.get('step_description'),'entities_equal':old.get('entities')==new.get('entities'),'renumber_only':{k:v for k,v in old.items() if k not in ('step_id','order')}=={k:v for k,v in new.items() if k not in ('step_id','order')},'before_request_sha256':refl['q_sha256'],'raw_post_response_sha256':refl['v_sha256']})
  table(root,'private_evidence_excerpts/'+cid+'_reflection_step_changes.csv',change_rows)
  mapped_after={m['after'] for z in chain_mapping(pre,post).get('rows',[]) for m in z['candidates']}
  save(root,'private_evidence_excerpts/'+cid+'_reflection_edge_changes.json',{'pre_edges':pre['causal_edges'] if pre else None,'post_edges':post['causal_edges'],'after_steps_without_identity_candidate':[s['step_id'] for s in post['attack_chain'] if s['step_id'] not in mapped_after],'candidate_step_mapping':chain_mapping(pre,post),'caution':'Raw step IDs/edge IDs cannot be compared as deletions across renumbering. Merge/split semantics remain POSTHOC_AGENT_JUDGMENT or AMBIGUOUS_MAPPING.'})
  reflection_rows.append({'case_id':cid,'seq':rseq,'pre_steps':len(pre['attack_chain']) if pre else 'SNAPSHOT_UNAVAILABLE','raw_post_steps':len(post['attack_chain']),'final_steps':len(ps),'pre_edges':len(pre['causal_edges']) if pre else 'SNAPSHOT_UNAVAILABLE','raw_post_edges':len(post['causal_edges']),'final_edges':len(pred['causal_edges']),'added_citations':sorted(postids-preids) if pre else 'SNAPSHOT_UNAVAILABLE','removed_citations':sorted(preids-postids) if pre else 'SNAPSHOT_UNAVAILABLE','added_reference_ids':sorted((postids-preids)&G) if pre else 'SNAPSHOT_UNAVAILABLE','removed_reference_ids':sorted((preids-postids)&G) if pre else 'SNAPSHOT_UNAVAILABLE','raw_post_to_final_removed':sorted(postids-CO),'raw_post_to_final_added':sorted(CO-postids),'raw_post_content_equal_final':post=={k:v for k,v in pred.items() if k!='metadata'},'pre_source_sha256':refl['q_sha256'],'post_source_sha256':refl['v_sha256'],'final_source_sha256':sha(a/'prediction.json'),'mapping_status':'CANDIDATE_MAPPING_NOT_HUMAN_SEMANTIC_LABEL'})
  fates=collections.Counter();expcounts=collections.Counter();case_rows=[];positive=sorted(G&CO,key=lambda e:digest(cid+'\0'+e))[:2];details=[]
  for eid in sorted(G):
   card=cards.get(eid,{});leaves=field_leaves(str(card.get('content','')));required=[x['field_path'] for x in leaves if x['field_path'].split('.')[-1] in ROLE_FIELDS and x['value'] not in ('',None,[])];action_fields=[x['field_path'] for x in leaves if x['field_path'].split('.')[-1] in ACTION_FIELDS and x['value'] not in ('',None,[])]
   # A complete host/event header does not establish a script's behavior.
   necessary_basis='POSTHOC_AGENT_JUDGMENT: conservative all nonempty structured action/object/identity fields; source-card scope only, not all Gold mechanisms'
   exposures=[]
   for req in requests:
    seq=req['q']['seq'];v=visibility(req['q']['prompt_utf8'],blocks_by_seq[seq],eid,card,required)
    if not action_fields:v['necessary_complete']=False
    v.update(seq=seq,phase=req['q']['phase'],request_sha256=req['q_sha256'],prompt_sha256=req['q']['prompt_sha256']);exposures.append(v)
   fate,transitions,ever=classify(eid,snapshots,raw_uses[eid],exposures,rseq)
   if eid in CO:fate='FINAL_REFERENCED'
   elif eid not in O:fate='NEVER_OBSERVED'
   if eid in D:fates[fate]+=1;expcounts['ANY_NECESSARY_COMPLETE' if any(x['necessary_complete'] for x in exposures) else 'NO_CONFIRMED_NECESSARY_COMPLETE']+=1
   # Exact duplicates only; same process/time is insufficient for equivalence.
   duplicates=[e for e,c in cards.items() if e!=eid and (c.get('source_type'),c.get('line'),c.get('timestamp'),c.get('content'))==(card.get('source_type'),card.get('line'),card.get('timestamp'),card.get('content'))]
   gold_refs=[s['step_id'] for s in gs if eid in ev.canonical_evidence_ids(s)]
   complete_seqs=[x['seq'] for x in exposures if x['necessary_complete']];payload_seqs=[x['seq'] for x in exposures if x['card_boundaries']];lastctrl=next((x for x in reversed(exposures) if x['phase']=='controller'),None);reflection_exp=next(x for x in exposures if x['phase']=='reflection')
   row={'case_id':cid,'evidence_id':eid,'composite_key':[cid,eid],'gold_step_ids':gold_refs,'gold_step_reuse_count':len(gold_refs),'in_O':eid in O,'first_observed_metadata_turn':firstturn.get(eid,'NEVER_OBSERVED'),'retrieval_return_ids_first_turn':firstturn.get(eid,'NEVER_OBSERVED'),'retrieval_raw_payload_first_seq':'SNAPSHOT_UNAVAILABLE','first_actual_full_card_prompt_seq':min(payload_seqs) if payload_seqs else 'NOT_FOUND_IN_AVAILABLE_REQUEST','first_necessary_complete_seq':min(complete_seqs) if complete_seqs else 'NOT_CONFIRMED','necessary_fields':required,'observable_action_fields':action_fields,'necessary_field_selection_basis':necessary_basis,'any_required_complete_seqs':complete_seqs,'last_controller_visibility':lastctrl['visibility'] if lastctrl else 'VISIBILITY_UNVERIFIED','last_controller_missing_fields':lastctrl['missing_required'] if lastctrl else required,'reflection_visibility':reflection_exp['visibility'],'reflection_missing_fields':reflection_exp['missing_required'],'source_content_parse_status':source_parse_status(str(card.get('content',''))),'whole_card_content_complete_seqs':[x['seq'] for x in exposures if x['whole_content_complete']],'raw_model_citation_events':raw_uses[eid],'accepted_ever_cited':ever,'accepted_snapshot_labels':[s['label'] for s in snapshots if s['chain'] is not None and eid in union_ids(s['chain'])],'last_disappearance':transitions[-1] if transitions else 'NO_OBSERVED_ACCEPTED_DISAPPEARANCE','all_disappearance_transitions':transitions,'restored_after_last_disappearance':any(eid in union_ids(s['chain']) for s in snapshots[snapshots.index(next((x for x in snapshots if transitions and x['label']==transitions[-1]['to']),snapshots[-1]))+1:]) if transitions else False,'final_step_cited':eid in CS,'final_edge_cited':eid in CE,'in_D':eid in D,'primary_fate':fate,'necessary_field_status':'SOURCE_ACTION_OBJECT_FIELDS_FULLY_EXPOSED_AT_LEAST_ONCE' if complete_seqs else 'PARTIAL_OR_UNVERIFIED','source_all_field_paths':[x['field_path'] for x in leaves],'source_header_only':bool(leaves) and all(x['field_path'] in HEADER_FIELDS for x in leaves),'reference_claim_observability':'ALERT_ASSERTION_ONLY_NOT_INDEPENDENT_ATTACK_PROOF' if 'alert' in str(card.get('source_type','')) else 'SOURCE_CARD_ACTION_FIELDS_ONLY_HIGH_LEVEL_GOLD_CLAIM_NOT_ESTABLISHED' if action_fields else 'EVENT_HEADER_ONLY_NO_ACTION_OBJECT_FIELD','semantic_effect':'NOT_IDENTIFIABLE','exact_duplicate_card_candidates':duplicates,'near_duplicate_status':'NOT_MERGED_NO_EQUIVALENCE_FROM_TIME_OR_PROCESS_ALONE','equivalent_final_event':'NOT_IDENTIFIABLE','classification_basis':'MEASURED_ARTIFACT_FACT for citation states and exact spans; necessary-field roles POSTHOC_AGENT_JUDGMENT; semantic loss NOT_IDENTIFIABLE','confidence':'HIGH_FOR_RECORDED_CITATION_TRANSITIONS_ONLY','source_json_path':f'evidence_cards[{next((i for i,c in enumerate(inp["evidence_cards"]) if c["evidence_id"]==eid),-1)}]','input_sha256':paths['input']['sha256'],'gold_sha256':paths['ground_truth']['sha256'],'trace_sha256':case['trace_sha256'],'positive_check':eid in positive}
   life.append(row);case_rows.append(row)
   if eid in D:missing.append(row)
   if eid in D or eid in positive:
    details.append({'evidence_id':eid,'source_json_path':row['source_json_path'],'required_fields':required,'reference_steps':gold_refs,'field_visibility':exposures,'source_field_values':{x['field_path']:x['value'] for x in leaves if x['field_path'] in required},'source_content_chars':len(str(card.get('content',''))),'source_content_parse_status':source_parse_status(str(card.get('content',''))),'source_missing_tail':'UNKNOWN_NOT_RECONSTRUCTED' if source_parse_status(str(card.get('content','')))!='COMPLETE_JSON' else 'NONE','necessary_field_selection_basis':necessary_basis,'positive_check':eid in positive})
  save(root,'private_evidence_excerpts/'+cid+'_field_checks.json',details)
  table(root,'04_reference_evidence_lifecycle_private.csv',life);table(root,'05_missing_reference_evidence_36_private.csv',missing);table(root,'03_successful_logical_message_ledger.csv',ledger)
  bm=official['best_matches'];cm=official['ceaf_matches'];by_pred={x['pred_index']:x for x in bm};by_gold={x['gold_index']:x for x in bm};ce_pred={x['pred_index']:x for x in cm};ce_gold={x['gold_index']:x for x in cm};lifemap={x['evidence_id']:x for x in case_rows}
  selected_examples=sorted([s['step_id'] for i,s in enumerate(gs) if i not in by_gold])[:4];examples=[]
  for side,steps,matches,ce in [('prediction',ps,by_pred,ce_pred),('reference',gs,by_gold,ce_gold)]:
   for i,s in enumerate(steps):
    evs=ev.canonical_evidence_ids(s);groups=sorted({lifemap[e]['primary_fate'] for e in evs if e in lifemap});tags=[]
    for e in evs:
     if e not in lifemap:continue
     x=lifemap[e]
     if not x['in_O']:tags.append('未检索')
     if x['necessary_field_status']=='PARTIAL_OR_UNVERIFIED':tags.append('未完整展示或必要字段未知')
     if x['primary_fate']=='NEVER_USED_WITH_COMPLETE_FIELD_EXPOSURE':tags.append('完整展示但未引用')
     if x['accepted_ever_cited'] and not (x['final_step_cited'] or x['final_edge_cited']):tags.append('曾引用后消失')
     if x['final_step_cited'] or x['final_edge_cited']:tags.append('最终引用但该参考步骤未匹配' if i not in matches else '最终引用且该参考步骤匹配')
    alignment.append({'case_id':cid,'side':side,'index':i,'step_id':s['step_id'],'best_match':matches.get(i),'ceaf_match':ce.get(i),'evidence_ids':evs,'reference_lifecycle_groups':groups,'reference_coverage_tags':sorted(set(tags)) if side=='reference' else [],'matched_is_not_semantic_verdict':True,'source_sha256':sha(a/'prediction.json') if side=='prediction' else paths['ground_truth']['sha256'],'json_path':f'attack_chain[{i}]','fixed_example':side=='reference' and s['step_id'] in selected_examples})
    if side=='reference' and s['step_id'] in selected_examples:examples.append({'reference_step_id':s['step_id'],'attack_step_excerpt':str(s.get('attack_step',''))[:240],'description_excerpt':str(s.get('step_description',''))[:600],'support_ids':evs,'lifecycle_tags':sorted(set(tags)),'semantic_verdict':'NOT_IDENTIFIABLE; unmatched is not proof of wrong action'})
  save(root,'private_evidence_excerpts/'+cid+'_fixed_step_examples.json',examples)
  prededges=ev.edge_positions(pred.get('causal_edges',[]),ps);goldedges=ev.edge_positions(gt.get('causal_edges',[]),gs);mapping={m['pred_index']:m['gold_index'] for m in bm}
  both={e for e in prededges if all(i in mapping for i in e)};eligible={e for e in both if e[0]<e[1]};mapped={(mapping[x],mapping[y]) for x,y in eligible};order_tp=len(prededges&goldedges)
  ed={'case_id':cid,'original_pred_edges':len(pred.get('causal_edges',[])),'original_gold_edges':len(gt.get('causal_edges',[])),'unique_valid_pred_edges':len(prededges),'unique_valid_gold_edges':len(goldedges),'both_endpoints_matched':len(both),'excluded_unmatched_endpoint':len(prededges-both),'excluded_nonforward_pred_position':len(both-eligible),'mapped_pred_pairs':sorted(mapped),'bestmatch_TP':len(mapped&goldedges),'bestmatch_FP':len(mapped-goldedges),'bestmatch_FN':len(goldedges-mapped),'order_aligned_TP':order_tp,'order_aligned_FP':len(prededges-goldedges),'order_aligned_FN':len(goldedges-prededges),'edge_comparison_ignores_relation_and_supporting_evidence':True,'bestmatch_order_pairs':len(bm)*(len(bm)-1)//2,'ceaf_order_pairs':len(cm)*(len(cm)-1)//2,'examples':[]}
  for x,y in (sorted(eligible)[:1]+sorted(prededges-both)[:1])[:2]:ed['examples'].append({'pred_positions':[x,y],'mapped_gold_positions':[mapping.get(x),mapping.get(y)],'both_endpoints_matched':(x,y) in both,'forward_eligible':(x,y) in eligible,'mapped_pair_in_gold':(mapping.get(x),mapping.get(y)) in goldedges,'reason':'UNMATCHED_ENDPOINT' if (x,y) not in both else 'NONFORWARD_FILTER' if (x,y) not in eligible else 'MAPPED_ENDPOINT_OR_DIRECTION_DIFFERS' if (mapping[x],mapping[y]) not in goldedges else 'MATCH'})
  edges.append(ed)
  recomputed=ev.evaluate(pred,gt,inp)
  for metric,value in official['metrics'].items():
   actual=recomputed['metrics'].get(metric)
   same=actual==value or isinstance(value,(int,float)) and isinstance(actual,(int,float)) and abs(value-actual)<1e-12
   reconciliation.append({'case_id':cid,'metric':metric,'EXPECTED_saved_official':value,'ACTUAL_C14_pure_recalculation':actual,'status':'MATCH' if same else 'MISMATCH','source_sha256':sha(a/'official_evaluation.json'),'impact':'NONE' if same else 'REVIEW_REQUIRED','scope':'FROZEN_FINAL_RECONCILIATION'})
  assert recomputed['best_matches']==bm and recomputed['ceaf_matches']==cm
  for label,snap in [('pre',pre),('raw_post',post),('accepted_final',pred)]:
   if snap is None:continue
   errors=ev.validate_prediction_schema(snap)
   if errors:
    snapshot_metrics.append({'case_id':cid,'snapshot':label,'status':'NON_COMPARABLE_SCHEMA','schema_errors':errors});continue
   result=ev.evaluate(snap,gt,inp);save(root,'private_evidence_excerpts/'+cid+'_snapshot_'+label+'_evaluation.json',result)
   for m in ['n_pred_steps','bestmatch_matched_steps','bestmatch_step_f1','ceaf_aligned_steps','ceaf_step_f1','evidence_precision','evidence_recall','evidence_f1','bestmatch_edge_f1','causal_edge_f1_order_aligned','bestmatch_pairwise_order_accuracy']:
    snapshot_metrics.append({'case_id':cid,'snapshot':label,'metric':m,'value':result['metrics'][m],'status':'C14_POSTHOC_SNAPSHOT_DIAGNOSTIC','input_sha256':paths['input']['sha256'],'gold_sha256':paths['ground_truth']['sha256'],'evaluator_sha256':sha(source/'evaluate_chain_reconstruction.py'),'attribution_comparable':label=='accepted_final','metadata_note':'metadata absent preserved; attribution/retrieval excluded from snapshot comparison' if label!='accepted_final' else 'original frozen metadata retained','format_diff':'NONE'})
  summary.append({'case_id':cid,'G':len(G),'O':len(O),'G_intersect_O':len(G&O),'C_step':len(CS),'C_edge':len(CE),'C_official':len(CO),'final_reference_step_citations':len(G&CS),'final_reference_union_citations':len(G&CO),'D':len(D),'G_minus_O':len(G-O),'nonreference_step_citations':len(CS-G),'fates':dict(fates),'necessary_exposure_counts':dict(expcounts),'final_step_count':len(ps),'gold_step_count':len(gs),'best_matches':len(bm),'ceaf_matches':len(cm),'unmatched_pred_steps':len(ps)-len(bm),'unmatched_gold_steps':len(gs)-len(bm),'reference_support_reuse_extra':sum(len(ev.canonical_evidence_ids(s)) for s in gs)-len(G),'positive_checks':positive,'payload_card_unique_ids':len({e for b in blocks_by_seq.values() for e in b}),'actual_full_card_unique_ids':len({e for b in blocks_by_seq.values() for e,v in b.items() if any(z['form']=='FULL_CARD' for z in v)}),'source_incomplete_content_D_count':sum(x['in_D'] and x['source_content_parse_status']!='COMPLETE_JSON' for x in case_rows),'source_header_only_D_count':sum(x['in_D'] and x['source_header_only'] for x in case_rows),'reflection_seq':rseq,'new_cli_calls':sum(x['new_cli_or_replay']=='NEW_CLI' for x in ledger if x['case_id']==cid),'logical_messages':len(requests),'phase_counts':dict(collections.Counter(x['q']['phase'] for x in requests))})
  save(root,'analysis_progress.json',{'completed_cases':[x['case_id'] for x in summary],'reference_rows':len(life),'D_rows':len(missing),'new_research_model_calls':0})
  print(cid,'COMPLETE',len(G),len(D),dict(fates),flush=True)
 table(root,'02_official_metric_reconciliation.csv',reconciliation);table(root,'06_casewise_fate_summary.csv',summary);table(root,'07_step_alignment_and_reference_coverage_private.csv',alignment);table(root,'08_reflection_changes_private.csv',reflection_rows);table(root,'09_snapshot_metric_comparison.csv',snapshot_metrics)
 save(root,'edge_diagnosis_private.json',edges);save(root,'casewise_summary.json',summary);save(root,'source_dependencies_private.json',frozen);save(root,'reflection_summary_private.json',reflection_rows)
 save(root,'analysis_execution_receipt.json',{'version':VERSION,'source_commit':'SOURCE_COMMIT_UNVERIFIABLE_COPY','gold_access':'AUTHORIZED_POSTHOC_READ_IN_PLACE','new_model_calls':0,'reference_rows':len(life),'focus_rows':len(missing),'pred_step_rows':sum(x['side']=='prediction' for x in alignment),'gold_step_rows':sum(x['side']=='reference' for x in alignment),'metric_reconciliation_mismatches':[x for x in reconciliation if x['status']!='MATCH'],'evaluator_sha256':sha(source/'evaluate_chain_reconstruction.py'),'script_sha256':sha(Path(__file__)),'future_experiment_executed':False})

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();run(read(a.config),a.out)
