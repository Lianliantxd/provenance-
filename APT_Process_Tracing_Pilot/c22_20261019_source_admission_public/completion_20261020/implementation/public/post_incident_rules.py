"""Reference-independent post-incident identity and temporal rules."""
import datetime
import hashlib
import json
from session_identity_rules import parse_context,valid_guid,pid_number,windows_path,process_creation_match

def utc(value, declared_utc=False):
    if not value:return None
    try:d=datetime.datetime.fromisoformat(str(value).replace('Z','+00:00'))
    except (TypeError,ValueError):return None
    if d.tzinfo is None:
        if not declared_utc:return None
        d=d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc)

def native_time(e: dict) -> dict:
    provider=e.get('SourceName',e.get('ProviderName'))
    field=None;d=None
    if provider=='Microsoft-Windows-Sysmon' and e.get('UtcTime'):
        field='UtcTime';d=utc(e[field],True)
    else:
        for k in ['SystemTime','TimeCreated','EventTime']:
            if e.get(k) is not None:
                field=k;d=utc(e[k]);break
    raw=e.get(field) if field else None
    # No ingestion timestamp fallback and no clock fitting.
    return {'field':field,'raw':raw,'utc':d.isoformat() if d else None,
            'timezone_status':'NATIVE_UTC_BY_PROVIDER_SEMANTICS' if d and field=='UtcTime' else 'EXPLICIT_OFFSET' if d else 'NATIVE_TIMEZONE_UNRESOLVED',
            'precision':'SUBSECOND' if raw and '.' in str(raw).split(' ')[-1] else 'SECOND_OR_UNKNOWN',
            'collection_time':e.get('@timestamp'),'collection_role':'COLLECTION_ONLY_NOT_EVENT_TIME'}

def time_relation(t: dict, lower: str, cutoff: str) -> str:
    d=utc(t.get('utc'));a=utc(lower);b=utc(cutoff)
    if d is None:return 'NATIVE_TIMEZONE_UNRESOLVED'
    if d<a:return 'BEFORE_WINDOW'
    if d>b:return 'POST_B'
    if d==b or t.get('precision')!='SUBSECOND' and d.replace(microsecond=0)==b.replace(microsecond=0):return 'SAME_SECOND_ORDER_UNRESOLVED'
    return 'NATIVE_PRE_B'

def context(e: dict) -> dict:
    if isinstance(e.get('ContextInfo'),str):return parse_context(e['ContextInfo'],'$.ContextInfo')
    if isinstance(e.get('MessageDetails'),str):return parse_context(e['MessageDetails'],'$.MessageDetails')
    msg=e.get('Message')
    if not isinstance(msg,str):return {'status':'UNPARSED','fields':{}}
    pos=msg.find('Details:')
    return parse_context(msg[pos+len('Details:'):] if pos>=0 else msg,'$.Message Details section' if pos>=0 else '$.Message explicit context lines')

def host(e: dict) -> str:return str(e.get('Hostname',e.get('Computer',''))).casefold()
def eid(e: dict) -> int:return int(e.get('EventID',0))
def provider(e: dict) -> str:return str(e.get('SourceName',e.get('ProviderName','')))

def build_candidates(records: list, config: dict) -> list:
    # Receives no B parent identity and no reference. Native target locators already frozen.
    ps=[];processes=[];audits=[];ends=[]
    for r in records:
        e=r['event']
        if host(e)!=config['host'].casefold():continue
        if provider(e)=='Microsoft-Windows-Sysmon' and eid(e)==1:processes.append(r)
        if provider(e)=='Microsoft-Windows-Sysmon' and eid(e)==5:ends.append(r)
        if provider(e)=='Microsoft-Windows-Security-Auditing' and eid(e)==4688:audits.append(r)
        if provider(e) in ['PowerShell','Microsoft-Windows-PowerShell']:
            c=context(e);f=c.get('fields',{})
            if c.get('status')=='PARSED_EXPLICIT_CONTEXT_LINES' and valid_guid(f.get('runspaceid',{}).get('value')):
                ps.append({**r,'context':c})
    groups={}
    for r in ps:
        f=r['context']['fields'];rid=valid_guid(f['runspaceid']['value']);hid=valid_guid(f.get('hostid',{}).get('value'))
        k=(host(r['event']),hid,rid)
        if not hid:k=k+(r['idx'],) # missing identity does not collapse unrelated records
        groups.setdefault(k,[]).append(r)
    out=[]
    for k,evs in sorted(groups.items(),key=lambda x:str(x[0])):
        possible={};binding_evidence=[]
        for r in evs:
            e=r['event'];f=r['context']['fields'];emitter=pid_number(e.get('ExecutionProcessID'))
            # 400/403 may report logger PID zero. Only native module emittingPID is receiver evidence.
            if provider(e)!='Microsoft-Windows-PowerShell' or eid(e)!=4103 or not emitter:continue
            if f.get('hostname',{}).get('value')!='ServerRemoteHost':continue
            command=f.get('hostapplication',{}).get('value')
            for p in processes:
                pe=p['event'];guid=valid_guid(pe.get('ProcessGuid'))
                if not guid or emitter!=pid_number(pe.get('ProcessId')) or not command or windows_path(command)!=windows_path(pe.get('CommandLine')):continue
                # Independent audit identity corroboration; absent target logon does not substitute creator token.
                audit_matches=[a['idx'] for a in audits if process_creation_match(pe,a['event'])]
                if not audit_matches:continue
                term=[z for z in ends if host(z['event'])==host(pe) and valid_guid(z['event'].get('ProcessGuid'))==guid]
                pt=native_time(pe);endtimes=[native_time(z['event']) for z in term]
                contradiction=any(utc(t['utc']) and utc(pt['utc']) and utc(t['utc'])<utc(pt['utc']) for t in endtimes)
                if contradiction:continue
                possible[guid]={'guid':guid,'pid':pid_number(pe.get('ProcessId')),'creation_idx':p['idx'],'creation_time':pt,'termination':[{ 'idx':z['idx'],'time':native_time(z['event'])} for z in term],'audit_corrob_indices':audit_matches,'lifecycle_identity':'NATIVE_GUID_ANCHORED_OBSERVED_PROCESS_LIFETIME','historical_creation_relation':time_relation(pt,config['historical_lower'],config['T_B'])}
                binding_evidence.append({'module_idx':r['idx'],'process_idx':p['idx'],'audit_indices':audit_matches,'rule':'EXPLICIT_NATIVE_MODULE_PID_AND_HOSTAPPLICATION_AND_AUDIT_IDENTITY','use':'POSTHOC_IDENTITY_CORROBORATION'})
        # Multiple compatible native lifecycles are not arbitrarily selected.
        receiver=next(iter(possible.values())) if len(possible)==1 else None
        times=[{'idx':r['idx'],**native_time(r['event']),'relation':time_relation(native_time(r['event']),config['historical_lower'],config['T_B'])} for r in evs]
        engine_start=[];engine_stop=[]
        for r in evs:
            f=r['context']['fields'];seq=pid_number(f.get('sequencenumber',{}).get('value'))
            if eid(r['event'])==400:engine_start.append({'idx':r['idx'],'sequence':seq})
            if eid(r['event'])==403:engine_stop.append({'idx':r['idx'],'sequence':seq})
        full_identity=bool(receiver and k[1] and k[2])
        # Runspace itself must have independently comparable preB remote execution evidence.
        pre_modules=[r['idx'] for r in evs if provider(r['event'])=='Microsoft-Windows-PowerShell' and eid(r['event'])==4103 and r['idx'] in [b['module_idx'] for b in binding_evidence] and time_relation(native_time(r['event']),config['historical_lower'],config['T_B'])=='NATIVE_PRE_B']
        historical=bool(full_identity and pre_modules and receiver['historical_creation_relation']=='NATIVE_PRE_B')
        temporal='HISTORICAL_CAUSAL_PREDECESSOR_ELIGIBLE' if historical else 'HISTORICAL_ORIGIN_TIME_UNRESOLVED'
        identity={'host':k[0],'receiverProcessGuid':receiver['guid'] if receiver else None,'HostId':k[1],'RunspaceId':k[2]}
        anon='C_'+hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:16]
        out.append({'candidate_id':anon,'universe_status':'PARTIAL_UNIVERSE','identity':identity,'identity_complete':full_identity,'candidate_class':'FULL_RUNSPACE_INSTANCE' if historical else 'POSTHOC_CONTEXT_ONLY' if full_identity else 'PARTIAL_RUNSPACE_INSTANCE','observed_original_indices':sorted(r['idx'] for r in evs),'context_field_provenance':[{'idx':r['idx'],'parsed_context':r['context']} for r in evs],'possible_receiver_lifecycles':list(possible.values()),'receiver':receiver,'identity_binding_evidence':binding_evidence,'engine_lifecycle':{'starts':engine_start,'stops':engine_stop,'sequence_scope':'SAME_HOST_HOSTID_RUNSPACEID_ONLY_NOT_CROSS_PROVIDER_TIME'},'native_times':times,'post_incident_identity_eligibility':full_identity,'historical_causal_eligibility':historical,'historical_grade':temporal,'post_B_only_known':bool(times and all(t['relation']=='POST_B' for t in times)),'requires_post_B_identity_evidence':any(utc(t['collection_time']) and utc(t['collection_time'])>utc(config['T_B']) for t in times),'dedupe_rule':'host+nativeHostId+nativeRunspaceId; receiver ambiguity preserved without PID merge','unknowns':[] if historical else ['NATIVE_TIMEZONE_OR_RUNSPACE_PRE_B_CONTROL_UNRESOLVED'],'competitor_label':'UNLABELED_COMPETITOR'})
    return out

def baseline(b: dict, candidates: list, coverage_complete: bool, identity_scope_complete: bool) -> dict:
    """Posthoc equality is reported, but never automatically graded as historical success."""
    parent=valid_guid(b.get('ParentProcessGuid'));h=host(b);bt=utc(native_time(b).get('utc'))
    def lifecycle_compatible(c: dict) -> bool:
        r=c.get('receiver')
        if not c.get('identity_complete') or not r:return False
        start=utc(r.get('creation_time',{}).get('utc'))
        if bt and start and start>bt:return False
        for end in r.get('termination',[]):
            et=utc(end.get('time',{}).get('utc'))
            if bt and et and et<bt:return False
        return not r.get('temporal_contradiction',False)
    valid=[c for c in candidates if c['identity']['host']==h and lifecycle_compatible(c)]
    matches=[c['candidate_id'] for c in valid if parent and c['identity']['receiverProcessGuid']==parent]
    historical=[c['candidate_id'] for c in valid if c.get('historical_causal_eligibility')]
    n=len(matches);result='NO_DIRECT_IDENTITY_MATCH' if n==0 else 'UNIQUE_DIRECT_IDENTITY_MATCH' if n==1 else 'MULTIPLE_DIRECT_IDENTITY_MATCHES'
    historical_all=bool(valid and len(historical)==len(candidates))
    eligible=bool(coverage_complete and identity_scope_complete and historical_all)
    return {'baseline_name':'B_DIRECT_PARENT_SESSION_JOIN','candidate_count':len(candidates),'full_native_identity_count':sum(bool(c.get('identity_complete')) for c in candidates),'partial_identity_count':sum(not c.get('identity_complete') for c in candidates),'identity_compatible_candidate_count':len(valid),'historical_eligible_candidate_count':len(historical),'matched_candidate_ids':matches,'identity_join_match_count':n,'join_result':result,'evaluation_state':'ELIGIBLE_FOR_INDEPENDENT_REFERENCE_CHECK' if eligible else 'BASELINE_NOT_EVALUABLE','raw_coverage_complete':coverage_complete,'frozen_scope_identity_resolution_complete':identity_scope_complete,'whole_scenario_recall_claim':False,'all_candidates_historically_qualified':historical_all,'multiple_identity_matches':n>1,'identity_match_is_historical_source_success':False,'source_metrics_generated':False,'path_metrics_generated':False}

def difficulty(baseline_result: dict, reference_match: bool) -> str:
    if baseline_result['evaluation_state']=='BASELINE_NOT_EVALUABLE':return 'DATA_OR_TEMPORAL_ELIGIBILITY_UNRESOLVED'
    if baseline_result['identity_join_match_count']==1 and reference_match:return 'DIRECT_PARENT_JOIN_SOLVES_CASE_NO_MULTIHOP_INNOVATION'
    if baseline_result['identity_join_match_count']>1:return 'DIRECT_PARENT_JOIN_AMBIGUOUS_NOT_INNOVATION_PROOF'
    return 'NO_CONFIRMED_SOLUTION'
