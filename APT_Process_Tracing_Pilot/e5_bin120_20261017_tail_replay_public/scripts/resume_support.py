"""Bounded forward replay and read-only composition with a frozen prefix index."""
from __future__ import annotations
import collections,json,time
from pathlib import Path

def replay_to_anchor(stream, sync: bytes, config: dict, root: Path) -> dict:
    target=config['resume_header_offset']
    if not isinstance(target,int) or target<stream.delivered+16:raise ValueError('INVALID_REPLAY_ANCHOR')
    start=stream.delivered;rolling=b''
    while stream.delivered<target:
        n=min(1048576,target-stream.delivered);data=stream.read(n)
        if len(data)!=n:raise EOFError('EOF_DURING_FORWARD_PREFIX_REPLAY')
        rolling=(rolling+data)[-16:]
    if rolling!=sync:raise ValueError('FROZEN_PREFIX_END_SYNC_ANCHOR_MISMATCH')
    value={'sequential_gzip_replay_from_start':True,'no_compressed_random_seek':True,'target_uncompressed_block_header_offset':target,'delivered_prefix_bytes_including_header':stream.delivered,'discarded_replay_payload_bytes':target-start,'preceding_sync_matches_current_embedded_sync':True,'replayed_prefix_top_level_CDM_decode_attempts':0,'resume_global_record_ordinal':config['resume_record_ordinal'],'resume_global_block_ordinal':config['resume_block_ordinal'],'source_and_prefix_index_sha256_verified_before_run':True,'old_decoder_state_not_claimed_restored':True}
    with (root/'03_forward_replay_anchor.json').open('x') as f:json.dump(value,f,indent=2);f.write(chr(10))
    return value

def row_core(row: dict) -> dict:
    d=row.get('datum') or {}
    return {'kind':d.get('_record_type'),'uuid':d.get('uuid'),'host':row.get('hostId'),**{k:d.get(k) for k in ('timestampNanos','type','subject','predicateObject','predicateObject2')}}

def validate_first_row(row: dict, anchor: dict) -> None:
    if row_core(row)!=anchor['record_core']:raise ValueError('REDECODED_BOUNDARY_RECORD_DIFFERS_FROM_FROZEN_INDEX')

def attach_prefix_views(db, config: dict) -> None:
    path=Path(config['prefix_index_path'])
    for p in [path,*path.parents]:
        if p.is_symlink():raise ValueError('PREFIX_INDEX_SYMLINK')
    db.execute('ATTACH DATABASE ? AS prefix',(path.as_uri()+'?mode=ro&immutable=1',))
    db.execute('PRAGMA prefix.mmap_size=0');db.execute('PRAGMA prefix.cache_size=-32768')
    n=config['resume_record_ordinal'];b=config['resume_block_ordinal']
    if not isinstance(n,int) or not isinstance(b,int) or min(n,b)<1:raise ValueError('INVALID_ORDINAL_SCOPE')
    for table in ('events','entities','hint_matches'):
        # Only fixed identifiers and validated integer bounds enter this DDL.
        db.execute('CREATE TEMP VIEW '+table+' AS SELECT * FROM prefix.'+table+' WHERE ord<'+str(n)+' UNION ALL SELECT * FROM main.'+table)
    db.execute('CREATE TEMP VIEW blocks AS SELECT * FROM prefix.blocks WHERE block<'+str(b)+' AND sync_valid=1 UNION ALL SELECT * FROM main.blocks')
    db.execute('CREATE TEMP TABLE overlap_coverage(host TEXT,bucket_ns INTEGER,event_type TEXT,n INTEGER)')
    event=config['resume_anchor'].get('overlap_event')
    if event and isinstance(event['ns'],int):db.execute('INSERT INTO overlap_coverage VALUES(?,?,?,-1)',(event['host'],event['ns']//300000000000*300000000000,event['event_type']))
    db.execute('CREATE TEMP VIEW coverage AS SELECT host,bucket_ns,event_type,sum(n) n FROM (SELECT * FROM prefix.coverage UNION ALL SELECT * FROM main.coverage UNION ALL SELECT * FROM overlap_coverage) GROUP BY host,bucket_ns,event_type HAVING sum(n)>0')
    db.commit()

def install_query_progress(budget, root: Path, stats: dict, write_json, rss) -> None:
    last=[0.]
    def hook(now: float) -> None:
        if now-last[0]<60:return
        last[0]=now
        value={'pid':stats['process_identity']['pid'],'phase':'INDEX_QUALIFICATION_READ_ONLY_PREFIX_PLUS_TAIL','combined_record_cursor':stats['record_count'],'new_tail_decode_attempts':stats['record_decode_attempts'],'expanded_bytes_delivered':stats['expanded_bytes_delivered'],'file_eof_reached':stats['file_eof_reached'],'active_seconds':now-budget.start,'peak_rss_bytes':rss(),'remaining_active_seconds':max(0,budget.config['seconds']-(now-budget.start))}
        write_json(root/'query_progress.json',value,replace=True)
        print(json.dumps(value),flush=True)
    budget.progress_hook=hook

def merge_prior_stats(s: dict, prior: dict, config: dict) -> None:
    s['aggregation_scope']='VERIFIED_PREFIX_REUSED_PLUS_REDECODED_BOUNDARY_AND_TAIL'
    s['old_prefix_index_opened_read_only']=True
    s['prior_unvalidated_record_excluded_from_prefix_views']=config['resume_record_ordinal']
    s['additional_unique_record_positions_this_run']=max(0,s['record_count']-prior['record_count'])
    if not s.get('first_redecoded_anchor_record_matches_frozen_index'):
        s['combined_aggregate_status']='NOT_MERGED_NO_SUCCESSFUL_BOUNDARY_REDECODE';return
    anchor=config['resume_anchor'];core=anchor['record_core'];event=anchor.get('overlap_event')
    for key in ('record_types','event_types','cdm_versions','host_ids_all_records','timestamp_counts'):
        combined=collections.Counter(prior[key]);combined.update(s[key]);s[key]=combined
    s['record_types'][core['kind']]-=1;s['host_ids_all_records'][core['host']]-=1
    s['cdm_versions'][anchor['CDMVersion']]-=1
    if event:
        s['event_types'][event['event_type']]-=1;s['timestamp_counts']['event_total']-=1
        s['timestamp_counts']['integer_timestamp' if isinstance(event['ns'],int) else 'missing_or_noninteger_timestamp']-=1
    fields={}
    for key in prior['path_field_availability']:
        c=collections.Counter(prior['path_field_availability'][key]);c.update(s['path_field_availability'][key])
        if event:
            value=event['path' if key=='predicateObjectPath' else 'path2'];c['null' if value is None else 'empty_string' if value=='' else 'nonempty_string']-=1
        fields[key]=c
    s['path_field_availability']=fields
    ranges={}
    for host in set(prior['host_event_ranges'])|set(s['host_event_ranges']):
        a=prior['host_event_ranges'].get(host);b=s['host_event_ranges'].get(host)
        if not a:ranges[host]=b;continue
        if not b:ranges[host]=dict(a);continue
        h=dict(b);overlap=bool(event and event['host']==host)
        h['event_count']=a['event_count']+b['event_count']-int(overlap)
        h['valid_timestamp_count']=a['valid_timestamp_count']+b['valid_timestamp_count']-int(overlap and isinstance(event['ns'],int))
        h['first_event_ns']=a['first_event_ns'];h['last_event_ns']=b['last_event_ns']
        h['min_ns']=min(v for v in (a['min_ns'],b['min_ns']) if v is not None)
        h['max_ns']=max(v for v in (a['max_ns'],b['max_ns']) if v is not None)
        for key in ('time_regressions_in_read_order','time_ties_in_read_order'):h[key]=a[key]+b[key]
        if not overlap and a['last_event_ns'] is not None and b['first_event_ns'] is not None:
            h['time_regressions_in_read_order']+=int(b['first_event_ns']<a['last_event_ns'])
            h['time_ties_in_read_order']+=int(b['first_event_ns']==a['last_event_ns'])
        h['duplicate_event_identity_conflicts']=None
        ranges[host]=h
    for h in ranges.values():h['duplicate_event_identity_conflicts']=None
    s['host_event_ranges']=ranges
    s['combined_aggregate_status']='MERGED_WITH_ONE_REDECODED_BOUNDARY_RECORD_DEDUPLICATED_BY_SOURCE_POSITION'

def uuid_duplicate_stats(db, config: dict, budget) -> dict:
    """Merge two UUID-ordered index cursors; bounded memory per UUID group."""
    import heapq
    n=int(config['resume_record_ordinal'])
    fields='uuid,host,ns,event_type,subject,obj,obj2'
    left=db.execute('SELECT '+fields+' FROM prefix.events WHERE uuid IS NOT NULL AND ord<? ORDER BY uuid',(n,))
    right=db.execute('SELECT '+fields+' FROM main.events WHERE uuid IS NOT NULL ORDER BY uuid')
    groups=extra=conflicts=0;last=None;count=0;fingerprint=None;different=False;total=0
    for row in heapq.merge(left,right,key=lambda row:row[0]):
        total+=1
        if total%10000==0:budget.check()
        if row[0]!=last:
            if count>1:groups+=1;extra+=count-1;conflicts+=int(different)
            last=row[0];count=0;fingerprint=row[1:];different=False
        count+=1;different=different or row[1:]!=fingerprint
    if count>1:groups+=1;extra+=count-1;conflicts+=int(different)
    return {'duplicate_event_uuid_groups':groups,'additional_event_positions_with_repeated_uuid':extra,'event_uuid_identity_conflict_groups':conflicts,'duplicate_statistics_method':'Streaming merge of two physical UUID indexes, excluding the overlapping old position; no whole-member Python UUID set or unbounded SQL DISTINCT fingerprint store.'}
