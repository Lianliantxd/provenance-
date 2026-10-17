"""One authorized, serial CDM scan with a private, position-preserving SQLite index."""
from __future__ import annotations
import argparse,collections,csv,hashlib,json,os,resource,shutil,signal,sqlite3,stat,sys,time,zlib
from pathlib import Path
import bounded_probe as util
import stream_cdm20_guarded as reader

class LimitStop(Exception): pass
class ContainerError(ValueError): pass

def write_json(path: Path, value: object, replace: bool=False) -> None:
    util.safe_path(path)
    text=json.dumps(value,ensure_ascii=False,indent=2)+chr(10)
    if replace:
        tmp=path.with_name(path.name+'.pending')
        with tmp.open('x') as f:f.write(text)
        tmp.chmod(0o600);os.replace(tmp,path)
    else:
        with path.open('x') as f:f.write(text)
        path.chmod(0o600)

def disk_bytes(root: Path) -> int:
    total=0
    for p in root.rglob('*'):
        if p.is_symlink():raise ContainerError('SYMLINK_IN_RUN')
        if p.is_file():total+=p.stat().st_size
    return total

class Budget:
    def __init__(self, root: Path, config: dict):
        self.root,self.config=root,config
        self.start=time.monotonic();self.last=0.;self.output=0;self.free=0;self.stopping=False
    def check(self, force: bool=False) -> None:
        if self.stopping:return
        now=time.monotonic()
        if now-self.start>=self.config['seconds']:raise LimitStop('ACTIVE_WALL_CLOCK_LIMIT')
        if force or now-self.last>=0.5:
            self.last=now
            if util.rss_bytes()>self.config['memory_bytes']:raise LimitStop('MEMORY_LIMIT')
            self.output=disk_bytes(self.root);self.free=shutil.disk_usage(self.root).free
            if self.output>=self.config['output_bytes']-self.config['database_reserve_bytes']:raise LimitStop('OUTPUT_RESERVE_LIMIT')
            if self.free<self.config['minimum_free_bytes']:raise LimitStop('MINIMUM_DISK_FREE_LIMIT')
    def sql_check(self) -> int:
        try:self.check();return 0
        except LimitStop as exc:self.sql_stop=str(exc);return 1

class StrictSingleGzip:
    """zlib gzip wrapper validates CRC/ISIZE; reject trailing bytes or a second member.

    Internal expanded chunks are at most 64 KiB. Only outer DeliveredGzip counts
    bytes delivered to the Avro reader, not internal generated/read-ahead bytes.
    """
    def __init__(self, raw, check):
        self.raw,self.check=raw,check;self.z=zlib.decompressobj(31)
        self.pending=b'';self.buffer=b'';self.eof=False
    def read(self,n: int) -> bytes:
        if n<0 or n>16*1024*1024:raise reader.AllocationGuard('GZIP_READ_ALLOCATION_GUARD')
        result=bytearray()
        while len(result)<n:
            self.check()
            if self.buffer:
                take=min(n-len(result),len(self.buffer));result.extend(self.buffer[:take]);self.buffer=self.buffer[take:];continue
            if self.eof:break
            data=self.pending or self.raw.read(65536);self.pending=b''
            if not data:raise EOFError('TRUNCATED_GZIP_BEFORE_TRAILER')
            self.buffer=self.z.decompress(data,65536)
            self.pending=self.z.unconsumed_tail
            if self.z.eof:
                if self.z.unused_data or self.pending or self.raw.read(1):raise ContainerError('EXTRA_GZIP_MEMBER_OR_TRAILING_CONTENT')
                self.eof=True
        return bytes(result)

DDL='''
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE blocks(block INTEGER PRIMARY KEY,header_offset INTEGER,declared_records INTEGER,declared_bytes INTEGER,read_records INTEGER,sync_valid INTEGER,start_ord INTEGER,end_ord INTEGER,min_ns INTEGER,max_ns INTEGER);
CREATE TABLE entities(ord INTEGER PRIMARY KEY,block INTEGER,inblock INTEGER,host TEXT,kind TEXT,uuid TEXT,parent TEXT,raw_fields TEXT);
CREATE INDEX entity_scope ON entities(host,kind,uuid,ord);
CREATE INDEX entity_uuid ON entities(uuid,host,kind);
CREATE TABLE events(ord INTEGER PRIMARY KEY,block INTEGER,inblock INTEGER,offset_in_block INTEGER,uuid TEXT,host TEXT,ns INTEGER,event_type TEXT,subject TEXT,obj TEXT,obj2 TEXT,path TEXT,path2 TEXT);
CREATE INDEX event_subject ON events(subject,host);
CREATE INDEX event_object ON events(obj,host);
CREATE INDEX event_object2 ON events(obj2,host);
CREATE INDEX event_uuid ON events(uuid,host);
CREATE TABLE coverage(host TEXT,bucket_ns INTEGER,event_type TEXT,n INTEGER,PRIMARY KEY(host,bucket_ns,event_type));
CREATE TABLE hint_matches(ord INTEGER,role TEXT,hint_uuid TEXT,PRIMARY KEY(ord,role,hint_uuid));
CREATE TABLE commits(id INTEGER PRIMARY KEY,committed_ord INTEGER,validated_block INTEGER,expanded_bytes INTEGER,elapsed_seconds REAL);
'''

def open_index(path: Path, config: dict) -> sqlite3.Connection:
    util.safe_path(path)
    with path.open('xb'):pass
    path.chmod(0o600)
    db=sqlite3.connect(path)
    db.enable_load_extension(False)
    db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA temp_store=MEMORY');db.execute('PRAGMA cache_size=-32768')
    db.execute('PRAGMA mmap_size=0');db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA max_page_count='+str(max(64,(config['output_bytes']-2*config['database_reserve_bytes'])//4096)))
    db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,32*1024*1024) if hasattr(db,'setlimit') else None
    db.executescript(DDL);return db

def fingerprint_stats(s: dict) -> dict:
    return {k:s[k] for k in ('record_count','record_types','event_types','host_ids_all_records','host_event_ranges','last_complete_record')}

def run_scan(input_path: Path, root: Path, config: dict, intake: dict, seeds: dict, expected: dict | None=None) -> dict:
    budget=Budget(root,config);budget.check(True)
    if budget.free<config['start_free_bytes']:raise LimitStop('START_DISK_FREE_BELOW_REQUIRED')
    db=open_index(root/'index/member_index.sqlite',config);db.set_progress_handler(budget.sql_check,10000)
    db.execute('INSERT INTO meta VALUES(?,?)',('source_sha256',intake['actual_sha256']))
    db.execute('INSERT INTO meta VALUES(?,?)',('schema_version','1: source file SHA in meta + ord keys; all definitions versioned'))
    objects={seeds['published_object_hint']['normalized_fixed16_hex']} if seeds else set()
    subjects={v['normalized_fixed16_hex'] for v in seeds.get('nginx_subject_hints',[])}
    s={'record_count':0,'record_decode_attempts':0,'record_types':collections.Counter(),'event_types':collections.Counter(),'cdm_versions':collections.Counter(),'host_ids_all_records':collections.Counter(),'host_event_ranges':{},'path_field_availability':{k:collections.Counter() for k in ('predicateObjectPath','predicateObject2Path')},'timestamp_counts':collections.Counter(),'block_count_started':0,'block_count_fully_validated':0,'last_complete_record':None,'partial_record_start':None,'file_eof_reached':False,'gzip_crc_status':'NOT_VERIFIED_TO_EOF','parse_anomalies':[],'B':'B_UNRESOLVED','index_committed_through_record':0,'source_identity_before':util.identity(input_path.stat()),'limits':config,'candidate_export_truncated':False}
    s['process_identity']={'pid':os.getpid(),'linux_start_ticks':Path('/proc/self/stat').read_text().split(') ',1)[1].split()[19] if Path('/proc/self/stat').exists() else None}
    last_progress=budget.start;last_commit_ord=0;txn_bytes=0;current=None;block=None;stream=None;gzip_stream=None;raw=None;prefix_saved=False
    def snapshot() -> dict:
        v=json.loads(json.dumps(s))
        for h in v['host_event_ranges'].values():
            for key in ('min','max','first_event','last_event'):h[key+'_utc']=util.utc(h[key+'_ns']) if v.get('timestamp_units_verified') else None
            h['host_mapping_status']='HOST_NAME_UNRESOLVED_IN_READ_SCOPE'
        return v
    def commit(progress: bool=False) -> None:
        nonlocal last_commit_ord,txn_bytes,last_progress
        db.execute('INSERT INTO commits(committed_ord,validated_block,expanded_bytes,elapsed_seconds) VALUES(?,?,?,?)',(s['record_count'],s['block_count_fully_validated'],stream.delivered if stream else 0,time.monotonic()-budget.start))
        db.commit();last_commit_ord=s['record_count'];s['index_committed_through_record']=last_commit_ord;txn_bytes=0
        if progress:
            budget.check(True)
            p={'pid':os.getpid(),'process_start_identity':s.get('process_identity'),'records_completed':s['record_count'],'records_decode_attempts':s['record_decode_attempts'],'index_committed_through_record':last_commit_ord,'blocks_validated':s['block_count_fully_validated'],'current_record':current,'expanded_bytes_delivered':stream.delivered if stream else 0,'active_seconds':time.monotonic()-budget.start,'peak_rss_bytes':util.rss_bytes(),'output_bytes':budget.output,'free_bytes':budget.free,'remaining_active_seconds':max(0,config['seconds']-(time.monotonic()-budget.start)),'remaining_expanded_bytes':config['expanded_bytes']-(stream.delivered if stream else 0),'host_ranges':snapshot()['host_event_ranges']}
            write_json(root/'progress.json',p,replace=True)
            with (root/'progress.jsonl').open('a') as f:f.write(json.dumps(p)+chr(10))
            print(json.dumps({k:v for k,v in p.items() if k not in ('host_ranges','process_start_identity')}),flush=True);last_progress=time.monotonic()
    def prefix_checkpoint() -> None:
        nonlocal prefix_saved
        actual=snapshot()
        for h in actual['host_event_ranges'].values():h.pop('previous_valid_ns',None)
        comparison={}
        if expected:
            for k in ('record_count','record_types','event_types','host_ids_all_records','host_event_ranges','last_complete_record','expanded_bytes_delivered'):
                a=stream.delivered if k=='expanded_bytes_delivered' else actual.get(k)
                comparison[k]={'expected':expected.get(k),'actual':a,'equal':expected.get(k)==a}
        write_json(root/'03_prefix_checkpoint_comparison.json',{'checkpoint_record':s['record_count'],'all_equal':all(v['equal'] for v in comparison.values()),'comparison':comparison,'continues_beyond_checkpoint':True})
        prefix_saved=True;commit(True)
        if expected and not all(v['equal'] for v in comparison.values()):raise ContainerError('PREFIX_CONSISTENCY_MISMATCH')

    old_alarm=signal.signal(signal.SIGALRM,lambda *_: (_ for _ in ()).throw(LimitStop('ACTIVE_WALL_CLOCK_LIMIT')))
    signal.setitimer(signal.ITIMER_REAL,config['seconds'])
    try:
        raw=input_path.open('rb');s['source_fd_identity_before']=util.identity(os.fstat(raw.fileno()))
        if raw.read(2)!=b'\x1f\x8b':raise ContainerError('NOT_GZIP')
        raw.seek(0);gzip_stream=StrictSingleGzip(raw,budget.check)
        stream=util.DeliveredGzip(gzip_stream,config['expanded_bytes'],budget.check)
        if reader.read_exact(stream,4)!=b'Obj\x01':raise ContainerError('NOT_AVRO_OCF')
        metadata=reader.read_map_bytes(stream);sync=reader.read_exact(stream,16);schema=json.loads(metadata['avro.schema'])
        codec=metadata.get('avro.codec',b'null').decode('utf8')
        if codec!='null':raise ContainerError('UNSUPPORTED_INNER_CODEC')
        names={};reader.collect_names(schema,names)
        short_names=collections.defaultdict(set)
        for name,node in names.items():short_names[name.rsplit('.',1)[-1]].add(id(node))
        s['ambiguous_schema_short_names']=[k for k,v in short_names.items() if len(v)>1]
        uuid_schema=names.get('UUID');s['uuid_schema']=uuid_schema
        if uuid_schema and (uuid_schema.get('type')!='fixed' or uuid_schema.get('size')!=16):raise ContainerError('UUID_SCHEMA_NOT_FIXED16')
        ts_doc=next((f.get('doc','') for f in names.get('Event',{}).get('fields',[]) if f['name']=='timestampNanos'),'')
        s.update(embedded_schema_sha256=hashlib.sha256(metadata['avro.schema']).hexdigest(),embedded_schema_namespace=schema.get('namespace'),embedded_schema_name=schema.get('name'),ocf_codec=codec,event_timestamp_schema_doc=ts_doc,timestamp_units_verified='unix epoch' in ts_doc.lower() and 'nanosecond' in ts_doc.lower())
        write_json(root/'logs/embedded_writer_schema.json',schema)
        while True:
            budget.check();offset=stream.delivered;count=reader.maybe_long(stream)
            if count is None:
                if not gzip_stream.eof:raise ContainerError('GZIP_TRAILER_NOT_VALIDATED')
                s.update(file_eof_reached=True,gzip_crc_status='VERIFIED_TO_EOF',termination_reason='MEMBER_EOF');break
            size=reader.long(stream)
            if count<0 or size<0 or size>134217728:raise ContainerError('INVALID_OR_UNSUPPORTED_BLOCK_SIZE_COUNT')
            s['block_count_started']+=1;bn=s['block_count_started'];block=util.BlockStream(stream,size);start_ord=s['record_count']+1;bmin=bmax=None;read=0
            for index in range(count):
                budget.check();current={'top_level_record_ordinal_1based':s['record_count']+1,'block_ordinal_1based':bn,'record_index_in_block_0based':index,'ocf_uncompressed_block_header_offset':offset,'uncompressed_offset_in_block':block.consumed,'locator_note':'Sequential OCF locator; not a random-access compressed-file offset'}
                s['record_decode_attempts']+=1;row=reader.decode(block,schema,names)
                d=row.get('datum') or {};kind=str(d.get('_record_type','UNKNOWN'));host=str(row.get('hostId')) if row.get('hostId') is not None else '__MISSING_HOST_ID__';uid=d.get('uuid');ordinal=s['record_count']+1
                if host not in s['host_ids_all_records'] and len(s['host_ids_all_records'])>=1024:raise LimitStop('HOST_AGGREGATE_CARDINALITY_GUARD')
                if len(s['record_types'])>1024:raise LimitStop('DATUM_TYPE_CARDINALITY_GUARD')
                if kind=='Event':
                    stamp=d.get('timestampNanos');valid=isinstance(stamp,int) and not isinstance(stamp,bool);typ=str(d.get('type'))
                    event=(ordinal,bn,index,current['uncompressed_offset_in_block'],uid,host,stamp if valid else None,typ,d.get('subject'),d.get('predicateObject'),d.get('predicateObject2'),d.get('predicateObjectPath'),d.get('predicateObject2Path'))
                    estimate=sum(len(v.encode('utf8')) if isinstance(v,str) else 8 for v in event)
                    if estimate>32*1024*1024:raise reader.AllocationGuard('INDEX_ROW_ALLOCATION_GUARD')
                    db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',event);txn_bytes+=estimate
                    s['event_types'][typ]+=1;s['timestamp_counts']['event_total']+=1;s['timestamp_counts']['integer_timestamp' if valid else 'missing_or_noninteger_timestamp']+=1
                    h=s['host_event_ranges'].setdefault(host,{'event_count':0,'valid_timestamp_count':0,'min_ns':None,'max_ns':None,'first_event_ns':stamp if valid else None,'last_event_ns':None,'previous_valid_ns':None,'time_regressions_in_read_order':0,'time_ties_in_read_order':0,'duplicate_event_identity_conflicts':0})
                    h['event_count']+=1;h['last_event_ns']=stamp if valid else None
                    if valid:
                        h['valid_timestamp_count']+=1
                        if h['previous_valid_ns'] is not None:h['time_regressions_in_read_order']+=int(stamp<h['previous_valid_ns']);h['time_ties_in_read_order']+=int(stamp==h['previous_valid_ns'])
                        h['previous_valid_ns']=stamp;h['min_ns']=stamp if h['min_ns'] is None else min(h['min_ns'],stamp);h['max_ns']=stamp if h['max_ns'] is None else max(h['max_ns'],stamp)
                        bmin=stamp if bmin is None else min(bmin,stamp);bmax=stamp if bmax is None else max(bmax,stamp)
                        bucket=(stamp//300000000000)*300000000000
                        db.execute('INSERT INTO coverage VALUES(?,?,?,1) ON CONFLICT(host,bucket_ns,event_type) DO UPDATE SET n=n+1',(host,bucket,typ))
                        if util.utc(stamp) is None:s['timestamp_counts']['integer_outside_datetime_range']+=1
                    for field,counter in s['path_field_availability'].items():
                        val=d.get(field);counter['missing' if field not in d else 'null' if val is None else 'nonempty_string' if isinstance(val,str) and val else 'empty_string' if val=='' else 'other_type']+=1
                    for field in ('subject','predicateObject','predicateObject2'):
                        value=d.get(field)
                        if value in objects|subjects:db.execute('INSERT INTO hint_matches VALUES(?,?,?)',(ordinal,field,value))
                    for field in ('predicateObjectPath','predicateObject2Path'):
                        if d.get(field)==config['object_path']:db.execute('INSERT INTO hint_matches VALUES(?,?,?)',(ordinal,field,'DIRECT_REGISTERED_PATH'))
                else:
                    payload=json.dumps(d,ensure_ascii=False,separators=(',',':'))
                    if len(payload.encode('utf8'))>32*1024*1024:raise reader.AllocationGuard('ENTITY_ROW_ALLOCATION_GUARD')
                    db.execute('INSERT INTO entities VALUES(?,?,?,?,?,?,?,?)',(ordinal,bn,index,host,kind,uid,d.get('parentSubject'),payload));txn_bytes+=len(payload.encode('utf8'))
                    for field in ('uuid','parentSubject'):
                        if d.get(field) in objects|subjects:db.execute('INSERT INTO hint_matches VALUES(?,?,?)',(ordinal,'entity.'+field,d[field]))
                s['record_count']+=1;read+=1;s['record_types'][kind]+=1;s['cdm_versions'][str(row.get('CDMVersion'))]+=1;s['host_ids_all_records'][host]+=1;s['last_complete_record']=dict(current);current=None
                if s['record_count']==config['checkpoint_records'] and not prefix_saved:
                    if index < count-1:prefix_checkpoint()
                if s['record_count']-last_commit_ord>=config['transaction_records'] or txn_bytes>=4*1024*1024:commit()
            if block.consumed!=size:raise ContainerError('BLOCK_PAYLOAD_SIZE_MISMATCH')
            if reader.read_exact(stream,16)!=sync:raise ContainerError('BLOCK_SYNC_MISMATCH')
            s['block_count_fully_validated']+=1
            db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?,?)',(bn,offset,count,size,read,1,start_ord,s['record_count'],bmin,bmax))
            if s['record_count']==config['checkpoint_records'] and not prefix_saved:prefix_checkpoint()
            if s['record_count']%config['checkpoint_records']==0 or time.monotonic()-last_progress>=config['progress_seconds']:commit(True)
        commit(True)
    except (LimitStop,util.BudgetStop) as exc:s['termination_reason']=str(exc);s['resource_limit']=True
    except reader.AllocationGuard as exc:s['termination_reason']=str(exc);s['resource_limit']=True;s['decoder_allocation_guard']=True
    except (EOFError,zlib.error,ContainerError,ValueError,sqlite3.Error,MemoryError,OSError) as exc:
        reason=getattr(budget,'sql_stop',None)
        if reason:s['termination_reason']=reason;s['resource_limit']=True
        elif isinstance(exc,sqlite3.Error) and ('full' in str(exc).lower() or 'memory' in str(exc).lower()):s['termination_reason']='SQLITE_OUTPUT_OR_MEMORY_GUARD';s['resource_limit']=True
        else:s['termination_reason']='SCAN_ERROR';s['parse_anomalies'].append({'type':type(exc).__name__,'message':str(exc)[:500],'record':current})
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        s['partial_record_start']=current
        if raw:
            s['source_fd_identity_after']=util.identity(os.fstat(raw.fileno()));raw.close()
        s['source_identity_after']=util.identity(input_path.stat());s['source_unchanged']=s['source_identity_before']==s['source_identity_after']==s.get('source_fd_identity_before')==s.get('source_fd_identity_after')
        s['expanded_bytes_delivered']=stream.delivered if stream else 0
        if not s['file_eof_reached']:
            # Complete records remain indexable, but an incomplete/invalid block is explicitly marked.
            db.set_progress_handler(None,0)
            if block is not None and s['block_count_started']>s['block_count_fully_validated']:
                try:db.execute('INSERT OR IGNORE INTO blocks VALUES(?,?,?,?,?,?,?,?,?,?)',(s['block_count_started'],offset,count,size,read,0,start_ord,s['record_count'],bmin,bmax))
                except sqlite3.Error:pass
            try:commit()
            except sqlite3.Error:db.rollback();s['index_committed_through_record']=last_commit_ord;s['uncommitted_records_not_indexed']=s['record_count']-last_commit_ord
    s['scan_seconds']=time.monotonic()-budget.start
    # Read-only index queries are inside the same active time/resource envelope.
    queries_complete=False
    try:
        db.set_progress_handler(budget.sql_check,10000);budget.check(True)
        signal.setitimer(signal.ITIMER_REAL,max(0.001,config['seconds']-(time.monotonic()-budget.start)))
        analysis=analyze_index(db,root,config,objects,subjects,budget)
        s['index_analysis']=analysis;queries_complete=True
    except (LimitStop,sqlite3.Error) as exc:
        s['index_query_stop']=getattr(budget,'sql_stop',str(exc));s['index_query_complete']=False
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old_alarm);budget.stopping=True
        db.set_progress_handler(None,0)
        s['index_query_complete']=queries_complete;s['active_scan_and_query_seconds']=time.monotonic()-budget.start
        db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',('final_record_count',str(s['index_committed_through_record'])))
        db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',('eof_validated',json.dumps(s['file_eof_reached'])))
        db.commit();db.close()
    s['peak_rss_bytes']=util.rss_bytes();s['output_bytes_after_close']=disk_bytes(root)
    s['source_compressed_sha256']=intake['actual_sha256'];s['source_compressed_size']=intake['actual_size']
    s['new_record_positions_beyond_old_prefix']=max(0,s['record_count']-250000);s['record_position_coverage']=[1,s['record_count']] if s['record_count'] else []
    s['lifetime_decode_attempts_including_previous_repeated_probes']=500000+s['record_decode_attempts']
    s['status']='FULL_MEMBER_SCANNED_B_UNRESOLVED' if s['file_eof_reached'] and not s['parse_anomalies'] and s['source_unchanged'] else 'PARTIAL_SCAN_RESOURCE_LIMIT' if s.get('resource_limit') else 'SCAN_ABORTED_WITH_PARSE_OR_INTEGRITY_ERROR'
    s['gzip_implementation']='Bounded zlib gzip wrapper CRC/ISIZE verified; exactly one member and no ignored trailing bytes'
    s['expanded_byte_accounting']='Exact outer DeliveredGzip bytes returned to the Avro reader, including writer header and sync. Internal gzip generated/read-ahead bytes are not claimed measured. No inner codec decompression.'
    s['utf8_replacement_strings']=reader.UTF8_REPLACEMENT_STRINGS
    s['semantic_matching_completeness']='INCOMPLETE_UTF8_OR_SCHEMA_AMBIGUITY' if reader.UTF8_REPLACEMENT_STRINGS or s.get('ambiguous_schema_short_names') else 'NO_UTF8_REPLACEMENTS_OR_SHORT_NAME_AMBIGUITIES_OBSERVED_NOT_A_GENERAL_SEMANTIC_PROOF'
    for h in s['host_event_ranges'].values():
        h.pop('previous_valid_ns',None)
        for k in ('min','max','first_event','last_event'):h[k+'_utc']=util.utc(h[k+'_ns']) if s.get('timestamp_units_verified') else None
        definitions=[v for v in s.get('index_analysis',{}).get('host_definitions',[]) if v['uuid']==next(k for k,val in s['host_event_ranges'].items() if val is h)]
        names_found={v['fields'].get('hostName') for v in definitions if v['fields'].get('hostName')}
        h['host_definition_versions']=definitions
        if len(names_found)==1:h['hostName']=next(iter(names_found));h['host_mapping_status']='HOST_NAME_FROM_RAW_HOST_UUID_DEFINITION'
        elif len(names_found)>1:h['host_mapping_status']='HOST_DEFINITION_NAME_CONFLICT'
        else:h['host_mapping_status']='HOST_MAPPING_UNRESOLVED_IN_MEMBER' if s['file_eof_reached'] else 'HOST_MAPPING_UNRESOLVED_IN_READ_SCOPE'
    write_json(root/'04_full_scan_summary.json',s)
    write_json(root/'progress.json',{'pid':os.getpid(),'process_state':'FINISHED','records_completed':s['record_count'],'index_committed_through_record':s['index_committed_through_record'],'status':s['status'],'expanded_bytes_delivered':s['expanded_bytes_delivered'],'file_eof_reached':s['file_eof_reached']},replace=True)
    print(json.dumps({'final_status':s['status'],'records':s['record_count'],'events':sum(s['event_types'].values()),'eof':s['file_eof_reached'],'active_seconds':s['active_scan_and_query_seconds'],'expanded_bytes':s['expanded_bytes_delivered'],'output_bytes':s['output_bytes_after_close']}),flush=True)
    return s


def analyze_index(db: sqlite3.Connection, root: Path, config: dict, objects: set, subjects: set, budget: Budget) -> dict:
    """No compressed input is read here; retain role/scope and all entity versions."""
    result={'indexed_events':db.execute('SELECT count(*) FROM events').fetchone()[0],'indexed_entities':db.execute('SELECT count(*) FROM entities').fetchone()[0],'validated_blocks':db.execute('SELECT count(*) FROM blocks WHERE sync_valid=1').fetchone()[0]}
    result['host_definitions']=[{'host':r[0],'uuid':r[1],'record_ordinal':r[2],'fields':json.loads(r[3])} for r in db.execute("SELECT host,uuid,ord,raw_fields FROM entities WHERE kind='Host'")]
    hints=[]
    for value in sorted(objects|subjects):
        role_rows=list(db.execute('SELECT h.role,count(*),count(DISTINCT h.ord),count(DISTINCT e.uuid) FROM hint_matches h LEFT JOIN events e ON e.ord=h.ord WHERE hint_uuid=? GROUP BY h.role',(value,)))
        roles={r[0]:{'total':r[1],'distinct_record_positions':r[2],'distinct_event_uuids':r[3]} for r in role_rows}
        hints.append({'uuid':value,'hint_type':'object' if value in objects else 'subject','roles':roles,'distinct_record_positions':db.execute('SELECT count(DISTINCT ord) FROM hint_matches WHERE hint_uuid=?',(value,)).fetchone()[0]})
    result['fixed_hints']=hints
    obj=next(iter(objects),None);sub=list(subjects)
    direct="(e.path=? OR e.path2=?)";params=[config['object_path']]*2
    match="("+direct+" OR e.obj=? OR e.obj2=?";params.extend([obj,obj])
    for v in sub:match+=' OR e.subject=?';params.append(v)
    # Late entity associations use only same-host definitions and explicit source fields.
    associations="EXISTS(SELECT 1 FROM entities n WHERE n.host=e.host AND n.kind='FileObject' AND (n.uuid=e.obj OR n.uuid=e.obj2) AND (json_extract(n.raw_fields,'$.baseObject.properties.path')=? OR json_extract(n.raw_fields,'$.baseObject.properties.filename')=?))"
    match+=' OR '+associations+')';params.extend([config['object_path']]*2)
    result['candidate_total']=db.execute('SELECT count(*) FROM events e WHERE '+match,params).fetchone()[0]
    result['entity_path_association_events']=db.execute('SELECT count(*) FROM events e WHERE '+associations,[config['object_path']]*2).fetchone()[0]
    result['direct_path_events']=db.execute('SELECT count(*) FROM events e WHERE '+direct,[config['object_path']]*2).fetchone()[0]
    result['object_and_subject_events']=0;result['object_and_subject_read_events']=0
    for v in sub:
        result['object_and_subject_events']+=db.execute('SELECT count(*) FROM events WHERE (obj=? OR obj2=?) AND subject=?',(obj,obj,v)).fetchone()[0]
        result['object_and_subject_read_events']+=db.execute("SELECT count(*) FROM events WHERE (obj=? OR obj2=?) AND subject=? AND event_type='EVENT_READ'",(obj,obj,v)).fetchone()[0]
    result['candidate_export_limit']=config['candidate_export_limit'];result['candidate_exported']=0
    columns=[r[1] for r in db.execute('PRAGMA table_info(events)')]
    with (root/'private_candidates/candidates.jsonl').open('x') as out:
        for row in db.execute('SELECT e.* FROM events e WHERE '+match+' ORDER BY e.ord LIMIT ?',params+[config['candidate_export_limit']]):
            budget.check();event=dict(zip(columns,row));defs={}
            for role in ('subject','obj','obj2'):
                vals=[]
                for rec in db.execute('SELECT ord,host,kind,uuid,raw_fields FROM entities WHERE host=? AND uuid=? ORDER BY ord LIMIT 17',(event['host'],event[role])):
                    vals.append({'record_ordinal':rec[0],'host':rec[1],'kind':rec[2],'uuid':rec[3],'fields':json.loads(rec[4])})
                defs[role]={'versions_retained_up_to_16':vals[:16],'definition_export_truncated':len(vals)>16,'association_only_not_time_validity_proof':True}
            event['entity_versions_in_same_host']=defs;event['B']='B_UNRESOLVED';event['reference_guided_not_independent_event_truth']=True
            line=json.dumps(event,ensure_ascii=False)+chr(10)
            if disk_bytes(root)+len(line.encode())>=config['output_bytes']-config['database_reserve_bytes']:raise LimitStop('CANDIDATE_OUTPUT_RESERVE_LIMIT')
            out.write(line);result['candidate_exported']+=1
    (root/'private_candidates/candidates.jsonl').chmod(0o600)
    result['candidate_export_truncated']=result['candidate_exported']<result['candidate_total']
    unresolved={}
    for col,kind in (('subject','Subject'),('obj',None),('obj2',None)):
        typefilter=" AND n.kind=?" if kind else ''
        args=[kind] if kind else []
        query='SELECT count(*),count(DISTINCT e.'+col+') FROM events e WHERE e.'+col+" IS NOT NULL AND NOT EXISTS(SELECT 1 FROM entities n WHERE n.host=e.host AND n.uuid=e."+col+typefilter+')'
        n,u=db.execute(query,args).fetchone();unresolved[col]={'event_reference_occurrences_unresolved_same_host':n,'distinct_uuid_strings_unresolved_same_host':u,'definition_temporal_validity_not_inferred':True}
    result['unresolved_event_references']=unresolved
    result['unresolved_entity_references']={}
    for field in ('parentSubject','localPrincipal'):
        count=db.execute("SELECT count(*) FROM entities e WHERE json_extract(e.raw_fields,?) IS NOT NULL AND NOT EXISTS(SELECT 1 FROM entities n WHERE n.host=e.host AND n.uuid=json_extract(e.raw_fields,?))",('$.'+field,'$.'+field)).fetchone()[0]
        result['unresolved_entity_references'][field]={'occurrences_not_defined_in_same_host_scope':count}

    duplicates=db.execute('SELECT count(*),coalesce(sum(n-1),0) FROM (SELECT count(*) n FROM events WHERE uuid IS NOT NULL GROUP BY uuid HAVING n>1)').fetchone()
    result['duplicate_event_uuid_groups']=duplicates[0];result['additional_event_positions_with_repeated_uuid']=duplicates[1]
    result['event_uuid_identity_conflict_groups']=db.execute("SELECT count(*) FROM (SELECT uuid FROM events WHERE uuid IS NOT NULL GROUP BY uuid HAVING count(DISTINCT coalesce(host,'')||'|'||coalesce(ns,'')||'|'||event_type||'|'||coalesce(subject,'')||'|'||coalesce(obj,'')||'|'||coalesce(obj2,''))>1)").fetchone()[0]
    result['event_uuid_conflict_fingerprint_fields']=['host','ns','event_type','subject','obj','obj2']
    result['repeated_entity_definitions_same_host_type_uuid_groups']=db.execute('SELECT count(*) FROM (SELECT host,kind,uuid FROM entities WHERE uuid IS NOT NULL GROUP BY host,kind,uuid HAVING count(*)>1)').fetchone()[0]
    with (root/'05_host_and_time_coverage.csv').open('x',newline='') as f:
        w=csv.writer(f);w.writerow(['host','utc_5minute_bucket_ns','utc_bucket_start','event_type','event_count'])
        for row in db.execute('SELECT host,bucket_ns,event_type,n FROM coverage ORDER BY host,bucket_ns,event_type'):
            budget.check();w.writerow([row[0],row[1],util.utc(row[1]),row[2],row[3]])
    write_json(root/'07_hint_match_summary.json',result)
    return result


def main() -> None:
    ap=argparse.ArgumentParser();ap.add_argument('--run-dir',type=Path,required=True);args=ap.parse_args();root=args.run_dir
    util.safe_path(root);assert root.stat().st_uid==os.getuid();os.umask(0o077)
    assert not (root/'04_full_scan_summary.json').exists()
    config=json.loads((root/'02_scan_config.json').read_text());intake=json.loads((root/'00_input_runtime_and_authorization.json').read_text())
    assert intake['authorization']['state']=='APPROVED_BY_USER' and intake['raw_integrity']['status']=='FILE_VERIFIED'
    for name,sha in json.loads((root/'02_scan_config_and_code_hashes.json').read_text())['script_sha256'].items():assert hashlib.sha256((root/'scripts'/name).read_bytes()).hexdigest()==sha
    path=Path(intake['raw_integrity']['path']);util.safe_path(path);assert util.identity(path.stat())==intake['raw_integrity']['after']
    assert not list((root/'index').iterdir()),'One scan per run; existing index forbids restart'
    seeds=json.loads((root/'01_private_reference_lookup_seeds.json').read_text()) if (root/'01_private_reference_lookup_seeds.json').exists() else {}
    expected=json.loads((root/'01_frozen_prefix_expected.json').read_text())
    os.environ['TMPDIR']=str(root/'tmp');os.environ['SQLITE_TMPDIR']=str(root/'tmp')
    soft,hard=resource.getrlimit(resource.RLIMIT_AS)
    if sys.platform.startswith('linux'):resource.setrlimit(resource.RLIMIT_AS,(min(config['memory_bytes'],hard) if hard!=-1 else config['memory_bytes'],hard))
    os.nice(10)
    write_json(root/'logs/process_runtime.json',{'pid':os.getpid(),'python':sys.executable,'version':sys.version,'sqlite':sqlite3.sqlite_version,'rlimit_as':resource.getrlimit(resource.RLIMIT_AS),'niceness':os.nice(0),'no_bytecode':os.environ.get('PYTHONDONTWRITEBYTECODE'),'memory_mode':'RLIMIT_AS_SINGLE_WORKER_PLUS_RSS_NO_CHILDREN','database_temp_store':'MEMORY inside process cap','journal_mode':'DELETE synchronous FULL','temp_directory':str(root/'tmp')})
    run_scan(path,root,config,intake['raw_integrity'],seeds,expected)

if __name__=='__main__':main()
