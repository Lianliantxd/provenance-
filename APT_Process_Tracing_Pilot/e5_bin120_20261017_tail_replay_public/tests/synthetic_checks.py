"""Synthetic fixtures only. No real member is opened by this test suite."""
from pathlib import Path
import contextlib,gzip,hashlib,io,json,os,sqlite3,sys,tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import full_member_scan as m

def av(n):
    v=(n<<1)^(n>>63);out=bytearray()
    while v>=128:out.append((v&127)|128);v>>=7
    out.append(v);return bytes(out)
def text(v):v=v.encode();return av(len(v))+v
def optional(v):return av(0) if v is None else av(1)+text(v)
def prop(path):return av(0) if path is None else av(1)+text('path')+text(path)+av(0)
fields=[{'name':'uuid','type':'string'},{'name':'parentSubject','type':['null','string']},{'name':'baseObject','type':{'type':'record','name':'BaseObject','fields':[{'name':'properties','type':{'type':'map','values':'string'}}]}}]
schema={'type':'record','name':'TCCDMDatum','namespace':'synthetic','fields':[{'name':'hostId','type':'string'},{'name':'CDMVersion','type':'string'},{'name':'datum','type':[{'type':'record','name':'Event','fields':[{'name':k,'type':'string'} for k in ('uuid','type','subject','predicateObject','predicateObject2')]+[{'name':k,'type':['null','string']} for k in ('predicateObjectPath','predicateObject2Path')]+[{'name':'timestampNanos','type':'long','doc':'Nanoseconds since the unix epoch'}]},{'type':'record','name':'FileObject','fields':fields},{'type':'record','name':'Subject','fields':[{'name':'uuid','type':'string'},{'name':'parentSubject','type':['null','string']}]},{'type':'record','name':'NetFlowObject','fields':[{'name':'uuid','type':'string'},{'name':'parentSubject','type':['null','string']}]}]}]}
sync=b'0123456789abcdef';sj=json.dumps(schema).encode();header=b'Obj\x01'+av(2)+text('avro.schema')+av(len(sj))+sj+text('avro.codec')+text('null')+av(0)+sync
def event(uid='duplicate',host='host1',sub='sub',obj='obj',path=None,stamp=1550000000000000000):
    return text(host)+text('20')+av(0)+b''.join(text(v) for v in (uid,'EVENT_READ',sub,obj,'none'))+optional(path)+optional(None)+av(stamp)
def entity(variant=1,host='host1',uid='obj',path='/synthetic/target'):
    return text(host)+text('20')+av(variant)+text(uid)+optional(None)+(prop(path) if variant==1 else b'')
def ocf(rows):payload=b''.join(rows);return header+av(len(rows))+av(len(payload))+payload+sync
seed={'published_object_hint':{'normalized_fixed16_hex':'obj'},'nginx_subject_hints':[{'normalized_fixed16_hex':'sub'}]}
config={'seconds':120,'expanded_bytes':100*1024*1024,'memory_bytes':4294967296,'output_bytes':256*1024*1024,'database_reserve_bytes':16*1024*1024,'start_free_bytes':0,'minimum_free_bytes':0,'checkpoint_records':2,'progress_seconds':60,'transaction_records':1000,'candidate_export_limit':1,'object_path':'/synthetic/target'}
results=[]
with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='continuation_fixture_') as td:
    base=Path(td);prefix=base/'prefix.sqlite'
    cfg={'seconds':60,'scan_seconds':30,'expanded_bytes':10485760,'memory_bytes':4294967296,'output_bytes':268435456,'database_reserve_bytes':16777216,'start_free_bytes':0,'minimum_free_bytes':0,'checkpoint_records':250000,'progress_seconds':60,'transaction_records':1000,'candidate_export_limit':1,'object_path':'/synthetic/target'}
    rows=[entity(variant=2,uid='sub'),event(uid='duplicate',stamp=1550000000000000001),event(uid='duplicate',stamp=1550000000000000000),entity(),entity(host='host2'),event(uid='new',stamp=1550000000000000002)]
    offsets=[];raw=header
    for row in rows:
        offsets.append(len(raw));raw+=av(1)+av(len(row))+row+sync
    packed=gzip.compress(raw,mtime=0)
    db=m.open_index(prefix,cfg)
    db.execute('INSERT INTO entities VALUES(1,1,0,?,?,?,?,?)',('host1','Subject','sub',None,json.dumps({'_record_type':'Subject','uuid':'sub','parentSubject':None})))
    for ordinal,ns in ((2,1550000000000000001),(3,1550000000000000000)):
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(ordinal,ordinal,0,0,'duplicate','host1',ns,'EVENT_READ','sub','obj','none',None,None))
    for i in range(3):db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?,?)',(i+1,offsets[i],1,len(rows[i]),1,int(i<2),i+1,i+1,None,None))
    bucket=1550000000000000000//300000000000*300000000000
    db.execute('INSERT INTO coverage VALUES(?,?,?,2)',('host1',bucket,'EVENT_READ'));db.commit();db.close();prefix_sha=hashlib.sha256(prefix.read_bytes()).hexdigest()
    prior={'record_count':3,'record_types':{'Subject':1,'Event':2},'event_types':{'EVENT_READ':2},'cdm_versions':{'20':3},'host_ids_all_records':{'host1':3},'timestamp_counts':{'event_total':2,'integer_timestamp':2},'path_field_availability':{'predicateObjectPath':{'null':2},'predicateObject2Path':{'null':2}},'host_event_ranges':{'host1':{'event_count':2,'valid_timestamp_count':2,'min_ns':1550000000000000000,'max_ns':1550000000000000001,'first_event_ns':1550000000000000001,'last_event_ns':1550000000000000000,'time_regressions_in_read_order':1,'time_ties_in_read_order':0,'duplicate_event_identity_conflicts':0}}}
    anchor={'record_core':{'kind':'Event','uuid':'duplicate','host':'host1','timestampNanos':1550000000000000000,'type':'EVENT_READ','subject':'sub','predicateObject':'obj','predicateObject2':'none'},'overlap_event':{'host':'host1','ns':1550000000000000000,'event_type':'EVENT_READ','path':None,'path2':None},'CDMVersion':'20','target_block':{'declared_records':1,'declared_bytes':len(rows[2])}}
    def run(name,override=None):
        root=base/name;root.mkdir()
        for d in ('index','logs','private_candidates','tmp'):(root/d).mkdir()
        p=root/'fixture.gz';p.write_bytes(packed)
        priorpath=root/'prior.json';priorpath.write_text(json.dumps(prior))
        c=dict(cfg,prefix_index_path=str(prefix),resume_record_ordinal=3,resume_block_ordinal=3,resume_header_offset=offsets[2],resume_anchor=anchor,prior_summary_path=str(priorpath),prior_decode_attempts=3)
        c.update(override or {})
        with contextlib.redirect_stdout(io.StringIO()):s=m.run_scan(p,root,c,{'actual_sha256':hashlib.sha256(packed).hexdigest(),'actual_size':len(packed)},seed)
        return root,s,c
    root,s,c=run('valid');a=s['index_analysis']
    assert s['file_eof_reached'] and s['record_count']==6 and s['record_decode_attempts']==4 and s['new_tail_records_completed']==4
    assert a['indexed_events']==3 and a['indexed_entities']==3 and a['validated_blocks']==6
    assert a['duplicate_event_uuid_groups']==1 and a['additional_event_positions_with_repeated_uuid']==1 and a['event_uuid_identity_conflict_groups']==1
    assert s['event_types']['EVENT_READ']==3 and sum(s['host_ids_all_records'].values())==6 and s['host_event_ranges']['host1']['time_regressions_in_read_order']==1
    assert a['candidate_total']==3 and a['candidate_export_truncated']
    with (root/'05_host_and_time_coverage.csv').open() as f:assert sum(int(r['event_count']) for r in __import__('csv').DictReader(f))==3
    assert json.loads((root/'03_forward_replay_anchor.json').read_text())['delivered_prefix_bytes_including_header']==offsets[2]
    assert hashlib.sha256(prefix.read_bytes()).hexdigest()==prefix_sha
    results.append({'check':'sequential_replay_boundary_redecode_readonly_prefix_union_late_definition_coverage_and_duplicate_dedup','status':'PASS'})
    _,bad,_=run('bad_offset',{'resume_header_offset':offsets[2]+1});assert not bad['file_eof_reached'] and bad['parse_anomalies'];results.append({'check':'wrong_boundary_anchor_rejected_without_target_tuning','status':'PASS'})
    _,limited,_=run('budget_replay',{'expanded_bytes':len(header)+8});assert not limited['file_eof_reached'] and limited['resource_limit'] and limited['record_decode_attempts']==0;results.append({'check':'discarded_replay_bytes_count_towards_byte_limit','status':'PASS'})
    db=sqlite3.connect(root/'index/member_index.sqlite',uri=True);m.resume.attach_prefix_views(db,c)
    try:
        try:db.execute("DELETE FROM prefix.events");raise AssertionError('frozen prefix writable')
        except sqlite3.OperationalError:pass
    finally:db.close()
    assert hashlib.sha256(prefix.read_bytes()).hexdigest()==prefix_sha
    results.append({'check':'frozen_prefix_cannot_be_modified_via_attached_connection','status':'PASS'})
receipt={'synthetic_only':True,'real_raw_records_read':0,'passed':len(results),'tests':results}
m.write_json(Path(__file__).parent/'synthetic_checks_receipt.json',receipt);print(json.dumps(receipt))
