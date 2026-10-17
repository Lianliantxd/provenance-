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
with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='fixtures_') as td:
    base=Path(td)
    def run(name,data,override=None):
        root=base/name;root.mkdir()
        for d in ('index','logs','private_candidates','tmp'): (root/d).mkdir()
        path=root/'fixture.gz';path.write_bytes(data)
        intake={'actual_sha256':hashlib.sha256(data).hexdigest(),'actual_size':len(data)}
        with contextlib.redirect_stdout(io.StringIO()):s=m.run_scan(path,root,dict(config,**(override or {})),intake,seed)
        return root,s
    rows=[event(),entity(),entity(host='host2'),entity(variant=3),entity(variant=2,uid='sub'),event(),event(uid='third',obj='other',path='/synthetic/target')]
    root,s=run('full',gzip.compress(ocf(rows),mtime=0));a=s['index_analysis']
    assert s['file_eof_reached'] and s['record_count']==7 and a['indexed_events']==3 and a['indexed_entities']==4
    assert a['entity_path_association_events']==2
    assert a['additional_event_positions_with_repeated_uuid']==1 and a['candidate_total']==3 and a['candidate_exported']==1 and a['candidate_export_truncated']
    db=sqlite3.connect(root/'index/member_index.sqlite')
    assert db.execute("SELECT count(*) FROM entities WHERE uuid='obj'").fetchone()[0]==3
    assert db.execute('SELECT committed_ord FROM commits ORDER BY id DESC LIMIT 1').fetchone()[0]==s['index_committed_through_record']==7
    assert db.execute("SELECT count(*) FROM events e JOIN entities n ON e.host=n.host AND e.obj=n.uuid AND n.kind='FileObject' WHERE n.ord>e.ord").fetchone()[0]>=1
    db.close();results.append({'check':'EOF_index_versions_late_entity_duplicates_export_cap_commit_consistency','status':'PASS'})
    for name,raw in [('truncated_sync',ocf(rows)[:-1]),('truncated_varint',header+b'\x80')]:
        _,v=run(name,gzip.compress(raw,mtime=0));assert not v['file_eof_reached'] and v['parse_anomalies'];results.append({'check':name,'status':'PASS'})
    corrupted=bytearray(gzip.compress(ocf(rows),mtime=0));corrupted[-8]^=1
    _,v=run('crc_error',bytes(corrupted));assert not v['file_eof_reached'] and v['parse_anomalies'];results.append({'check':'CRC_error_not_EOF','status':'PASS'})
    _,v=run('bytes',gzip.compress(ocf(rows),mtime=0),{'expanded_bytes':len(header)+3});assert not v['file_eof_reached'] and v.get('resource_limit') and not v['parse_anomalies'];results.append({'check':'byte_budget_distinct_from_parse_error','status':'PASS'})
    _,v=run('extra_tail',gzip.compress(ocf(rows),mtime=0)+b'\0');assert not v['file_eof_reached'] and v['parse_anomalies'];results.append({'check':'ignored_gzip_padding_disallowed','status':'PASS'})
    # Literal 250000 checkpoint must continue within the same block and scan.
    root,v=run('250001_records',gzip.compress(ocf([entity(variant=2,uid='tiny')]*250001),mtime=0),{'checkpoint_records':250000})
    assert v['record_count']==250001 and v['file_eof_reached'] and (root/'03_prefix_checkpoint_comparison.json').exists()
    results.append({'check':'literal_250000_checkpoint_continues_to_250001_in_same_block','status':'PASS'})
    link=base/'linked';link.symlink_to(root)
    try:m.util.safe_path(link);raise AssertionError('symlink accepted')
    except ValueError:pass
    try:m.reader.read_exact(io.BytesIO(b''),16777217);raise AssertionError('allocation accepted')
    except m.reader.AllocationGuard:pass
    try:m.reader.decode(io.BytesIO(b''),'null',{},129);raise AssertionError('depth accepted')
    except m.reader.AllocationGuard:pass
    original=m.util.rss_bytes;m.util.rss_bytes=lambda:4294967297
    try:
        try:m.Budget(root,config).check(True);raise AssertionError('RSS accepted')
        except m.LimitStop:pass
    finally:m.util.rss_bytes=original
    try:m.Budget(root,dict(config,seconds=0)).check();raise AssertionError('time accepted')
    except m.LimitStop:pass
    results.append({'check':'symlink_single_read_recursion_memory_and_time_guards','status':'PASS'})
receipt={'synthetic_only':True,'real_raw_records_read':0,'tests':results,'passed':len(results)}
m.write_json(Path(__file__).parent/'synthetic_checks_receipt.json',receipt)
print(json.dumps(receipt))
