from pathlib import Path
import sys,json,gzip,hashlib,tempfile,os
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import bounded_probe as b

def av(n):
 value=(n<<1)^(n>>63);out=bytearray()
 while value>=128:out.append((value&127)|128);value>>=7
 out.append(value);return bytes(out)
def blob(v):return av(len(v))+v
def string(v):return blob(v.encode())
schema={'type':'record','name':'TCCDMDatum','namespace':'synthetic.fixture','fields':[{'name':'type','type':'string'},{'name':'hostId','type':'string'},{'name':'CDMVersion','type':'string'},{'name':'datum','type':[{'type':'record','name':'Subject','fields':[{'name':'uuid','type':'string'},{'name':'type','type':'string'},{'name':'cid','type':'int'},{'name':'parentSubject','type':['null','string']},{'name':'startTimestampNanos','type':'long'},{'name':'cmdLine','type':'string'}]},{'type':'record','name':'Event','fields':[{'name':'uuid','type':'string'},{'name':'type','type':'string'},{'name':'subject','type':'string'},{'name':'predicateObject','type':'string'},{'name':'predicateObjectPath','type':'string'},{'name':'timestampNanos','type':'long','doc':'Nanoseconds from the unix epoch, 1 January 1970 UTC.'}]}]}]}
metadata={'avro.schema':json.dumps(schema).encode(),'avro.codec':b'null'};sync=b'0123456789abcdef'
header=b'Obj\x01'+av(len(metadata))+b''.join(string(k)+blob(v) for k,v in metadata.items())+av(0)+sync
subject=string('SUBJECT')+string('fixture_host')+string('20')+av(0)+string('subject0')+string('PROCESS')+av(1)+av(0)+av(1550000000000000000)+string('SYNTHETIC_ONLY')
def event(n,path):return string('EVENT')+string('fixture_host')+string('20')+av(1)+string('event'+str(n))+string('EVENT_READ')+string('subject0')+string('object'+str(n))+string(path)+av(1550000000000000000+n)
payload=subject+event(1,'/synthetic/report-object')+event(2,'/synthetic/other');blockhead=av(3)+av(len(payload));raw=header+blockhead+payload+sync
results=[]
with tempfile.TemporaryDirectory(dir=Path(__file__).parent,prefix='synthetic_') as td:
 root=Path(td);p=root/'fixture.gz';p.write_bytes(gzip.compress(raw,mtime=0))
 def run(label,limits,check):
  stats,candidates=b.probe(p,limits,'/synthetic/report-object');assert check(stats,candidates),label
  results.append({'check':label,'status':'PASS','records':stats['record_count'],'termination':stats['termination_reason'],'eof':stats['file_eof_reached']})
 limits={'records':10,'expanded_bytes':1048576,'seconds':5,'memory_bytes':4294967296}
 run('true_eof_and_all_record_types',dict(limits),lambda s,c:s['file_eof_reached'] and s['record_count']==3 and s['record_types']=={'Subject':1,'Event':2} and s['candidate_records_matched']==1)
 run('record_cap_counts_subject_before_events',dict(limits,records=1),lambda s,c:s['record_count']==1 and not s['event_types'] and not s['file_eof_reached'] and s['termination_reason']=='TOP_LEVEL_RECORD_LIMIT')
 byte_cap=len(header)+len(blockhead)+3
 run('byte_limit_stops_partial_record_before_allocation',dict(limits,expanded_bytes=byte_cap),lambda s,c:s['expanded_bytes_delivered']<=byte_cap and s['partial_record_start'] is not None and not s['parse_anomalies'] and not s['file_eof_reached'])
 run('time_limit_stops_without_eof',dict(limits,seconds=0),lambda s,c:s['termination_reason']=='WALL_CLOCK_LIMIT' and not s['file_eof_reached'])
 run('no_match_is_only_read_scope',dict(limits,records=1),lambda s,c:s['candidate_records_matched']==0 and s['B']=='B_UNRESOLVED' and s['coverage_scope']=='READ_PREFIX_ONLY_UNTIL_VERIFIED_EOF')
 saved_decode=b.reader.decode
 def delayed_decode(*args):
  b.time.sleep(0.05)
  return saved_decode(*args)
 b.reader.decode=delayed_decode
 try:run('positive_wall_alarm_interrupts_record',dict(limits,seconds=0.01),lambda s,c:s['termination_reason']=='WALL_CLOCK_LIMIT' and s['partial_record_start'] is not None and not s['file_eof_reached'])
 finally:b.reader.decode=saved_decode
 valid=b.hash_file(p,p.stat().st_size,hashlib.md5(p.read_bytes()).hexdigest());assert valid['status']=='FILE_VERIFIED'
 mismatch=b.hash_file(p,p.stat().st_size+1,'0'*32);assert mismatch['status']=='INPUT_INTEGRITY_MISMATCH'
 results.append({'check':'streaming_integrity_expected_actual_mismatch_stops','status':'PASS'})
 output=root/'exclusive.json';b.save(output,{'old':'retain'});before=output.read_bytes()
 try:b.save(output,{'new':'forbidden'});raise AssertionError('overwrite accepted')
 except FileExistsError:assert output.read_bytes()==before
 link=root/'symlink.gz';link.symlink_to(p)
 try:b.safe_path(link);raise AssertionError('symlink accepted')
 except ValueError:pass
 results.append({'check':'exclusive_output_and_symlink_guard','status':'PASS'})
 p.write_bytes(p.read_bytes()[:-1]);stats,_=b.probe(p,dict(limits),'/synthetic/report-object');assert stats['parse_anomalies'] and not stats['file_eof_reached']
 results.append({'check':'truncated_gzip_not_successful_eof','status':'PASS'})
result={'synthetic_checks_only':True,'real_raw_records_read':0,'tests':results,'passed':len(results)}
b.save(Path(__file__).parent/'synthetic_checks_receipt.json',result)
print(json.dumps(result))
