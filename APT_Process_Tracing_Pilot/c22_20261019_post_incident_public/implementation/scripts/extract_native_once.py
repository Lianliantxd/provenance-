"""Single-use authorized extraction. This module never runs on import."""
import datetime, hashlib, json, os, pathlib, resource, stat, sys, time, zipfile
R=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'public'))
from native_stream_support import JsonlReader, ReadLimit, canonical_hash, field_state

def sha(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        while chunk:=f.read(1048576):h.update(chunk)
    return h.hexdigest()
def identity(p: pathlib.Path) -> list:
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def rss() -> int:
    n=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return n if sys.platform=='darwin' else n*1024
def memory_guard() -> None:
    if rss()>4*1024**3:raise ReadLimit('RSS_SUPERVISION_THRESHOLD')
def val(d: dict, *names):
    return next((str(d[k]) for k in names if d.get(k) is not None and d[k]!=''),None)
def historical_index_time(d: dict):
    # Used solely to compare with historical locator, never for causal clock fitting.
    v=val(d,'UtcTime','TimeCreated','@timestamp')
    if v is None:return None
    dt=datetime.datetime.fromisoformat(v.replace('Z','+00:00'))
    if dt.tzinfo is None:dt=dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).isoformat(timespec='milliseconds')
def verify_target(d: dict, raw: bytes, expected: dict) -> dict:
    observed={'eid':int(d['EventID']),'record_number':val(d,'RecordNumber','EventRecordID'),
              'provider':val(d,'SourceName','ProviderName'),'host':val(d,'Hostname','Computer'),
              'raw_sha':hashlib.sha256(raw).hexdigest(),'canonical_sha':canonical_hash(d),
              'channel':val(d,'Channel'),'guid':val(d,'ProcessGuid'),'ts':historical_index_time(d)}
    mismatches={k:{'expected':expected[k],'observed':observed.get(k)} for k in observed if k in expected and expected[k]!=observed.get(k)}
    if mismatches:raise ValueError('RAW_RECORD_LOCATOR_MISMATCH:'+json.dumps(mismatches))
    return observed
def main() -> None:
    os.umask(0o077)
    # An actual user reply must first be recorded by the supervising agent; never generated here.
    approval_path=R/'source_receipts/C22_EXPLICIT_USER_READ_APPROVAL.json'
    if not approval_path.exists():raise SystemExit('C22_NATIVE_READ_AUTHORIZATION_PENDING')
    approval=json.loads(approval_path.read_text())
    if approval.get('task_id')!='C22_POST_INCIDENT_SOURCE_TRACING_EVALUATION_ADMISSION_V1' or approval.get('explicit_human_approval') is not True or not approval.get('verbatim_user_message'):
        raise SystemExit('C22_NATIVE_READ_AUTHORIZATION_PENDING')
    lock=R/'logs/NATIVE_REPLAY_STARTED.json'
    if lock.exists():raise SystemExit('ONE_REPLAY_ALREADY_RESERVED_NO_RESTART')
    frozen=R/'input_contract/MISSING_NATIVE_TARGETS_PRIVATE.json';c=json.loads(frozen.read_text())
    hashes=json.loads((R/'source_receipts/PRE_READ_HASHES.json').read_text())
    for rel,h in hashes['files'].items():
        if sha(R/rel)!=h:raise SystemExit('PRE_READ_FROZEN_INPUT_OR_CODE_CHANGED:'+rel)
    path=pathlib.Path(c['source_archive']['path']);before=identity(path)
    if before!=c['source_archive']['identity'] or sha(path)!=c['source_archive']['sha256']:
        raise SystemExit('SOURCE_INTEGRITY_MISMATCH')
    if approval.get('frozen_contract_sha256')!=sha(frozen) or approval.get('pre_read_hashes_sha256')!=sha(R/'source_receipts/PRE_READ_HASHES.json'):raise SystemExit('APPROVAL_SCOPE_DIGEST_MISMATCH')
    with zipfile.ZipFile(path) as z:
        info=z.getinfo(c['source_archive']['member']);pp=pathlib.PurePosixPath(info.filename)
        if pp.is_absolute() or '..' in pp.parts or stat.S_ISLNK(info.external_attr>>16):raise SystemExit('UNSAFE_ZIP_MEMBER')
        if info.file_size!=c['source_archive']['declared_uncompressed_bytes'] or info.CRC!=c['source_archive']['CRC32_integer'] or info.compress_type!=8:
            raise SystemExit('ZIP_METADATA_MISMATCH')
        with lock.open('x') as f:json.dump({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':sys.argv,'frozen_contract_sha256':sha(frozen),'approval_sha256':sha(approval_path),'one_attempt_reserved':True},f,indent=2)
        lock.chmod(0o600)
        targets={x['idx']:x for x in c['targets']};matched=[];saved=[];mismatch=None;reader=None;reason=None;start=time.monotonic();output_bytes=0
        def save(p: pathlib.Path, data: bytes) -> None:
            nonlocal output_bytes
            existing=sum(q.stat().st_size for q in R.rglob('*') if q.is_file())
            if existing+len(data)>c['resources']['max_new_output_bytes']-1048576:raise ReadLimit('OUTPUT_BUDGET_WITH_RECEIPT_RESERVE')
            with p.open('xb') as f:f.write(data)
            p.chmod(0o600);output_bytes+=len(data)
        try:
            with z.open(info,'r') as stream:
                reader=JsonlReader(stream,c['resources']['max_delivered_bytes'],c['resources']['max_event_attempts'],c['resources']['max_wall_seconds'],memory_guard)
                for line,raw,obj in reader:
                    if line not in targets:continue
                    memory_guard();expected=targets[line];observed=verify_target(obj,raw,expected);matched.append(line)
                    name=expected['neutral_target_id'];save(R/'private_native_records'/(name+'.raw.jsonl'),raw)
                    fields={k:field_state(obj,k) for k in c['requested_fields']}
                    native={'target_id':name,'physical_line':line,'observed_identity':observed,'archive_sha256':c['source_archive']['sha256'],'member':info.filename,
                            'complete_unmodified_original_fields':obj,'requested_field_states':fields,'tool_sha256':sha(pathlib.Path(__file__))}
                    save(R/'private_native_records'/(name+'.native.json'),(json.dumps(native,ensure_ascii=False,indent=2)+'\n').encode());saved.append(line)
                reason='ZIP_MEMBER_READ_TO_EOF_AND_CRC_VERIFIED' if reader.eof else 'TARGET_EXTRACTION_COMPLETED_MEMBER_EOF_NOT_REACHED'
        except (ReadLimit,ValueError,KeyError,zipfile.BadZipFile,OSError) as e:
            reason=type(e).__name__+':'+str(e);mismatch=str(e) if 'RAW_RECORD_LOCATOR_MISMATCH' in str(e) else None
        finally:
            after=identity(path)
            x={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ZIP_replays_reserved':1,'delivered_uncompressed_bytes':reader.delivered if reader else 0,'event_parse_attempts':reader.attempts if reader else 0,
               'complete_events_parsed':reader.parsed if reader else 0,'physical_lines_processed':reader.physical_lines if reader else 0,'matched_targets':len(matched),'saved_targets':len(saved),
               'unmatched_line_locators':sorted(set(targets)-set(matched)),'unsaved_line_locators':sorted(set(targets)-set(saved)),'duplicate_locator_count':0,'stop_reason':reason,
               'member_EOF_reached':reader.eof if reader else False,'member_CRC_verified':bool(reader and reader.eof and reason=='ZIP_MEMBER_READ_TO_EOF_AND_CRC_VERIFIED'),
               'actual_delivered_CRC32':f'{reader.CRC32:08x}' if reader else None,'declared_CRC32':f'{info.CRC:08x}',
               'wall_seconds':time.monotonic()-start,'max_RSS_bytes':rss(),'new_native_output_bytes':output_bytes,'source_identity_before':before,'source_identity_after':after,'source_unchanged':before==after,
               'raw_locator_mismatch':mismatch,'non_target_events_were_actually_read_and_parsed':True}
            receipt=R/'source_receipts/NATIVE_EXTRACTION_RECEIPT.json'
            with receipt.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
            receipt.chmod(0o600);print(json.dumps(x,indent=2))
            if before!=after:raise RuntimeError('SOURCE_CHANGED')
if __name__=='__main__':main()
