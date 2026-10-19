"""One preparation generation, then a separate predeclared completion after approval.
No reference parsing. Outputs are exclusive-create within each immutable phase.
"""
import argparse,collections,csv,datetime,glob,hashlib,io,json,os,pathlib,resource,sys,time
R=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'public'))
from native_stream_support import canonical_hash
from post_incident_rules import build_candidates,native_time,context
from access_gate import SoftwareAccessGate

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write_json(p,d):
    with p.open('x') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')

def main():
    os.umask(0o077);start=time.monotonic()
    a=argparse.ArgumentParser();a.add_argument('--phase',choices=['preparation','completion'],required=True);args=a.parse_args()
    phase=args.phase;out=R/'candidate_output'/phase
    if out.exists():raise SystemExit('PHASE_ALREADY_GENERATED_NO_OVERWRITE')
    if phase=='completion' and not (R/'source_receipts/NATIVE_EXTRACTION_RECEIPT.json').exists():raise SystemExit('COMPLETION_REQUIRES_ACTUAL_AUTHORIZED_READ_RECEIPT')
    cfg=R/'input_contract/GENERATOR_CONFIG.json';targets=R/'input_contract/C21_TARGETS_288_PRIVATE.json';cache=R/'input_contract/REUSED_RAW_82_CATALOG.json';missing=R/'input_contract/MISSING_NATIVE_TARGETS_PRIVATE.json'
    # Bootstrap reads are a narrow allowlist; no B or reference access is permitted.
    gate=SoftwareAccessGate(R,[cfg,targets,cache,missing]);sys.addaudithook(gate.audit)
    config=json.loads(cfg.read_text());t=json.loads(targets.read_text());catalog=json.loads(cache.read_text())
    source={r['idx']:pathlib.Path(r['path']) for r in catalog['entries']}
    if phase=='completion':
        m=json.loads(missing.read_text())
        for r in m['targets']:
            p=R/'private_native_records'/(r['neutral_target_id']+'.raw.jsonl')
            if p.exists():source[r['idx']]=p
    for p in source.values():gate.allowed_reads.add(str(p.resolve()))
    # Actual prohibited reference-read probe. Denial is recorded; the file is never opened.
    probe_denied=False
    try:(R/'reference_only/A_instance_private.json').read_text()
    except PermissionError:probe_denied=True
    assert probe_denied
    assert 'B' not in config and 'ParentProcessGuid' not in json.dumps(config)
    records=[];coverage=[];tot=0;counts=collections.Counter()
    for row in sorted(t['records'],key=lambda x:x['idx']):
        p=source.get(row['idx']);e=None
        if p:
            raw=p.read_bytes();tot+=len(raw);assert hashlib.sha256(raw).hexdigest()==row['raw_sha'];e=json.loads(raw);assert canonical_hash(e)==row['canonical_sha'];records.append({'idx':row['idx'],'event':e,'raw_sha':row['raw_sha']})
        cat='session' if row['provider'] in ['PowerShell','Microsoft-Windows-PowerShell','Microsoft-Windows-WinRM'] else 'process' if row['provider']=='Microsoft-Windows-Sysmon' else 'authentication'
        counts[(cat,'total')]+=1;counts[(cat,'available' if e is not None else 'missing')]+=1
        f=context(e).get('fields',{}) if e else {}
        coverage.append({'physical_line':row['idx'],'member':row['member'],'provider':row['provider'],'event_id':row['eid'],'record_number':row['record_number'],'raw_record_sha256':row['raw_sha'],'canonical_json_sha256':row['canonical_sha'],'cache_status':'REUSED_VERIFIED_RAW' if p and phase=='preparation' else 'AVAILABLE_HASH_VERIFIED' if p else 'NOT_EXTRACTED','new_extraction_status':'NOT_AUTHORIZED_NOT_READ' if phase=='preparation' else 'ACTUAL_RECEIPT_REQUIRED','native_time':json.dumps(native_time(e),ensure_ascii=False) if e else 'NOT_EXTRACTED','raw_field_states':json.dumps({k:('MISSING' if k not in e else 'NULL' if e[k] is None else 'EMPTY' if e[k]=='' else 'PRESENT') for k in ['HostId','RunspaceId','ExecutionProcessID','ProcessGuid','TargetLogonId','SubjectLogonId','EventTime','UtcTime','TimeCreated']}) if e else 'NOT_EXTRACTED','parsed_RunspaceId_status':'PRESENT' if f.get('runspaceid') else 'MISSING_OR_UNPARSED' if e else 'NOT_EXTRACTED','parsed_HostId_status':'PRESENT' if f.get('hostid') else 'MISSING_OR_UNPARSED' if e else 'NOT_EXTRACTED','scope_class':cat,'locator_status':'RAW_AND_CANONICAL_HASH_VERIFIED' if p else 'INDEX_LOCATOR_ONLY','new_ZIP_member_reads_this_generation':0,'exception':''})
    candidates=build_candidates(records,config)
    out.mkdir(mode=0o700)
    universe=out/'RUNSPACE_UNIVERSE_PRIVATE.jsonl'
    with universe.open('x') as f:
        for c in candidates:f.write(json.dumps(c,ensure_ascii=False)+'\n')
    cp=out/'NATIVE_288_COVERAGE_AUDIT.csv'
    with cp.open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(coverage[0]));w.writeheader();w.writerows(coverage)
    audit={'phase':phase,'target_count':len(t['records']),'raw_available':len(records),'raw_missing':len(t['records'])-len(records),'candidate_count':len(candidates),'complete_identity_count':sum(c['identity_complete'] for c in candidates),'historical_candidate_count':sum(c['historical_causal_eligibility'] for c in candidates),'partial_universe':True,'native_time_recall_proven_complete':False,'category_counts':{k:{v:counts[(k,v)] for v in ['total','available','missing']} for k in ['session','process','authentication']},'reference_reads':0,'B_parent_identity_reads':0,'raw_bytes_loaded':tot,'ZIP_member_reads':0,'SQL_statements':0,'downloads':0,'wall_seconds':time.monotonic()-start,'RSS_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),'note':'Uniform processing of actual available raws; not complete observation coverage. C21 index retrieval envelope is not proven exhaustive over all native-time historical candidates.'}
    write_json(out/'GENERATION_AUDIT.json',audit)
    access={'reference_probe_denied':probe_denied,'isolation':'PYTHON_AUDIT_ALLOWLIST_NOT_OS_SANDBOX','events':gate.events,'unexpected_denials':[d for d in gate.denied if 'reference_only' not in d['path']]}
    assert not access['unexpected_denials'];write_json(out/'ACCESS_LOG.json',access)
    freeze={'phase':phase,'outputs':{},'input_hashes':{str(p.relative_to(R)):sha(p) for p in [cfg,targets,cache]},'A_reference_read_before_freeze':False,'B_parent_read_before_freeze':False,'generation_count':1}
    for p in [universe,cp,out/'GENERATION_AUDIT.json',out/'ACCESS_LOG.json']:
        gate.generated(p);freeze['outputs'][str(p.relative_to(R))]=sha(p)
    write_json(out/'CANDIDATE_FREEZE.json',freeze)
    print(json.dumps(audit,ensure_ascii=False))
if __name__=='__main__':main()
