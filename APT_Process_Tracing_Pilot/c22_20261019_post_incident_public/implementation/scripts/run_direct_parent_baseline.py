"""Read frozen candidates and query B, never reference A; return every legal match."""
import argparse,csv,datetime,glob,hashlib,json,os,pathlib,sys
R=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'public'))
from post_incident_rules import baseline
from access_gate import SoftwareAccessGate

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    os.umask(0o077);a=argparse.ArgumentParser();a.add_argument('--phase',choices=['preparation','completion'],required=True);args=a.parse_args();out=R/'candidate_output'/args.phase
    paths=[out/'CANDIDATE_FREEZE.json',out/'RUNSPACE_UNIVERSE_PRIVATE.jsonl',out/'GENERATION_AUDIT.json',out/'ACCESS_LOG.json',out/'NATIVE_288_COVERAGE_AUDIT.csv',R/'input_contract/query_B_private.json']
    g=SoftwareAccessGate(R,paths);sys.addaudithook(g.audit)
    frozen=json.loads(paths[0].read_text())
    for rel,h in frozen['outputs'].items():assert sha(R/rel)==h
    cs=[json.loads(x) for x in paths[1].read_text().splitlines()];audit=json.loads(paths[2].read_text());b=json.loads(paths[-1].read_text())
    result=baseline(b['raw_event'],cs,audit['raw_missing']==0,audit['native_time_recall_proven_complete']);result['candidate_freeze_sha256']=sha(paths[0]);result['B_raw_sha256']=b['raw_record_sha256'];result['reference_reads']=0;result['matched_original_indices']=[c['observed_original_indices'] for c in cs if c['candidate_id'] in result['matched_candidate_ids']]
    p=out/'DIRECT_PARENT_BASELINE_RESULTS.csv'
    with p.open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(result));w.writeheader();w.writerow({k:json.dumps(v) if isinstance(v,(list,dict)) else v for k,v in result.items()})
    q=out/'BASELINE_RESULT_PRIVATE.json'
    with q.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    g.generated(p);g.generated(q)
    freeze={'candidate_freeze_sha256':sha(paths[0]),'outputs':{str(p.relative_to(R)):sha(p),str(q.relative_to(R)):sha(q)},'reference_reads':0,'B_parent_identity_used_only_after_candidate_freeze':True,'phase':args.phase}
    with (out/'BASELINE_FREEZE.json').open('x') as f:json.dump(freeze,f,indent=2);f.write('\n')
    print(json.dumps(result))
if __name__=='__main__':main()
