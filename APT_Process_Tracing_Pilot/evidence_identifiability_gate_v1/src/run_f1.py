#!/usr/bin/env python3
"""Run preregistered benign histories on Linux; keep raw and oracle private."""
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN = json.loads((ROOT / "02_PRE_REGISTERED_TASK_AND_CASES.json").read_text())
CASES = [(mode, payload) for _ in range(3) for mode,payload in (("F","K"),("N","K"),("F","Z"),("N","Z"))]


def sha(data): return hashlib.sha256(data).hexdigest()


def parse(trace):
    events=[]; times=[]
    for line in trace.splitlines():
        m=re.match(r"^(\d+\.\d+) (openat|read|write|close)\((.*)\) = (.*)$",line)
        if not m: continue
        ts,op,args,ret=m.groups();times.append(float(ts))
        if op=="openat":
            obj=re.search(r'"(input|output)\.bin"',args)
            if not obj: continue
            object_name=obj.group(1)+".bin"
            flags="O_RDONLY" if "O_RDONLY" in args else "O_WRONLY|O_CREAT|O_TRUNC"
            events.append({"op":op,"object":object_name,"flags":flags,"requested":None,"returned":int(ret.split("<")[0])>=0,"process":"CASE_MAIN"})
        else:
            obj=re.search(r'<[^>]*(input|output)\.bin>',args)
            if not obj: continue
            requested=int(re.search(r", (\d+)\s*$",args).group(1)) if op in {"read","write"} else None
            events.append({"op":op,"object":obj.group(1)+".bin","flags":None,"requested":requested,"returned":int(ret.split()[0]),"process":"CASE_MAIN"})
    return events, (max(times)-min(times))*1e6 if times else None


def main():
    assert sha((ROOT / "src/f1.c").read_bytes())==FROZEN["program_source_sha256"]
    assert sha((ROOT / "f1").read_bytes())==FROZEN["executable_sha256"]
    private=ROOT / "private"; raw=private / "raw_sensor"; oracle=private / "oracle"
    projected=ROOT / "outputs/projected_observations"
    for p in (raw,oracle,projected):p.mkdir(parents=True,exist_ok=True)
    assert not list(raw.glob("*.strace")),"refusing to overwrite actual traces"
    manifest=[]; oracle_rows=[]
    env_digest=sha("\0".join(f"{k}={v}" for k,v in sorted(os.environ.items())).encode())
    for n,(mode,payload) in enumerate(CASES,1):
        run_id=f"r{n:02d}"
        (ROOT / "input.bin").write_bytes((mode+payload*16).encode())
        output=ROOT / "output.bin"
        if output.exists():output.unlink()
        trace_file=raw / f"{run_id}.strace"
        start=time.perf_counter_ns()
        p=subprocess.run(["strace","-ttt","-yy","-s","256","-e","trace=openat,read,write,close","-o",str(trace_file),"./f1","input.bin","output.bin"],cwd=ROOT,check=False,capture_output=True)
        wall_us=(time.perf_counter_ns()-start)/1000
        assert p.returncode==0,p.stderr.decode(errors="replace")
        data=output.read_bytes(); trace=trace_file.read_text()
        events,trace_duration_us=parse(trace)
        assert len(events)==6,events
        projection={"events":events}
        (projected / f"{run_id}.json").write_text(json.dumps(projection,sort_keys=True,indent=2)+"\n")
        manifest.append({"run_id":run_id,"raw_sha256":sha(trace_file.read_bytes()),"raw_bytes":trace_file.stat().st_size,"projection_sha256":sha(json.dumps(projection,sort_keys=True).encode()),"wall_us":wall_us,"trace_duration_us":trace_duration_us,"argv_shape":"./f1 input.bin output.bin","environment_sha256":env_digest,"exit_code":p.returncode})
        oracle_rows.append({"run_id":run_id,"condition":mode,"payload":payload*16,"output_hex":data.hex(),"output_sha256":sha(data)})
    (oracle / "cases.json").write_text(json.dumps(oracle_rows,indent=2)+"\n")
    (ROOT / "outputs/sensor_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    (ROOT / "input.bin").unlink();(ROOT / "output.bin").unlink()
    print(json.dumps({"runs":len(manifest),"projection_unique":len({x["projection_sha256"] for x in manifest}),"raw_unique":len({x["raw_sha256"] for x in manifest}),"oracle_private":True},indent=2))


if __name__=="__main__":main()
