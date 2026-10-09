#!/usr/bin/env python3
"""Measure an app-level pointer observation; do not read F1 oracle."""
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CASES=[(m,p) for _ in range(3) for m,p in (("F","K"),("N","K"),("F","Z"),("N","Z"))]


def run(binary):
    rows=[]
    for n,(mode,payload) in enumerate(CASES,1):
        (ROOT/"input.bin").write_bytes((mode+payload*16).encode())
        for f in ("output.bin","pointer_observation.bin"):
            p=ROOT/f
            if p.exists():p.unlink()
        start=time.perf_counter_ns()
        p=subprocess.run(["./"+binary,"input.bin","output.bin"],cwd=ROOT,capture_output=True)
        wall_us=(time.perf_counter_ns()-start)/1000
        assert p.returncode==0,p.stderr
        record={"run_id":f"r{n:02d}","wall_us":wall_us,"exit_code":0}
        if binary=="f1_pointer_probe":
            data=(ROOT/"pointer_observation.bin").read_bytes()
            match=re.fullmatch(rb"read_payload_ptr=(0x[0-9a-f]+) write_source_ptr=(0x[0-9a-f]+)\n",data)
            assert match
            record.update({"observation_bytes":len(data),"pointer_equal":int(match.group(1),16)==int(match.group(2),16),"raw_observation_sha256":hashlib.sha256(data).hexdigest()})
        rows.append(record)
    for f in ("input.bin","output.bin","pointer_observation.bin"):
        p=ROOT/f
        if p.exists():p.unlink()
    return rows


def main():
    out={"mechanism":"application-instrumented pointer identity, not general value taint","baseline_untraced":run("f1"),"instrumented_untraced":run("f1_pointer_probe")}
    (ROOT/"outputs/pointer_measurement.json").write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({"runs_per_binary":12,"pointer_equal_true":sum(x["pointer_equal"] for x in out["instrumented_untraced"]),"pointer_equal_false":sum(not x["pointer_equal"] for x in out["instrumented_untraced"])},indent=2))


if __name__=="__main__":main()
