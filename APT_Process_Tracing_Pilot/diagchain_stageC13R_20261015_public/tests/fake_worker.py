"""Trusted synthetic process; fixture content is data, never a command."""
import json, os, sys, time
from pathlib import Path
f=json.loads(Path(sys.argv[1]).read_text())
assert f['data_class']=='SYNTHETIC_ONLY'
sys.stdin.buffer.read()
time.sleep(f.get('delay_before',0))
if f.get('stderr'):sys.stderr.write(f['stderr']);sys.stderr.flush()
if f.get('canonical') is not None:Path(sys.argv[2]).write_bytes(f['canonical'].encode())
for part in f['stdout_chunks']:
 os.write(1,part.encode());time.sleep(f.get('chunk_delay',0))
time.sleep(f.get('delay_after',0))
raise SystemExit(f.get('exit_code',0))
