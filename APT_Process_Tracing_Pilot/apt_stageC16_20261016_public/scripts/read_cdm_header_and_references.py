"""Bounded read-only OCF header / whitelisted public-reference acquisition.
Does not scan events, execute log commands, build an attack graph, or run a model.
"""
from __future__ import annotations
import argparse,base64,datetime,gzip,hashlib,importlib.util,json,os,sys,time,urllib.request
from pathlib import Path
URLS={
 'backtracker.pdf':'https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf',
 'priotracker.pdf':'https://www.princeton.edu/~pmittal/publications/priotracker-ndss18.pdf',
 'atlas.pdf':'https://www.usenix.org/system/files/sec21-alsaheel.pdf',
 'minos_v1.html':'https://arxiv.org/html/2607.00440v1',
 'anchor_v1.html':'https://arxiv.org/html/2609.36494v1',
}
def sha(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
 return h.hexdigest()
def safe(p:Path)->Path:
 if '..' in p.parts:raise ValueError('PATH_ESCAPE')
 for q in [p,*p.parents]:
  if q.is_symlink():raise ValueError('SYMLINK')
 return p
def save(p:Path,v:object)->None:
 safe(p);p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 with p.open('x') as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write(chr(10))
 p.chmod(0o600)
def header(root:Path,raw:Path,parser:Path)->None:
 safe(raw);safe(parser);before=sha(raw);ps=sha(parser);sys.dont_write_bytecode=True
 spec=importlib.util.spec_from_file_location('trusted_prior_stream_cdm20',parser);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 with gzip.open(raw,'rb') as g:
  magic=m.read_exact(g,4)
  if magic!=b'Obj\x01':raise ValueError('NOT_AVRO_OCF')
  meta=m.read_map_bytes(g);sync=m.read_exact(g,16);schema=json.loads(meta['avro.schema'].decode())
 actual={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'raw_path':str(raw),'raw_bytes':raw.stat().st_size,'raw_sha256':before,'parser_path':str(parser),'parser_sha256':ps,'gzip_magic_verified':True,'avro_ocf_magic':magic.hex(),'schema_namespace':schema.get('namespace'),'schema_name':schema.get('name'),'embedded_schema_sha256':hashlib.sha256(meta['avro.schema']).hexdigest(),'top_level_fields':[x['name'] for x in schema['fields']],'codec':meta.get('avro.codec',b'null').decode(),'sync_marker_bytes':len(sync),'raw_events_scanned':0,'whole_gzip_crc_or_event_range_rechecked':False,'attack_instance_or_B_mapped':False,'data_role':'HEADER_ONLY_EXISTING_SOURCE_MEMBER','new_model_calls':0}
 save(root/'probe/existing_bin121_header.json',actual);print(json.dumps({k:v for k,v in actual.items() if k not in ['raw_path','parser_path','top_level_fields']}))
def references(root:Path)->None:
 receipts=[]
 for name,url in URLS.items():
  out=safe(root/'references'/name)
  if out.exists():receipts.append({'name':name,'state':'ALREADY_PRESENT_NOT_REFETCHED','sha256':sha(out),'bytes':out.stat().st_size});continue
  start=time.monotonic()
  try:
   req=urllib.request.Request(url,headers={'User-Agent':'C16 bounded academic source verification'})
   with urllib.request.urlopen(req,timeout=25) as res:
    expected=res.headers.get('Content-Length');limit=8*1024*1024
    if expected is not None and int(expected)>limit:raise ValueError('REFERENCE_OVER_LIMIT')
    b=res.read(limit+1)
    if len(b)>limit:raise ValueError('REFERENCE_OVER_LIMIT')
    finalurl=res.url;typ=res.headers.get('Content-Type')
   if name.endswith('.pdf') and not b.startswith(b'%PDF-'):raise ValueError('NOT_PDF')
   with out.open('xb') as f:f.write(b)
   out.chmod(0o600);receipts.append({'name':name,'requested_url':url,'final_url':finalurl,'content_type':typ,'bytes':len(b),'sha256':sha(out),'state':'DOWNLOADED_PRIVATE_REFERENCE_NOT_PUBLICLY_REDISTRIBUTABLE','elapsed_seconds':time.monotonic()-start})
  except Exception as e:receipts.append({'name':name,'requested_url':url,'state':'NOT_OBTAINED','error':type(e).__name__+':'+str(e),'elapsed_seconds':time.monotonic()-start})
 save(root/'logs/public_reference_acquisition.json',{'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':receipts,'security_raw_data_downloaded_bytes':0,'new_model_calls':0});print(json.dumps(receipts))
if __name__=='__main__':
 os.umask(0o077);sys.dont_write_bytecode=True;p=argparse.ArgumentParser();p.add_argument('mode',choices=['header','references']);p.add_argument('--root',type=Path,required=True);p.add_argument('--raw',type=Path);p.add_argument('--parser',type=Path);a=p.parse_args();safe(a.root)
 if a.mode=='header':header(a.root,a.raw,a.parser)
 else:references(a.root)
