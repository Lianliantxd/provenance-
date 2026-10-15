"""Batch case-scope adapter; invoke the exact frozen V2 native Controller wrapper."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from c15_common import configure_case_scope,atomic_create,utc
import server_native_controller as original
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--attempt',required=True);a=p.parse_args();root=Path(a.attempt)
 try:
  configure_case_scope(ROOT);original.main(root)
 except BaseException as e:
  try:atomic_create(root,'controller_aborted.json',{'utc':utc(),'state':'FAILED_AND_SEALED','error_type':type(e).__name__,'reason':str(e)[:500]})
  except BaseException:pass
  raise SystemExit(3)
