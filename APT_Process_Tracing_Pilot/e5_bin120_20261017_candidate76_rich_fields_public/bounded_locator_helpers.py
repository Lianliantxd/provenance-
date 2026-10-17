"""Generic fixed-position extraction helpers. No case data or payloads."""
import hashlib,json

def field_state(d,k):
 if k not in d:return 'MISSING'
 if d[k] is None:return 'NULL'
 if d[k] in ('',[],{}):return 'EMPTY'
 return 'PRESENT'


def merge_positions(rows):
 out={}
 for row in rows:
  n=row['ord']
  if n in out and out[n]!=row:raise ValueError('SAME_SOURCE_POSITION_FIELDS_DIFFER')
  out[n]=row
 return list(out.values())


class RecordBytes:
 def __init__(self,source):self.source=source;self.digest=hashlib.sha256();self.n=0
 def read(self,n):
  data=self.source.read(n);self.digest.update(data);self.n+=len(data);return data


def skip_to(stream,offset,sync,rolling):
 if offset<stream.delivered:raise ValueError('LOCATOR_BEHIND_CURRENT_POSITION')
 while stream.delivered<offset:
  n=min(1048576,offset-stream.delivered);data=stream.read(n)
  if len(data)!=n:raise EOFError('EOF_BEFORE_TARGET')
  rolling=(rolling+data)[-16:]
 if rolling!=sync:raise ValueError('LOCATOR_OR_SCHEMA_MISMATCH:PRECEDING_SYNC')
 return rolling


def validate(row,t):
 r=t['index_row'];d=row.get('datum') or {};host=row.get('hostId')
 if d.get('_record_type')!=t['kind'] or host!=r['host'] or d.get('uuid')!=r['uuid']:raise ValueError('LOCATOR_OR_SCHEMA_MISMATCH:IDENTITY')
 if t['kind']=='Event':
  pairs={'type':'event_type','timestampNanos':'ns','subject':'subject','predicateObject':'obj','predicateObject2':'obj2','predicateObjectPath':'path','predicateObject2Path':'path2'}
  if any(d.get(k)!=r[v] for k,v in pairs.items()):raise ValueError('LOCATOR_OR_SCHEMA_MISMATCH:EVENT_FIELDS')
 else:
  if d!=json.loads(r['raw_fields']):raise ValueError('LOCATOR_OR_SCHEMA_MISMATCH:ENTITY_FIELDS')


