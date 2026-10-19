"""Standard-library JSONL reader and conservative identity primitives. No payloads."""
import datetime
import hashlib
import json
import time
import zlib

class ReadLimit(RuntimeError):
    pass

class JsonlReader:
    def __init__(self, stream, max_bytes: int, max_attempts: int, max_seconds: float,
                 check_memory=lambda: None, chunk_size: int=65536, max_line: int=16777216):
        self.stream=stream;self.max_bytes=max_bytes;self.max_attempts=max_attempts
        self.max_seconds=max_seconds;self.check_memory=check_memory;self.chunk_size=chunk_size
        self.max_line=max_line;self.delivered=0;self.attempts=0;self.parsed=0
        self.physical_lines=0;self.eof=False;self.start=time.monotonic()
        self.CRC32=0
    def guard(self) -> None:
        if time.monotonic()-self.start>=self.max_seconds:raise ReadLimit('WALL_TIME_LIMIT')
        self.check_memory()
    def __iter__(self):
        pending=bytearray()
        while True:
            self.guard()
            if self.delivered>=self.max_bytes:raise ReadLimit('DELIVERED_BYTE_LIMIT_EOF_UNVERIFIED')
            data=self.stream.read(min(self.chunk_size,self.max_bytes-self.delivered))
            self.delivered+=len(data)
            self.CRC32=zlib.crc32(data,self.CRC32)
            if not data:
                self.eof=True
                if pending:yield self.parse_line(bytes(pending))
                return
            pending.extend(data)
            while True:
                end=pending.find(b'\n')
                if end<0:
                    if len(pending)>self.max_line:raise ReadLimit('RECORD_BYTE_LIMIT')
                    break
                if end+1>self.max_line:raise ReadLimit('RECORD_BYTE_LIMIT')
                raw=bytes(pending[:end+1]);del pending[:end+1]
                yield self.parse_line(raw)
    def parse_line(self, raw: bytes):
        self.guard();self.physical_lines+=1
        if self.attempts>=self.max_attempts:raise ReadLimit('EVENT_ATTEMPT_LIMIT')
        self.attempts+=1
        obj=json.loads(raw)
        if not isinstance(obj,dict):raise ValueError('TOP_LEVEL_NOT_EVENT_OBJECT')
        self.parsed+=1
        return self.physical_lines,raw,obj

def canonical_hash(obj: dict) -> str:
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def field_state(obj: dict, name: str) -> dict:
    if name not in obj:return {'status':'MISSING','path':'$.'+name}
    v=obj[name]
    return {'status':'NULL' if v is None else 'EMPTY' if v=='' or v==[] or v=={} else 'PRESENT',
            'path':'$.'+name,'type':type(v).__name__,'value':v}

def scoped_logon_key(host: str, boot: str, native_id: str):
    if not host or not boot or not native_id:return None
    return host.casefold(),boot,native_id.casefold()

def same_process(a: dict, b: dict) -> bool:
    return bool(a.get('host') and a.get('guid') and
                a['host'].casefold()==str(b.get('host','')).casefold() and
                a['guid'].casefold()==str(b.get('guid','')).casefold())

def receiver_direction(record_host: str, receiver_host: str, destination: str,
                       receiver_addresses: set, initiated) -> str:
    if isinstance(initiated,str):
        initiated={'true':True,'false':False}.get(initiated.casefold())
    if record_host.casefold()!=receiver_host.casefold():return 'OTHER_HOST_NOT_RECEIVER_PROOF'
    if initiated is False and destination in receiver_addresses:return 'RECORDED_INBOUND_ENDPOINT_ONLY'
    return 'UNRESOLVED_OR_NOT_INBOUND'

def a2_qualified(facts: dict) -> bool:
    required=('stable_instance','receiving_lifecycle','inbound_control','independent_B_binding',
              'raw_locator_verified','competitors_resolved')
    return all(facts.get(k) is True for k in required)

def explicit_utc(value: str):
    """Never infer an offset for an unzoned event time."""
    try:
        d=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    except (TypeError,ValueError):return None
    return d.astimezone(datetime.timezone.utc).isoformat() if d.tzinfo else None
