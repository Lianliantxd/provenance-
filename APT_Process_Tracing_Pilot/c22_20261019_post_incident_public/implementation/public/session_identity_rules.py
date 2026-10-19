"""Text-only native-field parsing and scoped identity checks, with no case values."""
import re
import uuid

CONTEXT_KEYS={'hostname','hostid','hostapplication','runspaceid','pipelineid','shellid',
              'user','connecteduser','sequencenumber','newenginestate','previousenginestate'}

def pid_number(value):
    if value is None:return None
    try:
        s=str(value).strip()
        return int(s,16) if s.casefold().startswith('0x') else int(s)
    except (TypeError,ValueError):return None

def valid_guid(value):
    try:
        v=uuid.UUID(str(value).strip('{}'))
        return str(v) if v.int else None
    except (ValueError,TypeError,AttributeError):return None

def windows_path(value):
    return re.sub(r'\\+',r'\\',str(value or '')).casefold()

def parse_context(text: str, source_path: str) -> dict:
    """Parse only complete named key=value lines in a declared context section."""
    if not isinstance(text,str):return {'status':'UNPARSED','fields':{},'reason':'not text'}
    out={};offset=0;conflicts=[]
    for number,line in enumerate(text.splitlines(keepends=True),1):
        m=re.fullmatch(r'[ \t]*([A-Za-z][A-Za-z ]*)[ \t]*=[ \t]*(.*?)[ \t]*(?:\r?\n)?',line)
        if m:
            key=m.group(1).replace(' ','').casefold()
            if key in CONTEXT_KEYS:
                v=m.group(2)
                entry={'value':v,'path':source_path,'line':number,'char_span':[offset+m.start(2),offset+m.end(2)],
                       'status':'EMPTY' if v=='' else 'PRESENT'}
                if key in out and out[key]['value']!=v:conflicts.append(key)
                else:out[key]=entry
        offset+=len(line)
    return {'status':'UNPARSED' if conflicts else 'PARSED_EXPLICIT_CONTEXT_LINES',
            'fields':out,'conflicts':conflicts,'source_path':source_path}

def creation_logon_id(event: dict, explicit_same_token_semantics: bool=False):
    """Missing target never falls back. Explicit zero needs separate semantic evidence."""
    target=pid_number(event.get('TargetLogonId'))
    if target not in [None,0]:return target
    if target==0 and explicit_same_token_semantics is True:
        return pid_number(event.get('SubjectLogonId'))
    return None

def process_creation_match(process: dict, audit: dict) -> bool:
    return (str(process.get('Hostname','')).casefold()==str(audit.get('Hostname','')).casefold()
            and pid_number(process.get('ProcessId'))==pid_number(audit.get('NewProcessId'))
            and windows_path(process.get('Image'))==windows_path(audit.get('NewProcessName'))
            and pid_number(process.get('ParentProcessId'))==pid_number(audit.get('ProcessId'))
            and pid_number(process.get('LogonId')) not in [None,0]
            and pid_number(process.get('LogonId'))==creation_logon_id(audit)
            and process.get('EventTime') is not None and process.get('EventTime')==audit.get('EventTime'))

def process_shell_match(process: dict, module: dict, context: dict, lifecycle_corrob: bool) -> bool:
    f=context.get('fields',{})
    def v(k):return f.get(k,{}).get('value')
    return (context.get('status')=='PARSED_EXPLICIT_CONTEXT_LINES'
            and module.get('SourceName')=='Microsoft-Windows-PowerShell' and int(module.get('EventID',0))==4103
            and str(process.get('Hostname','')).casefold()==str(module.get('Hostname','')).casefold()
            and pid_number(module.get('ExecutionProcessID')) not in [None,0]
            and pid_number(module.get('ExecutionProcessID'))==pid_number(process.get('ProcessId'))
            and windows_path(v('hostapplication'))==windows_path(process.get('CommandLine'))
            and v('hostname')=='ServerRemoteHost' and valid_guid(v('runspaceid')) is not None
            and valid_guid(v('hostid')) is not None and lifecycle_corrob is True)
