"""Case-independent temporal, identity and software access gates."""
import datetime
import os
import pathlib

def instant(value, declared_utc=False):
    if not value:return None
    try:
        d=datetime.datetime.fromisoformat(str(value).replace('Z','+00:00'))
    except ValueError:return None
    if d.tzinfo is None:
        if not declared_utc:return None
        d=d.replace(tzinfo=datetime.timezone.utc)
    return d.astimezone(datetime.timezone.utc)

def qualify_time(native, collection, lower, cutoff):
    if native is None:
        grade='TIME_DOMAIN_UNRESOLVED';retro=False
    elif native<lower:
        grade='OUTSIDE_FROZEN_WINDOW';retro=False
    elif native>cutoff:
        grade='POST_B';retro=False
    elif native==cutoff:
        grade='AT_B_ORDER_UNRESOLVED';retro=False
    else:
        retro=True
        grade=('NATIVE_PRE_B_AVAILABILITY_UNKNOWN' if collection is None else
               'STRICT_PRE_B_AND_AVAILABLE' if collection<=cutoff else 'REFERENCE_ONLY_POSTHOC')
    return {'grade':grade,'native_pre_B_proven':retro,'online_available':bool(retro and collection is not None and collection<=cutoff),
            'retrospective_event_time_eligible':retro,
            'collection_relation':'UNKNOWN' if collection is None else 'AFTER_B' if collection>cutoff else 'AT_OR_BEFORE_B'}

def instance_key(host, process_guid, host_id, runspace_id, lifecycle_scope):
    # Explicit scope prevents cross-host and reused-PID merging. Missing fields stay partial.
    return host.casefold(),process_guid or None,host_id,runspace_id,lifecycle_scope or None

def direct_join_count(parent_guid, candidates):
    return sum(bool(parent_guid) and c.get('receiver_ProcessGuid')==parent_guid for c in candidates)

def difficulty(candidates, parent_guid):
    n=len(candidates);joined=direct_join_count(parent_guid,candidates)
    return {'candidate_count':n,'direct_identity_join_candidate_count':joined,
            'direct_identity_join_triviality':'DIRECT_PARENT_IDENTITY_JOIN_SUFFICIENT' if joined==1 else 'NO_LEGAL_CANDIDATES' if n==0 else 'NOT_UNIQUELY_RESOLVED_BY_PARENT',
            'nontrivial_candidate_universe':bool(n>1 and joined!=1),'abstention_needed':joined!=1}

class SoftwareAccessGate:
    """Python audit/allowlist control, not an operating-system sandbox."""
    def __init__(self, root, allowed_reads):
        self.root=pathlib.Path(root).resolve();self.allowed_reads={str(pathlib.Path(p).resolve()) for p in allowed_reads}
        self.events=[];self.denied=[];self.sqlite_uri=None
    def audit(self,event,args):
        if event=='sqlite3.connect':
            uri=str(args[0]);ok=uri==self.sqlite_uri and uri.endswith('?mode=ro')
            entry={'operation':'sqlite_connect','path':uri,'allowed':ok};self.events.append(entry)
            if not ok:self.denied.append(entry);raise PermissionError('SQLite path not whitelisted')
        if event!='open' or not isinstance(args[0],(str,bytes,os.PathLike)):return
        p=pathlib.Path(os.fsdecode(args[0])).resolve();mode=args[1] or '';flags=args[2] or 0
        write=any(x in mode for x in 'wax+') or bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
        forbidden='reference_only' in p.parts
        if write:
            ok=not forbidden and self.root in p.parents and str(p) not in self.allowed_reads
        else:ok=not forbidden and str(p) in self.allowed_reads
        entry={'operation':'write' if write else 'read','path':str(p),'allowed':ok};self.events.append(entry)
        if not ok:self.denied.append(entry);raise PermissionError('Input path not whitelisted')
    def generated(self,p):self.allowed_reads.add(str(pathlib.Path(p).resolve()))
