"""Generic identity-scope query/context helpers; no case identifiers or payloads."""
COLS=('ord', 'block', 'inblock', 'offset_in_block', 'uuid', 'host', 'ns', 'event_type', 'subject', 'obj', 'obj2', 'path', 'path2')
SLOTS={"obj":"predicateObject","obj2":"predicateObject2"}
TYPES=("EVENT_OPEN","EVENT_READ","EVENT_CLOSE")
SQL={slot:"SELECT "+",".join(COLS)+" FROM events INDEXED BY event_subject WHERE subject=? AND host=? AND "+slot+"=? AND event_type IN (?,?,?)" for slot in SLOTS}

def key_for(a):return (a['host'],a['subject'],a['object'],a['object_index_slot'])


def compose_ok(index_number,ordinal,boundary):return (index_number==0 and ordinal<boundary) or (index_number==1 and ordinal>=boundary)


def point_query(db,key,slot):
 host,subject,obj,_=key
 return db.execute(SQL[slot],(subject,host,obj,*TYPES))


def raw_context_status(open_row,event_row,peer_opens,closes,role_status='SAME_ANCHOR_OBJECT_ROLE'):
 """Conservative within-scope context, never a unique handle-lifecycle claim."""
 if open_row is None or event_row is None:return 'RAW_CONTEXT_UNAVAILABLE','Complete raw context was not obtained'
 if role_status!='SAME_ANCHOR_OBJECT_ROLE':return 'SAME_IDENTITY_CANDIDATE','OTHER_ROLE_CANDIDATE; READ operand semantics not positively verified'
 od=open_row['datum'];ed=event_row['datum'];op=od.get('properties') or {};ep=ed.get('properties') or {}
 comparable=(open_row.get('hostId')==event_row.get('hostId') and od.get('subject')==ed.get('subject') and od.get('threadId') is not None and od.get('threadId')==ed.get('threadId') and isinstance(od.get('sequence'),int) and isinstance(ed.get('sequence'),int))
 if not comparable:return 'AMBIGUOUS_OPEN_ASSOCIATION','Sequence scope or thread/subject compatibility not established'
 if not isinstance(od.get('timestampNanos'),int) or not isinstance(ed.get('timestampNanos'),int):return 'AMBIGUOUS_OPEN_ASSOCIATION','Timestamp unavailable'
 if od['timestampNanos']>ed['timestampNanos'] or od['sequence']>=ed['sequence']:return 'TEMPORAL_OR_DESCRIPTOR_CONFLICT','OPEN occurs later by comparable sequence or timestamp; file ordinal not used'
 if op.get('ret_fd1') is None or ep.get('fd') is None:return 'AMBIGUOUS_OPEN_ASSOCIATION','Returned OPEN descriptor or operation fd is absent'
 if op['ret_fd1']!=ep['fd']:return 'TEMPORAL_OR_DESCRIPTOR_CONFLICT','OPEN ret_fd1 differs from operation fd; OPEN fd is not substituted'
 for close in closes:
  d=close['datum'];p=d.get('properties') or {}
  if close.get('hostId')==open_row.get('hostId') and d.get('subject')==od.get('subject') and d.get('threadId')==od.get('threadId') and p.get('fd')==op['ret_fd1'] and isinstance(d.get('sequence'),int) and od['sequence']<d['sequence']<ed['sequence'] and od['timestampNanos']<=d.get('timestampNanos',-1)<=ed['timestampNanos']:
   return 'TEMPORAL_OR_DESCRIPTOR_CONFLICT','An observed same-scope CLOSE lies between this OPEN and operation'
 possible=[];paths=set()
 for other in peer_opens:
  d=other['datum'];p=d.get('properties') or {}
  if d.get('predicateObjectPath'):paths.add(d['predicateObjectPath'])
  if other.get('hostId')==event_row.get('hostId') and d.get('subject')==ed.get('subject') and d.get('threadId')==ed.get('threadId') and isinstance(d.get('sequence'),int) and d['sequence']<ed['sequence'] and isinstance(d.get('timestampNanos'),int) and d['timestampNanos']<=ed['timestampNanos'] and p.get('ret_fd1')==ep.get('fd'):possible.append(other)
 if len(possible)>1:return 'AMBIGUOUS_OPEN_ASSOCIATION','Multiple compatible prior OPEN records; nearest one is not selected'
 if len(paths)>1:return 'AMBIGUOUS_OPEN_ASSOCIATION','Different OPEN paths in this identity scope; alias/version temporal applicability unresolved'
 return 'SUPPORTED_PRIOR_OPEN_CONTEXT','Same host/subject/thread, timestamp, sequence and returned descriptor support current-scope prior OPEN only'


