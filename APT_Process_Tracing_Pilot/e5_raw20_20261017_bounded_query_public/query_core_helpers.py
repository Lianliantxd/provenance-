"""Generic helpers used by the actual bounded diagnostic query runner."""

def statekey(s):return (s['host'],s['entity_type'],s['uuid'],s['cutoff'],s.get('scope_subject'),s.get('sequence'),s.get('threadId'),s['view'],s.get('operation_only',False))


def order_status(event,state,raw=None,explicit_creation=False):
 ns=event['ns'];cut=state['cutoff']
 if cut is None:return 'TIME_UNRESOLVED'
 if ns>cut:return 'TIME_CONFLICT'
 d=(raw or {}).get('datum') or {};same=(event['host']==state['host'] and event['subject']==state.get('scope_subject') and d.get('threadId') is not None and d.get('threadId')==state.get('threadId') and isinstance(d.get('sequence'),int) and isinstance(state.get('sequence'),int))
 if same and d['sequence']>=state['sequence']:return 'TIME_CONFLICT'
 if ns<cut:return 'ORDER_SUPPORTED'
 if explicit_creation:return 'ORDER_SUPPORTED'
 return 'ORDER_SUPPORTED' if same and d['sequence']<state['sequence'] else 'TIME_UNRESOLVED'


def path_kind(edges):
 if any(e['traversal_use']=='CANDIDATE_ONLY' or e['source_verification']=='UNVERIFIED_REQUIRED_FIELDS' or e['temporal_status']=='TIME_CONFLICT' for e in edges):return 'UNRESOLVED_CANDIDATE_PATH'
 if any(e['traversal_use']=='STRUCTURAL_ONLY' for e in edges):return 'STRUCTURAL_LINEAGE_PATH'
 if any(e['temporal_status']!='ORDER_SUPPORTED' for e in edges):return 'UNRESOLVED_CANDIDATE_PATH'
 return 'ORDERED_DEPENDENCY_MODEL_PATH'


def exec_boundary_crossed(input_event,input_raw,state,exec_events,raw_cache):
 for boundary in exec_events:
  if boundary['ord']==input_event['ord'] or boundary['ns']<input_event['ns']:continue
  br=raw_cache.get(boundary['ord'])
  if order_status(boundary,state,br)=='TIME_CONFLICT':continue
  if boundary['ns']>input_event['ns']:return True
  bd=(br or {}).get('datum',{});d=input_raw.get('datum',{})
  if bd.get('threadId')==d.get('threadId') and isinstance(bd.get('sequence'),int) and isinstance(d.get('sequence'),int):
   if bd['sequence']>d['sequence']:return True
  else:return True
 return False


