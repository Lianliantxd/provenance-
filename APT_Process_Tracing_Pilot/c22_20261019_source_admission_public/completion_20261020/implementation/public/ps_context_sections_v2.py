"""Versioned diagnostic fix: parse the named context section before Details for EID800.
This helper is not substituted into the frozen candidate generator.
"""
import re
from session_identity_rules import parse_context
from post_incident_rules import context

def diagnostic_context(event: dict) -> dict:
    provider=event.get('SourceName',event.get('ProviderName'))
    if provider!='PowerShell' or int(event.get('EventID',0))!=800:return context(event)
    msg=event.get('Message')
    if not isinstance(msg,str):return {'status':'UNPARSED','fields':{},'reason':'MISSING_MESSAGE'}
    start=re.search(r'(?im)^[ \t]*Context Information:[ \t]*\r?\n',msg)
    if not start:return {'status':'UNPARSED','fields':{},'reason':'NO_DECLARED_CONTEXT_SECTION'}
    end=re.search(r'(?im)^[ \t]*Details:[ \t]*(?:\r?\n|$)',msg[start.end():])
    if not end:return {'status':'UNPARSED','fields':{},'reason':'NO_DECLARED_SECTION_END'}
    first=start.end();last=first+end.start()
    result=parse_context(msg[first:last],'$.Message.Context Information')
    result['section_span_in_Message']=[first,last]
    for field in result['fields'].values():field['char_span']=[n+first for n in field['char_span']]
    result['version']='SECTION_SELECTION_DIAGNOSTIC_V2_NOT_FROZEN_METHOD'
    return result
