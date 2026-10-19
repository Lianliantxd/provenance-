import hashlib,json,pathlib,sys,unittest,uuid
R=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'public'))
from ps_context_sections_v2 import diagnostic_context
from session_identity_rules import valid_guid

def identifier(n):return str(uuid.UUID(int=n))
def event(body,details='benign synthetic text'):
    return {'SourceName':'PowerShell','EventID':800,'Message':'Header\r\nContext Information:\r\n'+body+'\r\nDetails:\r\n'+details}
class PostReadControls(unittest.TestCase):
    def test_800_named_context_before_details(self):
        c=diagnostic_context(event('RunspaceId='+identifier(1)+'\nHostId='+identifier(2)));self.assertEqual(valid_guid(c['fields']['runspaceid']['value']),identifier(1))
    def test_details_payload_not_identity(self):
        c=diagnostic_context(event('RunspaceId='+identifier(1),'RunspaceId='+identifier(9)));self.assertEqual(valid_guid(c['fields']['runspaceid']['value']),identifier(1))
    def test_missing_heading_no_payload_mining(self):
        e=event('RunspaceId='+identifier(1));e['Message']=e['Message'].replace('Context Information:','Other:');self.assertEqual(diagnostic_context(e)['status'],'UNPARSED')
    def test_empty_identity_not_next_line(self):
        c=diagnostic_context(event('RunspaceId=\nHostId='+identifier(2)));self.assertEqual(c['fields']['runspaceid']['status'],'EMPTY');self.assertEqual(c['fields']['hostid']['value'],identifier(2))
    def test_conflicting_native_context_stays_unparsed(self):
        c=diagnostic_context(event('RunspaceId='+identifier(1)+'\nRunspaceId='+identifier(2)));self.assertEqual(c['status'],'UNPARSED')
    def test_source_spans_point_into_original_message(self):
        e=event('RunspaceId='+identifier(1));c=diagnostic_context(e);p=c['fields']['runspaceid']['char_span'];self.assertEqual(e['Message'][p[0]:p[1]],identifier(1))
    def test_completed_read_is_one_actual_attempt_no_restart(self):
        p=R/'source_receipts/NATIVE_EXTRACTION_RECEIPT.json'
        if not p.exists():self.skipTest('No real read receipt in generic public package')
        d=json.loads(p.read_text());self.assertEqual(d['ZIP_replays_reserved'],1);self.assertEqual(d['saved_targets'],206);self.assertTrue(d['member_EOF_reached']);self.assertTrue(d['member_CRC_verified'])
    def test_original_runtime_files_still_frozen(self):
        p=R/'source_receipts/PRE_READ_HASHES.json'
        if not p.exists():self.skipTest('No private runtime inputs in public package')
        for rel,h in json.loads(p.read_text())['files'].items():self.assertEqual(hashlib.sha256((R/rel).read_bytes()).hexdigest(),h,rel)
