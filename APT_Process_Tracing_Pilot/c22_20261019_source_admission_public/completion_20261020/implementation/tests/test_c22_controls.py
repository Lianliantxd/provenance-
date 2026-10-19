import copy,datetime,hashlib,io,json,pathlib,subprocess,sys,tempfile,unittest,uuid
R=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(R/'public'));sys.path.insert(0,str(R/'scripts'))
from post_incident_rules import utc,native_time,time_relation,build_candidates,baseline,difficulty,context
from session_identity_rules import creation_logon_id,process_creation_match,valid_guid
from native_stream_support import JsonlReader,ReadLimit
from access_gate import SoftwareAccessGate
from extract_native_once import verify_target

def guid(n):return str(uuid.UUID(int=n))
def cfg():return {'host':'h','historical_lower':'2020-01-01T00:00:00Z','T_B':'2020-01-01T00:30:00.500Z'}
def context_event(idx=1,pid=7,host='h',run=1,hostid=2):
    text='Runspace ID = '+guid(run)+'\nHost ID = '+guid(hostid)+'\nHost Name = ServerRemoteHost\nHost Application = receiver -Embedding\nSequence Number = 16\n'
    return {'idx':idx,'event':{'Hostname':host,'SourceName':'Microsoft-Windows-PowerShell','EventID':4103,'ExecutionProcessID':pid,'ContextInfo':text,'EventTime':'2020-01-01 00:29:00','@timestamp':'2020-01-01T01:00:00Z'}}
def process(idx=2,pid=7,g=3):
    return {'idx':idx,'event':{'Hostname':'h','SourceName':'Microsoft-Windows-Sysmon','EventID':1,'ProcessGuid':guid(g),'ProcessId':pid,'ParentProcessId':4,'Image':'receiver','CommandLine':'receiver -Embedding','LogonId':'0x42','EventTime':'2020-01-01 00:29:00','UtcTime':'2020-01-01 00:29:00.100'}}
def audit(idx=3,pid=7):
    return {'idx':idx,'event':{'Hostname':'h','SourceName':'Microsoft-Windows-Security-Auditing','EventID':4688,'NewProcessId':pid,'ProcessId':4,'NewProcessName':'receiver','TargetLogonId':'0x42','SubjectLogonId':'0x99','EventTime':'2020-01-01 00:29:00'}}
def candidate(n=1,g=3,historical=True):
    return {'candidate_id':str(n),'identity':{'host':'h','receiverProcessGuid':guid(g),'HostId':guid(2),'RunspaceId':guid(n)},'identity_complete':True,'historical_causal_eligibility':historical,'receiver':{'historical_creation_relation':'NATIVE_PRE_B'}}
class Controls(unittest.TestCase):
    def test_reference_access_denied(self):
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d);p=r/'reference_only/A_instance_private.json';gate=SoftwareAccessGate(r,[p])
            with self.assertRaises(PermissionError):gate.audit('open',(str(p),'r',0))
    def test_reference_replacement_invariance(self):
        records=[context_event(),process(),audit()];a=build_candidates(records,cfg())
        # Neither evaluator answer can enter function/config. Replacement is external only.
        for answer in [guid(17),guid(99)]:self.assertEqual(a,build_candidates(copy.deepcopy(records),cfg()))
    def test_uniform_fields(self):
        cs=build_candidates([context_event(),context_event(4,hostid=5,run=6),process(),audit()],cfg())
        self.assertEqual(len(cs),2);self.assertEqual(set(cs[0]),set(cs[1]))
    def test_missing_ids_not_invented(self):
        r=context_event();r['event']['ContextInfo']='Runspace ID = '+guid(1)
        c=build_candidates([r],cfg())[0];self.assertIsNone(c['identity']['HostId']);self.assertIsNone(c['identity']['receiverProcessGuid']);self.assertEqual(c['candidate_class'],'PARTIAL_RUNSPACE_INSTANCE')
    def test_cross_host_not_merge(self):
        cs=build_candidates([context_event(),context_event(2,host='another')],cfg());self.assertEqual(len(cs),1);self.assertEqual(cs[0]['observed_original_indices'],[1])
        other=cfg();other['host']='another';self.assertNotEqual(cs[0]['candidate_id'],build_candidates([context_event(2,host='another')],other)[0]['candidate_id'])
    def test_reused_pid_lifetimes_ambiguous(self):
        cs=build_candidates([context_event(),process(),process(4,g=4),audit()],cfg())
        self.assertIsNone(cs[0]['receiver']);self.assertEqual(len(cs[0]['possible_receiver_lifecycles']),2)
    def test_hostid_not_shell_configuration(self):
        r=context_event();r['event']['ContextInfo']='Runspace ID = '+guid(1)+'\nShell ID = Microsoft.PowerShell'
        self.assertIsNone(build_candidates([r],cfg())[0]['identity']['HostId'])
    def test_event_time_not_collection(self):
        e=context_event()['event'];t=native_time(e);self.assertIsNone(t['utc']);self.assertEqual(t['collection_time'],e['@timestamp'])
    def test_posthoc_not_causal(self):
        c=build_candidates([context_event(),process(),audit()],cfg())[0]
        self.assertTrue(c['identity_complete']);self.assertFalse(c['historical_causal_eligibility']);self.assertEqual(c['candidate_class'],'POSTHOC_CONTEXT_ONLY')
    def test_no_four_hour_fit(self):
        self.assertIsNone(utc('2020-05-02 04:18:37'));self.assertEqual(native_time({'SourceName':'PowerShell','EventTime':'2020-05-02 04:18:37'})['timezone_status'],'NATIVE_TIMEZONE_UNRESOLVED')
    def test_same_second_order_unresolved(self):
        t=native_time({'EventTime':'2020-01-01T00:30:00Z'});self.assertEqual(time_relation(t,cfg()['historical_lower'],cfg()['T_B']),'SAME_SECOND_ORDER_UNRESOLVED')
    def test_post_b_context_not_origin(self):
        r=context_event();r['event']['TimeCreated']='2020-01-01T00:31:00Z'
        c=build_candidates([r,process(),audit()],cfg())[0];self.assertFalse(c['historical_causal_eligibility']);self.assertTrue(c['post_B_only_known'])
    def test_4688_roles_no_missing_target_fallback(self):
        self.assertIsNone(creation_logon_id({'SubjectLogonId':'0x42'}));self.assertEqual(creation_logon_id({'TargetLogonId':'0x42','SubjectLogonId':'0x99'}),66)
        self.assertIsNone(creation_logon_id({'TargetLogonId':'0x0','SubjectLogonId':'0x42'}));self.assertEqual(creation_logon_id({'TargetLogonId':'0x0','SubjectLogonId':'0x42'},True),66)
    def test_creator_not_target(self):
        a=audit();a['event'].pop('TargetLogonId');a['event']['SubjectLogonId']='0x42';self.assertFalse(process_creation_match(process()['event'],a['event']))
    def test_parent_used_only_baseline(self):
        self.assertNotIn('ParentProcessGuid',json.dumps(cfg()));a=build_candidates([context_event(),process(),audit()],cfg());b={'Hostname':'h','ParentProcessGuid':guid(3)};before=copy.deepcopy(a);baseline(b,a,False,False);self.assertEqual(before,a)
    def test_baseline_all_ties(self):
        result=baseline({'Hostname':'h','ParentProcessGuid':guid(3)},[candidate(1),candidate(2)],True,True)
        self.assertEqual(result['matched_candidate_ids'],['1','2']);self.assertEqual(result['join_result'],'MULTIPLE_DIRECT_IDENTITY_MATCHES')
    def test_wrong_host_not_join(self):
        c=candidate();c['identity']['host']='another';self.assertEqual(baseline({'Hostname':'h','ParentProcessGuid':guid(3)},[c],True,True)['identity_join_match_count'],0)
    def test_competitors_not_benign(self):
        self.assertEqual(build_candidates([context_event()],cfg())[0]['competitor_label'],'UNLABELED_COMPETITOR')
    def test_no_metrics_when_ineligible(self):
        b=baseline({'Hostname':'h','ParentProcessGuid':guid(3)},[candidate(historical=False)],False,False);self.assertEqual(b['evaluation_state'],'BASELINE_NOT_EVALUABLE');self.assertFalse(b['source_metrics_generated']);self.assertFalse(b['path_metrics_generated'])
    def test_trivial_not_multihop_innovation(self):
        b=baseline({'Hostname':'h','ParentProcessGuid':guid(3)},[candidate()],True,True);self.assertEqual(difficulty(b,True),'DIRECT_PARENT_JOIN_SOLVES_CASE_NO_MULTIHOP_INNOVATION')
    def test_reference_not_generation_argument(self):
        with self.assertRaises(TypeError):build_candidates([],cfg(),reference=guid(1))
    def test_zero_logger_pid_not_receiver(self):
        r=context_event(pid=0);self.assertIsNone(build_candidates([r,process(),audit()],cfg())[0]['receiver'])
    def test_byte_budget_counts_nontargets(self):
        reader=JsonlReader(io.BytesIO(b'{"a":1}\n{"b":2}\n'),10,10,10)
        with self.assertRaises(ReadLimit):list(reader)
        self.assertEqual(reader.delivered,10);self.assertEqual(reader.attempts,1)
    def test_attempt_budget_counts_all(self):
        reader=JsonlReader(io.BytesIO(b'{}\n{}\n'),100,1,10)
        with self.assertRaises(ReadLimit):list(reader)
        self.assertEqual(reader.attempts,1);self.assertFalse(reader.eof)
    def test_eof_crc_actual(self):
        import zlib
        data=b'{"a":"unicode"}\n';reader=JsonlReader(io.BytesIO(data),100,10,10);list(reader);self.assertTrue(reader.eof);self.assertEqual(reader.CRC32,zlib.crc32(data))
    def test_locator_rejects_changed_raw(self):
        d={'EventID':1,'SourceName':'test'}
        with self.assertRaises(ValueError):verify_target(d,b'bad',{'raw_sha':'0'*64})
    def test_extractor_fails_before_member_read_without_approval(self):
        p=subprocess.run([sys.executable,'-B',str(R/'scripts/extract_native_once.py')],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(p.returncode,0);self.assertIn('C22_NATIVE_READ_AUTHORIZATION_PENDING',p.stderr);self.assertFalse((R/'logs/NATIVE_REPLAY_STARTED.json').exists())
class RevisedContractControls(unittest.TestCase):
    def test_posthoc_join_kept_without_causal_promotion(self):
        b=baseline({'Hostname':'h','ParentProcessGuid':guid(3)},[candidate(historical=False)],False,False)
        self.assertEqual(b['identity_join_match_count'],1);self.assertEqual(b['join_result'],'UNIQUE_DIRECT_IDENTITY_MATCH');self.assertEqual(b['historical_eligible_candidate_count'],0);self.assertEqual(b['evaluation_state'],'BASELINE_NOT_EVALUABLE')
    def test_explicit_ended_lifetime_rejected(self):
        c=candidate();c['receiver']['termination']=[{'time':{'utc':'2020-01-01T00:29:00Z'}}]
        b={'Hostname':'h','ParentProcessGuid':guid(3),'SourceName':'Microsoft-Windows-Sysmon','UtcTime':'2020-01-01 00:30:00.500'}
        self.assertEqual(baseline(b,[c],True,True)['identity_join_match_count'],0)
    def test_explicit_future_creation_rejected(self):
        c=candidate();c['receiver']['creation_time']={'utc':'2020-01-01T00:31:00Z'}
        b={'Hostname':'h','ParentProcessGuid':guid(3),'SourceName':'Microsoft-Windows-Sysmon','UtcTime':'2020-01-01 00:30:00.500'}
        self.assertEqual(baseline(b,[c],True,True)['identity_join_match_count'],0)
    def test_unresolved_session_ledger_is_part_of_freeze(self):
        s=(R/'scripts/build_candidates.py').read_text()
        self.assertIn('SESSION_EVENT_RESOLUTION_PRIVATE.jsonl',s);self.assertIn('UNRESOLVED_SESSION_EVENT',s)
    def test_session_reference_not_transport_reference(self):
        source={'A_reference_level':'A2_REMOTE_EXECUTION_SESSION','A2_TRANSPORT_CONNECTION':False,'INITIATOR_ENDPOINT_BOUND':False}
        self.assertFalse(source['A2_TRANSPORT_CONNECTION']);self.assertFalse(source['INITIATOR_ENDPOINT_BOUND'])
if __name__=='__main__':unittest.main()
