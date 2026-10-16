import json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from c15_transport_compat import CompatParser,REASONS,VERSION
from jsonl_final_message_parser import JsonlParser,ParseFailure

def encoded(events):return ('\n'.join(json.dumps(e) for e in events)+'\n').encode()
def prefix():return [{'type':'thread.started','thread_id':'synthetic'}, {'type':'turn.started'}]
def end():return [{'type':'item.completed','item':{'id':'synthetic_message','type':'agent_message','text':'{}'}}, {'type':'turn.completed','usage':{}}]
def error(reason,index=2):return {'type':'error','message':f'Reconnecting... {index}/5 ({reason})'}

class TransportCompatTests(unittest.TestCase):
    def test_each_new_reason_can_recover_to_exact_canonical_reply(self):
        for reason in REASONS:
            with self.subTest(reason=reason):
                parser=CompatParser();parser.feed(encoded(prefix()+[error(reason)]+end()))
                self.assertEqual(parser.finish(b'{}',0)['status'],'CANONICAL_FINAL_VERIFIED')
    def test_old_parser_still_rejects_both_new_reasons(self):
        for reason in REASONS:
            parser=JsonlParser()
            with self.assertRaises(ParseFailure):parser.feed(encoded(prefix()+[error(reason)]))
    def test_unknown_auth_billing_tool_errors_still_stop(self):
        for reason in ['authentication failed','quota exhausted','workspace routing discovery timed out extra','unrecognized warning']:
            with self.assertRaises(ParseFailure):CompatParser().feed(encoded(prefix()+[error(reason)]))
        with self.assertRaises(ParseFailure):CompatParser().feed(encoded(prefix()+[{'type':'item.completed','item':{'id':'x','type':'command_execution'}}]))
    def test_retry_numbers_stay_bounded_and_monotonic(self):
        for indices in [(2,2),(2,1),(6,), (0,)]:
            with self.assertRaises(ParseFailure):CompatParser().feed(encoded(prefix()+[error(REASONS[0],i) for i in indices]))
    def test_error_before_turn_or_after_completion_still_stops(self):
        for seq in [[error(REASONS[0])],prefix()+end()+[error(REASONS[0])]]:
            with self.assertRaises(ParseFailure):CompatParser().feed(encoded(seq))
    def test_no_response_empty_or_nonzero_exit_cannot_pass(self):
        for body,raw,code in [(prefix()+[error(REASONS[0])],b'',0),(prefix()+end(),b'',0),(prefix()+end(),b'{}',1)]:
            parser=CompatParser();parser.feed(encoded(body))
            with self.assertRaises(ParseFailure):parser.finish(raw,code)
    def test_mismatched_final_message_still_stops(self):
        parser=CompatParser();parser.feed(encoded(prefix()+[error(REASONS[1])]+end()))
        with self.assertRaises(ParseFailure):parser.finish(b'{"different":1}',0)
    def test_only_known_fallback_after_valid_reconnect(self):
        fallback={'type':'item.completed','item':{'id':'warning','type':'error','message':'Falling back from WebSockets to HTTPS transport. '+REASONS[0]}}
        parser=CompatParser();parser.feed(encoded(prefix()+[error(REASONS[0]),fallback]+end()));self.assertTrue(parser.finish(b'{}',0)['https_fallback_observed'])
        for events in [prefix()+[fallback],prefix()+[error(REASONS[0]),fallback,fallback]]:
            with self.assertRaises(ParseFailure):CompatParser().feed(encoded(events))

if __name__=='__main__':unittest.main()
