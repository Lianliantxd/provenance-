"""Synthetic offline boundary tests only; no service/model simulation."""
import copy,importlib.util,json,sys,unittest
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'scripts/analyze_reflection_snapshots.py'
spec=importlib.util.spec_from_file_location('analysis',p);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class Boundaries(unittest.TestCase):
 def prompt(self,obj):return '中文前缀🌍\n'+a.MARKER+json.dumps(obj,ensure_ascii=False)+a.END+'card data'
 def test_nested_unicode_span(self):
  obj={'attack_chain':[{'step_description':'嵌套 " { } \\ 🌍','supporting_evidence':['E1']}],'causal_edges':[]};t=self.prompt(obj);v,span=a.extract_pre(t);self.assertEqual(v,obj);self.assertEqual(a.loads(t.encode()[slice(*span['utf8_span'])].decode()),obj)
 def test_duplicate_markers_rejected(self):
  with self.assertRaises(ValueError):a.extract_pre(self.prompt({})+self.prompt({}))
 def test_boundary_required(self):
  with self.assertRaises(ValueError):a.extract_pre(a.MARKER+'{} wrong trailing')
 def test_partial_json_not_completed(self):
  with self.assertRaises(ValueError):a.extract_pre(a.MARKER+'{"attack_chain":['+a.END)
 def test_duplicate_keys(self):
  with self.assertRaises(ValueError):a.extract_post('{"working_chain":{},"working_chain":{}}')
 def test_post_nested_reflection(self):
  v,_=a.extract_post('{"reflection":{"message":"{ working_chain }"},"working_chain":{"incident_summary":"值"}}');self.assertEqual(v,{'incident_summary':'值'})
 def test_two_messages_not_concatenated(self):
  with self.assertRaises(ValueError):a.extract_post('{"working_chain":{}}\n{"working_chain":{}}')
 def test_missing_snapshot_not_empty(self):self.assertIsNone(a.citation_ids(None));self.assertEqual(a.chain_mapping(None,{}),{'status':'SNAPSHOT_UNAVAILABLE'})
 def test_case_isolation(self):
  c={'attack_chain':[{'supporting_evidence':['E1','E1']} ]};self.assertFalse(a.citation_ids(c,case_id='A')&a.citation_ids(c,case_id='B'));self.assertEqual(len(a.citation_ids(c,case_id='A')),1)
 def test_renumbering_not_removed_reference(self):
  v={'attack_chain':[{'step_id':'S1','order':1,'attack_step':'a','step_description':'b','supporting_evidence':['E1']}]};w=copy.deepcopy(v);w['attack_chain'][0].update(step_id='S9',order=9);m=a.chain_mapping(v,w);self.assertTrue(m['rows'][0]['candidates'][0]['exact_ignoring_step_id_and_order']);self.assertEqual(a.citation_ids(v),a.citation_ids(w))
 def test_ambiguous_mapping_retained(self):
  b={'attack_chain':[{'supporting_evidence':['E1'],'attack_step':'a','step_description':'b'}]};c={'attack_chain':b['attack_chain']*2};self.assertEqual(a.chain_mapping(b,c)['rows'][0]['status'],'AMBIGUOUS_MAPPING')
 def test_metadata_not_inherited_or_semantics_ignored(self):
  pre={'incident_summary':'a'};post={'incident_summary':'b','metadata':{'retrieved':100}};self.assertEqual(a.semantic(pre),pre);self.assertNotEqual(a.semantic(pre),a.semantic(post));self.assertNotIn('metadata',pre)
 def exchange(self):
  u={'run_id':'r','attempt_id':'a','case_id':'c','seq':7};q={**u,'phase':'reflection','prompt_utf8':'text','prompt_sha256':a.digest('text')};v={**q,'raw_reply_utf8':'reply','reply_sha256':a.digest('reply')};pr={'reply_sha256':v['reply_sha256'],'messages_concatenated':False,'status':'CANONICAL_FINAL_VERIFIED','selection':'EXACT_LAST_COMPLETED_MESSAGE_MATCHES_CANONICAL_FILE','selected_message_id':'last','completed_message_count':2};ack={'reply_sha256':v['reply_sha256'],'state':'SERVER_ACCEPTED'};cons={**u,'phase':'reflection','prompt_sha256':q['prompt_sha256'],'reply_sha256':v['reply_sha256']};return u,q,v,'reply',pr,ack,cons
 def test_multiple_messages_only_frozen_last(self):a.verify_exchange(*self.exchange())
 def test_wrong_run_rejected(self):
  args=list(self.exchange());args[1]['run_id']='wrong'
  with self.assertRaises(ValueError):a.verify_exchange(*args)
 def test_repair_cannot_be_reflection(self):
  args=list(self.exchange());args[1]['phase']='repair'
  with self.assertRaises(ValueError):a.verify_exchange(*args)
 def test_earlier_message_cannot_substitute_final(self):
  args=list(self.exchange());args[3]='earlier'
  with self.assertRaises(ValueError):a.verify_exchange(*args)
 def test_final_score_tolerance(self):
  self.assertTrue(a.scalar_equal(.8,.8+1e-11));self.assertFalse(a.scalar_equal(.8,.81));self.assertFalse(a.scalar_equal(float('nan'),float('nan')))
if __name__=='__main__':unittest.main()
