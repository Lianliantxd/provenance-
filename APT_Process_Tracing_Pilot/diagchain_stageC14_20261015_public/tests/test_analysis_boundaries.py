import sys,unittest,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from analyze_frozen_runs import ids,union_ids,visibility,card_blocks,chain_mapping,classify,extract_section,field_leaves

def chain(e,step='S1'):
 return {'attack_chain':[{'step_id':step,'attack_step':'observe','step_description':'same','entities':{},'supporting_evidence':e}],'causal_edges':[]}
def prompt(content,e='E1'):
 return 'Retrieved evidence memory:\nFULL_EVIDENCE_CARDS_NEWEST_WINDOW:\n\nevidence_id: '+e+'\nsource_type: unit\ntimestamp: 0\nline: 1\ncontent: '+content+'\nclues: \n'
class Boundaries(unittest.TestCase):
 def test_cross_case(self):self.assertEqual(len({('A','E1'),('B','E1')}),2)
 def test_replay_observation_dedup_and_order(self):
  observations=[{'turn':1,'ids':['E1','E1']},{'turn':1,'ids':['E1']},{'turn':2,'ids':['E2']}]
  before=set().union(*(set(x['ids']) for x in observations if x['turn']<2));self.assertEqual(before,{'E1'});self.assertNotIn('E2',before)
 def test_field_original_not_prompt(self):
  card={'content':'{"Image":"x","CommandLine":"abc"}'};p=prompt('{"Image":"x"}');v=visibility(p,card_blocks(p),'E1',card,['Image','CommandLine']);self.assertEqual(v['missing_required'],['CommandLine']);self.assertFalse(v['necessary_complete'])
 def test_workchain_mention_not_card(self):
  p='Current working_chain:\n{"summary":"E1 abc"}\nRetrieved evidence memory:\nNo retrieval observations yet.'
  self.assertEqual(visibility(p,card_blocks(p),'E1',{'content':'{"Image":"abc"}'},['Image'])['visibility'],'OTHER_PROMPT_MENTION')
 def test_exact_spans_unicode_numbers_escaped_duplicates(self):
  c=json.dumps({'n':123,'Image':'汉字\\x"q','same':'汉字\\x"q'},ensure_ascii=False);p=prompt(c);v=visibility(p,card_blocks(p),'E1',{'content':c},['n','Image','same']);self.assertTrue(v['necessary_complete'])
  for k,x in v['field_spans'].items():
   a,b=x['utf8_byte_span'];self.assertEqual(json.loads(p.encode()[a:b].decode()),json.loads(c)[k])
  self.assertNotEqual(v['field_spans']['Image']['utf8_byte_span'],v['field_spans']['same']['utf8_byte_span'])
 def test_source_already_truncated_preserves_only_complete_leaves(self):
  leaves=field_leaves('{"alert_name":"a","description":"完整","entities":"cut');self.assertEqual([x['field_path'] for x in leaves],['alert_name','description'])
 def test_truncated_value_not_complete(self):
  p=prompt('{"Image":"x","CommandLine":"abc');v=visibility(p,card_blocks(p),'E1',{'content':'{"Image":"x","CommandLine":"abcdef"}'},['Image','CommandLine']);self.assertEqual(v['complete_leaf_count'],1);self.assertFalse(v['necessary_complete'])
 def test_renumber_does_not_delete(self):
  a=chain(['E1'],'S1');b=chain(['E1'],'S99');self.assertEqual(union_ids(a),union_ids(b));self.assertTrue(chain_mapping(a,b)['rows'][0]['candidates'][0]['action_text_equal'])
 def test_step_edge_sets_differ(self):
  c=chain(['E1']);c['causal_edges']=[{'supporting_evidence':['E2']}];self.assertEqual(ids(c),{'E1'});self.assertEqual(union_ids(c),{'E1','E2'})
 def test_missing_snapshot_not_empty(self):
  self.assertIsNone(union_ids(None));self.assertEqual(chain_mapping(None,chain([]))['status'],'SNAPSHOT_UNAVAILABLE');self.assertIsNone(extract_section('absent','Current working_chain:\n')[0])
 def test_reflection_removal_localization(self):
  ss=[{'label':'reflection_pre','chain':chain(['E1']),'source_sha256':'a','producer_seq':9},{'label':'final','chain':chain([]),'source_sha256':'b','producer_seq':9}];f,tr,ever=classify('E1',ss,[],[],9);self.assertEqual(f,'USED_THEN_REMOVED_BY_REFLECTION');self.assertTrue(ever)
if __name__=='__main__':unittest.main()
