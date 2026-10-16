"""Small postscore structural / plot adapter; no Gold reads or reevaluation."""
from __future__ import annotations
import argparse,collections,csv,importlib.metadata,os,sys
from pathlib import Path
from analyze_reflection_snapshots import UNITS,read,write,table,chain_mapping,citation_ids,sha,canon,utc

def run(root:Path)->None:
 rows=[]
 for uid in UNITS:
  d=root/'private_snapshots'/uid;snaps={s:read(d/(s+'.json')) for s in ['PRE_REFLECTION','POST_MODEL_RAW']};evals={s:read(d/(s+'_official_evaluation.json')) for s in snaps};before,after=snaps.values();eb,ea=evals.values()
  b_gold={x['gold_index'] for x in eb['best_matches']};a_gold={x['gold_index'] for x in ea['best_matches']}
  relations={s:dict(collections.Counter(e['relation'] for e in c['causal_edges'])) for s,c in snaps.items()}
  # Candidate identity mapping may be ambiguous; never turn that into certain edge deletion.
  mapping=chain_mapping(before,after);unique={x['before_id']:x['candidates'][0]['after_id'] for x in mapping['rows'] if len(x['candidates'])==1};after_edges={(e['source'],e['target']) for e in after['causal_edges']};resolved=[]
  for i,e in enumerate(before['causal_edges']):
   mapped=(unique.get(e['source']),unique.get(e['target']))
   resolved.append({'before_edge_index':i,'before_edge':e,'candidate_mapped_endpoints':mapped,'status':'AMBIGUOUS_OR_UNAVAILABLE_STEP_IDENTITY' if None in mapped else 'CANDIDATE_ENDPOINT_PAIR_RETAINED' if mapped in after_edges else 'CANDIDATE_ENDPOINT_PAIR_NOT_PRESENT','semantic_causal_truth':'NOT_IDENTIFIABLE'})
  detail={'run_unit_id':uid,'matched_gold_indices_before':sorted(b_gold),'matched_gold_indices_after':sorted(a_gold),'matched_gold_indices_gained':sorted(a_gold-b_gold),'matched_gold_indices_lost':sorted(b_gold-a_gold),'relations':relations,'edge_candidate_mapping':resolved,'step_mapping':mapping}
  write(root,f'private_snapshots/{uid}/edge_and_match_identity_audit_private.json',detail)
  rows.append({'run_unit_id':uid,'matched_gold_steps_retained':len(a_gold&b_gold),'matched_gold_steps_gained':len(a_gold-b_gold),'matched_gold_steps_lost':len(b_gold-a_gold),'edge_relations_before':relations['PRE_REFLECTION'],'edge_relations_after':relations['POST_MODEL_RAW'],'before_edges_ambiguous_identity':sum(x['status']=='AMBIGUOUS_OR_UNAVAILABLE_STEP_IDENTITY' for x in resolved),'before_edges_candidate_pair_retained':sum(x['status']=='CANDIDATE_ENDPOINT_PAIR_RETAINED' for x in resolved),'before_edges_candidate_pair_not_present':sum(x['status']=='CANDIDATE_ENDPOINT_PAIR_NOT_PRESENT' for x in resolved),'edge_mapping_limit':'Exact-reference/text candidates only; topology != real causality; official edge metric does not score relation/supporting_evidence'})
 table(root,'12_edge_and_match_structure_summary.csv',rows)
 try:import matplotlib
 except ImportError:
  write(root,'logs/plot_status.json',{'state':'PLOT_UNAVAILABLE_NO_INSTALL','new_model_calls':0});return
 matplotlib.use('Agg');os.environ['MPLCONFIGDIR']=str(root/'cache/matplotlib');import matplotlib.pyplot as plt
 metrics=list(csv.DictReader((root/'05_snapshot_metrics.csv').open()));idx={(x['run_unit_id'],x['stage']):x for x in metrics};colors=['#1d4ed8','#60a5fa','#047857','#34d399','#9333ea'];figs=root/'figures';figs.mkdir(mode=0o700,exist_ok=True)
 def save(fig:object,name:str)->None:
  for ext in ['pdf','png']:
   p=figs/(name+'.'+ext)
   if p.exists():raise ValueError('NO_PLOT_OVERWRITE')
   fig.savefig(p,dpi=180,bbox_inches='tight',metadata={'Creator':'C15-S offline aggregate plotting'})
   p.chmod(0o600)
  plt.close(fig)
 fig,ax=plt.subplots(figsize=(7.2,4.5))
 for uid,c in zip(UNITS,colors):
  y=[float(idx[uid,s]['bestmatch_step_f1']) for s in ['PRE_REFLECTION','POST_MODEL_RAW']];ax.plot([0,1],y,marker='o',label=uid,color=c,linewidth=2)
 ax.set_xticks([0,1],['Actual PRE','Consumed POST = FINAL']);ax.set_ylim(0,1);ax.set_ylabel('Official bestmatch_step_f1');ax.set_title('Five accepted Reflection revisions (posthoc)');ax.grid(axis='y',alpha=.2);ax.legend(loc='upper left',bbox_to_anchor=(1.01,1),frameon=False);fig.text(.02,-.02,'Three exposed cases; selected successful paths. No aggregate effect or error bars.',fontsize=9);save(fig,'figure-01-within-run-step-f1')
 fig,axes=plt.subplots(1,2,figsize=(10,4.2),sharex=True)
 for ax,key,title in zip(axes,['n_pred_steps','bestmatch_matched_steps'],['Output steps','Official matched steps']):
  for uid,c in zip(UNITS,colors):ax.plot([0,1],[float(idx[uid,s][key]) for s in ['PRE_REFLECTION','POST_MODEL_RAW']],marker='o',label=uid,color=c)
  ax.set_xticks([0,1],['PRE','POST']);ax.set_title(title);ax.set_ylabel('Count');ax.set_ylim(bottom=0);ax.grid(axis='y',alpha=.2)
 axes[1].legend(loc='upper left',bbox_to_anchor=(1.01,1),frameon=False);fig.text(.02,-.02,'More output is not always more reference matches. Lines are within-run diagnostics, not independent cases.',fontsize=9);save(fig,'figure-02-output-and-matched-counts')
 write(root,'logs/plot_status.json',{'state':'PLOTS_COMPLETE','python':sys.executable,'matplotlib':matplotlib.__version__,'matplotlib_module_sha256':sha(Path(matplotlib.__file__)),'adapter_sha256':sha(Path(__file__)),'utc':utc(),'new_model_calls':0,'Gold_read':False})
 print(canon({'state':'STRUCTURE_AND_PLOTS_COMPLETE','runs':5}))
if __name__=='__main__':
 os.umask(0o077);sys.dont_write_bytecode=True;p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);run(p.parse_args().root)
