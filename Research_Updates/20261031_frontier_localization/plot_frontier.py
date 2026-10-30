"""Descriptive figures for finite context reachability, not attack recovery."""
from pathlib import Path
import argparse
import csv
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True)
    root=ap.parse_args().root.resolve();out=root/'figures';out.mkdir(exist_ok=False)
    profiles={int(x['mask']):x for x in csv.DictReader((root/'artifacts/CONDITION_PROFILES.csv').open())}
    masks=[0,11,4,15];labels=['Original','K / gap / hops\nrelaxed','Tie context\nonly','All four\nrelaxed']
    counts=[int(profiles[m]['reference_nodes_reachable']) for m in masks]
    events=[int(profiles[m]['reachable_events']) for m in masks]
    plt.rcParams.update({'font.size':10,'pdf.fonttype':42,'axes.spines.top':False,
                         'axes.spines.right':False,'savefig.bbox':'tight'})
    colors=['#657784','#a1a8ae','#b4774d','#397e78']
    fig,axes=plt.subplots(1,2,figsize=(11,4.2))
    axes[0].bar(labels,counts,color=colors)
    for i,v in enumerate(counts):axes[0].text(i,v+.7,str(v),ha='center')
    axes[0].axhline(43,color='#888888',ls=':',lw=1,label='43 reference nodes')
    axes[0].set(ylim=(0,47),ylabel='Reference nodes context-reachable')
    axes[0].legend(fontsize=8,loc='upper left')
    axes[1].bar(labels,events,color=colors)
    for i,v in enumerate(events):axes[1].text(i,v+500,format(v,','),ha='center',fontsize=9)
    axes[1].set(ylim=(0,max(events)*1.18),ylabel='Candidate events before ranking')
    for ax in axes:ax.tick_params(axis='x',labelsize=8)
    fig.suptitle('Input A: expanded context coverage also expands investigation input',fontsize=12)
    fig.tight_layout()
    for ext in ['png','pdf']:fig.savefig(out/('figure-01-frontier-coverage-cost.'+ext),dpi=220)
    plt.close(fig)
    cases=list(csv.DictReader((root/'artifacts/FRONTIER_CASES.csv').open()))
    partition=[sum(json.loads(x['minimal_relaxation_masks'])==[4] for x in cases),
               sum(bool(json.loads(x['minimal_relaxation_masks'])) and json.loads(x['minimal_relaxation_masks'])!=[4] for x in cases),
               sum(not json.loads(x['minimal_relaxation_masks']) for x in cases)]
    reasons=json.loads((root/'witness_group_audit/WITNESS_GROUP_RECEIPT.json').read_text())
    names=['Source group\nabstention','Target tie\nbarrier','Intermediate\ntie barrier','Neighbor\nlimit']
    values=[reasons['baseline_block_reason_step_counts_overlapping'].get(k,0) for k in
            ['SOURCE_GROUP_ABSTENTION','TARGET_GROUP_BARRIER','INTERMEDIATE_GROUP_BARRIER','NEIGHBOR_GROUP_LIMIT']]
    fig,axes=plt.subplots(1,2,figsize=(11,4.2))
    axes[0].bar(['Tie family\nalone','Tie plus hop\nor neighbor','Still no\ncontext path'],partition,color=['#397e78','#b4774d','#8c8e91'])
    for i,v in enumerate(partition):axes[0].text(i,v+.3,str(v),ha='center')
    axes[0].set(ylim=(0,17),ylabel='Mutually exclusive target-node classes (17 total)')
    axes[1].bar(names,values,color='#657784')
    for i,v in enumerate(values):axes[1].text(i,v+.4,str(v),ha='center')
    axes[1].set(ylim=(0,36),ylabel='Blocked-step reason counts (overlapping)')
    axes[1].set_title('28 blocked steps out of 36 witness steps',fontsize=10)
    for ax in axes:ax.tick_params(axis='x',labelsize=8)
    fig.suptitle('Posthoc diagnosis: context links do not establish attack causality',fontsize=12)
    fig.tight_layout()
    for ext in ['png','pdf']:fig.savefig(out/('figure-02-node-classes-and-barriers.'+ext),dpi=220)
    plt.close(fig)


if __name__=='__main__':main()
