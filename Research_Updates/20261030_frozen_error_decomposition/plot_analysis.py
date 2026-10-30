"""Plot fixed descriptive contrasts. One exposed attack, no inferential error bars."""
from pathlib import Path
import csv
import argparse
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    root = ap.parse_args().root.resolve()
    rows = list(csv.DictReader((root/'artifacts/RETRIEVAL_METRICS.csv').open()))
    out = root/'figures'
    out.mkdir(exist_ok=False)
    plt.rcParams.update({'font.size':10, 'pdf.fonttype':42, 'axes.spines.top':False,
                         'axes.spines.right':False, 'savefig.bbox':'tight'})
    methods = [('frozen_node_anomaly_score','Anomaly rank','#596773'),
               ('first_order_diffusion','Plain diffusion','#2d7f9e'),
               ('operation_gate_only','Operation only','#6e8d56'),
               ('memory_only','Memory only','#b58a35'),
               ('operation_plus_memory','Full module','#a34753')]
    fig, axes = plt.subplots(1,2,figsize=(10,3.6),sharey=True)
    for ax,v in zip(axes,['A','B']):
        for method,label,color in methods:
            hits=[]
            for n in [25,50,100,200]:
                r=next(x for x in rows if x['input']==v and x['method']==method
                       and x['condition']=='n%d_e500'%n)
                hits.append(int(r['annotation_hits']))
            ax.plot([25,50,100,200],hits,marker='o',ms=4,label=label,color=color)
        ax.axhline(24,color='#999999',ls=':',lw=1,label='Candidate ceiling')
        ax.set(title='Input '+v, xlabel='Node cap (event cap = 500)',xticks=[25,50,100,200],ylim=(11,25))
        ax.grid(axis='y',alpha=.2)
    axes[0].set_ylabel('Reference nodes retrieved / 43')
    axes[1].legend(fontsize=8,loc='lower right')
    fig.suptitle('Budget sensitivity on one exposed development case',fontsize=12)
    fig.tight_layout()
    for ext in ['png','pdf']:fig.savefig(out/('figure-01-budget-sensitivity.'+ext),dpi=220)
    plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11.5,4.5))
    labels=['Full A','Anomaly A','Full B','Anomaly B']
    conditions=[('A','operation_plus_memory'),('A','frozen_node_anomaly_score'),
                ('B','operation_plus_memory'),('B','frozen_node_anomaly_score')]
    totals=[int(next(x for x in rows if x['input']==v and x['method']==m
                     and x['condition']=='n100_e500')['annotation_hits']) for v,m in conditions]
    coverage=json.loads((root/'artifacts/COVERAGE_PARTITIONS.json').read_text())
    colors=['#3d8c83','#dcbd73','#cf875b','#888b93']
    left=[0]*4
    parts=[totals,[coverage[v]['reference_in_candidates']-x for (v,m),x in zip(conditions,totals)],
           [coverage[v]['reference_scored_but_outside_candidates'] for v,m in conditions],
           [coverage[v]['reference_outside_scored_universe'] for v,m in conditions]]
    for values,label,color in zip(parts,
            ['Retrieved','Candidate, not returned','Outside frontier','Outside scored input'],colors):
        axes[0].barh(labels,values,left=left,label=label,color=color)
        for y,(a,b) in enumerate(zip(left,values)):
            if b:axes[0].text(a+b/2,y,str(b),ha='center',va='center',fontsize=9)
        left=[a+b for a,b in zip(left,values)]
    axes[0].set(xlim=(0,43),xlabel='Reference nodes (total = 43)')
    handles,legend_labels=axes[0].get_legend_handles_labels()
    fig.legend(handles,legend_labels,fontsize=8,loc='lower center',
               bbox_to_anchor=(.5,.005),ncol=4,frameon=False)
    concentration=list(csv.DictReader((root/'artifacts/EVENT_CONCENTRATION.csv').open()))
    selected=[next(x for x in concentration if x['input']==v and x['method']==m)
        for v,m in [('A','frozen_node_anomaly_score'),('B','frozen_node_anomaly_score'),
                    ('B','time_distance'),('B','operation_plus_memory')]]
    names=['A anomaly','B anomaly','B time','B full']
    values=[100*float(x['largest_pair_fraction']) for x in selected]
    axes[1].bar(names,values,color=['#596773','#a34753','#b58a35','#3d8c83'])
    for i,x in enumerate(values):axes[1].text(i,x+2,'%.1f%%'%x,ha='center',fontsize=9)
    axes[1].set(ylim=(0,110),ylabel='Largest pair share of returned events (%)',title='Primary output concentration')
    axes[1].tick_params(axis='x',labelsize=8)
    fig.suptitle('Where reference nodes are lost; repeated pairs are real events',fontsize=12,y=.98)
    fig.subplots_adjust(bottom=.23,top=.8,wspace=.38,left=.09,right=.99)
    for ext in ['png','pdf']:fig.savefig(out/('figure-02-loss-and-concentration.'+ext),dpi=220)
    plt.close(fig)


if __name__=='__main__':
    main()
