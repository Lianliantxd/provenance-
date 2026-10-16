"""Post-seal metadata/cost disclosure; official scoring and selection are unchanged."""
from __future__ import annotations
import argparse,csv,datetime,json,statistics
from pathlib import Path
from c15_common import *
from c15_evaluate_and_report import table,summary,verify_local_frozen_unit

def metadata(root:Path,unit:dict)->dict:
    d=root/'runs'/unit['run_unit_id'];t=read(d/'terminal.json');phases=dict.fromkeys(['controller','repair','synthesis','reflection'],0)
    usage=[];validated=0;empty=0
    for x in sorted(d.glob('exchange_*')):
        if not (x/'cli_start_receipt.json').exists():continue
        phases[read(x/'request.json')['phase']]+=1;validated+=int((x/'parser_receipt.json').exists())
        if (x/'cli_exit_receipt.json').exists():
            e=read(x/'cli_exit_receipt.json');empty+=int(e['cli_exit_code']==0 and e['final_reply_bytes']==0)
        completed=[]
        for line in (x/'stdout.raw').read_text().splitlines():
            try:event=strict_json(line)
            except (ValueError,SafetyError):continue
            if event.get('type')=='turn.completed':completed.append(event.get('usage',{}))
        if len(completed)==1:usage.append(completed[0])
    starts=sum(phases.values());assert starts==t['actual_cli_starts']
    p=root/'transport_versions'/(unit['run_unit_id']+'.json');s=root/'ssh_transport_versions'/(unit['run_unit_id']+'.json')
    result={'run_unit_id':unit['run_unit_id'],'parser_transport_version':read(p)['version'] if p.exists() else 'BASE_V2',
        'ssh_transport_version':read(s)['version'] if s.exists() else 'BASE_NEW_CONNECTION_PER_RPC',
        'bridge_original_terminal_status':t.get('bridge_original_status',t['status']),
        'same_original_attempt_completion_reconciled':bool(t.get('resolution_kind')),
        'native_termination_reason':t.get('termination_reason','NO_FROZEN_NATIVE_TERMINAL'),
        'canonical_replies_validated':validated,'empty_canonical_reply_count':empty,
        'observed_reflection_cli_starts':phases['reflection'],'accepted_reflection_revisions':sum(t.get('revision_accepted',[])),
        'cli_with_turn_usage':len(usage),'cli_total':starts,
        'usage_coverage':'NO_CLI_STARTED' if not starts else 'ALL_CLI_HAVE_TURN_USAGE' if len(usage)==starts else 'PARTIAL_OBSERVED_ONLY',
        **{'observed_cli_'+k+'_starts':v for k,v in phases.items()}}
    for key in ['input_tokens','cached_input_tokens','output_tokens','reasoning_output_tokens']:
        values=[u[key] for u in usage if isinstance(u.get(key),int)]
        result['observed_cli_'+key+'_sum']=sum(values) if values or starts==0 else 'UNAVAILABLE'
        result['observed_cli_'+key+'_coverage']=str(len(values))+'/'+str(starts)
    return result

def render(root:Path)->None:
    batch=evaluation_gate(root);units=read(root/'configs/run_units_private.json')['units'];metas=[metadata(root,u) for u in units];lookup={x['run_unit_id']:x for x in metas}
    for name in ['10_all_18_runs.csv','13_cost_and_realized_reflection.csv']:
        path=root/'reports'/name
        with path.open() as f:rows=list(csv.DictReader(f))
        for row in rows:row.update(lookup[row['run_unit_id']])
        table(path,rows)
    table(root/'reports/22_transport_versions_and_cost_coverage.csv',metas)
    matrices={};paired=[]
    for u in units:
        f=root/'evaluation'/u['run_unit_id']/'official_metrics_summary.json'
        matrices[u['run_unit_id']]=read(f)['metrics'] if f.exists() else {}
    for case in ['C1','C2','C3']:
        for rep in ['R1','R2','R3']:
            a=matrices[case+'_'+rep+'_ON'];b=matrices[case+'_'+rep+'_OFF'];ok='bestmatch_step_f1' in a and 'bestmatch_step_f1' in b
            paired.append({'case_alias':case,'repeat_id':rep,'complete_scored_pair':ok,
                'delta_pred_steps_ON_minus_OFF':a['n_pred_steps']-b['n_pred_steps'] if ok else None,
                'delta_reference_matched_steps_ON_minus_OFF':a['bestmatch_matched_steps']-b['bestmatch_matched_steps'] if ok else None})
    table(root/'reports/23_paired_output_and_reference_match_counts.csv',paired)
    terms=[read(root/'runs'/u['run_unit_id']/'terminal.json') for u in units];begins=[read(root/'runs'/u['run_unit_id']/'active_start.json')['start_epoch'] for u in units]
    latest=max(datetime.datetime.fromisoformat(t['utc']).timestamp() for t in terms);active=sum(t['active_elapsed_seconds'] for t in terms);calendar=latest-min(begins)
    cost={'state':'ACTUAL_LEDGER_NOT_ACCOUNT_BILL','cli_starts':sum(t['actual_cli_starts'] for t in terms),'reservations':sum(t['new_cli_reservations'] for t in terms),
        'active_runner_seconds':active,'calendar_first_start_to_last_terminal_seconds':calendar,
        'non_runner_calendar_intervals_seconds':calendar-active,
        'calendar_interval_note':'Includes quota checks, engineering and pauses; no fabricated per-cause time attribution',
        'validated_reply_token_columns_note':'Original input/output token columns use parser receipts; observed_cli_* fields also include available failed-turn usage. Partial coverage is a lower observed sum, not an exact bill.',
        'all_limits_unchanged':True,'worker_model_requested':'gpt-6-luna','client_version':'codex-cli 0.160.0','server_snapshot':'UNVERIFIED','temperature_forwarding':'UNVERIFIED_NOT_FORWARDED_BY_TEXT_BRIDGE'}
    assert cost['cli_starts']<=LIMITS['total_new_cli'] and active<=LIMITS['batch_active_seconds']
    assert all(t['actual_cli_starts']<=LIMITS['per_run_new_cli'] and t['active_elapsed_seconds']<=LIMITS['run_active_seconds'] for t in terms)
    write_state(root/'reports/24_actual_budget_and_calendar.json',cost)
    gate=read(root/'reports/16_final_gate.json');gate.update(execution_versions_amended=True,parser_compat_freeze_sha256=sha((root/'17_transport_compat_freeze.json').read_bytes()),ssh_mux_freeze_sha256=sha((root/'19_ssh_mux_freeze.json').read_bytes()),original_failures_retained=True,reflection_cli_starts=sum(x['observed_reflection_cli_starts'] for x in metas),accepted_reflection_revisions=sum(x['accepted_reflection_revisions'] for x in metas));write_state(root/'reports/16_final_gate.json',gate)
    names={'C1':'CVE-2023-25157','C2':'ExCyTIn incident-34','C3':'Mordor APT29 Day 1'}
    frozen=sum(t['status']=='FROZEN' for t in terms);failed=len(terms)-frozen
    text=f'当前不足以选择Reflection开或关：18个预登记单元均已取得真实终态，{frozen}个冻结输出已统一官方评价，{failed}个失败保留NA。下面仅报告逐案例探索性结果；缺失和执行版本修订限制比较，不作显著性、普遍因果或语义正确性主张。\n\n'
    text+='| 案例 | 条件 | R1 / R2 / R3：bestmatch_step_f1 | 可评价/3 | 均值 | 中位数 | 样本标准差 | 范围 |\n|---|---|---|---|---|---|---|---|\n'
    def fmt(v):return 'NA' if v is None else f'{v:.6f}' if isinstance(v,(int,float)) else str(v)
    for case in ['C1','C2','C3']:
        for arm in ['ON','OFF']:
            values=[matrices[case+'_R'+str(i)+'_'+arm].get('bestmatch_step_f1') for i in range(1,4)];s=summary(values)
            text+='| '+names[case]+' | '+arm+' | '+' / '.join(fmt(v) for v in values)+' | '+str(s['valid_count'])+'/3 | '+fmt(s['mean'])+' | '+fmt(s['median'])+' | '+fmt(s['sample_sd'])+' | '+fmt(s['min'])+'–'+fmt(s['max'])+' |\n'
    text+='\n配对差值ON−OFF见12表，预测步骤数与参考匹配数变化见23表；仅在同案同轮两边均可评价时计算。没有跨案例F1总体均值或p值。\n\n'
    on=[x for x in metas if x['run_unit_id'].endswith('_ON')];off=[x for x in metas if x['run_unit_id'].endswith('_OFF')]
    text+=f'ON实际Reflection CLI调用{sum(x["observed_reflection_cli_starts"] for x in on)}次，作者规则接纳修订{sum(x["accepted_reflection_revisions"] for x in on)}次；OFF调用{sum(x["observed_reflection_cli_starts"] for x in off)}次。按分配条件分析，失败前未进入Reflection的ON不移入OFF。\n\n'
    text+=f'共{cost["cli_starts"]}次CLI启动，活跃运行{active:.2f}秒，首轮启动至末轮终态日历跨度{calendar:.2f}秒；其差额包含检查、修复和暂停，不能作为精确按原因计时。详细成本、覆盖率和所有18条失败/完成状态见10、13、22、24工件。失败早停导致低调用数，不能当作同等质量下的低成本。观测token非精确账单。\n\n'
    text+='原作者/V2源码、模型请求gpt-6-luna、CLI 0.160.0、输入、原生开关和预算未更换；途中新增两份版本化传输适配。原5个单元使用基础传输，第6个使用重连兼容但未启动模型，后12个使用兼容层和临时SSH复用。逐单元版本见22表；不能把全批称为执行版本完全相同。服务端模型快照、temperature实际采用和精确收费UNVERIFIED。\n\n'
    text+='官方完整字段原名原值保存在私有official_evaluation.json；最佳匹配边与按顺序对齐边分别报告。Bestmatch和CEAF排序分母分别按各自匹配对计算，少于2个匹配步骤均标记NO_COMPARABLE_PAIRS，即使官方精度返回1也不解读为排序完美。非参考引用、未匹配步骤不等于真实幻觉。没有独立人工语义真值，SEMANTIC_TRUTH_NOT_INDEPENDENTLY_VALIDATED、NOVELTY_UNVERIFIED保持。旧C13/C14结果未混入，没有补样本或第19次运行。\n\n'
    text+='原始桥接账本保留7条FAILED，其中最后C1_R3_OFF经只读消歧确认原生预测早已冻结，且4条原请求/回复/消费ACK完全匹配；仅完成同一attempt的工件取回和两端冻结确认，新增模型调用0。原terminal.json未覆盖，独立terminal_resolution.json记录完成状态。因此最终为12个可评价输出、6个无法评价失败，不是选择性重跑或补样本。\n\n'
    text+='有限决策：'+gate['decision']+'。保留所有缺失，不据本次不完整小样本选择统一的Reflection配置。\n'
    (root/'reports/15_plain_language_conclusion_zh.md').write_text(text)
    for u in units:
        t=read(root/'runs'/u['run_unit_id']/'terminal.json')
        if t['status']=='FROZEN':verify_local_frozen_unit(root,t)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--metadata-check',action='store_true');a=p.parse_args()
    if a.metadata_check:
        units=read(ROOT/'configs/run_units_private.json')['units'];done=[u for u in units if (ROOT/'runs'/u['run_unit_id']/'terminal.json').exists()]
        items=[metadata(ROOT,u) for u in done];print(json.dumps({'terminal_units_checked':len(items),'cli_starts':sum(x['cli_total'] for x in items),'Gold_read':False}))
    else:render(ROOT)
