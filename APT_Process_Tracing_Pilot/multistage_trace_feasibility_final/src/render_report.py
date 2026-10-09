#!/usr/bin/env python3
"""Render the executed, hash-addressable experiment without changing outputs."""
import csv
import hashlib
import json
from pathlib import Path

R = Path(__file__).resolve().parents[1]
f = json.loads((R / "01_PRESEARCH_FROZEN_ANCHORS.json").read_text())
t1 = json.loads((R / "outputs/t1_b_only.json").read_text())
t2 = json.loads((R / "outputs/t2_known_endpoints.json").read_text())
m = json.loads((R / "outputs/background_manifest.json").read_text())
A, B = f["A_evaluation_only"], f["B_query_POI"]


def put(name, body):
    (R / name).write_text(body.strip() + "\n")


with (R / "03_RAW_ANCHORS_AND_STEP_REFERENCES.csv").open("w", newline="") as h:
    cols = ["role","report_page_pdf","report_step","event_uuid","event_type","timestamp_ns","host_uuid","subject_uuid","object_uuid","raw_member","raw_offset","raw_sha256","mapping_rule","uncertainty"]
    w = csv.DictWriter(h, fieldnames=cols); w.writeheader()
    for role, event, page, step, rule, uncertainty in [
        ("A_eval_only", A, "27-28", "nginx connects to loaderDrakon 155.162.39.48:80", "remote IP/port, operation, report-aligned 14:00", "report clock conversion inferred; no packet-content proof"),
        ("B_POI", B, "26-27", "14:02 putfile tmux-1002", "unique EVENT_WRITE path and minute; same file UUID as /tmp/tmux-1002 EVENT_OPEN", "same-nanosecond OPEN/WRITE order unresolved; bytes unknown"),
    ]:
        w.writerow({"role":role,"report_page_pdf":page,"report_step":step,"event_uuid":event["event_uuid"],"event_type":event["operation"],"timestamp_ns":event["timestamp_ns"],"host_uuid":event["host_uuid"],"subject_uuid":event["subject_uuid"],"object_uuid":event["object_uuid"],"raw_member":m["member"],"raw_offset":event["raw_offset"],"raw_sha256":event["raw_sha256"],"mapping_rule":rule,"uncertainty":uncertainty})

links = []
chain = list(reversed(t2["path_B_to_A"]))
for x,y in zip(chain,chain[1:]):
    links.append({"source_event_uuid":x["event_uuid"],"target_event_uuid":y["event_uuid"],"source_timestamp_ns":x["timestamp_ns"],"target_timestamp_ns":y["timestamp_ns"],"source_subject_uuid":x["subject_uuid"],"target_subject_uuid":y["subject_uuid"],"source_raw_offset":x["raw_offset"],"source_raw_sha256":x["raw_sha256"],"target_raw_offset":y["raw_offset"],"target_raw_sha256":y["raw_sha256"],"relation_semantics":"MODEL_POSSIBLE_DEPENDENCY","evidence_strength":"coarse candidate","uncertainty_reason":"same long-lived process; no specific cross-operation byte/control-flow evidence"})
with (R / "outputs/t2_candidate_links.csv").open("w",newline="") as h:
    w=csv.DictWriter(h,fieldnames=list(links[0]));w.writeheader();w.writerows(links)

rank=t1["all_pool_event_ids"].index(A["event_uuid"])+1
put("00_ASSET_REPORT_TIME_AUDIT.md", f"""
# 输入、报告与时间审计

- 直接可访问本机输入：`{m['archive']}`，成员 `{m['member']}`；原归档预期 SHA256 `{m['archive_sha256_expected']}`。此次流式扫描成员 4,299,097,329 字节，5,000,000 行。没有重新下载或启动虚拟机。
- 原报告：`{f['report']['path']}`，SHA256 `{f['report']['sha256']}`，§3.13，PDF 第 26–28 页（印刷 23–25 页）。报告记载 14:00 nginx/Drakon 活动、14:02 `putfile tmux-1002`、14:37 micro 扫描。报告自身未明确时区；以 14:02→18:02:10 UTC 的多字段对应推断 EDT，仍保留时区不确定性。
- B 原始操作 `EVENT_WRITE`，UUID `{B['event_uuid']}`，UTC 18:02:10.376185722，offset `{B['raw_offset']}`，SHA256 `{B['raw_sha256']}`。相同文件 UUID 的 `EVENT_OPEN` 路径 `/tmp/tmux-1002`，但两操作同一纳秒，不能声称严格先后。
- A 原始操作 `EVENT_CONNECT`，UUID `{A['event_uuid']}`，UTC 18:00:23.166196193，offset `{A['raw_offset']}`，SHA256 `{A['raw_sha256']}`；网络对象远端 `155.162.39.48:80`，符合报告 loaderDrakon 地址与 nginx 连接描述。
- 两个 offset/hash 已在重新打开原 TAR 成员后逐字节验证，见 `outputs/raw_anchor_verification.json`。原始存在和步骤匹配不证明 A 的字节导致 B。
- 备选排序在搜索前冻结：14:02 文件写入第一；14:37 目标端口扫描在相应分钟未找到报告目标 IP/22/6000 的 `EVENT_CONNECT`；`/tmp/test` 有四条 `EVENT_EXECUTE`，不具唯一性。
""")
put("02_FULL_BACKGROUND_SCOPE_AND_GRAPH.md", f"""
# 背景图范围和查询语义

从单个已有 CDM TAR 成员，按主机 `{m['host_uuid']}` 和 2018-04-12 17:59:00–18:39:00 UTC 流式抽取全部事件；**没有攻击标签预过滤**。共 {m['counts']['events_written']:,} 条事件、{m['counts']['entity_definitions_written']:,} 条实体定义记录；其中 {m['counts']['direct_operation_events']:,} 条记录具有受支持方向，{m['counts']['unsupported_or_missing_endpoint']:,} 条原样保留但不设分析方向。全背景事件压缩 CSV、定义压缩 CSV、82,976,768 字节的 SQLite 索引及构建清单位于 `outputs/`。索引有事件 UUID、subject/time、object/time、time；直接操作边另表，过程状态边按相邻严格时间组按需查询，不物化长进程全部两两边。

方向规则：READ/RECVFROM/EXECUTE 为 object→subject；WRITE/SENDTO/CONNECT/FORK 为 subject→object。它们是 `DIRECT_OPERATION`，只证明每条传感器操作本身。FORK/EXECUTE 可标为传感器记录的创建/执行事件，但未在本例跨事件路径中使用。其他类型保留为背景，不凭操作名生成直接方向。两个相邻、时间严格递增的同一 subject 时间组之间可产生 `MODEL_POSSIBLE_DEPENDENCY`；这是进程状态可能传播，绝非特定字节因果。同一纳秒组内 `ORDER_UNRESOLVED`，无严格边。不同 UUID 无可靠同一性材料时为 `IDENTITY_UNRESOLVED`；日志空白处为 `MISSING_OBSERVATION`。

**范围限制：**只有一个 40 分钟成员，不是整个 E3；按当前主机过滤。T1 实际查询只展开 B 所属 subject 的进程时间线，没有穷尽文件版本、网络流或其它实体分支。B0 因而是“同进程上游候选池”，不能宣称全图上游召回率。最早观察到的同进程事件仅是窗口边界，不是失陷 Root。

可重复命令：`python3 src/extract_background.py`（新目录中已有产物时不要覆盖）、`python3 src/build_index.py`、`python3 src/run_t1.py`、`python3 src/run_t2.py`、`python3 src/verify_raw.py`、`python3 -m unittest discover -s tests -v`。本轮对应命令退出码均为 0。背景扫描耗时 {m['counts']['elapsed_seconds']} 秒；查询在 SQLite 索引上完成，未创建大型进程两两边。哈希和原始引用见冻结 JSON 与各输出。
""")
put("05_T2_ENDPOINT_PATH_DIAGNOSIS.md", f"""
# T2：已知 A/B 的路径诊断

此诊断在 B-only T1 落盘后运行；T1 输出 SHA256 `{t2['T1_output_sha256_before_T2']}`，T2 未回写 T1。已知端点 A、B 属于同一 subject；严格时间组路径有 {t2['path_event_count']} 条原始事件、{t2['strict_timestamp_steps']} 个跨事件连接，最小成本在当前“相邻时间组各取一事件”的规则下为 {t2['path_event_count']} 事件。32 事件预算不可行；128/512 可显示候选路径，但只能到观察边界。中间等时组代表事件按 UUID 选取；组内顺序未决，没有组内跳边。

两端各一条 `DIRECT_OPERATION` 原始传感器关系（A 的 nginx→网络对象，B 的 nginx→文件对象）；**A→B 跨事件路径的 37 段全是 `MODEL_POSSIBLE_DEPENDENCY`，0 段独立传感器记录的跨步骤因果边**。去掉模型可能依赖即断开。具体 37 段及双端 offset/hash 见 `outputs/t2_candidate_links.csv`；完整事件路径见 `outputs/t2_known_endpoints.json`。

关键断裂是缺少能把 loader 网络连接的输入/状态，独立接到后来文件写入内容的证据。报告只支持步骤先后和攻击场景，不能补足具体传播关系。Structural Precision/Recall/F1 = NA。
""")
put("06_EVIDENCE_CHAIN_CASEBOOK.md", f"""
# A→B 证据链个案

报告 §3.13 支持“nginx 向 loaderDrakon 地址连接，后有 putfile tmux-1002”。原始 CDM 分别观察到 A=`{A['event_uuid']}` 和 B=`{B['event_uuid']}`；A 的 NetFlowObject 远端为 `155.162.39.48:80`，B 的 FileObject UUID 为 `{B['object_uuid']}`。这些是 `OBSERVED_EVENT`；各自 subject/object 操作是 `DIRECT_OPERATION`。两者 subject UUID 同为 `{A['subject_uuid']}`。

按严格时间组回溯，从 B 到 A 跨 {t2['strict_timestamp_steps']} 个同进程状态跳；逐段源/目标 UUID、时间、offset/hash 在 `outputs/t2_candidate_links.csv`。每段只归类 `MODEL_POSSIBLE_DEPENDENCY`，没有 `INDEPENDENTLY_SUPPORTED_CROSS_STEP_RELATION`。报告提供 `REPORT_SUPPORTED_STEP_ORDER`，但没有这两个操作间特定内容传播证据。A 之前、B 之后和组内并列操作的具体状态均为 `UNRESOLVED`。不能把同一长寿命 nginx 上的候选链包装成已证实的攻击因果链。

T1 的 B0 候选池含 A，按冻结的近到远/UUID 次序排第 {rank}；预算 32/128 不显示，512 才显示。B1-Min 和三条无标签备选均未选到 A；这说明路径选择歧义，**不构成已验证的算法缺陷**，因为跨步骤关系没有独立真值且这些基线仅按受限的同进程时间线工作。
""")
put("07_FINAL_RESEARCH_DECISION.md", f"""
# 最终研究决策

**任务是否可评价：部分可评价。** A/B 的报告步骤、原始操作、时间顺序、同进程候选上游可核查；完整攻击因果结构的精确率、召回率和 F1 无真值，均为 NA。结论状态：`MULTISTAGE_CANDIDATE_ONLY`。

**方法缺陷是否成立：否。** `METHOD_GAP_NOT_ESTABLISHED`。B0 在 512 事件预算中显示 A（第 {rank}），32/128 的候选池超预算，必须标 `FULL_POOL_EXCEEDS_OUTPUT_BUDGET`；B1-Min 与三条备选没有选 A，但 T2 的 {t2['strict_timestamp_steps']} 段连接全部为粗粒度同 nginx 可能传播，缺少独立跨步骤关系真值。不能把仅因路径选择未中 A 定为真实攻击依赖遗漏。32 预算中 38 事件的已知端点路径本身也不可行。简单方法没有被证明存在可评价的失效。

失败分类：`COARSE_DEPENDENCY_ONLY`；在 B1 输出层还观察到 `PATH_SELECTION_MISS`，但它不是经独立因果真值认证的方法失败。没有证据支持 `RAW_ABSENT`、`NO_LEGAL_DEPENDENCY_PATH` 或 `WRONG_POI_ASSOCIATION`。B0 的 32/128 预算为输出截断，不是图内不可达。

**止损：关闭 CADETS 04-12 当前“关键事件级结构恢复的新算法主张”，不再扩写 B2、不追加人工 Root 标签、不以同一案例调整预算。** 可保留原始 CDM 解析、时间/UUID/offset 回链和不确定性分级工具。

下一个、仅作为候选且本轮不开发的第四研究子任务：**审计证据缺口定位与可验证性判别**。输入调查点和现有 provenance；输出哪些跨步骤关系有传感器直接支持、哪些仅有模型可能依赖，以及缺失何种日志/版本信息。这与前三项的检测、实体识别、意图理解不同；其评价可以针对明确可观测的证据类型和缺口，而非假定完整攻击因果 GT。是否有足够公开案例支撑一般化仍未验证。
""")
print("rendered 00,02,03,05,06,07 and t2 links")
