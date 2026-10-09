# 执行与资产审计（2026-10-09）

本轮决策为 **EVALUATION_NOT_READY**。两个案例属于不同攻击执行，但均已在前期工程中被查看，因此 WS12 不能称为盲测。只使用本机已有日志、Python 与文件工具；未训练模型、未部署虚拟机、未修改旧 GT/B2、未同步服务器或 GitHub。

## 已读取的输入

- 上轮八份调研文件：`../../APT_Attack_Provenance_2026/`（实际路径为本文件目录的兄弟目录 `../../APT_Attack_Provenance_2026/`）；其中路线比较与决策均是**有条件选题**，不是已证实的新方法。
- 04-12：`../results/cadets_20180412_q1/events.csv`、`../comparison_v1/outputs/frozen_pool.json`、`../comparison_v1/evaluation_refs/reference_events.csv`、E3 报告摘录、原始 CDM tar 成员。先前 `comparison_v1` 和 `comparison_v2_transfer` 已提示 B0 近时裁剪失效与 B1-Min/B2 目标对齐后相同。本轮未运行 B2。
- WS12：本机 `/Users/tianxd/Downloads/SimulatedWS12/hw20/anomaly.json`、发布方 `research/repos/nodlink/doc/SimulatedWS12-attack/attack_annotation/A2.txt` 及前期摘录。本机未发现同目录 `benign.json`；因此 WS12 的候选域是**anomaly 通道及一个有限时间窗**，不能用于“从全背景恢复攻击”的声明。
- 旧 Root 审计仅作边界检查。`CASE_NODLINK_WS12/08_case_status.md` 已记录初始失陷左侧不确定；本轮不把原精确 Root GT 当作先验。

两个案例的所有源文件路径、SHA-256、时间窗、POI 和覆盖缺口已先于本轮基线输出写入 [01_FROZEN_CASES.json](01_FROZEN_CASES.json)。04-13 是 04-12 同 campaign，未计作第二攻击。冻结时脚本 SHA 在 JSON 内；随后修正了时间列拆分、预算失败文字、小规模候选路径组合的可行性枚举，并扩大本轮输出回读核查范围。原输入/POI/候选域和路径选择规则未变；四次 `run` 的脚本 SHA、命令、退出码、UTC 时间与耗时均在 `outputs/execution_log.jsonl`，不得把最终代码版本误称为冻结时版本。

## 实际执行与结果

|命令或核查|退出码|结果|
|---|---:|---|
|`python3 src/run.py freeze`|0|2 案例冻结；WS12 窗内 34 条候选操作（27 条 Process/Start，加 7 条该文件的 I/O/加载）|
|`python3 src/run.py run`（最终代码版本）|0|54 行方法/查询/预算结果、15 行证据、6 行预算不可行诊断；9/9 个重点证据、166/166 个去重后的方法输出原始事件哈希及身份吻合|
|原 `src/trace.py:b1` 重新执行 04-12 两 POI|0|上游事件集合分别 11/11、162/162 与旧冻结候选域完全一致；状态数 10、160，均未搜索截断；见 `outputs/fresh_search_check.json`|
|`python3 -m unittest discover -s tests -v`|0|12 项语义与评测护栏通过；合成断言仅检查程序，不算真实攻击实验|

`outputs/ws12_candidate_edges.csv` 是 ETW 子域的**透明适配器**：`ParentID` 构建进程启动边，同一进程操作/同路径文件构建候选边。它不是 NODLINK、SLEUTH 或 ORTHRUS 原生输出。WS12 的 `UniqueProcessKey` 在 `ws12@1270525` 与 `ws12@1590222` 两个不同 PID 的 `Process/Start` 中相同；故不能仅用该字段合并进程实例。适配器以窗口内同 PID 的最近较早启动记录作父实例候选，但没有完整生命周期结束记录，仍保留身份风险。

04-12 的 B0 是完整的时间/方向上游候选集合，不再使用旧版“按查询邻近时间截前 N 条”冒充强基线。其 162 条候选在预算 8 下无法作为完整集合输出，结果标记 `FULL_POOL_EXCEEDS_OUTPUT_BUDGET`，不能将其候选覆盖当作预算 8 的等价胜利。B1-Min 保留每个 POI 一条最短完整路径，B1-Alternatives 每个 POI 最多三条；评测参考不进入路径选择评分。所有方法共享各查询候选域、POI 和输出预算。WS12 的域是从 anomaly 通道和报告定义时间窗选取的操作，明显弱于全日志调查输入。

**公开强方法状态：`STRONG_BASELINE_NOT_COMPARABLE_YET`。** [ORTHRUS 官方入口](https://github.com/ubc-provenance/orthrus)默认串行运行图构建、特征、GNN 检测和重构；[入口代码](https://github.com/ubc-provenance/orthrus/blob/main/src/orthrus.py)的 `tracing.main(cfg)` 接收前面检测产物；[重构接口](https://github.com/ubc-provenance/orthrus/blob/main/src/attack_reconstruction/tracing.py)读取检测 `result_*.pth` 和窗口图；[追踪实现](https://github.com/ubc-provenance/orthrus/blob/main/src/attack_reconstruction/tracing_methods/depimpact.py)用预测阳性节点及节点分数生成 POI，并输出子图节点。其 [官方配置](https://github.com/ubc-provenance/orthrus/blob/main/config/orthrus.yml)中的重构方法为 `depimpact`。本轮没有同版 Torch 窗口图、检测分数或可保真 CDM→该图的接口；也不能按本轮禁令训练检测器或伪造分数。故未运行原生 ORTHRUS，也未将“未运行”记作方法失败。DEPIMPACT 作者 demo 已在旧审计运行，但其 Sysdig demo 输入和本轮 CDM/ETW 案例不同，正式同版评价材料未齐，不能套用 demo 数字。

逐行结果中的 `raw_refs_checked/raw_refs_matched` 对应该行**实际输出事件**，不是把全轮的 9 条重点核查重复填入各行。全轮输出去重后 162 条 CADETS、4 条 WS12 事件的回读结果见 `outputs/output_raw_verification.json`。完整文件与运行摘要见 `outputs/`；`outputs/ARTIFACT_SHA256.txt` 给出本轮产物哈希。脚本与数据表均不覆盖旧目录。
