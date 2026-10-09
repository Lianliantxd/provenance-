# 最终研究决策：EVALUATION_NOT_READY

**不能进入新算法设计。** 两个不同执行的真日志足以确认若干操作与 WS12 父子创建关系，但本轮没有发现“原始信息存在、独立关系参考支持、候选域可达、预算可行，而透明单路径/备选路径基线仍遗漏”的实例。缺少的是足以判断攻击关键**跨操作依赖**是否恢复的独立参考及完整背景案例，不能用更复杂模型替代。

## 结果与失败归因

04-12 的 196 条局部事件构成旧冻结输入；两个 POI 的新鲜 B1 搜索分别找到 11 和 162 条候选事件，和旧冻结集合完全一致，未触发搜索截断。loader 查询在预算 8 下，B1-Min 用 2 个原始事件显示包含 report-mapped 入站 receive 的完整候选路径，B1-Alternatives 用 4 个；二者在**已知事件、正确 POI**的唯一可评价正例上均为 1/1。双 POI 查询预算 8 下二者分别用 3、7 个事件，参考仍为 1/1；此数字不是依赖边 recall。B0 全候选 162 条，超过预算 8，不能直接比较输出规模。04-12 的同时间戳分支不进入严格依赖分母。曾有旧版 B0“邻近时间裁剪”漏掉路径，但它是弱显示规则，不是本轮强基线失败。

WS12 在 anomaly 限定、34 条操作候选域中，两条 `ParentID` 父子关系在预算 8 下由 B0、B1-Min、B1-Alternatives 对正确 POI 均恢复 2/2；B1 方法输出 4 条原始事件。这个 2/2 仅限直接记录的父子边和发布方 A2 步骤，不能扩展为全攻击因果边覆盖或背景调查性能。文件写→读只可作同路径潜在依赖，且 read 晚于 agent 启动，不能当作启动前因。

`05_FAILURE_DIAGNOSIS.csv` 的 6 行全属 `OUTPUT_BUDGET_INFEASIBLE`（CADETS 双点预算 2 与 WS12 agent 相关预算 2）；没有可行候选池中的路径选择遗漏。B0 完整池大于预算时，结果单列 `FULL_POOL_EXCEEDS_OUTPUT_BUDGET`，不算策略错误。本轮 9/9 条重点证据以及去重后的 166/166 条方法输出原始事件回读吻合；这只证明记录身份，不能证明攻击因果。**Edge Precision/F1 = NA**：未标注输出边均为 unknown，不是假阳性。这里不报告标准意义的边级召回。

## 与最接近方法的边界

|观察问题|最近工作及原文位置|已有机制|本轮可能的问题|证据充分？|
|---|---|---|---|---|
|长寿命进程的伪依赖|[BackTracker §2–3](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)追踪潜在依赖；[BEEP §III–VI](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)在采集时拆分执行单元；[ProTracer §III–V](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)组合日志与污点|已有事前提高依赖粒度的方法，不能把“同进程≠因果”称首次发现|既有粗日志的保守报告与拒答是否有可测新能力|**否**：目前简单 UNKNOWN 规则已处理展示问题|
|缺口与关键组件选择|[DEPIMPACT §3–5、Table 4–5](https://www.usenix.org/system/files/sec22-fang.pdf)反向加权/入口与前向过滤；[SLEUTH §5.1](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)来源判断|已有候选缩减与入口评价；其作者 demo 不能直接评价此 CDM/ETW 关系|是否存在参考支持但其可行候选遗漏|**否**：无同任务原生比较/独立逐边参考|
|多 POI 归属与检测后重构|[ORTHRUS 论文](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)和[官方 tracing 接口](https://github.com/ubc-provenance/orthrus/blob/main/src/attack_reconstruction/tracing.py)，另见[官方 depimpact 追踪](https://github.com/ubc-provenance/orthrus/blob/main/src/attack_reconstruction/tracing_methods/depimpact.py)|预测阳性节点作 POI，按分数/窗口图重构；并非本轮 CDM/ETW 事件级、独立给定 POI 的相同接口|正确 POI 与事件级关系语义能否形成单独任务|**否**：当前正确归属规则已避免误计；无可行失败|

**强基线：`STRONG_BASELINE_NOT_COMPARABLE_YET`。** ORTHRUS 官方入口需要窗口图及检测输出 `result_*.pth`，其重构方法接收节点分数；本轮既无同版输入，也不能按任务约束训练检测模型。现有 DEPIMPACT JAR demo 的输入是另一个 Sysdig 示例，不允许把其输出作为 CADETS/WS12 GT。这里是接口/评价不匹配，不是 ORTHRUS 或 DEPIMPACT 性能差。

## 第四内容的当前定义与下一步

推荐暂用工作题目：**《面向部分观测主机审计日志的证据可识别性约束与保守攻击溯源》**。输入是审计事件、可回读的事件级依赖候选图、独立 POI 和采集范围元数据；输出是按证据级别标注的操作/父子关系、仅有模型支持的候选依赖、不能确定的备选解释及缺口，不输出未经核实的唯一初侵或进程内部传递。这个题目仍是**候选研究问题**，并未证明超过“把未知标 UNKNOWN”的规则基线。

唯一优先下一步：**取得一份不由待评路径算法生成、与原始日志同版本的攻击关键事件对关系参考，并完成可行性门槛审计**。优先从现有发布方 WS12 注释/配套说明中核查能否明确到事件对及关系语义；终止条件是：至少一个非 POI、非仅父子元数据的跨操作正例，具有双方原始偏移/哈希、独立出处、正确 POI、时间与实例核对，且在冻结候选池和预算内存在完整路径；若官方材料只支持步骤而非关系，就记录“无此参考”，停止将该材料用于边级方法优越性主张。无需精确 Root GT、两名真人标注者或虚拟机。
