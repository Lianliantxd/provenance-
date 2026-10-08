# 数据、标签与 baseline 可获得性审计

核查截至2026-10-08。`可获得`表示入口/本机文件已核查，**不等于**已具同任务完整真值或已复现论文指标。既有细目见[前期数据审计](../research/datasets.md)及[本机工件状态](../APT_Process_Tracing_Pilot/official_artifact_evaluation/07_FINAL_STATUS.md)。

|资源|当前可核实|标签真正支持|缺口及本题角色|
|---|---|---|---|
|DARPA TC E3 CADETS|本机有若干日志片段与报告映射；[官方入口](https://github.com/darpa-i2o/Transparent-Computing)|攻击叙述、部分实体/事件线索|不是完整关键边GT；适合小样本事件回链与已知步骤覆盖|
|DARPA TC E5|官方仓库说明STARC注释；原始包及注释未在本机完整就位|报告/注释可能提供攻击线索|需要下载前先核实具体同版事件ID、标注语义和可获取性；不当成已得GT|
|NODLINK模拟WS12/Ubuntu|本机已解析部分包与步骤文档；[论文](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf)|攻击步骤与部分节点|WS12入口左截断；Ubuntu入口歧义；可评已知行为，不可自动定义精确root|
|OpTC|[公开仓库及红队报告](https://github.com/FiveDirections/OpTC-data)|主机/PID/时间/操作线索|需同版本日志事件回链；多主机不保证单一入口|
|ATLAS / ATLASv2|[官方ATLAS仓库](https://github.com/purseclab/ATLAS)可见；本机ATLASv2 EDR原始包未取得|报告与训练/处理流程|不可把处理脚本输出当独立GT；原始包可得性需另查|
|REAPr|[标注工具及材料](https://bitbucket.org/sts-lab/reapr-ground-truth/src/main/)存在|进程/根/影响等研究者标签|标签和本课题事件边定义不同；只能辅助对齐与标签审计|
|PIDSMaker|[官方代码](https://github.com/ubc-provenance/PIDSMaker)存在|数据处理和部分标签导入|数据装载器不是攻击路径独立参考|

## Baseline按任务对齐

|方法|可得状态|能否作为同目标对照|本轮限制|
|---|---|---|---|
|时间方向约束反向BFS＋预算|本机能实现|是，简单基线|必须与强方法同POI、图、时间窗、预算；不能只比图大小|
|BackTracker/SLEUTH策略|论文可据以重实现；[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)|来源候选/可达图对照|适配版需命名，不能冒充作者原版|
|DEPIMPACT|本机官方JAR demo已运行；[论文](https://www.usenix.org/system/files/sec22-fang.pdf)、[原始运行结论](../APT_Process_Tracing_Pilot/native_investigation_alignment/04_FINAL_DECISION.md)|原生POI→关键依赖/入口强对照|官方正式评价ZIP内列OVA；无虚拟机约束下同版property/评价器不可得；不可在旧demo贴新标签|
|DEPCOMM|[全文](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)可核查；代码状态未确认|图摘要结构对照，须声明粒度差|社区级输出需可核查event-ID读出器|
|KAIROS/NODLINK/ORTHRUS|官方工件/代码入口已在前期审计；见矩阵|调查子图近邻对照|任务为检测+调查，统一适配器应与原版结果分开|
|TraceBack|[正式条目](https://doi.org/10.1016/j.knosys.2026.116816)可见，作者代码/完整GT本次未确认|最接近关键组件恢复，应至少做文献级对照|截至10-08其卷期cover date 10-09；不可声称已做原版复现|

## 数据与指标硬边界

当前本机已有事件解析、局部图、原始记录回链，但没有可用于事件边精度的**闭世界独立标签**。报告列出的少数正例只能评价 `known-step recall` 或 `positive-reference coverage`；未列边是 `unknown`，不能全部算假阳性。只有在冻结且充分核查的子图范围内，才计算事件边Precision/F1。训练/验证/测试按独立攻击episode分开；样本数是episode数，不能把百万事件当百万独立实验。缺失日志的实验要分别设计截断窗口、传感器关闭/字段缺失等机制，不能单靠随机删边代替。

**不得混分母：**DEPIMPACT论文的FPR使用反向依赖图边作分母，不等于标准`FP/(FP+TN)`或本题`1−Precision`；TraceBack可见材料的FPR具体定义仍须正文逐项对照。[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)。

结论：存在无精确root标签仍可做的原型和报告步骤覆盖实验；现阶段不具备直接宣布事件级攻击因果精度或跨场景方法优越性的评价条件。
