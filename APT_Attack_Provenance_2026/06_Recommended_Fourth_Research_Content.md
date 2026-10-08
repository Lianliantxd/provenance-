# 博士第四研究内容建议：条件性推荐

**决策 B：CONDITIONAL RECOMMENDATION。** 第一推荐为“部分观测下、证据约束的攻击关键依赖恢复”；第二推荐为“审计图中误关联的可识别性与保守消歧”。这是选题判断，不是已完成的新算法贡献或论文质量保证。既有精确Root Gate为BLOCKED，本机B2少边优势在目标匹配后消失；两点不能扩展为整个溯源方向失败。[本机Gate](../APT_Root_Phase3_5/13_GATE1_FINAL.md)、[B2复测](../APT_Process_Tracing_Pilot/native_investigation_alignment/04_FINAL_DECISION.md)。

## 第一推荐

中文题目：**面向部分观测主机审计日志的APT攻击关键依赖证据恢复**。英文：**Evidence-Constrained Recovery of Attack-Relevant Dependencies from Partially Observed Host Audit Logs**。

**Research problem：**既有反向/前向追踪可产生可达图，[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)已做入口排序和关键组件，[DEPCOMM](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)已做社区摘要，[TraceBack](https://doi.org/10.1016/j.knosys.2026.116816)公开目标为紧凑关键图。本题若成立，新增问题必须限于：在观测缺口和多个可达解释同时存在时，怎样只输出有原始记录支持的攻击相关依赖、保留关键分支，对证据不足的连接拒答，并把成本与已知证据覆盖一起评价。**这仍是待证实的差异，不宣称全球首次。**

输入：审计事件、事件级时序图、一个或数个独立于待评算法的POI、观测范围元数据。输出：可回链原始offset/UUID/hash的关键事件和依赖子图；边的`observed / unresolved`标记；线索覆盖与缺口清单。来源候选可作为辅助输出，不强制唯一root；不要求研究内容二的恶意分类器或研究内容三的ATT&CK意图模型先完成。

必要方法模块最多三项：①时序、进程生命周期和方向约束的候选图；②在同一POI/预算下筛选并保留证据分支，要求每一输出边可回链；③对日志缺口/等价解释拒答和边界报告。模块②若与强基线相同，不因“联合”或更少边而另称创新。

**数据：**本机CADETS与NODLINK片段可做Level 1；OpTC、E5、ATLASv2是Level 2候选，但原始事件及标签同版可得性须实查。现有精确root、闭世界事件边、跨主机因果GT均**未取得**。不部署VM，不下载全量大型归档，不要求真人重新标精确Root。

**同任务对照至少三类：**时间约束BFS/独立最短合法路径（简单）；SLEUTH/BackTracker来源追踪适配（经典）；DEPIMPACT原生或明确标注的适配版，以及可得时TraceBack（近期直接近邻）。DEPCOMM作摘要成本对照；NODLINK/KAIROS作调查图近邻。原生方法、适配器、文献级对比应分栏，不混合结果或改变POI定义。[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)、[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)。

**主指标：**独立已知关键步骤的事件ID覆盖；在充分标注范围内的关键边P/R/F1；已知关键分支断裂数；错误确定连接率及拒答覆盖—风险曲线。**辅助：**节点召回、图规模、查询时间/内存、来源候选Hit@K（仅有独立root参考的案例）；图越小不能单独算更好。标签只有正例时，边Precision/F1=`NA`。

可能贡献上限三项：1) 明确观测缺口下可判/不可判的依赖语义；2) 在同预算下提高独立核查关键边/分支保持率且控制无依据边；3) 公开同版、事件回链的评价协议与拒答评测。三项都须用独立数据、强基线和消融检验；若无法取得GT，只保留原型与协议，不称投稿级算法贡献。

## 第二推荐及不推荐路线

第二推荐 C：研究长寿命进程、共享文件/会话造成的**可识别误关联**，前提是原始日志含执行上下文或能采集对照。BEEP/ProTracer说明该问题重要，但其事前插桩信息不能从旧日志凭空恢复。[BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)、[ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)。

暂不推荐单独多POI共享路径：RapSheet/NODLINK/PicoSDN已有多点机制，B2局部优势未成立，且缺混合攻击独立案。暂不推荐“恢复完整真实因果链”：传感器缺口与闭世界边GT未解决。暂不推荐跨机AD主路线：HADES/Commander已覆盖重要机制，本机缺完整会话、认证与企业多机参考。[HADES](https://doi.org/10.1109/tdsc.2025.3611866)、[Commander](https://doi.org/10.1016/j.jisa.2025.104057)。纯检测/ATT&CK叙事分别重叠研究内容二/三。

## 论文级风险与停止规则

数据风险：独立事件级参考仍缺。方法风险：简单合法路径或DEPIMPACT可能达到相同覆盖—成本边界。评价风险：报告正例不能估Precision；作者预存结果不可当本轮输出。新颖性风险：TraceBack与DEPCOMM的实际目标可能覆盖拟议贡献。若独立标签不可得或强基线无稳定增益，应缩窄到可识别依赖审计/评价协议，甚至对该方法主张作D结论。所谓一区潜力须按学校当年成果认定及期刊实际分区核查，不能保证发表。
