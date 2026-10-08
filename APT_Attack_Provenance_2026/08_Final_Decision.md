# 最终决策：B — CONDITIONAL RECOMMENDATION

**第一，APT攻击溯源是什么？** 在明确观测范围内，从攻击相关线索出发，恢复来源、经过和影响之间可回链原始事件的依赖证据，并说明未知关系。图可达、节点恶意分类、ATT&CK意图和攻击组织归因均不自动构成已证明的攻击过程溯源。

**第二，已有研究怎样做？** [BackTracker](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)、[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)从异常反向追踪；[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)排序入口并前向筛关键图；[ATLAS](https://www.usenix.org/system/files/sec21-alsaheel.pdf)、[DEPCOMM](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)恢复/摘要调查图；[BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)、[ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)提高依赖精度；[HADES](https://doi.org/10.1109/tdsc.2025.3611866)扩展跨主机追踪。2026 PRISM两篇属**workshop**，不能写成NDSS主会。

**第三，成熟与未解决之处？** 反向/前向搜索、告警关联、入口候选、摘要图均已有强先例。困难在粗粒度伪依赖、缺失观测、关键事件边的独立参考和不同输出目标间的可比评价。小图不一定保住关键攻击分支，已知步骤正例也不能给闭世界precision。

**第四，不做精确Root GT能否做真正的溯源？** 可以：恢复POI到已知攻击步骤的时序依赖与可回链关键子图，用已核验步骤覆盖、合法路径、断裂分支、成本和拒答率评价；边P/F1仅限充分标注窗口。不能由此断言唯一初侵或完整真实因果链。

**第五，当前最易实施路线？** 推荐“部分观测下的证据约束关键依赖恢复”（路线B+D），输入本机CADETS/NODLINK日志与POI，输出带原始事件引用和未知边界的关键路径/子图。现有解析和回链工具可支持原型，无需虚拟机或前三项模型。B2共享路径分支继续关闭。

**第六，怎样独立支撑博士第四项？** 题目为《面向部分观测主机审计日志的APT攻击关键依赖证据恢复》。贡献只可围绕依赖可识别边界、证据约束筛选、拒答/评价协议三项检验；对照时间约束BFS、SLEUTH适配、DEPIMPACT及可得时TraceBack。最小实验冻结两个既有片段，回链报告正例并做同预算路径比较。投稿级还需多个独立episode、同版充分标注事件边窗口、强基线同协议比较及缺失机制消融。当前这些条件**尚未齐**，所以是B而不是A；若无法满足，应收窄为依赖证据可靠性任务（C），不能硬称完整过程重构。

博士总题目可以继续使用“APT攻击检测与溯源”，但第四项须明确限定为**观测证据支持的攻击关键依赖/过程溯源**，不宣称真实世界完整因果链或攻击组织归因。
