# 六条技术路线：方法目标先于模型

核查截至2026-10-08。30篇记录见论文矩阵；含边界/数据工作，不把30篇都算直接溯源。近邻工作与历史复测决定了下列竞争边界。

|路线|代表方法、起点与输出|已建立能力|仍可检验的问题|本机适配|
|---|---|---|---|---|
|A 反向／前向依赖|[BackTracker](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)异常状态→反向图；[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)来源与影响；[PrioTracker](https://www.ndss-symposium.org/ndss2018/)优先探索；[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)POI→加权入口排序＋前向筛选|从线索找到可达上游和下游已有成熟方法；DEPIMPACT已排名入口|候选依赖怎样转为有证据的攻击关系；来源漏观测时如何拒答|高：已有局部图/路径工具；不把唯一root当必需|
|B 攻击相关子图及关键依赖|[ATLAS](https://www.usenix.org/system/files/sec21-alsaheel.pdf)一个或多个症状→故事；[DEPCOMM](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)依赖图→社区摘要；[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)关键组件；[TraceBack](https://doi.org/10.1016/j.knosys.2026.116816)POI→紧凑关键图|路径、分支、摘要均已有强先例，图少不是创新|在既定证据预算下保留哪些**独立核验**的关键事件边；缺口是否可识别|最高：可在现有事件回链工具上先做受限原型；论文验证条件尚缺|
|C 依赖精度|[BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)二进制执行单元；[ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)记录/污点交替；[Windows EDR workshop](https://www.ndss-symposium.org/ndss-paper/auto-draft-660/)事件语义启发|长寿命进程和共享资源伪依赖可以通过更细执行上下文减少|旧审计日志是否含足够上下文区分两条路径；不可识别时必须承认|中低：事前插桩型不能离线移植；可做有限误关联审计|
|D 不完整观测|[Improv](https://www.ndss-symposium.org/ndss-paper/auto-draft-661/)采集时补上下文；旧案例显示left censor|缺边是真实问题，不能将“未记录”视为“不存在”|不同缺失机制下的保守解释、拒答和证据充分性；随机删边不等于真实故障|中：可做可控压力测试，但论文需真实缺失案例/采集元数据|
|E 多告警组织|[RapSheet](https://adambates.org/documents/Hassan_Oakland20.pdf)多告警IIP及有根图；[KAIROS](https://www.ndss-symposium.org/ndss-paper/kairos-practical-intrusion-detection-and-investigation-using-whole-system-provenance/)异常队列；[NODLINK](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf)多terminal连接|多点关联并非新概念；B1-Min与B2在两片段成本/稀疏覆盖相同|混合真假告警和独立攻击分组仍可能有价值，但需独立多episode GT|中低：当前可确认独立多攻击案不足；B2方法分支关闭|
|F 跨主机|[多主机因果](https://www.ndss-symposium.org/ndss2005/enriching-intrusion-alerts-through-multi-host-causality/)IDS线索→跨机图；[PicoSDN](https://web.mit.edu/ha22286/www/papers/USENIX21.pdf)多证据共同祖先；[HADES](https://doi.org/10.1109/tdsc.2025.3611866)AD会话追踪；[Commander](https://doi.org/10.1016/j.jisa.2025.104057)多阶段跨机图|跨主机关联和会话分区已有研究|跨源时间、身份、会话与网络因果对齐|低：缺企业多机传感器与可用真值|

## 容易混淆的边界

1. [NODLINK](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf)的多terminal连图、[RapSheet](https://adambates.org/documents/Hassan_Oakland20.pdf)的多告警根图和[PicoSDN](https://web.mit.edu/ha22286/www/papers/USENIX21.pdf)共同祖先，均反驳“多点首次”说法。本机B1-Min/B2目标匹配的局部复测也已否定单纯少边主张，见[原始结论](../APT_Process_Tracing_Pilot/native_investigation_alignment/04_FINAL_DECISION.md)。
2. [DEPCOMM](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)保留社区层代表流；它的摘要质量不能直接视为原始攻击事件边准确率。[Attack structure matters](https://doi.org/10.1016/j.cose.2025.104578)研究结构评价，不能自行生产GT。
3. B+D组合可提出“证据约束、部分观测下的关键依赖恢复与拒答”，但此为**候选问题**，不是检索后已证明的新颖性。需与DEPIMPACT、DEPCOMM、TraceBack逐项核对任务和评测语义。尤其不能将作者算法输出当独立参考。

## 12 篇方法与评价精读索引

“精读”表示核对方法与评价章节，不表示重跑作者系统。前期核查笔记在 `research/foundations.md`、`research/modern.md`；以下给出可直接追溯到原文的章节。

|论文|方法章节|评价或案例章节|对本题的限制|
|---|---|---|---|
|[BackTracker](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)|§2–3 反向图|§4–5 蜜罐案例|潜在依赖非逐边真因果|
|[多主机因果](https://www.ndss-symposium.org/wp-content/uploads/2017/09/Enriching-Intrusion-Alerts-Through-Multi-Host-Causality-Morley-Mao.pdf)|§2–3 跨主机消息关联|§4–5 攻击与告警关联|跨机追踪早有先例|
|[BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)|§III–VI 执行单元|§VII 开销、100文件和攻击案例|需采集期语义|
|[ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)|§III–V 记录与污点交替|§VI-C/Table III–IV 来源/影响查询|图小还须检验路径|
|[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)|§5.1 来源选择|评价章节中的来源和场景|已有入口识别|
|[NoDoze](https://kangkookjee.github.io/publications/nodoze-ndss2019.pdf)|§IV–VII 告警图摘要|§VIII/Table III 事件/进程|告警摘要不等于根|
|[RapSheet](https://adambates.org/documents/Hassan_Oakland20.pdf)|§IV-D IIP与多告警图|§VII/附录C 场景排序|多告警有根图已有|
|[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)|§3–4 反向加权与前向筛选|§5/Table 8 入口排名|论文FPR与边精度分母不同|
|[DEPCOMM](https://xusheng-xiao.github.io/papers/depcomm-ieeesp2022.pdf)|§III–IV 社区与InfoPath|§V 6个实验室/8个DARPA攻击|社区F1不等于原始边F1|
|[NODLINK](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf)|§IV–V terminal hopset|§VI 模拟/企业案例|多点隐式关联已有|
|[R-CAID](https://ieeexplore.ieee.org/abstract/document/10646671)|root上下文检测方法|节点检测/辅助标注实验|结构root不等于初侵|
|[ORTHRUS](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)|候选入口/出口评分|精简攻击链/节点评价|已有入口评分|
