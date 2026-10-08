# APT 攻击溯源：概念、任务与证据边界

核查截至 2026-10-08。以下是本课题的**操作性定义**，不是声称全领域存在统一标准。严格区分事实、研究建议与未确认事项。经典依据：[BackTracker](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)、[多主机因果](https://www.ndss-symposium.org/ndss2005/enriching-intrusion-alerts-through-multi-host-causality/)、[SLEUTH](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/hossain)、[DEPIMPACT](https://www.usenix.org/system/files/sec22-fang.pdf)。

## 概念边界

|概念|输入→核心输出|必然是攻击？|必需初始入口／标签／溯源图？|关系与依据|
|---|---|---|---|---|
|Data provenance|数据及变换记录→来源/派生历史|否|否／否／否|一般数据谱系；不自动推断恶意。|
|System provenance|系统活动→实体间信息流记录|否|否／否／通常图|审计层表示，[BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)说明粒度改变关系。|
|Whole-system provenance|跨进程、文件、网络的广域系统记录→全局依赖图|否|否／否／通常图|“全”指采集范围，非真实因果完全可见，[ProTracer](https://www.ndss-symposium.org/wp-content/uploads/2017/09/protracer-towards-practical-provenance-tracing-alternating-logging-tainting.pdf)。|
|Attack provenance|攻击观察＋系统证据→来源、传播或影响的证据链|是|否／评测通常需参考／否|本课题重点；至少有攻击相关结论与原始证据。|
|Attack tracing|线索＋时序关系→上游/下游活动|通常|否／否／否|可用图、日志或跨主机事件，[BackTracker](https://web.eecs.umich.edu/~pmchen/papers/king03_1.pdf)。|
|Attack investigation|告警及证据→分析师可核查解释|通常|否／否／否|上位工作流，追踪只是组成部分。|
|Attack scenario reconstruction|证据及线索→攻击步骤、路径或子图|是|否／评价需参考／否|重构可不定位唯一root，[ATLAS](https://www.usenix.org/system/files/sec21-alsaheel.pdf)。|
|Attack source identification|症状→可观测来源实体/状态|通常|定义来源，不等于初始失陷事件／需参考／否|[SLEUTH](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-hossain.pdf)。|
|Root cause analysis|症状→被选定语义下的解释源|否|取决于定义／取决于评价／否|需注明根是告警起点、信息源还是初侵。|
|Impact analysis|给定源→后续可达及受影响对象|通常|不需要找入口／需影响参考／否|方向与反向回溯不同，[多主机因果](https://www.ndss-symposium.org/ndss2005/enriching-intrusion-alerts-through-multi-host-causality/)。|
|Causal dependency analysis|事件关系→潜在依赖|否|否／否／否|happens-before/信息流给可能关系，不证明恶意因果。|
|Attack attribution|证据→责任主体/组织或某事件来源|是|否／通常要外部情报／否|必须说明是“实体来源”还是“威胁组织归因”；后者不属于本课题第四项。|
|Threat hunting|威胁假设/IOC→候选线索|通常|否／否／否|找到线索不等于过程已恢复，[POIROT](https://par.nsf.gov/servlets/purl/10298256)。|
|IP traceback|可疑包/地址→网络发送源路径|通常|不要求主机初侵／通常需网络参考／否|网络层源路由问题，不等同主机事件重构。|

“必须”是概念的逻辑要求，不表示某论文具备数据或代码。攻击检测给出是否/何处可疑；溯源需要对至少一个攻击相关现象给出上游来源关系、经过或后续影响中的**可核查联系**。使用 provenance graph 仅说明表示方式。可达路径是候选解释，不是历史真实因果的证明。攻击组织归因还需图外情报。

## 最小成立条件与形式化

必要条件：①明确调查线索和观测边界；②输出至少一项跨事件的来源/过程/影响关系，且不是单纯节点分类；③关系有时间、方向、原始记录的证据；④将无法确定的关系标为未知。常见但非必要：反向搜索、前向筛选、攻击子图、告警聚合。可选增强：唯一初侵定位、ATT&CK叙事、概率校准、跨主机追踪。

设观测日志为 (L_Ω)，图为 (G_Ω=(V,E,τ,mathrm{type},mathrm{ref}))，线索集 (P)。追踪器输出 (H\subseteq G_Ω)、若干来源候选 (S)、每条边的原始记录引用、状态 `observed / inferred / unknown`。对 `observed` 边要求类型、方向、时间和原日志定位一致；对跨事件恶意关系还须有独立攻击参考或明确限为“候选解释”。若缺失传感器/前置时间窗，输出可为 `left-censored` 或 `undetermined`，不能补造事件。

## 可写入开题报告的定义（约150字）

APT攻击溯源是在明确的主机与时间观测范围内，以攻击相关线索为起点，利用审计事件及其时序依赖，追查线索的可观测来源、连接攻击步骤并识别后续影响，输出能回链原始记录的路径或关键依赖子图。该任务重点是恢复和检验事件间的攻击相关关系，而非仅判定节点恶意、解释攻击意图或断言唯一初始失陷点。对日志缺口、歧义及无法区分的候选解释，须保留不确定状态。

**严格版：**输出关系经独立事件级参考或受控重演验证，并标明传感器覆盖与因果可识别边界。**工程版：**输出方向和时间一致、可回链的候选依赖及报告已知步骤覆盖，未知边不判假；可用于调查演示，但不声称真实因果边精度。二者差别在独立证据与可评价的分母，不在图大小。
