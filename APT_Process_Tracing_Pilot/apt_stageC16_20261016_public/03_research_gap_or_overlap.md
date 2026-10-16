# 与已有方法的重叠及当前方法准入

任务定义已有直接先行工作，不能以“B-only + provenance + Agent”本身为新贡献。本轮核对10篇原始论文/作者材料，方法与评价章节均可读；其中Minos和ANCHOR仅为2026预印本，未被本项目独立复现。逐项输入、种子、边语义、参考与代码状态见02表。未核实的代码或配套数据明确写NOT_VERIFIED，不把未找到写成不存在。

SOURCE_VERIFIED：DEPIMPACT从POI反向传播影响、排名三类入口、再前向恢复关键子图（§4.3、§5.4），与来源候选及到B的路径最直接重叠，选为唯一优先B1。BackTracker已从单检测点找可能入口；SLEUTH有标签约束的来源识别；PrioTracker已研究时间预算内优先级调查。因此“逆向遍历”“根排名”“预算检索”都不是本轮新机制。[DEPIMPACT原文](https://www.usenix.org/system/files/sec22-fang.pdf)、[PrioTracker原文](https://www.princeton.edu/~pmittal/publications/priotracker-ndss18.pdf)。

SOURCE_VERIFIED：POIROT依赖CTI查询图/多个IOC，不是相同B-only权限；HOLMES以TTP相关检测产生高层图；KAIROS以训练后的异常窗口和社区形成总结图。ATLAS接受症状节点并学习攻击故事，较接近调查，但不等于原生来源实体排名。它们可作为分层辅助，不能为了“强基线数量”混入同输入主榜。

SOURCE_VERIFIED：Minos §2.2/§4/§5.1已给出POI反向追踪、多Agent、RAG、状态记忆和count-first受控查询，POI按最后恶意GT事件选择；它还使用CTI/ATT&CK/schema库。ANCHOR §4与附录B/C是正常上下文+案例状态的叙事调查，并给出E5窗口标签修订。其标签不是入站连接实例或逐边来源真值；匿名代码链接存在，但本轮web读取没有可审阅正文，代码内容NOT_VERIFIED。[Minos v1](https://arxiv.org/html/2607.00440v1)、[ANCHOR v1](https://arxiv.org/html/2609.36494v1)。不将这些作者报告的成绩当本项目实测。

来源忠实性说明：Minos §5.1把DEPIMPACT的LDA展开为Latent Dirichlet Allocation；DEPIMPACT原论文§4.2及相关工作说明实际采用Linear Discriminant Analysis。B1按原论文和作者工件识别，不转抄近邻对其方法的描述。这不构成本项目对Minos整体效果的复现结论。

PRIOR_PROJECT_CONCLUSION：B2共享路径成本分支匹配目标后未优于B1-Min，维持关闭。WS12/E3/Mordor历史资格结论不重跑、不改名为新发现。C15-S仅引用结项：5次2升3降，原18终态/12评价/6NA/121CLI及HETEROGENEOUS_OR_INCONCLUSIVE不变。其Step F1没有变成Source Accuracy。

CURRENT_AGENT_INFERENCE：目前能确认的是问题重叠与具体实现准入缺口，尚无“已有文献未覆盖的明确机制 + 当前数据确有该问题”的联合证据。方法状态为METHOD_GAP_NOT_ESTABLISHED；对全部潜在机制与未取得实现的覆盖仍SEARCH_INCOMPLETE。不是SUPPORTED_GAP，也不声称整个来源追溯方向被穷尽。

研究问题卡：给独立选定B和同范围原始事件，能否在合法预算内区分入站来源候选并保留原事件路径？实体层级是本轮建议，非最终论文标题。当前证据是已有方法、真实E5容器和官方发布/报告；缺的是目标执行的原始成员/映射、可评价来源及B1同输入适配验证。支持条件是映射出B、独立来源等价集合、可核查关系，并在同输入/预算下发现稳定失败；否证条件是强基线已覆盖候选或问题仅来自未观测数据。最小动作仅为精确取数资格请求。候选新方法METHOD_DESIGN_PENDING；不开发H2/H3/H4、记忆、反思或通用新框架。
