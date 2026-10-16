# 单一主线最小正式基线方案（DRAFT_NOT_EXECUTED）

实验对象只有E5 2019-05-17 CADETS-1 F2执行。任务是末端B到入站连接/会话来源及可回链路径；不追加Reflection、通用链生成或新模型。此文件是具体准入合同，不声称当前可直接启动。

|项目|固定方案与目前状态|
|---|---|
|原始成员|下一候选ta1-cadets-1-e5-official-2.bin.120.gz，299647139B，官方MD5 09e6d64ac074582833eee1ab3cb2a34a；NOT_OBTAINED。时间范围未测，不按编号保证覆盖|
|已知参考|官方更新TA5.1 Rev1.0 §10.4 PDF100–105，报告F2晚期文件读B1；参考A与中间关系还没有原始映射|
|B选择|评估侧先按报告固定F2晚期文件读取动作，独立校准host/clock，再按timestampNanos→EventUUID→原成员记录号排序选首个满足完整匹配的事件。若多条不能消歧则B_UNRESOLVED；不得按能否找到A选B。QUERY=REFERENCE_SEEDED_QUERY|
|检索器输入|仅B的原事件定位及同范围全部原始背景/上游事件、schema、统一预算；不得读取E1/E3报告全链、来源A、完整IOC表和评分|
|来源层级|本轮建议入站连接实例；进程/文件为中间实体。网络UUID/生命周期未清则来源指标不可计算；不改成最早祖先或组织|
|B0|时间约束逆向依赖检索/候选集合。按(node,time bound)遍历，保存正向原事件边和断点；只给搜索空间，遍历次序不是来源分数。B0与资格用DIAGNOSTIC_BACKWARD_TRAVERSAL同一语义。当前未实现空壳框架、未运行|
|B1唯一主候选|作者DEPIMPACT main725263849b3656060504ce8156b0e85f13747338；本机已有原JAR与94B示例property，Main-Class pagerank.Artifact。原README入口：java -jar DepImpactJar-1.0-SNAPSHOT-jar-with-dependencies.jar LOG OUT PROPERTY|
|B1适配闸门|上述入口是真实作者命令，不是可立即跑E5的完整命令。示例是文本日志/文件POI，CDM20事件级B、UUID/版本及时间截断兼容性NOT_VERIFIED。必须先有作者支持的配套输入入口或经验证的保真适配；不能把Avro改后缀、伪造Linux日志或把自写规则命名官方算法|
|B1参数权限|POI、高信誉/相关属性、detectionSize等先查作者定义；仅允许由共享B和原始记录可见字段确定。不能传入参考A或全链答案，也不直接套新标签到旧crackhost2演示|
|单一对照差异|共同原始事件/图语义/时间范围/B/候选层级/预算，比较B0搜索空间与B1作者影响排序/剪枝。若作者实现不能维持事件级B或同候选层级，暂停公平主比较，不能偷偷放宽只给B|
|额外知识分层|POIROT/Minos的CTI模板/库、SLEUTH标签、PrioTracker参考profile及KAIROS/ANCHOR自选异常锚点均另列辅助输入层，不混主榜；Oracle只资格/上界|
|最大工作量|共享索引扫描≤250000原事件、≤1000000关系；每个串行CPU作业≤600秒、目标≤4GiB；一个执行、一个独立固定B，B0/B1各一次。无GPU、LLM、安装或不可信序列化。超限RESOURCE_TRUNCATED，保持已读范围与未闭包实体|
|事件语义|Subject UUID+host+生命周期处理PID复用；文件读写按对象/版本及方向，字节依赖未知则MAY_INFORMATION_FLOW；网络连接按原事件+会话，跨机要匹配会话/时钟。原边方向与逆向查询分开；不以时间邻近补边|
|停止/失败|缺B/来源标签或作者入口时INPUT_GATE_BLOCKED；缺父节点/WINDOW_BOUNDARY；已读范围内无路径才NO_PATH_IN_AVAILABLE_SCOPE；超限不当真正不可达，NA不填0|
|评价|有独立来源等价集合才对B1计算网络来源Top1/3/5、MRR；B0未排序集合仅来源候选覆盖/数量。没有可核查逐边/路径参考，路径与边P/R=NOT_ESTIMABLE。保留背景误纳、身份未解、时间/内存/候选量。单实例只证明流程可行性|
|候选新方法|METHOD_DESIGN_PENDING；无联合机制缺口/数据证据，不加入B2或新LLM机制|

下一轮实际能用的已有文件是官方报告、校验表、CDM20 schema、既有stream_cdm20.py解析入口，以及作者JAR/README；缺的是120字节及其覆盖验证、目标B/A/关系原始映射和B1 CDM20/事件B兼容验证。不能给这些未知项写假路径、空预测或可执行占位命令。当前只有本轮scripts/read_cdm_header_and_references.py的真实头部/公开文献读取入口已执行，未冒充调查基线。

下一阶段若获得数据并通过映射，原始索引/边构建先冻结且不读参考A；评估侧再在预测冻结后加载报告映射。当前Agent已接触报告和历史，标EXPLORATORY_DATA_QUALIFICATION，不称新盲测。B可由外部检测或发布记录提供，不必调用研究一/二模型。新实验输出必须另建授权目录，本C16目录封存后不改写。

本文件全部模型相关扩展为DRAFT_NOT_EXECUTED，C15额度不继承。本轮不自动启动此方案或C17。
