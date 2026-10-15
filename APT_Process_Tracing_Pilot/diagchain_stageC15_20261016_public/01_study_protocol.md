# C15 预注册：三案例 Reflection 原生开关，3×2×3

状态：C15_PREPARED_AWAITING_BATCH_AUTHORIZATION。研究类型是 DEVELOPMENT_EXPOSED_EXPLORATORY_COMPONENT_ABLATION；SEMANTIC_TRUTH_NOT_INDEPENDENTLY_VALIDATED、NOVELTY_UNVERIFIED。本文不是模型调用授权，模板和既往许可不覆盖18个新运行。

唯一主比较为三案例各3次新的端到端ON/OFF运行。ON=agent_method reflection；OFF=plain。两者均planner llm、ECRAG、structured_attack_chain、typed actions、investigation_memory/support_audit/grounding_check on、oracle none、max_turns15、top_k32。共同固定compression on、memory budget12000、max observation chars900、max memory cards48、no-new-evidence patience3、JSON repair2、visible_anchor、author temperature request0、native timeout360。参数来自实际C13-R模块默认值及合同，不以CLI名称推断服务端设置。

本轮均用KNOWN_LENGTH_METADATA_REMOVED_V1：仅删案例Input根级length_bucket、length_bucket_label。每案两个删除路径保留差异与前后SHA；卡片与顺序完全相同，Docs/Graph原文件只读共用。真实stub及Controller/Reflection/Repair/Synthesis提示入口已用无模型计算核查未重新注入这两个结构化键；日志字符串不做全局替换。作者最终Prediction metadata可能原生写出这两个键的null值，这不是模型输入，既不改作者代码也不伪造桶。只声称去除这两个已知字段，不声称消除所有泄漏。历史C13/C14保留长度桶、时间不同，不进入本轮样本或均值。

源码方法读取的三个行为分支在当前agentic_reconstruction.py 660、688、766行，均为终止/提交路径决定是否调用原生Reflection；其他agent_method出现于声明、调用参数和输出metadata。相同合成回复的初始/中间Controller Prompt、检索选择和工作链一致；ON正常多一次原生Reflection，OFF零次。原生空修订/过度收缩拒收、规范化、Grounding、Repair、Synthesis保留。give_up或解析失败等路径下ON可以不触发Reflection，按assigned_arm计入，不强制补调用。

请求模型固定gpt-6-luna，沿用相同SHA的Codex CLI 0.160.0与V2 worker参数、最终消息选择和事件审计；新会话ephemeral、不resume、不送工程对话/Gold/历史评分/诊断答案。原生num_predict/max_tokens/num_ctx/reasoning_effort均未设有效值；CLI是否实际采用temperature0、服务端精确snapshot、采样与模型内部重试数UNVERIFIED。前台限制完整回复1MiB、stdout8MiB、stderr1MiB为既有V2传输字节限制，不冒充token或模型输出长度设置。不会补自制schema指令改JSON成功率。

保持服务器控制Python3.9.24、既有评价Python3.10.20；准备测试另用既有Mac项目Python3.12，不新建环境或安装依赖。服务器目录副本记SOURCE_COMMIT_UNVERIFIABLE_COPY；60e04064f9b3cf59505ee159379cf851956b8394仅是已知作者发布定位，实际依赖以逐文件SHA为准。

只新增批次配置/输入/排程/预算/封存/评价适配。C13-R V2源文件逐字节复制保留；三案例白名单通过新批次配置适配器设置，不改原验证函数的身份/字节规则。实际Mailbox、final-message parser、精确ACK消歧和worker权限参数保持原字节。新监督入口名称c15_server_native_controller.py调用原包装器main，仍由既有PID/root监督规则识别。跨案例/重复/条件不使用历史reply；同live attempt重复put只许原envelope幂等ACK恢复，不触发新CLI。记录新匿名run_id，不在模型Prompt额外注入arm/unit标签；Worker工作目录为匿名空UUID目录。访问能力不等于读取已发生，无工具事件不证明完整OS隔离。

排程种子C15_REFLECTION_SWITCH_V1只决定执行顺序。R1→R2→R3，每轮案例顺序确定性伪随机；9个配对块相邻运行。5块ON先、4块OFF先；每案2:1或1:2。18个run_id固定唯一，每次空链/空观测/新原生Controller进程与新Worker会话；不强迫相同真实检索ID或相同随机噪声。静态只读数据与OS缓存共享政策相同，不flush系统缓存。

硬封顶：每单元46次新增CLI（所有phase及任何获准新启动），单CLI最多360秒；每单元1800秒活跃墙钟，全批828次与32400秒活跃时间，并发1。启动前持久化预留，失败/不明启动不退款；PID、实际CLI启动与预留另列。Controller每轮最多1+2Repair，max15；再考虑Synthesis/Reflection的保守并集可能超过46，因此46是实际拦截上限，不保证所有原生路径都能完成；第47次预留拒绝、停止该单元，不能扩预算。实际进程内活跃计时用monotonic，跨块终态时间累加；已开始单元不能重新begin清零。配额等待/审批暂停与日历耗时分开；结束清理耗时如超出截止要披露，不增加推理机会。

只用ChatGPT套餐内含额度，禁止API Key、付费Credits、充值或额度重置。每配对块前读取当前usage状态并保存不超过15分钟的新回执，要求ordinaryUsageAllowed、无耗尽、Credits余额0/hasCredits false/unlimited false；自动充值关闭需本批用户当前确认。不能验证或状态不符即PAUSED，不用字符串flag代替账务证据。共享账号额度变化不是实验精确账单，828是上限而非保证能完成。Worker临时/缓存环境指向C15；CLI既有认证机制复用，不修改登录材料、TLS或代理。

成功/失败均封存；ON未触发保留ON；OFF出现Reflection视协议违例暂停。原生合法空链保留，缺最终输出/通信不明不补空链，不按F1择优重跑。已确认读故障/ACK歧义使用V2有界恢复；模型完成不明不重发。会话中断时先读排程/状态/锁：已冻结单元不重跑，已开始而无终态的孤儿单元先只读核对，不自动启动新的同run模型请求或重置时间。需要整次新生成的attempt不作为替换重复，超既定恢复范围另行授权。运行失败先安全暂停审查原因；安全/身份/结构性故障未消歧不启动下一条。没有运行时如实写PAUSED。

18单元都有FROZEN/FAILED终态后才生成BATCH_PREDICTIONS_SEALED，统一调用同版官方evaluate。准备阶段Gold只检查存在和SHA，不解析正文；未完成批次不读取Gold语义/成绩。评价不用旧deadline拒绝已封存早期单元，而是在全批闸门后使用独立180秒CPU评价截止；这只改变评价调度，不改变官方算法、阈值、参考或预测。全批封存前评价入口拒绝；若明确终止部分批次须另记PARTIAL_BATCH_CLOSED，不能看分后再补成原设计。

主要指标bestmatch_step_f1。保留官方所有原字段/原值；其次Step P/R/匹配数、预测/参考步数、CEAF、Evidence P/R/F1、attack B3、两种Edge F1分别报告、Best-match/CEAF排序及实际n(n−1)/2分母、observed/retrieved/cited reference与attribution gap。0对即使官方1也标NO_COMPARABLE_PAIRS。步骤引用与步骤+边attribution集合口径分开；引用不是语义裁决，非参考不是无关，拓扑不是传感器因果。

18行主表保留失败NA，不给未运行/缺结果填0。逐案例逐arm列R1–R3原值、完成/3、均值、中位数、样本标准差、范围；只有1值时SD NOT_ESTIMABLE，0值不填0。case+repeat双边可评价才计算ON−OFF差。按assigned_arm主分析；触发/接纳为描述性附表，不事后移组。无跨案例F1总体均值、无p值/总体显著性。缺失或成本不对称明确报告，不仅展示成功子集。

保守决策规则预先固定：任一协议不可比→ABLATION_INVALID_OR_INCOMPLETE；缺失或案例/重复方向不一致→HETEROGENEOUS_OR_INCONCLUSIVE。完整9对若每对Δ≥0且每案至少1对>0，可在实际成本与资源上限内给KEEP_NATIVE_REFLECTION的有限探索性判断；若每对Δ≤0且每案至少1对<0、OFF每案平均CLI不高于ON，给PREFER_PLAIN_FOR_CURRENT_BACKEND_EXPLORATORY；其他为不确定。即使KEEP也不声称预算外收益成本比普遍合算。任何协议违例优先标无效，不可被上述分数规则覆盖。

内部Reflection快照评价仅可在全批封存后、真实快照可用且schema兼容时选择执行；不是独立OFF重复，不回填元数据或为补快照发新请求。本批不重做C14逐证据诊断，无新算法/新Root标注/整套真人盲审。主实验完成后不自动追加第19运行或研发守卫。研究建议最多1个。

本机/服务器保留私有工件；GitHub新C15目录仅公开泛化代码、参数合同、排程、聚合成绩/失败和限制。不得公开Prompt/回复/Gold或支持ID映射/授权聊天/账号用量/私人路径。准备阶段可同步PREPARED与18行PENDING表，不称已执行。授权、quota与同步回执不纳入自循环封存hash，审批/权限实际拒绝遵守，不绕过。

官方资料只用于核对产品边界，不据此升级软件或替换模型：
- [认证](https://learn.chatgpt.com/docs/auth)
- [非交互CLI与最终消息](https://learn.chatgpt.com/docs/non-interactive-mode)
- [Credits与内含额度](https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-personal-plans)：内含额度优先，耗尽后可使用余额；自动充值是额外控制项，所以旧额度或“未购新Credits”都不足以证明本轮仅内含额度。
