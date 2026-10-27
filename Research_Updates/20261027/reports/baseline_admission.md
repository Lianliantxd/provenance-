> 公开编辑版：私有路径与端点已删；本轮状态按原实验时间解释。相对链接指私有工件，未随本文发布。

# 已有成果继承与正式攻击过程重构基线准入审查

**新增推荐：NONE。新增READY_FOR_REPRODUCTION=0；新增FORMAL_BASELINE_ADMISSIBLE=0。终态：D. NO_NEW_REPRODUCIBLE_BASELINE。**

本轮在继承历史结果后完成固定12项候选筛查：4项传统（包括DEPIMPACT既有二进制demo核查）、8项新LLM/Agent；按严格“此前未研究”计新增11项。深审3项工件链，没有为了填满4项降低发表门槛。未运行任何新算法、LLM、GPU、攻击或正式评分，也未创建/安装环境。

时间基准：从2026-10-26 15:43:44 UTC开始，核查日期跨至2026-10-27 Asia/Shanghai；不把跨午夜当预算重置。范围内终止筛选，不自动续期。公开正文取得量以evidence/verification_receipts.json最终数字为准；大型数据/模型未下载。

## 1. NODLINK到底完成了什么？

用户确认“此前已复现过”予以保留，且本轮找到了真实历史运行工件。服务器源码在`[PRIVATE_PATH]`，HEAD `434dbe2d0be88bd034c4af0c819aed641d2b3758`，13个跟踪文件有修改，并有外部CDM数据适配分支。不能把HEAD当全部实际执行文件的原作者身份。

历史TRACE报告记载50轮VAE、398659个进程/4阳性，TP4、TN374790、FP23865、FN0；P0.0001675814、R1、F1=0.0003351066。hw17和THEIA另有真实检测报告，分别481/5642样本，不能混分母或用另一份零阳性TRACE结果替换。以上是历史进程/实体检测指标，不是本轮结果、路径F1或官方调查精度。

可证实L2（训练/检测组件及适配结果）；完整原作者在线L3、官方调查评价L4、正式过程基线L5为UNKNOWN。在线main.py存在，本次项目深度6、最多10000文件的有界元数据检查实际372文件，未找到DOT/GraphML/GEXF；不据此断言其他目录没有子图。当前不能直接证明已有L5，但绝不能改写为NODLINK从未运行。

历史环境及完整shell执行记录UNKNOWN。报告mtime主要为2025-12至2026-01，不是“最近一个月新运行”，也不等于精确执行日期。保留资产、不重跑。详见继承报告（私有工件）和历史矩阵（私有工件）。

## 2. 哪些历史方法不再重复投入？

|方法|真实已完成部分|当前不可重复投入的原因|
|---|---|---|
|ORTHRUS|独立环境、原作者入口、15项生产者—消费者合同；原始CDM存在|最新为ORTHRUS_BLOCKED_BY_DATABASE_OR_PERMISSION；必须先写入配套TC PostgreSQL，当前无合法同版DB/工件，Detection/Reconstruction/Evaluation均NOT_RUN；不重装|
|OCR-APT|自定义OCRGCN源码、GNN导入/CLI预检|缺同版数据/PyG/权重、GraphDB及报告—原CSV配对；部分LLM类型注解兼容未解决；不把导入通过叫真实调查成功|
|KnowHow|45SVO、64记录限定分支及旧适配实验|主SVO模块、原80CTI/CKD、精确模型/聚类和完整原评价不齐；旧适配/限定分支不能升级完整论文复现|
|PROVSEEK|336文档1536维向量接口真实自查询|完整Agent未运行，DB/模型服务/授权不齐；合格正式发表仍未确认；只作实现参考|
|KAIROS、ATLAS|按历史/用户边界保留|用户已排除主要基线，不再次推荐或从零复现|
|SAGA|r13–r19真实实验|SAGA_PROCESS_EVIDENCE_LIMITED_UNDER_TESTED_CONTRACT；仅辅助数据，不重开步骤Gold或关联规则|

这些是具体工件/权限/评价问题，不能统一称环境问题。最新ORTHRUS专门恢复报告优先于较早四方法总表；较早NODLINK NOT_RUN记录也不能覆盖后来找到的阳性历史证据。

## 3. DEPCOMM能否更容易形成闭环？

**当前不能推荐为完整作者源码复现。** [S&P2022正式论文](https://www.ieee-security.org/TC/SP2022/program-papers.html)满足CCF-A；[固定作者仓库](https://github.com/ieeesp2021sub/depcomm/tree/54ead8669221acb037c7c801f0a762b8c338a722)完整458项目录没有核心.py源码，入口`DEPCOMM/core/Start`是13304944字节封装程序及随附旧Python库。无法定位InfoPath与图压缩源码，Gate B失败；不反编译/自行重写填补。

示例输入确有split TAR（合计29286637字节）及POI参数，预存community/summary图和InfoPath文本也在；不能写成没有输入/没有输出。实际读到的11页Ground Truth PDF是手工社区划分与专家修订，不是完整机器可读独立事件路径参考，评价程序未在固定树找到。论文社区F1/攻击社区召回不可当路径F1。Python2.7旧依赖是额外兼容风险，源码/评价硬缺口已足以停止，没必要先安装。

详见DEPCOMM依赖链（私有工件）。

## 4. DEPIMPACT和AIRTAG是否源码及评价完整？

**DEPIMPACT：否。** [当前公开目录](https://github.com/usenixsub/DepImpact)HEAD仍为已有`725263849b3656060504ce8156b0e85f13747338`，JAR和示例真实可用，先前原生demo成功必须继承。本轮未发现新增公开Java核心算法源码。正式评价器/配套图/property的独立包仍未取得，不能把虚拟机附录说明当实际文件，也不能用新标签套旧demo。保留`ARTIFACT_ACCESS_BLOCKED_UNDER_NO_VM_CONSTRAINT`的获取边界；本轮不取VM。源码门槛本身仍失败。

**AIRTAG：检测和调查图源码存在，但不能证明完整端到端过程评价链。** [固定仓库](https://github.com/dhl123/Airtag-2023/tree/9b8d019019ac5e31f0b348ec81c94a72e87f0370)42项/14个Python文件，`connect/connect_true.py`可构图、补连、抽象，最后写`connected_graph.dot`，不能说它只有恶意实体检测。`find_logs`补边只有`type=added`，缺逐原始事件ID/时间附着，需映射审查。

[作者公开Drive](https://drive.google.com/drive/folders/1u5VNiYvFZaxLezK7uEsPRrIR5dtdfkHC?usp=sharing)实际能列训练(1.22GB)、嵌入(1.82GB)、模型(1.9GB)及参考包，故不再说材料不存在/目录无法取得。大型包不下载，内部版本/哈希绑定未核。实际取得469643字节Ground Truth TAR，16个.npy为恶意日志行号字符串数组；这是检测参考，不能直接评分补连抽象后的图。分类脚本只打印检测指标，未找到预测写入`filtered_log`的实际交接；Drive额外源码也不是该BERT/OCSVM交接。最终图的独立边/路径参考及评价入口未找到，Gate D/E不通过。

详见DEPIMPACT链（私有工件）、AIRTAG链（私有工件）。

## 5. 有没有新的合格LLM/Agent？

本轮8项新候选中，**已确认通过Gate A的数量为0**。这是有界池结论，不是全领域没有正式研究。

- MINOS已正式发表：[Springer DOI](https://doi.org/10.1007/978-3-032-38692-2_19)在线2026-10-08，会议ESORICS2026，卷版权2027；但[CCF官网B表](https://www.ccf.org.cn/Academic_Evaluation/NIS/)列ESORICS为B，不能再写只有预印本，也不能降门槛。
- CLOUSEAU正式ACSAC2025，也是CCF-B；TRACKAGENT官方PDF明确PRISM Workshop，不是NDSS主会。三项为VENUE_FAIL。
- SherAgent、Ananke、CyberClear/CyberProvenance、ANCHOR、SHIELD(Sun)已阅读公开论文和当前出版线索，尚未确认合格正式出版，标VENUE_UNVERIFIED，不宣称永久未发表。Ananke/ANCHOR确有作者匿名源码声明，不能写成无代码；未因声明而认可完整性。
- 已有OCR-APT(CCS2025)与KnowHow(NDSS2026)是合格正式发表竞争方法，继续继承阻断；PROVSEEK正式级别未确认。新候选没有“代码工件全部齐全、值得立即复现”的一项。

SherAgent有动态SQL/查询放宽/分支选择；MINOS有FSM/count-first/检索引用/控辩记忆；PROVSEEK已有实际工具代码。它们与只解释子图、固定RAG或阶段故事流水线不同。完整机制和UNKNOWN边界见LLM/Agent矩阵（私有工件），不能把“GNN+LLM+RAG+多Agent”本身当创新。

## 6. 哪些方法实际恢复路径/过程？

DEPCOMM有InfoPath与社区信息流，DEPIMPACT有关键依赖子图，AIRTAG有调查图；ORTHRUS源码有真实重构入口，但本项目未运行。SherAgent恢复入口/调查树，MINOS/TRACKAGENT筛选攻击事件子图；不能把它们的入口成功、边召回或减图指标混为一条统一路径F1。

OCR-APT/KnowHow/ANCHOR/Ananke/PROVSEEK包含结构证据或多轮调查，但最终故事、阶段/IoC准确性并不自动证明所有活动连接。CyberProvenance的攻击复演证明行为可执行性，与证明这段历史日志中发生了该因果关系不同；其DOT编译Pass@1也不是攻击链正确率。

具体20问、GNN/LLM/Agent、共享实体、缺失日志、验证和数值单位见算法比较（私有工件）、过程可比性（私有工件）。所有文献数值均NOT_RECOMPUTED；未用检测F1冒充路径F1。

## 7. 至少有一条完整复现工件链吗？

**本轮没有确认新的、满足全部条件的“真实数据→作者源码→过程输出→对应独立评价”链。** DEPCOMM/DEPIMPACT的核心源码缺口是确定阻断；AIRTAG有公开候选材料但交接、版本绑定和最终图评价仍不完整。大包内部未读取的部分单独标ARTIFACT_AVAILABILITY_UNVERIFIED，不能与已发现缺口混称不存在。

已有NODLINK组件和DEPIMPACT二进制demo形成的局部链是真实资产，但不足以填补过程官方评价。最终矩阵为工件矩阵（私有工件），三份链逐项列生产者、消费者和来源，不依靠README一句话全通过。

## 8. 最多推荐两个什么算法？

**NONE。** 不推荐缺核心源码、输入交接或独立评价依据的项目，也不把重复NODLINK或再次启动ORTHRUS列为替代。没有准入对象，未来环境命名和资源需求不虚构填写；本轮环境创建0。

推荐决定（私有工件）列出将来只有出现哪些具体新增工件才值得重开审查，不自动获取或实验。

## 9. 当前下一步是什么？

选择 **D. NO_NEW_REPRODUCIBLE_BASELINE**：固定池已完成，新增准入为0，现在结束新增筛选与环境投入，冻结证据和历史资产。

A(EXISTING_BASELINE_READY)尚未证明，因为NODLINK L5未知；B没有新链通过；局部候选对应C所描述的部分材料，但不足以推荐进入正式复现；E不是全局终态，因为并非全部核查都因访问失败，核心源码/评价缺口已有直接证据。结论限本轮池和当前许可，绝不等于数据不存在、方法永远不可复现或研究方向失败。

方法研究仅保留待证问题：行为断言与原生事件实例/方向/时间是否一致、预算压缩是否丢失关系支持、何时应保留竞争解释或拒绝连接。该问题需与上述直接竞争方法逐项区分，在没有独立关系参考和完整基线前不宣称创新已证实，不自动开发新模型或重开SAGA。

## 执行和封存

依最新合同，本轮服务器仅必要只读核查；没有同步写入服务器，没有GitHub push。它优先于历史“每轮同步”要求。公开小源码/论文/说明与小型参考包保存在本机新目录，没有上传内部日志或调用研究模型。历史原文件未编辑，副本/原始路径/SHA及原报告优先级均保留。

evidence/verification_receipts.json记录实际时长、可计量下载正文与未计量的托管检索范围，evidence/SHA256SUMS.txt冻结交付文件。GitHub API限流、作者PDF TLS错误、Drive首次下载提示均保留；没有用失败网页证明文件不存在，也没有把预存图当本轮结果。

完整引文和证据位置见官方来源（私有工件）；筛选依据见发表表（私有工件）、候选短表（私有工件）。本轮结束后不自动开展下一轮复现。
