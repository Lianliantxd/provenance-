> 公开编辑版：私有路径与端点已删；本轮状态按原实验时间解释。相对链接指私有工件，未随本文发布。

# 四项APT方法真实复现与算法比较——结项报告

本轮完成四份源码/历史核查、四个全新独立环境和有边界的真实执行。**没有任何一项完成原始主要流程及官方指标复现；不能报告“四篇已成功复现”，也没有正式攻击过程重构基线已准入。** 真实运行的范围与阻断如下。

## 1. 四个独立环境

|算法|Python|依赖验收|环境磁盘占用|本轮终态|
|---|---|---|---:|---|
|ORTHRUS|3.9.24|核心导入通过|1.455 GiB|BLOCKED_BY_MODEL_OR_DATA|
|PROVSEEK|3.11.11|核心导入通过|2.456 GiB|BLOCKED_BY_EXTERNAL_SERVICE|
|OCR-APT|3.9.24|导入未齐|1.700 GiB|BLOCKED_BY_MODEL_OR_DATA|
|KnowHow|3.9.24|核心导入通过|0.685 GiB|PARTIAL_REPRODUCTION|

四个环境绝对路径均为 `[PRIVATE_PATH]<算法名>`，名称大小写分别为ORTHRUS、PROVSEEK、OCR-APT、KnowHow。实际sys.prefix、executable、base_prefix、site-packages、Torch/CUDA及pip清单已逐环境保存；四个prefix互不相同。前三者Python依据作者文档；KnowHow无作者版本清单，选择3.9.24依据历史CPU分支与实际依赖兼容性，明确是本轮工程选择。

## 2. 四个方法运行到哪里

ORTHRUS：环境与作者重构入口检查；未产生原生真实数据攻击重构输出。PROVSEEK：依赖、真实Q&A接口及已有向量检索smoke；未执行Agent、LLM或embedding生成。OCR-APT：核心自定义OCRGCN/评价器导入及CLI检查；未运行真实GNN检测、GraphDB子图或LLM。KnowHow：真实CTI上的作者优化SVO组件、64条真实日志的声明类型适配字典分支；不是原始完整嵌入/生命周期流程。所有官方评价均NOT_RUN。

原始和恢复后的退出码全部保留。导入、--help和检索smoke不算核心流程；作者静态报告、旧hw17结果不算本轮输出。详细逐次测试与真实值见各项目module_execution_results.md和comparisons/runtime_state.json。

## 3. OCR-APT和KnowHow历史问题是否解决

OCR-APT并非已证明“作者没有GNN源码”：自定义PyGOD/OCRGCN在本轮实际目录中存在。仍缺配套dataset/模型、原CSV—报告字节配对和可用GraphDB/模型服务。历史空查询、静态报告差异不能用新导入成功消除。

KnowHow此前已经跑过直接知识分支全量hw17及声明修复后的图/阶段，不应再写成从未执行。本轮普通NLP依赖与已有小模型可用，优化SVO及64条字典评分形成新输出；原gIoC入口缺SVO、原CTI/精确模型和原评价不齐，原始lifecycle仍失败。本轮不把旧修复结果或优化文件改名顶替作者缺模块。

## 4. ORTHRUS攻击重构

未实际恢复真实攻击图。作者attack_reconstruction确实存在，不是只有检测。其入口需要配套时窗图、嵌入、测试损失/评价结果和数据库映射；只有预训练weights不能完成。POI来自预测y_hat，但入口按测试统计MCC选择epoch，须与“完全无Gold参与的调查输入”区分。默认degree与论文度比+损失式不同，recon_loss字典判断还存在静态缺陷；本轮未改算法，也未声称量化其真实影响。

## 5. PROVSEEK是否真正调查

没有。LLM_INFERENCE_NOT_EXECUTED。该方法代码有多轮SQL/RAG、follow-up及安全审查，但当前导入含远程OpenAI embeddings，完整数据库/模型服务和授权条件不齐。已有向量的检索smoke不能当调查成功；示例执行不能当本轮轨迹。原界面share=True未启动。

## 6. 核心创新与实际证据

ORTHRUS：正常行为建模、异常质量与时序DAG依赖图筛选。PROVSEEK：面向数据库证据的多角色Agent与动态检索。OCR-APT：关系图单类异常检测、有限子图查询与分阶段RAG报告/IOC上下文增强。KnowHow：gIoC语义知识与日志对齐、攻击生命周期约束。四者输出、证据和指标的区别及逐代码入口见four_methods_algorithm_comparison.md，不能将所有方法都简化为“只检测”或“只讲故事”。

## 7. 正式基线资格

[CCF官方页面](https://www.ccf.org.cn/Academic_Evaluation/NIS/)确认CCS、USENIX Security、NDSS属A类；对应三篇正式发表身份已核验。PROVSEEK现有[arXiv元数据](https://arxiv.org/abs/2508.21323)及有限检索未确认合格发表，不能升级为正式基线，也不据此断言永未发表。

当前四项均FORMAL_BASELINE_ADMISSIBLE=FALSE。ORTHRUS是任务最接近的优先候选，尚未通过真实流程与评价准入。不存在可直接拿来作为用户独立攻击活动/因果路径Gold的已验证参考。评价单位不同，禁止合并为统一过程F1。

## 8. 后续有限研究候选

只提出证据断言回查、具体实例/平行事件保留、固定预算主动检索的可证伪问题；这些仍是假设，未取得本轮算法增益证据。不能以简单拼接GNN、LLM、RAG、多Agent宣称创新。详见process_reconstruction_compatibility.md。本轮不重开SAGA规则、不搜索新数据、不启动下一轮。

## 9. 成本、安全与交付

已记录服务器核查窗口：2026-10-26T09:54:12Z 至 2026-10-26T12:51:12Z，约177.0分钟；最初读合同/前置审批未完整计时。已记录子进程RSS高水位最大值：722.9 MiB（首个ORTHRUS安装未采样，不能称全局完整峰值）。新工作区已分配磁盘约9.924 GiB，最终封存文件会略增；环境大小见上表，缓存另见runtime_state.json。

研究LLM调用、付费API、GPU推理、训练、服务部署、攻击执行、原始数据库写入、GitHub推送均0。小型已有spaCy模型在CPU上执行，不是LLM。软件/公开论文下载获授权；没有大型模型或数据下载。网络字节未独立测量，不能把缓存大小等同真实网络下载量（缓存含本机Conda/软件复制）；安装和获取日志已保留。

外部HTTP访问仅用于普通软件、指定论文和出版元数据；业务Postgres/GraphDB查询和远端模型服务调用为0。Chroma在新复制的本机数据库上完成1次向量查询，网络审计钩子拦截了第三方库遥测尝试，无成功外传。首轮第三方导入缓存未做全路径写入追踪，后续已限定缓存路径，不能声称服务器上除本目录外绝无缓存写入。

测试均限制单CPU亲和性、禁联网，少量标准库CPU/字体/库位置探针单列允许；原包装器过严造成的失败与作者失败区分。C13等旧任务的模型授权未用于本轮。原始源码范围内哈希不匹配0；原始数据及历史实验未写入。Conda只创建新prefix，pip只指向各环境，不修改系统Python/服务/网络。未对整个服务器所有文件做全局“未变化”证明。

算法/模块始终使用各自环境绝对解释器；盘点及调度只使用服务器已有标准库Python，不向其中安装方法依赖。OCR普通依赖下载超时记录、core0.14.0限时尝试未完成、banks两行类型兼容补丁及仍存LLM | None导入错误均保留。原生GNN依赖和CLI已通过，LLM环境不能标为全就绪。两次严格PID匹配恢复未找到目标，未发送进程信号；随后使用分离CPU软件轮包/普通依赖的流程完成安装。

环境包下载流量的可核验下界及最终封存时间以DOWNLOAD_ARTIFACT_LEDGER.json、SERVER_SEAL_RECEIPT.json为准；它们记录成功取得的唯一软件包文件，不包含重复下载、失败部分流量或协议开销，不能当精确网络计费字节。

服务器主目录：`[PRIVATE_PATH]`。本机报告镜像：`[PRIVATE_PATH]`。私有运行输入/输出留在服务器；报告与必要回执同步本机。本轮合同禁止自动推送GitHub，因此未推送。

主要原始来源：[ORTHRUS正式论文](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf)、[PROVSEEK预印本](https://arxiv.org/abs/2508.21323)、[OCR-APT正式发表](https://doi.org/10.1145/3719027.3765219)、[KnowHow正式论文](https://www.ndss-symposium.org/wp-content/uploads/2026-s199-paper.pdf)、[CCF官方分类](https://www.ccf.org.cn/Academic_Evaluation/NIS/)。源码版本和逐文件SHA见各项目source_integrity.json。
