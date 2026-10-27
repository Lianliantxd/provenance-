> 后续审查更正：1,267 是恰好对应单行的输出边数，去重发布行定位为 2,010；以下保留早期报告语境。

> 公开编辑版：私有路径与端点已删；本轮状态按原实验时间解释。相对链接指私有工件，未随本文发布。

# 本轮基线调查执行与共同评价报告

**取得一项真实作者调查组件输出：AIRTAG，858节点、1,816边。尚未形成原生OS身份与独立攻击关系评价均齐备的正式过程基线。**

A. BASELINE_PROCESS_OUTPUT_VERIFIED（仅AIRTAG作者预计算输入后的调查组件，来源粒度有限）；NODLINK为BASELINE_EXECUTION_BLOCKED、历史L2保留。B. MINOS_AUTHOR_CODE_NOT_VERIFIED / MINOS_RUNTIME_BLOCKED。C. COMMON_EVALUATION_NOT_READY / PROCESS_LEVEL_REFERENCE_NOT_READY。

## 1. NODLINK以前完成了什么？

真实VAE训练/检测及适配分支L2已证实。TRACE398659进程、4阳性，TP4/FP23865/FN0、F1约0.0003351；hw17/THEIA另有报告。它们不是本轮过程指标。模型、FastText、TF-IDF、原始日志确在；在线main/ProvGraph/VAE与HEAD一致，修改的离线训练/嵌入和研究扩展另标身份。历史环境simulated的实际执行归属未被conda创建记录充分证明。见historical/及原始只读回执。

## 2. 本轮是否实际执行NODLINK调查？

**NO。** 首个阻断是NODLINK_INPUT_LINEAGE_NOT_ESTABLISHED，不是没模型。hw17当前AE.model修改时间晚于评价报告876.089秒，没有历史哈希将当前权重与报告阈值/逐实体预测绑定。mtime不能证明模型被错误覆盖，但无法据此证明合法复用旧阈值；也未找到可身份回查的缓存。按合同8.2不执行额外检测、不重训、不用Gold替代预测。已检查图ZIP等非DOT格式，它们是train/test缓存，不冒充历史调查结果。

## 3. 是否生成真实调查子图？

**YES，AIRTAG组件；NODLINK没有。** 固定作者commit 9b8d019019ac5e31f0b348ec81c94a72e87f0370，POI为作者文件指定[ENDPOINT_REDACTED]，输入raw_log95,065行、filtered_log8,815行，全部筛选行均能逐字节多重集合对应原发布输入。满足本轮合同11条件3；不是自行制造filtered_log，也不是本轮检测输出。

未改connect_true.py实际构图、补连、筛选/抽象，输出858节点/1,816边，包含28条type=added。节点边以真实author graph JSON为准，DOT为序列化兼容导出，绝不借用旧connect_result.dot。首轮最后写DOT因冒号引号失败，完整记录保留；第二轮只修正确引号，不改算法。调查+序列化2.878794秒，峰值RSS 281182208字节（约268.2MiB），整体进程墙钟另存。CPU线程1，无GPU/LLM。

真实输出：methods/AIRTAG/outputs/author_original_output/connected_graph.dot（兼容DOT）、derived_author_graph.json、reconstructed_nodes.csv、reconstructed_edges.csv、source_mapping.csv。观测式add_edge钩子不改变图，可使1,623边精确投影到作者预处理日志行，1,267为唯一行。**发布日志行不等于原始OS事件ID**；原始采集/转换链未核，所有OS-native身份保守UNKNOWN。剩余193边不强行匹配；added标AUTHOR_INFERRED/NON_NATIVE_OR_UNVERIFIED_EDGE。这证明算法真实输出，不证明其中边均为攻击因果。

## 4. MINOS官方完整源码是否取得？

**未核实取得。** [正式Springer章](https://link.springer.com/chapter/10.1007/978-3-032-38692-2_19)再核2026-10-08在线，ESORICS2026；本轮承认用户批准B类例外。检查arXiv正文/附录、作者主页、作者公开GitHub两页和实际相关仓库，未定位同名完整FSM/工具实现；一处TLS失败保留，不据此证明作者绝无代码。MINOS_AUTHOR_CODE_NOT_AVAILABLE_OR_NOT_VERIFIED。未猜仓库名无限搜索，不使用第三方复刻。附邮件草稿未发送。

## 5. MINOS是否真实Agent调查？

**NO。** 源码/入口未核、环境未建；导入、工具、LLM、多Agent调度、最终子图全部NOT_RUN。不模拟回复、不生成Token成本。另无获准上传日志/商业API条件，发表例外不豁免运行权限。

## 6. AIRTAG是否成为可用补充？

**调查组件层面YES，端到端检测/正式过程评价层面NO。** 作者现成配对输入在同commit发布且字节匹配，足以运行条件3；仍未取得检测器产生filtered_log的完整接口/运行轨迹，不能说这项缺口已消失。该实验验证作者图模块可运行，超出上轮静态核查。新增独立AIRTAG环境只含普通CPU依赖，旧环境未改；第一次审批误按旧合同拒绝，凭本轮7.3/7.4及输入证据重新提交后获准，未绕过。

## 7. 共同输入/输出接口是否建立？

**建立了单方法可执行接口，尚无两方法共同对照。** 真实输入和源码SHA冻结、作者POI原样保留。原图/CSV记录作者节点ID、类型、方向和时间字面值，缺失填UNKNOWN；不猜时区和OS实例。路径未明确输出，predicted_paths.json为null，不自行枚举当作者路径。EXPOSED_DEVELOPMENT_EVALUATION，不称盲测。

## 8. 共同评价是否完成？

节点、边、路径、活动关系准确性全部NA；没有本例同版独立参考。前轮16个恶意行号数组不能按数量相似猜本例S1并套标签。真实统计只有图规模、时间、内存和发布输入行投影89.37%，**不是攻击边Precision或OS原生回查率**。评价程序与预测分离、先验哈希，未传参考时明确输出NA。没有UNKNOWN当负例，也未使用内嵌NODLINK攻击节点造种子。

## 9. 哪项具备正式基线资格？

|方法|发表/源码|本轮执行/输出|共同评价资格|
|---|---|---|---|
|NODLINK|CCF-A，作者在线源码在|历史L2；本轮调查NO|不具备|
|MINOS|B类用户特批有效，官方完整代码未核|无Agent/图|不具备|
|AIRTAG|CCF-A，作者调查源码未改|真实858/1816调查图，作者预计算输入|组件资产可用；无同版独立参考与原OS映射，正式过程评分不准入|

没有将本轮结果宣称原论文全指标复现。ORTHRUS/OCR-APT/KnowHow/PROVSEEK、DEPCOMM/DEPIMPACT与SAGA均未重开。

## 10. 可进入算法研发吗？

**尚不能进入有正式有效性结论的新算法实验。** 已有真实调查组件，已观察28条补边与部分投影歧义，但无独立Gold，不能把这些直接宣布错误连接或算法失败率。最小条件是当前固定AIRTAG输入的OS事件转换合同与同版独立攻击边/路径参考；若只能给节点参考，就只做节点级评价。NODLINK的最小缺口是权重/阈值/身份预测绑定；MINOS是官方完整实现。当前不再泛化建议装环境、扩数据或改任务，也不自动下一阶段。

## 执行边界和交付

无训练、研究模型API/GPU、攻击程序、数据库部署/修改、全局安装、历史文件修改或GitHub push。仅在新目录安装AIRTAG普通依赖，真实有限CPU组件执行2次（首轮导出失败、一次序列化重试）。本轮新结果和必要报告同步到服务器新目录，排除本机env避免跨平台拷贝；实际路径/校验见logs/server_sync_receipt.json。完整冻结见SHA256_manifest.json。不得把导出CSV本身称共同评价完成。
