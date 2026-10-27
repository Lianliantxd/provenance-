> 公开编辑版：私有路径与端点已删；本轮状态按原实验时间解释。相对链接指私有工件，未随本文发布。

# ORTHRUS上游恢复与真实重构——本轮结项

**终态：ORTHRUS_BLOCKED_BY_DATABASE_OR_PERMISSION。** 本轮没有生成攻击图，Detection、Attack Reconstruction和官方评价均NOT_RUN；正式基线未准入。与上轮不同，本轮已追到真正的生产者接口，核验了实际原始数据、既有图ZIP和既有数据库目录，确认当前首个缺口无法靠继续安装Python依赖解除。

## 1. 原始源码位置与版本

实际路径为`[PRIVATE_PATH] /orthrus`，provenance后确有空格，不能与无空格目录混同。commit为`e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543`，与上轮一致；本轮开始工作区干净。记录64个已跟踪普通文件哈希，dotenv未复制；最终只导出INPUT_DIR/ARTIFACTS_DIR两个数据路径，其他键值未记录。Ground Truth子模块固定于`012f321f46137650496e639b0ad7e0a66db07a73`但未初始化。

复用原环境`[PRIVATE_PATH]`，Python3.9.24，Torch1.13.1+cpu，pip check通过；未新增或升级依赖。仅盘点调度使用已有标准库Python，配置/工件预检使用上述绝对解释器。

## 2. 缺失工件的真实生产者

详细逐函数/行号、输入输出路径和格式已列入`input_contract/artifact_producer_consumer.csv`。首条生产链是CDM JSON→create_database四表INSERT/commit→build_orthrus_graphs时窗图。Word2Vec从同版数据库节点文本生成，不是从哈希图标签反解。edge featurization同时读取DB、图和Word2Vec，输出272维TemporalData。训练/测试再生成匹配缓存、邻居历史和val/test losses；node_evaluation生成真实y_hat和stats；tracing从被选择epoch的y_hat扩展。

`--from_weights`仍运行上游和一轮训练，测试阶段先读state_dict/neighbor_loader缓存，再覆盖发布GNN参数；`--run_from_training`只跳过图/特征阶段，不能修复缺失缓存。因此只有weights不能闭环。

## 3. 现有资源能否组成完整链

不能，未选定任何完整数据集实验。CADETS_E3和THEIA_E3均为PARTIAL_ARTIFACT_CHAIN_NOT_REGENERABLE（限定当前资源与权限），不是没有真实数据。CADETS有5个顶层JSON成员；两个文件各读取2000条前缀，解析错误0，确认CDM18，均未到EOF。前缀时间范围及字节哈希已记录，不能当整文件或完整数据集覆盖。探针host_distinct_count只统计顶层hostId，不能解释为没有主机；Host记录类型已实际出现。

THEIA有13个JSON成员及7,877,492字节graphs.zip。归档只有metadata.json、train0—3.pkl和test0.pkl；元数据为节点5维、边17维、4train/1test。没有匹配的日期/身份/配置及特征基，不能认定为ORTHRUS272维原缓存，也没有强行转换。现有FastText风格文件未证明是作者匹配Word2Vec。TRACE pt分片不属于原版支持的数据集；CADETS_E5单一bin120不能替代完整六日期划分。

另发现PG17数据目录，但既有说明为ATLASV2_EDR；旧端口55439、默认5432和PGSQL Unix socket未见监听，postmaster.pid不存在。没有连接可获准只读的TC数据库。最终按作者Compose的INPUT_DIR/ARTIFACTS_DIR交叉核对，实际分别指向原仓库data和artifacts目录，两者均不存在。没有扩大为全服务器/未知远端数据库扫描。原作者从日志生成TC表需要DDL/INSERT，超出本轮只读DB权限。

## 4. 实际恢复了什么

恢复的是**可复核的输入生产合同、现有工件身份和配置路径**，不是图/embedding/loss。产生源码哈希快照、原配置副本、作者配置解析结果、两份发布权重哈希、图ZIP完整目录及静态字段核验、已有PG端点元数据和有界CDM格式探针。实际命令/输出见runs；没有新增模型预测或训练工件。

首轮安全权重加载因Torch1.13 weights_only不支持协议4退出1，记录保留。第二轮将这一诊断登记后继续静态检查，未退回执行普通pickle；权重张量形状及特征匹配仍NOT_VERIFIED，不宣称模型损坏或结构已通过。

## 5. 是否实际运行GNN Detection

**NOT_RUN。** Gate1已阻断在真实时窗图/节点属性与合法TC数据库入口；未盲跑测试、未用随机embedding或Gold填预测。环境可导入不是Detection成功。

## 6. 是否实际运行Attack Reconstruction

**NOT_RUN。** 本轮没有重复上轮缺test losses的失败入口。没有真实POI/重构节点边，无攻击图、无来源事件映射。也没有用参考节点进行诊断后冒充正式推理。不能登记空输出或无种子状态，因为检测本身没有执行。

## 7. 是否完成官方评价

**NOT_RUN。** official_metrics.csv中Full/Ano所有指标为NA并附原因；reconstructed_graph_summary为NOT_RUN/null，而非伪造零节点结果。没有Path F1或Causal Edge F1。独立关系Gold未取得，作者节点级Gold与过程关系评价不能混用。

## 8. 论文/代码差异与测试信息依赖

确认AUTHOR_PROTOCOL_TEST_LABEL_DEPENDENCE：evaluation及tracing读取测试Gold派生MCC选epoch，然后重构所选result；POI本身来自y_hat。from_weights只有一个候选epoch，不能把多epoch选优偏差定量套到该模式。默认degree与论文式11的归一化度比+异常分数不同；默认节点score取最大loss而式10定义平均loss；recon_loss查空字典的静态缺陷仍在。没有修作者算法或用未运行数据量化影响。默认KMeans预测也不能写成仅用验证阈值，具体证据见diagnostics/paper_code_consistency.md和evaluation_protocol_audit.md。

## 9. 能否作为正式攻击过程重构基线

**目前不能。** 会议和源码身份合格，但真实输入闭环、重构图、可回查来源及官方评价尚未验收。本轮主要阻断为数据库/权限，并非“统一缺模型数据”或核心算法缺失；也不是论文方向失败的证据。

## 10. 是否还有具体恢复操作

当前授权内没有继续改环境即可取得图的操作。停止本分支。只有新增明确配套证据后才值得恢复：已运行且合法只读的同版TC四表/UUID映射，或具有同一生成配置和来源的完整作者预处理/特征/邻居缓存包；还需固定Gold。重建TC数据库涉及建表/写入，超出本轮范围，本轮不启动也不自动扩权。单份无来源pt、其他算法图或仅重新下载参数均不能解除该缺口。

## 成本、封存和边界

单CPU亲和性与单数值线程预检，8GiB地址空间上限，未训练/推理GNN、未使用GPU/LLM、未下载数据或模型、未安装依赖、未启动服务、未执行SQL或日志命令、未推送GitHub。第二轮预检RSS高水位为192,456KiB（约188MiB）；不是整个会话未采样阶段的全局峰值。总墙钟、实际新增字节、原源码结束哈希和环境包清单一致性以runs/runtime_resources.json和runs/seal_receipt.json为最终凭据。没有修改原始日志/数据库/历史实验。

本轮服务器目录：`[PRIVATE_PATH]`；本机镜像为`[PRIVATE_PATH]`。前轮成果保留，当前文件单独封存。src/verify_recovery.py核验文件/哈希/配置/实际运行凭据，不能凭手填success标志判成功。完成本轮后停止，不自动切换算法或开启新实验。
