import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Each row is manually extracted from a linked publisher/author source. The
# study summaries are paraphrases and do not claim a full-paper reproduction.
DATA = r'''S01|KAIROS: Practical Intrusion Detection and Investigation using Whole-system Provenance|IEEE S&P 2024|https://spg.cs.ubc.ca/publication/2024-sp/|系统审计溯源图→事件异常与攻击摘要|时序图神经网络编码器—解码器学习图演化，利用事件异常分数重构攻击足迹|检测与调查系统；图摘要不自动等于已独立验证的攻击因果边|直接相关
S02|ORTHRUS: Achieving High Quality of Attribution in Provenance-based Intrusion Detection Systems|USENIX Security 2025|https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang|时序溯源图→节点异常与调查图|图表示学习识别异常节点，再按依赖分析扩展攻击结构，以归因质量为目标|本地首例已运行但训练日期不全；节点参考不提供完整关系真值|直接相关
S03|TAPAS: An Efficient Online APT Detection with Task-guided Process Provenance Graph Segmentation and Analysis|USENIX Security 2025|https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas|进程溯源图→任务引导分段与在线检测|LSTM-GRU压缩空间骨架；任务引导分割活跃子图以降低时间维冗余|核心目标是在线检测和资源效率，不能视为自动解决独立攻击关系真值|直接相关
S04|MAGIC: Detecting Advanced Persistent Threats via Masked Graph Representation Learning|USENIX Security 2024|https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian|良性溯源图→实体或日志批次异常|掩码图表示学习正常系统实体和行为，再进行离群检测，并设计漂移适应|实体或批次异常≠完整攻击步骤及关系|直接相关
S05|NODLINK: An Online System for Fine-Grained APT Attack Detection and Investigation|NDSS 2024|https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/|在线审计图→细粒度检测与调查子图|以Steiner Tree形式组织攻击检测，结合缓存、筛选和在线近似算法|原作者方法不等于自行写的Steiner基线；历史发布版需逐项核实任务合同|直接相关
S06|KnowHow: Automatically Applying High-Level CTI Knowledge for Interpretable and Accurate Provenance Analysis|NDSS 2026|https://www.ndss-symposium.org/ndss-paper/knowhow-automatically-applying-high-level-cti-knowledge-for-interpretable-and-accurate-provenance-analysis/|CTI文本知识＋系统事件→技术匹配和潜在攻击|用gIoC表示主体、对象、动作，将系统标识提升到自然语言语义后匹配，并推理攻击步骤时间逻辑|依赖CTI知识及语义映射；技术匹配与真实实例因果关系需要分开|直接相关
S07|Slot: Provenance-Driven APT Detection through Graph Reinforcement Learning|ACM CCS 2025|https://yebof.github.io/assets/pdf/qiao2025ccs.pdf|溯源图及有限标签→APT检测与攻击链|图强化学习结合图挖掘与半监督学习；对检测结果使用聚类构造攻击链|存在标签和训练假设；上下文或间接连接不应自动解释为已证实操作因果|直接相关
S08|Connecting the Extra Dots (Contexts): Correlating External Information about Point of Interest for Attack Investigation|IEEE S&P 2025|https://azadeht.github.io/papers/CONTEXTS-sp25.pdf|调查点、外部漏洞／攻击信息及溯源图→相关子图|从外部资料抽取上下文，映射图节点并关联，以辅助裁剪调查图|依赖可获得且与案例匹配的外部上下文；须隔离测试答案|直接相关
S09|Flash: A Comprehensive Approach to Intrusion Detection via Provenance Graph Representation Learning|IEEE S&P 2024|https://dartlab.org/assets/pdf/flash.pdf|溯源图→节点行为检测|上下文GNN结合Word2Vec和轻量分类器，缓存训练期节点嵌入减少在线开销|主要任务是检测；节点嵌入并非活动关系的独立参考|直接相关
S10|Sometimes Simpler is Better: A Comprehensive Analysis of State-of-the-Art Provenance-Based Intrusion Detection Systems|USENIX Security 2025|https://www.usenix.org/conference/usenixsecurity25/presentation/bilot|多个溯源检测系统→统一框架实证比较|统一实现多种系统，分析部署缺陷并比较简单模型与复杂模型|这是比较和评价研究，不是攻击过程重构器；论文结果不能代替本地等输入复测|评价直接相关
S11|AutoLabel: Automated Fine-Grained Log Labeling for Cyber Attack Dataset Generation|USENIX Security 2025|https://www.usenix.org/conference/usenixsecurity25/presentation/peng-yihao|可控攻击环境、多源日志和辅助信息→细粒度攻击子图标签|修改环境、应用及攻击工具产生辅助信息，关联应用、流量与审计记录并细化攻击子图|需要采集期间的额外信息，不能事后假装TC E3原日志已有同等辅助信号|评价直接相关
S12|Cost-effective Attack Forensics by Recording and Correlating File System Changes|USENIX Security 2024|https://www.usenix.org/conference/usenixsecurity24/presentation/yu-le|文件系统增量快照→与调查症状有关的内容溯源图|周期记录文件变化，解析并关联变化内容和语义，以规则推断文件与socket联系|依赖快照及文件内容；不是使用相同CDM审计输入的现成公平基线|间接相关
S13|vCause: Efficient and Verifiable Causality Analysis for Cloud-based Endpoint Auditing|USENIX Security 2026|https://www.usenix.org/conference/usenixsecurity26/presentation/song-qiyang|云端版本化溯源图查询→可验证的查询结果|结合图累加器和可验证溯源图，验证调查点查询及相关组件识别|验证计算结果的完整性不等于证明关系具有攻击因果语义|间接相关
S14|Cutting the Fuse: Actionable APT Attack Blocking in Provenance-based IDS|USENIX Security 2026|https://www.usenix.org/conference/usenixsecurity26/presentation/wu-weiheng|检测器告警图→关键边列表|ProvX采用模型反事实解释寻找扰动后会改变检测器预测的结构子集，并进行分阶段固化|模型预测解释不自动等于真实攻击因果或现实世界干预效果|直接相关
S15|TeRed: Normal Behavior-Based Efficient Provenance Graph Reduction for Large-Scale Attack Forensics|IEEE TIFS 2025|https://ieeexplore.ieee.org/document/11133429/|正常行为样本及溯源图→缩减图|利用单元测试学习正常行为模式，再用于溯源图缩减|依赖训练用正常行为与测试覆盖；节点被裁剪后能否保留新攻击须独立验证|直接相关
S16|TREC: APT Tactic / Technique Recognition via Few-Shot Provenance Subgraph Learning|ACM CCS 2024|https://nesa.zju.edu.cn/download/TREC.pdf|少样本标注的溯源子图→ATT&CK战术／技术识别|将技术识别建模为少样本子图学习，利用溯源结构迁移有限标签知识|分类或技术标签不直接验证实际执行实例的活动衔接|辅助相关
S17|Incorporating Gradients to Rules: Towards Lightweight, Adaptive Provenance-based Intrusion Detection|NDSS 2025|https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf|溯源事件与规则→在线入侵检测|CAPTAIN将可调整参数引入规则并利用梯度下降优化，使规则检测可适应变化|面向检测和规则适应；规则匹配不自动证明真实攻击因果关系|直接相关
N01|Synergetic Event Understanding: A Collaborative Approach to Cross-Document Event Coreference Resolution with Large Language Models|ACL 2024|https://aclanthology.org/2024.acl-long.164/|跨文档事件提及→同一事件簇|大模型概括事件上下文，小模型利用这些信息微调事件表示并识别共指|共指是同一发生的多次描述，不是同一攻击过程内不同行为的归属|跨领域辅助
N02|Identifying while Learning for Document Event Causality Identification|ACL 2024|https://aclanthology.org/2024.acl-long.210/|文本事件对→因果存在与方向|迭代建立高置信关系图并更新事件结构表示，辅助下一轮识别|文本因果模型和自举错误不构成原生操作证据|跨领域辅助
N03|MAVEN-ARG: Completing the Puzzle of All-in-One Event Understanding Dataset with Event Argument Annotation|ACL 2024|https://aclanthology.org/2024.acl-long.224/|文档事件→事件、论元角色及事件关系标注|扩充MAVEN事件数据以统一事件触发、论元和关系任务|数据集论文；语言文本与CDM系统事件角色、标注过程不同|评价方法参考
N04|Set-Aligning Framework for Auto-Regressive Event Temporal Graph Generation|NAACL 2024|https://aclanthology.org/2024.naacl-long.214/|文本事件→时序关系图|将图生成转换为条件集合生成，通过数据增强与集合性质正则降低边序列排序偏差|时间关系不等于依赖，更不自动构成攻击因果|跨领域辅助
N05|A Rationale-centric Counterfactual Data Augmentation Method for Cross-Document Event Coreference Resolution|NAACL 2024|https://aclanthology.org/2024.naacl-long.63/|事件提及对→跨文档事件共指|分析触发词匹配的伪相关，借助大模型对触发词和上下文做反事实数据增强|只在文本共指任务验证；生成反事实不能当真实主机事件|跨领域辅助
N06|In-context Contrastive Learning for Event Causality Identification|EMNLP 2024|https://aclanthology.org/2024.emnlp-main.51/|带上下文的文本事件对→因果标签|以正负示例和事件对对比学习增强上下文中的因果识别|依赖可靠示例；文本因果不是主机攻击因果真值|跨领域辅助
N07|Advancing Event Causality Identification via Heuristic Semantic Dependency Inquiry Network|EMNLP 2024|https://aclanthology.org/2024.emnlp-main.87/|文本事件对及上下文→因果关系|统一编码语义依赖，用填空分析器生成上下文提示并查询事件关系|文本语义模型无直接的原生日志事件见证保证|跨领域辅助
N08|LLMs Are Prone to Fallacies in Causal Inference|EMNLP 2024|https://aclanthology.org/2024.emnlp-main.590/|合成文本中的时间、空间及反事实关系→因果推理测试|用受控合成训练和测试分离记忆与推理，检查时间顺序等谬误|诊断论文而非攻击检测器；不可直接外推所有模型和所有日志任务|评价方法参考
N09|Explicit, Implicit, and Scattered: Revisiting Event Extraction to Capture Complex Arguments|EMNLP 2024|https://aclanthology.org/2024.emnlp-main.673/|在线健康讨论→显式、隐含和分散的事件论元|构建DiscourseEE并将复杂论元抽取表述为生成任务|论文域为健康文本；隐含论元不等于真实日志中被观测到的操作|跨领域辅助
N10|Linear Cross-document Event Coreference Resolution with X-AMR|LREC-COLING 2024|https://aclanthology.org/2024.lrec-main.920/|跨文档事件提及→事件共指|构建以提及为中心的跨文档事件图，采用多跳共指算法减少成对比较|语义图推理需要输入和标注支持；共指不同于攻击过程关系|跨领域辅助
N11|Enhancing Unrestricted Cross-Document Event Coreference with Graph Reconstruction Networks|LREC-COLING 2024|https://aclanthology.org/2024.lrec-main.541/|事件提及对分数→跨文档共指图|在提及对分类器上叠加轻量图重构算法，以图结构修正局部输出|恢复的是同一事件提及簇，而非攻击活动中的先后／依赖|跨领域辅助
N12|Document-Level Event Extraction via Information Interaction Based on Event Relation and Argument Correlation|LREC-COLING 2024|https://aclanthology.org/2024.lrec-main.459/|文档→事件及跨句论元|CAINet分别构建事件关系图和论元相关图，建模事件与参与者交互|测试为文档事件抽取；共享参与者本身不能证明攻击因果|跨领域辅助
N13|Enhancing Cross-Document Event Coreference Resolution by Discourse Structure and Semantic Information|LREC-COLING 2024|https://aclanthology.org/2024.lrec-main.523/|跨文档事件提及→共指聚类|结合篇章结构、词汇链、异质图注意力和提及对评分|高层文本语义与系统实体身份之间存在域差异|跨领域辅助
N14|Large Language Model-Based Event Relation Extraction with Rationales|COLING 2025|https://aclanthology.org/2025.coling-main.500/|文本及指定事件→多类型相关事件及解释|将关系抽取改为多答案问答，分区处理长文，并生成共指或传递链解释|生成的解释不是可回查原生日志；需独立验证且不能越权使用参考|跨领域辅助
N15|Causal Graph based Event Reasoning using Semantic Relation Experts|ACL 2025|https://aclanthology.org/2025.acl-long.1269/|文本情景→因果事件图及事件预测|用聚焦不同语义关系的大模型专家多轮讨论并整合图，应用于下游事件预测|生成因果图是模型假设，不能直接作为真实攻击因果证据|跨领域辅助
N16|Employing Discourse Coherence Enhancement to Improve Cross-Document Event and Entity Coreference Resolution|ACL 2025|https://aclanthology.org/2025.acl-long.1134/|跨文档实体或事件提及→共指|选取连贯文本，补充跨文档上下文后表示并识别共指|补充上下文可能产生域偏差；非攻击活动过程关系|跨领域辅助
N17|Beyond Benchmarks: Building a Richer Cross-Document Event Coreference Dataset with Decontextualization|NAACL 2025|https://aclanthology.org/2025.naacl-long.178/|文档事件→上下文补充后的提及对及共指标注|用大模型辅助去上下文化，构建更丰富的跨文档共指数据和基线|数据和标注研究；不可将辅助生成文字直接当日志事实|评价方法参考
N18|EventRelBench: A Comprehensive Benchmark for Evaluating Event Relation Understanding in Large Language Models|Findings EMNLP 2025|https://aclanthology.org/2025.findings-emnlp.482/|文档及句子级事件关系问题→模型关系评价|设计共指、时间、因果及上下位关系问题，并构建指令微调数据|Findings论文、NLP评价基准；不能直接作为APT关系地面真值|评价方法参考
N19|Dynamic Energy-Based Contrastive Learning with Multi-Stage Knowledge Verification for Event Causality Identification|EMNLP 2025|https://aclanthology.org/2025.emnlp-main.616/|文本事件对→因果识别|多源知识验证生成对比样本，SGLD生成动态对抗负样本并用能量函数学习边界|样本仍依赖知识及模型生成质量；不能将合成负样本说成已核实正常日志|跨领域辅助
N20|Are LLMs Good Annotators for Discourse-level Event Relation Extraction?|Findings EMNLP 2024|https://aclanthology.org/2024.findings-emnlp.1/|长文档事件关系→大模型标注质量评价|比较GPT-3.5、LLaMA-2和监督基线，分析虚构事件、传递性和长距离关系错误|结果限定于所测模型、数据和设置，不能外推所有后续模型|评价方法参考
N21|Revisiting Conversation Discourse for Dialogue Disentanglement|ACM TOIS 2024|https://smusg.elsevierpure.com/en/publications/revisiting-conversation-discourse-for-dialogue-disentanglement/|交错多方消息流→独立会话和消息配对|异质图表示说话者角色和动态上下文，分层排序联合消息对与会话层级，推理时采用先易后难的全局解码|假定对话语料和会话结构，跨会话共享进程及原生事件证据需额外处理|跨领域辅助
N22|Disentangling Approaches to Conversation Disentanglement: Fine-Tune or Learn from Scratch?|LREC 2026|https://lrec.elra.info/lrec2026-main-229|交错对话流→消息联系及会话分组比较|在相同训练数据下比较GPT-4o、微调GPT-4o Mini与从头训练模型，分析链路和完整会话表现|结果来自对话数据，不能保证主机日志同样排序；大模型文本解释不等于原生见证|评价方法参考
G01|ARC: A Generalist Graph Anomaly Detector with In-Context Learning|NeurIPS 2024|https://proceedings.neurips.cc/paper_files/paper/2024/hash/5acb720a361eecb34ee62d356859d246-Abstract-Conference.html|图和少量正常样本→节点异常|对齐跨数据集特征，编码邻域残差，用跨注意力结合少量正常样本评分|需要可信正常样本；节点异常不是攻击路径|跨领域辅助
G02|UniGAD: Unifying Multi-level Graph Anomaly Detection|NeurIPS 2024|https://proceedings.neurips.cc/paper_files/paper/2024/hash/f57de20ab7bb1540bcac55266ebb5401-Abstract-Conference.html|图→节点、边和图级异常|采样子图统一不同对象粒度，使用GraphStitch整合多个层级任务|多层异常不自动成为有证据的事件依赖|跨领域辅助
G03|Generative Semi-supervised Graph Anomaly Detection|NeurIPS 2024|https://proceedings.neurips.cc/paper_files/paper/2024/hash/085b4b5d1f81ad9e057ad2b3de922ad4-Abstract-Conference.html|图及少量已知正常节点→节点异常|利用局部亲和性和自我中心邻近先验生成伪异常，训练判别式单类分类器|伪异常并非真实APT标签；依赖可信正常节点|跨领域辅助
G04|CurvGAD: Leveraging Curvature for Enhanced Graph Anomaly Detection|ICML 2025|https://proceedings.mlr.press/v267/grover25a.html|图及节点特征→几何、结构和属性异常|混合曲率图自编码器并行重构边曲率及结构属性|研究几何异常，不能把曲率变化直接视为攻击关系|跨领域辅助
G05|PieClam: A Universal Graph Autoencoder Based on Overlapping Inclusive and Exclusive Communities|ICML 2025|https://proceedings.mlr.press/v267/zilberg25a.html|图→社区表示、重构及异常检测|学习节点社区隶属和潜在先验，同时描述连接密集与连接稀疏社区|图社区可借鉴重叠参与，但社区不是攻击活动真值|跨领域辅助
G06|IA-GGAD: Zero-shot Generalist Graph Anomaly Detection via Invariant and Affinity Learning|NeurIPS 2025|https://proceedings.neurips.cc/paper_files/paper/2025/hash/788f9787ec93e3e1f34658fb003a1f44-Abstract-Conference.html|跨域图→无需目标图再训练的节点异常|结合异常驱动的域不变表示与对结构变化不敏感的亲和性学习|跨图泛化实验不证明跨主机审计日志或攻击过程恢复有效|跨领域辅助
G07|Conditional Diffusion Anomaly Modeling on Graphs|NeurIPS 2025|https://proceedings.neurips.cc/paper_files/paper/2025/hash/e19a65fd53b6f9a88b354da98813465d-Abstract-Conference.html|图及预训练异常先验→图异常|将条件异常估计器嵌入前向和反向扩散，并依置信度调整去噪步骤|需要额外先验；扩散重构并非原生攻击事实|跨领域辅助
G08|Rethinking Reconstruction-based Graph-Level Anomaly Detection: Limitations and a Simple Remedy|NeurIPS 2024|https://proceedings.neurips.cc/paper_files/paper/2024/hash/ae03bdef276132fae089692445725635-Abstract-Conference.html|图集合→图级异常及误差分析|分析重构误差假设的反转反例，用多种误差统计而非仅均值识别异常|主要是图级检测；对ORTHRUS的启发是需检验分数假设，不直接证明本例错误|评价方法参考
G09|Semi-supervised Graph Anomaly Detection via Robust Homophily Learning|NeurIPS 2025|https://proceedings.neurips.cc/paper_files/paper/2025/hash/c273d135fed229f5724df9a0d354b36f-Abstract-Conference.html|图及少量正常节点→节点异常|自适应频率滤波与正常性对齐，学习不同正常节点的同配性模式|依赖已知正常节点；正常异质性与APT活动归属不是同一标签|跨领域辅助
G10|Out-of-Distribution Generalized Graph Anomaly Detection with Homophily-aware Environment Mixup|NeurIPS 2025|https://papers.nips.cc/paper_files/paper/2025/hash/5ee7ed60a7e8169012224dec5fe0d27f-Abstract-Conference.html|训练图和结构分布变化的目标图→异常检测|解耦自身与邻域表示，用同配性环境混合学习较稳定的跨环境模式|评估偏跨图分布漂移；不直接预测有操作见证的过程关系|跨领域辅助
G11|Learning Discriminative and Generalizable Anomaly Detector for Dynamic Graph with Limited Supervision|ICML 2026|https://proceedings.mlr.press/v306/tian26h.html|动态图、正常／未标注数据和少量异常→节点／交互异常|对当前交互与历史上下文取残差，使用限制损失和流模型形成双边界|少量标注异常可能造成数据泄漏；检测对象与过程关系需另外对齐|跨领域辅助
G12|Modeling Spectral Energy Shifts in Spatio-Temporal Graph Anomaly Detection|ICML 2026|https://proceedings.mlr.press/v306/liu26gb.html|静态或时序图→节点异常|建模频谱能量增加和减少，并以能量驱动的消息传递捕获伪装异常|节点级谱异常不能直接解释为攻击实例或多步路径|跨领域辅助
G13|ScatterAD: Temporal-Topological Scattering Mechanism for Time Series Anomaly Detection|NeurIPS 2025|https://proceedings.neurips.cc/paper_files/paper/2025/hash/4b52b3c50110fc10f6a1a86055682ea2-Abstract-Conference.html|多变量工业时间序列→时间点异常|分别编码拓扑与时间散射，用对比融合结合两个视角|输入为多变量时间序列，距离离散主机事件归属任务较远|跨领域辅助
G14|Self-Perturbed Anomaly-Aware Graph Dynamics for Multivariate Time-Series Anomaly Detection|NeurIPS 2025|https://papers.nips.cc/paper_files/paper/2025/hash/7a7fb67a148a9aac94cc6d85989d7757-Abstract-Conference.html|多变量时间序列→异常时间点|从正常数据重构中自扰动生成辅助样本，再动态调整变量关联图学习时空异常|自扰动是训练辅助，不能作为真实攻击步骤或测试真值|跨领域辅助
G15|Self-Supervised Learning of Graph Representations for Network Intrusion Detection|NeurIPS 2025|https://proceedings.neurips.cc/paper_files/paper/2025/hash/9ddb13ae9150f99298065d889f951014-Abstract-Conference.html|网络流量图→可疑网络流|GraphIDS以归纳式图编码器表示流量局部拓扑，掩码自编码器学习正常通信并据重构误差检测|网络流异常不等同主机跨进程攻击事件链|辅助相关
G16|GADBench: Revisiting and Benchmarking Supervised Graph Anomaly Detection|NeurIPS 2023 Datasets and Benchmarks|https://proceedings.neurips.cc/paper_files/paper/2023/hash/5eaafd67434a4cfb1cf829722c65f184-Abstract-Datasets_and_Benchmarks.html|多类图异常数据及监督方法→统一比较|建立图异常检测基准，对图神经网络和传统方法的效果及效率进行统一评估|基准面向图异常检测，不能代替攻击关系参考与调查任务适配|评价方法参考'''

HEAD = '''# 近三年跨领域研究：APT 攻击事件归属与过程重构

截至 2026-10-30。检索窗口：2023-10-30 至 2026-10-30。仅计窗口内正式发表的独立论文；同一论文的预印本、作者版和会议版去重。共 55 篇：安全溯源 17 篇、NLP 事件理解 22 篇、图与时序异常 16 篇。

## 适用范围与证据级别

本清单优先选择 USENIX Security、NDSS、IEEE S&P、ACM CCS、ACL、EMNLP、NAACL、NeurIPS、ICML 等会议或 TIFS 期刊；LREC-COLING、COLING 和 Findings 条目标明具体来源，不将其冒称其他会议主会。会议声誉仅是筛选依据，不能替代论文质量评审。安全领域直接相关 12 篇，另有评价/跨域参考；NLP与图异常论文是机制借鉴，不是已经证明适用于APT。

阅读深度：逐篇核对公开出版方／会议或作者论文入口和摘要；部分直接相关论文参考正文片段。不是逐篇代码复现，也没有逐篇读取全部实验、标注政策与附录。IEEE页面在浏览器工具中有机器人限制；Context、Flash、TREC采用作者论文及正式会议信息核对，TeRed采用已检索的IEEE出版信息。Crossref API 网络握手失败，未完成全部论文的第二数据库程序化核对；不声称全部独立双源核验、实验重现或论文优劣已确认。无BibTeX从记忆生成。

## 直接结论

1. **最接近的可研究问题是带调查线索的事件归属与关系恢复。** NLP的事件解缠、实体角色和关系预测提供方法，但事件共指不等同攻击过程：同一攻击中的两次不同系统调用不是同一次事件的不同提及。
2. **近年安全文献已有直接先例。** TAPAS已有任务引导溯源图分段，NODLINK已经把在线问题建模为Steiner Tree，KnowHow已将CTI主体／对象／动作与系统事件匹配，Slot已应用图强化学习。因此“分段”“Steiner”“语义对齐”或“RL”自身不能算新颖贡献。
3. **异常检测提供评分，不自动提供攻击真值。** ARC、UniGAD、GraphIDS等回答不同粒度异常；有的需要已知正常样本。G08展示某些图重构误差假设可反转；这不能单独证明ORTHRUS的本轮错误。
4. **关系评价与事件身份是最关键的实验差异。** AutoLabel通过额外环境和辅助数据获得细粒度标签，不能假定既有E3日志自带；MAVEN-ARG与EventRelBench支持分任务评价，但它们不是系统审计参考。
5. **当前本地证据仍是单案例。** ORTHRUS返回16个检测节点和99个重构节点，43个固定攻击节点参考命中分别为3和10；这不证明新增未标注节点是误报，也不提供完整因果路径F1。
6. **不可忽略本地失败结果。** 历史JACR-01已实现联合活动／操作证据选择，但过程因子消融64/64不变，同目标强对照重现或改善其完成的48个条件，历史决定拒绝独立创新主张；COWR也未展示超出同语义强基线的增量。此次跨领域类比不能撤销这些结果。具体统计及口径以对应历史结项报告为准。

## 研究路线比较

| 路线 | 可借鉴论文 | 实际解决的问题 | 当前迁移缺口 |
|---|---|---|---|
| 细粒度活动单元 | S03 TAPAS、S05 NODLINK | 在线分段、检测和调查图搜索 | 分段是否等于真实攻击活动、是否覆盖正常共享上下文 |
| 事件—论元—关系联合建模 | N02、N04、N12、N19 | 通过全局结构、方向和角色交互改进文本抽取 | 缺少对应的原生事件身份／关系标签，文本因果不能直接映射 |
| 过程行为异常 | S01、S04、G02、G08、G11 | 从节点、关系或图结构识别异常 | 正常过程基线和标注偏差；异常不必然恶意 |
| 语义与辅助知识 | S06 KnowHow、S08 Contexts、N14 | 外部知识或解释帮助定位 | 案例知识可能泄漏参考；合理生成不保证真实发生 |
| 参考和可辨识性 | S11 AutoLabel、N03、N18、N20 | 提供细粒度标注或检验事件关系能力 | 无法凭新论文补造已有E3的原始关系参考 |

## 七篇优先阅读：方法差别与可证伪比较

### S03 TAPAS——已有任务引导的图分段

输入是进程溯源图。空间上以骨架节点为中心，用堆叠LSTM-GRU吸收冗余邻居信息；时间上按任务引导切出活跃骨架子图，以实现在线APT检测。论文报告在DARPA TC与OpTC上的效率和检测结果。它不是简单按窗口做实体聚类，因而任何“任务级切分”方案都必须与其具体切分依据、依赖的数据、输出和成本对比。尚未验证其输出等同于我们所需的独立攻击活动关系；需要查源码和标注合同。

### S05 NODLINK——现有在线Steiner路线

其研究问题已经将在线检测建模为Steiner Tree问题，并为在线场景设计缓存、攻击筛选和近似算法。借鉴之处是比较同一调查图下结构选择和代价；不可把自行实现的静态Steiner森林冒充原作者完整系统。若新方法仅更换节点权重或路径打分，需要在同输入、相同线索与预算下证明对活动归属或事件关系有稳定价值。

### S06 KnowHow——已有攻击知识到事件的语义映射

以CTI中主体、对象和动作为gIoC，通过系统标识语义化与CTI技术描述匹配，再结合攻击步骤的时间逻辑。它说明“主体—动作—对象＋攻击知识”已有直接安全研究。可比较的问题不是是否出现这些字段，而是对同一实体多活动、模糊实例和可见／不可见依赖如何处理。CTI必须在预测前固定，不能使用测试案例的答案片段作为在线上下文。

### N02 Identifying while Learning——局部事件关系与图状态相互更新

输入文本事件对；论文迭代将高置信关系与方向组成事件关系图，再更新事件表示以改善下一轮判断。可转化的假设是：可靠局部原生见证能改善事件归属，归属又能减少错误关系。但自举可能将初始误判放大；应比较局部模型、相同约束的强逐边模型及不反馈版本，不能把一致性作为正确性的证明。

### N21 Revisiting Conversation Discourse——真正面向交错活动的联合解缠

这是2024年正式发表在ACM TOIS的期刊论文，与只做事件共指的论文任务不同。其输入是按时间交错的多方发言，输出是会话分组及发言配对。论文用异质图编码静态说话者角色和动态上下文；用分层排序覆盖发言对与会话两个粒度；推理采用先易后难的配对解码。迁移设想是以原生日志事件取代发言，以进程、文件和连接取代说话者，但必须保留一个进程同时参与不同活动的可能。该论文对话域的会话参考与APT原生操作依赖并不等同；不能直接作为攻击链真值。N22的LREC 2026比较进一步提示，不能预设通用大模型优于具有结构信息的小模型。

### G02 UniGAD——跨节点、边、图多粒度异常

将不同粒度对象映射为子图，通过采样和跨任务结构整合进行节点、边和图级检测。启发是在输出中分别处理事件、关系和活动分量，而不是仅报告节点分数。其原任务是异常检测，采样子图并不代表真实攻击实例；迁移须重新定义有方向的时序操作及外部评价。

### G08 MUSE——重构误差并非天然异常证据

论文发现某些条件下图自编码器出现重构误差反转，以多面误差统计替代单一均值。可以借此设计诊断：在相同输入和冻结权重下检查节点／关系分数的稳定性，且不把高损失当作真实攻击概率。MUSE的图级重构反例不直接证明本次ORTHRUS节点误差异常；需要实证。

## 推荐的最小可证伪研究问题

在同一日志事件全集、相同调查起点、相同输出预算和冻结参考条件下：联合事件归属与关系选择，是否能够相对于（1）局部关系独立评分、（2）相同证据与约束的逐边验证、（3）现有图扩展／分段，提升可回查活动联系的恢复，同时减少经独立核实的不相关活动？

比较单位应为事件或已明确映射的活动，不把进程节点标签直接替换为事件标签。过程参考须独立于预测形成；只具有作者报告顺序的样例只评顺序，原生日志仅支持操作依赖的样例只评操作依赖。未知项单列；不能用未标注节点充当已确认负例。若无法取得某类关系的独立参考，报告不可评价，而不是构造因果Edge F1。

建议先以实际已有案例核对“同一进程／文件参与不同活动”和“单事件不突出但操作组合相关”的具体候选。只有出现原始证据和独立参考能区分强基线错误，联合建模才有可证伪靶点。若同条件逐边方法已能达到相同结果，该动机不成立；若日志缺少必要的事件见证，应输出UNKNOWN，不将缺失观测当算法失败。

## 逐篇文献卡（55 篇）

每篇列出：原任务与输入输出、方法机制、迁移限制及与APT主题的相关性。每个标题均链接到出版方、会议或作者论文入口。方法概述基于可访问的摘要或正文片段，不能替代逐篇阅读全文。

'''

rows = []
for line in DATA.splitlines():
    parts = line.split('|')
    if len(parts) != 8:
        raise ValueError((len(parts), line))
    rows.append(dict(zip(['id','title','venue','url','input_output','method','limitation','relevance'], parts)))
if len(rows) != 55 or len({r['title'].casefold() for r in rows}) != len(rows):
    raise ValueError('paper count or uniqueness mismatch')
if len({r['url'] for r in rows}) != len(rows):
    raise ValueError('duplicated URL')

with (ROOT / 'PAPER_INVENTORY.csv').open('w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

text = [HEAD]
for section, title in [('S', '安全溯源及评价（17）'), ('N', 'NLP事件理解（22）'), ('G', '图与时序异常（16）')]:
    text.append('\n### ' + title + '\n')
    for r in rows:
        if r['id'].startswith(section):
            text.append('**{} · [{}]({})** — {}\n\n'.format(r['id'], r['title'], r['url'], r['venue']))
            text.append('- 原任务与输入输出：{}。\n'.format(r['input_output']))
            text.append('- 如何解决：{}。\n'.format(r['method']))
            text.append('- 迁移限制：{}。相关性：{}。\n\n'.format(r['limitation'],r['relevance']))

(ROOT / 'REVIEW_55_PAPERS.md').write_text(''.join(text), encoding='utf-8')
files = ['PAPER_INVENTORY.csv', 'REVIEW_55_PAPERS.md', 'build_review.py', 'verify_review.py']
manifest = {'date_window': ['2023-10-30','2026-10-30'], 'paper_count': len(rows),
            'groups': {k:sum(r['id'].startswith(k) for r in rows) for k in ('S','N','G')},
            'publication_verification': 'publisher/proceedings or author paper with conference confirmation; Crossref second-source automated verification unavailable',
            'reading_depth': 'abstract and selected excerpts, not full paper or code audit',
            'files': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}}
(ROOT / 'MANIFEST.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps(manifest, ensure_ascii=False, indent=2))
