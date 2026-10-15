# DiagChain C13-R V2：真实双案例复现完成

状态：`C13R_TWO_CASES_FROZEN_EVALUATED`。ExCyTIn 与 Mordor 均完成原生 Controller、Reflection、预测/Trace/交互冻结及独立官方评价。

OBSERVED：本轮新增20次实际模型请求CLI进程，均请求gpt-6-luna、正常退出0并被服务器消费；另有2条Prompt字节完全一致的历史有效回复回放。合计22次原生消息交接。历史C13的17次CLI、13次交接与V1 SSH失败完整保留；历史加本轮共37次实际模型CLI启动。状态查询及Fake Worker不计作模型请求。

| 案例 | 来源状态 | Best-match Step F1 | CEAF Step F1 | Evidence P / R / F1 | Attack B-cubed F1 | Edge F1 |
|---|---|---:|---:|---|---:|---:|
| AutoLabel CVE-2023-25157 | 历史完成，只读保留 | 0.5000 | 0.5000 | 0.5000 / 0.5000 / 0.5000 | 0.8000 | 0.0000 |
| excytin-incident-34.alert-evidence | 本轮完成 | 0.3333 | 0.3333 | 0.1290 / 0.3636 / 0.1905 | 0.5005 | 0.0000 |
| mordor-apt29-day1.L-noisy | 本轮完成 | 0.3429 | 0.4571 | 1.0000 / 0.2500 / 0.4000 | 0.4320 | 0.0000 |

三例来源与评价单元不同，不平均绝对Step F1。两例Edge F1均为0，结构和依赖恢复仍有明显差距；完成通信与评价不能单独证明攻击链语义正确。

| 本轮案例 | 预测/参考步骤 | 观察/唯一引用证据 | Ordering Accuracy / 有效比较对 | 原生 C/Rpr/Syn/Ref 消息 | 新CLI / 回放 | 服务器启动至评价完成 |
|---|---:|---:|---|---|---:|---:|
| excytin-incident-34.alert-evidence | 13/11 | 85/31 | 1.0000 / 6 | 8/0/0/1 | 7/2 | 361.214s |
| mordor-apt29-day1.L-noisy | 9/26 | 80/15 | 0.8667 / 15 | 9/3/0/1 | 13/0 | 597.902s |

C=Controller、Rpr=JSON Repair、Syn=Synthesis、Ref=Reflection；原生消息数包含回放。本轮Mac Runner墙钟962.455秒；CLI进程最长66.459秒。这些时间包含传输、客户端与控制器开销，不能当作纯模型生成延迟。AutoLabel历史Ordering Accuracy=1.0但有效对=0，不能据此证明排序可靠。

预算：累计新增CLI20/46，ExCyTIn7/23、Mordor13/23；单CLI上限360秒，每例1800秒，总3600秒，顺序执行。均未超限。20个模型CLI均正常完成，22条回复全部被消费；未自动重发任何新增模型请求。旧完成未知seq3按明确授权只新发出一次；历史内部是否重复生成/计费仍NOT_IDENTIFIABLE。

先冻结后评价：每例先保存服务端Prediction、Trace及交接账本，再由Mac完整下载并SHA核验、冻结全部交互；服务器接收Mac冻结证明后，独立已有Python3.10进程才读取配套Gold并运行未修改官方评价器。复核25项冻结源码/配置、8项输入/Gold哈希、两例全部冻结交互及AutoLabel原Prediction/Trace，均保持不变。两个Controller均已退出。

模型协议：20条新回复中15条为单文本消息、5条为双文本消息；不同message_id从未拼接，以output-last-message文件精确匹配最后完成消息。4条原始文本未通过严格JSON对象解析，未经桥接器改写，由作者原有解析/JSON Repair路径处理。Mordor实际Repair3次，不能把中途进度中的单次描述当作总数。两例最终schema_valid=1、unknown_evidence_id_count=0。

本轮已记录CLI transport error事件0，ACK消歧分支记录0；只读SSH重试次数未单独持久化，不能伪造为0。本轮实际覆盖双文本最终回复解析；ACK故障消歧另外经67项合成/适配器回归验证。NOT_IDENTIFIABLE：V2成功是否由等待延长、网络暂时恢复或其他外部状态单独导致；不能根据这次成功作因果归因。

历史故障保留：ExCyTIn旧180.015秒仅能定位为Python等待CLI超时，伴随TLS重连、HTTPS回退与计数回绕，不能断言模型生成慢。Mordor旧完整434字节回复被旧严格审计拦截，直接退出码收据缺失，因此未伪造为严格回放。V1新尝试SSH put等待30秒失败，新增模型0，旧Controller之后超时退出；本轮新独立attempt不回填或覆盖该尝试。TLS错误不证明证书验证失败；全程未关闭TLS、改代理/防火墙、下载模型、安装软件、使用GPU、运行攻击/日志命令、修改作者源码/原始数据/Gold或C4–C13结果。

消费与后端：使用现有ChatGPT订阅登录和gpt-6-luna请求名，保持仅套餐内额度限制；未使用API Key或额外付费API，未执行购买Credits或重置额度操作。后台模型快照、temperature/reasoning、精确账单及内部生成次数不可独立验证。共享账户窗口数据保留在私有报告，不公开个人账户使用率，也不将窗口变化归因于本实验。原生temperature=0不代表CLI已证明后台按0执行。

研究限制：三例都属于MAIN-69探索性原生基线，输入仍含Gold派生长度桶。不同后端/文本JSON修复约束不能冒充与论文原后端完全一致的严格盲测复现。HUMAN_REVIEW_PENDING；CONFIRMATORY_HOLDOUT_ESTABLISHED=NO；NEW_METHOD_SUPERIORITY=NOT_RUN；SCIENTIFIC_NOVELTY=UNVERIFIED。未新增H2/H3/H4或B2模型，未重新索取真人Root标注。

G0–G8：历史与源码/输入完整性、17次旧调用取证、两例诊断、合成回归、V2冻结、新授权闸门、ExCyTIn冻结评价、Mordor冻结评价、三例完整报告均已完成。服务器和GitHub最终同步结果以独立同步回执为准，不能仅从本报告推断发布已成功。

冻结哈希：

- excytin-incident-34.alert-evidence Prediction `a1d4aa148b88087718f99574a088dd486ed4279e02f732021282997a78f66db7`；Trace `972345b64243c9670522fb8e220389256e20a0fe9c2460ae0de087b2a3225e19`。

- mordor-apt29-day1.L-noisy Prediction `3169d14b684bf463f7f901a10519557f8353ff0dfd36c06bcd95dace9f626c73`；Trace `ce4e72f809713859b8533fd8af7ae4a99b41e7926a6e4bd53c29cd4d3e626052`。
