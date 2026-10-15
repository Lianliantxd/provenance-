# DiagChain C13-R：V2真实双案例复现完成

当前权威状态：**C13R_TWO_CASES_FROZEN_EVALUATED**。两例均通过原生Controller/Reflection、先冻结Prediction/Trace/交互后官方评价及独立哈希复核。

| 案例 | Best-match Step F1 | CEAF Step F1 | Evidence F1 | 状态 |
|---|---:|---:|---:|---|
| AutoLabel | 0.5000 | 0.5000 | 0.5000 | 历史结果只读保留 |
| ExCyTIn | 0.3333 | 0.3333 | 0.1905 | 本轮完成 |
| Mordor APT29 | 0.3429 | 0.4571 | 0.4000 | 本轮完成 |

本轮20次新增gpt-6-luna模型CLI调用全部成功，另有2条严格历史回放，22次原生消息全部消费；未超46次总限额或各例23次限额。ExCyTIn使用7次新调用，Mordor13次（Controller9、Repair3、Reflection1）。历史17次CLI与V1 SSH失败保留；历史加本轮共37次模型CLI启动。

完整结果见[RESULTS_zh.md](RESULTS_zh.md)、[RESULTS.csv](RESULTS.csv)、[CURRENT_RESULT.json](CURRENT_RESULT.json)。模型输入/回复、原始日志、Gold和凭据保留私有，不在本目录。公开报告隐去个人账户额度信息。服务器评价后25项冻结源码/配置、8项输入/Gold哈希、两例全部交互及AutoLabel原结果复核通过，见[CURRENT_SERVER_INTEGRITY.json](CURRENT_SERVER_INTEGRITY.json)。

V2激活绑定见[ACTIVE_V2_CONTEXT.json](ACTIVE_V2_CONTEXT.json)及冻结回执。candidate_v2目录保留原67项离线测试及已获准使用的源码；其中早期AWAIT_APPROVAL回执是历史快照。src目录和SERVER_RUNTIME_SYNC.json保留更早的V1状态，不作为当前完成状态。

本轮真实覆盖5次双文本回复，均以CLI最终消息文件精确匹配最后完成消息，不拼接不同消息ID。原始回复未被桥接器改写。两例最终schema有效、未知证据ID均0；两例Edge F1均0，攻击链语义和关键依赖质量仍需人工复核。

三来源评价单元不同，不平均绝对Step F1。原生输入含Gold派生长度桶，结果限定为MAIN-69探索性基线；HUMAN_REVIEW_PENDING，独立holdout未建立，新方法优越性未测试，创新性未验证。CLI后台模型快照、temperature/reasoning和内部计费请求数不能独立证明。没有新H2/H3/H4、GPU、额外API、安装、代理修改或TLS关闭。

候选回归测试（不调用模型）：在candidate_v2目录执行`python3 -B -m unittest discover -s tests`。完整原生复现需配套作者源码/数据和正式授权；不能手动填true替代授权。
