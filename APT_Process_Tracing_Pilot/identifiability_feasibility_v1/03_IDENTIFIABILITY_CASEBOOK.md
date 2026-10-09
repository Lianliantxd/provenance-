# 证据可识别性案例簿

评价单位参见 [02_EVIDENCE_RELATIONS.csv](02_EVIDENCE_RELATIONS.csv)。下列“观察到”只指原始审计操作；“模型依赖”是按方向、实体、时间连图；“攻击相关关系”须另有报告支持，且报告对步骤的支持不自动证明逐字节传播。

## A：CADETS 2018-04-12，同一 nginx 的入站与外连

调查起点是 loader 地址连接 `EBFB7595-F532-54F8-B51B-CE074AAAFE37`，原始 `EVENT_CONNECT` 时间为 18:00:23.166196 UTC。`21944BC3-1FFB-59C4-8B2E-18AC7F2020CE` 是 18:00:22.876190 UTC 的 `EVENT_RECVFROM`，两者 CDM Subject UUID 同为 `11C64B2C-3DC3-11E8-A5CA-3FA3753A265A`。本轮从原始 tar 偏移回读，UUID 和 SHA-256 均吻合。报告 §3.13 pp.26–28 把入站攻击与后续 loader 活动纳入同一情节，支持“攻击相关步骤存在且先后”；并未指明哪一次 receive 的具体 payload 触发连接，也没有 nginx 内部控制流或污点证据。其他输入、应用状态或另一 receive 都仍与当前记录相容。因此 `C_RECV_TO_LOADER` 是 `MODEL_POSSIBLE_DEPENDENCY`，不是确认的入站→loader 信息流。简单规则“同进程只标 possible”已足以避免过度确定断言；这里未见必须由新模型解决的漏洞。

另一 POI `E1EEC283-AA82-52C9-9677-498A5B9BE13B` 是 shellcode 地址 `EVENT_CONNECT`，与上述 receive 同为 18:00:22.876190 UTC。文件偏移与 `sequence_raw` 不能在当前 CDM 语义下当作可信的跨事件先后/因果顺序。`C_RECV_TO_SHELL` 标 `ORDER_UNRESOLVED`，不能把一个同时间戳的合法图路径算作严格时间确认。shellcode 连接与 loader 连接是 nginx 的两个输出分支，报告并未证明前者造成后者；把前者归入 loader POI 的“已恢复上游关系”会误记 H4。冻结参考把它列为 `CONTEXT_OTHER_BRANCH`。B0/B1 对 POI 归属的本轮评测规则没有这样误记。

可确认：三条原始操作、报告关联的步骤、receive 早于 loader 连接、同一 CDM Subject UUID。不可确认：特定 receive 的 payload 是否在 nginx 内导致任一外连、同时间戳 receive 与 shellcode 连接的先后、两个外连之间的真实传播。当前只能说**证据不足以判定**，不能声称已证明数学意义上不可识别。

## B：NODLINK WS12，进程父子边与同路径文件

调查点为 A2 中 `certutil` 启动 `ws12@1809315` 与后续 `agent` 启动 `ws12@15375641`。发布方 [A2 注释](../../research/repos/nodlink/doc/SimulatedWS12-attack/attack_annotation/A2.txt)描述复合命令、下载与启动。ETW `MSec` 是相对时标，绝对 UTC 起点仅由前期报告对齐推测，本轮不把它当已验证事实。

原始 `Process/Start` 在 127854.1959 MSec 记录 `cmd` PID 1996 (`ws12@1590222`)，127919.3304 MSec 的 `certutil` PID 3268 (`ws12@1809315`) 在同一记录中给出 `ParentID=1996`。这是一条**直接记录的父 PID 关系**；窗口内该 PID 最近较早的启动记录与 A2 命令对应，故可在此有限范围内核查 parent→child。143891.0271 MSec 的 `cmd` PID 4360 (`ws12@15345869`) 与 143906.2601 MSec 的 `agent` PID 4128 (`ws12@15375641`) 也由后者 `ParentID=4360` 支持。两条关系可评价的是父子创建边和正确 POI 连接，不是下载文件的字节内容或完整初侵链。

`certutil` PID 3268 在 143879.2098 MSec 对 `C:\Users\Public\agent.exe` 有 `FileIO/Write` (`ws12@15343712`)；`cmd` PID 4360 在 143906.9571 MSec 对同一路径有 `FileIO/Read` (`ws12@15379032`)。同路径且写先于读允许候选文件依赖，但日志未提供文件版本、字节哈希或读到的是哪一版。**该 read 晚于 agent 的 Process/Start（143906.2601）**，因此不能用这条 read 解释 agent 已发生的启动；时序规则即可拒绝这种错误连接。另有 `Image/Load`，也晚于启动记录，不能倒置为启动的前因。发布方 A2 注释说明整个操作意图，却没有逐事件文件字节流参考。这个候选只能标 `MODEL_POSSIBLE_DEPENDENCY`。

原始文件 1,087,311 行，记录顺序不单调；此处只用 `MSec` 排序。前期审计还发现 A1 前有 agent 活动且父进程入口不完整，因此不能把本地候选路径的最早节点认成真正初始失陷点。`UniqueProcessKey` 在两个不同 PID 的 `Process/Start` 中重用，本轮没有把它单独用作稳定实例身份。WS12 候选图只含 117000–145000 MSec 的 `Process/Start` 与 `agent.exe` 文件操作，且本机只有 anomaly 通道；它能验证上述关系，但不是全背景检索结果。

## 四个假设的本轮状态

|假设|实际观察|结论|
|---|---|---|
|H1 有证据且可行路径被基线漏掉|04-12 主参考在正确 POI 路径；WS12 两条父子边在预算可行时均出现；六条遗漏全属完整路径成本超过预算|**未支持**方法选择失败|
|H2 粗粒度进程导致错误解释|nginx receive→connect 可连但无内部传播；WS12 同路径文件缺版本|**观察到歧义**，简单保守标记能避免当前过断言|
|H3 部分观测导致路径不可判定|04-12 同时戳；WS12 相对时钟、入口/生命周期缺口；仅 anomaly 输入|**当前证据不足**，未证明一般不可识别定理|
|H4 多 POI 错误归属|shellcode 连接不可作为 loader POI 的确认上游；程序按 POI 分别计数|**风险真实存在，本轮评测未误计**|
