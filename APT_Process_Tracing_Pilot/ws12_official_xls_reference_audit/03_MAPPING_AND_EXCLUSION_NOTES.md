# A2 原始事件映射与排除理由

映射只用本机 ETW 原始 `anomaly.json` 的 `MSec`、PID、`ParentID`、事件类型、文件路径与回读偏移；每条关键记录的 SHA-256 见 `outputs/key_raw_event_checks.json` 和 [候选表](02_REFERENCE_PAIR_CANDIDATES.csv)。`MSec` 是相对时标；文件记录顺序不保证等于时间顺序。`UniqueProcessKey` 在 `ws12@1270525`（A1 cmd，PID 2124）与 `ws12@1590222`（A2 cmd，PID 1996）相同，不能单独作为实例身份。

|A2 记录|`MSec`|原始偏移|观察到的内容与关系边界|
|---|---:|---:|---|
|cmd `Process/Start`, PID 1996|127854.1959|1590222|A2 复合命令候选；父 PID 4452 的完整生命周期不在本次窗口确认|
|certutil `Process/Start`, PID 3268|127919.3304|1809315|记录 `ParentID=1996`；这是**传感器直接记录**的父 PID 边|
|certutil `FileIO/Write` agent.exe|143879.2098|15343712|确有写操作；未记录此次写入形成的字节/文件版本|
|cmd `Process/Start`, PID 4360|143891.0271|15345869|后续启动命令候选；`ParentID=1996`|
|agent `Process/Start`, PID 4128|143906.2601|15375641|记录 `ParentID=4360`；是第二条可核查的直接父 PID 边|
|cmd `FileIO/Read` agent.exe|143906.9571|15379032|同路径读取，但发生在 agent 启动**之后**，不能解释先前的启动|

官方 `Sheet1!C5` 和 `A2.txt` 的 agent `-opid` 为 `2f9c7075…`，而上述后续 cmd/agent 启动使用 `7fa51253…`。针对本机完整 `anomaly.json` 的**字符串定位**找到前者 1 次，落在 127916.8913 MSec、偏移 1807171 的 `Process/Stop`（PID 4612）；未找到具有该标识的 `Process/Start`。后者出现 9 次，覆盖本轮两条启动和其他停机/后续操作。此差异证明**公开命令与该次后续启动不能做精确标识匹配**；它不单独证明整个数据归档版本错误。定位摘要和哈希保存在 `outputs/opid_occurrences.json`。

`certutil` 写→`cmd` 读：时间先后且路径相同，属于**模型可能依赖**；没有文件对象版本或字节内容，不能证明后一次读消费了前一次写。写→agent 启动也是发布方步骤叙事及同路径命令的候选解释，不是官方逐事件依赖对。读→agent 启动则与 `MSec` 相矛盾，应拒绝。官方步骤支持 A2 的整体攻击意图，不能把这些三种关系混为一个“真值边”。

[候选表](02_REFERENCE_PAIR_CANDIDATES.csv)有 12 行：A1–A6 六个发布步骤的代表性行（含 A2 命令映射），另有两条传感器父子关系、两条模型文件依赖、一条时间矛盾和一条标识匹配排除。**行数不是独立 GT 数。** 其中 `SENSOR_DIRECT_RELATION=2` 可用于核查父子元数据；`PUBLISHED_PAIR_MATCHED=0`，跨操作内容流合格官方参考为 **0**。本轮没有把由前期图工具生成的路径反向写成参考。
