# A→B 证据链个案

报告 §3.13 支持“nginx 向 loaderDrakon 地址连接，后有 putfile tmux-1002”。原始 CDM 分别观察到 A=`EBFB7595-F532-54F8-B51B-CE074AAAFE37` 和 B=`58A15EC1-9BE9-5B97-9C54-1F5746A8AD2E`；A 的 NetFlowObject 远端为 `155.162.39.48:80`，B 的 FileObject UUID 为 `5453C813-1A0E-4359-8E1A-41B40943CDC5`。这些是 `OBSERVED_EVENT`；各自 subject/object 操作是 `DIRECT_OPERATION`。两者 subject UUID 同为 `11C64B2C-3DC3-11E8-A5CA-3FA3753A265A`。

按严格时间组回溯，从 B 到 A 跨 37 个同进程状态跳；逐段源/目标 UUID、时间、offset/hash 在 `outputs/t2_candidate_links.csv`。每段只归类 `MODEL_POSSIBLE_DEPENDENCY`，没有 `INDEPENDENTLY_SUPPORTED_CROSS_STEP_RELATION`。报告提供 `REPORT_SUPPORTED_STEP_ORDER`，但没有这两个操作间特定内容传播证据。A 之前、B 之后和组内并列操作的具体状态均为 `UNRESOLVED`。不能把同一长寿命 nginx 上的候选链包装成已证实的攻击因果链。

T1 的 B0 候选池含 A，按冻结的近到远/UUID 次序排第 286；预算 32/128 不显示，512 才显示。B1-Min 和三条无标签备选均未选到 A；这说明路径选择歧义，**不构成已验证的算法缺陷**，因为跨步骤关系没有独立真值且这些基线仅按受限的同进程时间线工作。
