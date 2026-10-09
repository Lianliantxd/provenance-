# T2：已知 A/B 的路径诊断

此诊断在 B-only T1 落盘后运行；T1 输出 SHA256 `0bc881025a194ed8e95964c66852a97441f0c08bc058a5503e862647581090ef`，T2 未回写 T1。已知端点 A、B 属于同一 subject；严格时间组路径有 38 条原始事件、37 个跨事件连接，最小成本在当前“相邻时间组各取一事件”的规则下为 38 事件。32 事件预算不可行；128/512 可显示候选路径，但只能到观察边界。中间等时组代表事件按 UUID 选取；组内顺序未决，没有组内跳边。

两端各一条 `DIRECT_OPERATION` 原始传感器关系（A 的 nginx→网络对象，B 的 nginx→文件对象）；**A→B 跨事件路径的 37 段全是 `MODEL_POSSIBLE_DEPENDENCY`，0 段独立传感器记录的跨步骤因果边**。去掉模型可能依赖即断开。具体 37 段及双端 offset/hash 见 `outputs/t2_candidate_links.csv`；完整事件路径见 `outputs/t2_known_endpoints.json`。

关键断裂是缺少能把 loader 网络连接的输入/状态，独立接到后来文件写入内容的证据。报告只支持步骤先后和攻击场景，不能补足具体传播关系。Structural Precision/Recall/F1 = NA。
