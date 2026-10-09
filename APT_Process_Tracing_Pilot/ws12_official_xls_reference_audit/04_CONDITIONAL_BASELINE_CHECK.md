# 条件性基线检查

进入新运行的门槛要求官方材料明确给出同版本、语义清楚且两端唯一可回读的**跨操作事件对**。本轮实读 XLS 与 A1–A6 后，`PUBLISHED_PAIR_MATCHED=0`，所以 **未运行新的 B0、B1-Min 或 B1-Alternatives 查询**，也未创建虚假的本轮基线结果。参考已在 `outputs/reference_freeze.json` 冻结；由于门槛未达，不把对简单基线调参当下一步。

仅核对既有、未改动的 `../identifiability_feasibility_v1/04_BASELINE_RESULTS.csv`（SHA-256 `5d04ff75fb29edf14fea13aee3843803fc0a653b71b358f767654a74ae265a3f`）：WS12 的 `W_BOTH`，预算 8，候选集合 4 条事件、输出 4 条，B0、B1-Min、B1-Alternatives 对两条**传感器 ParentID 父子关系**在正确 POI 路径的记录均为 2/2，输出原始引用 4/4 匹配。该结果属于 anomaly 限定的开发案例，不是全背景调查。上一轮把这两项记在 `evaluable_reference_pairs`；本轮官方资料审计明确收窄其语义：它们是可核查的传感器创建关系，**不是发布方独立标注的写入→消费或完整攻击因果对**。

因此本轮没有 `OBSERVED_BASELINE_FAILURE`；对于这两条直接父子关系，只能说 **`BASELINE_PASS_NO_NOVELTY`（既有受限运行）**。同路径文件候选没有独立内容流 GT，不能用其未被路径算法确认为真来声称算法失败。Edge Precision/F1 和完整攻击链准确率仍为 `NA`。
