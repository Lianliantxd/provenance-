# 标签来源、格式和评价语义

实际使用 PIDSMaker 提交 `438a05a7c55256f639e5b5945cf4828fe3ee078e` 的两个 04-12 CSV。它们**无表头**，每行是 `UUID,{'subject'|'file'|'netflow': '属性'},node_id`；第二列按 `ast.literal_eval` 作为数据读入，`node_id` 是图数据库索引，不是 CDM 事件 UUID 或原始偏移。两个文件都无 `malicious=1` 字段、无时间化逐事件标签、无事件对/边标签。

|来源|内容 SHA-256|行数/去重 UUID|实体类型|本机 40 分钟成员观察|10 秒图|上游候选|
|---|---|---:|---|---:|---:|---:|
|REAPr `node_Nginx_Backdoor_12.csv`|`03486125bc23c64a772b373f8a8358f204aa4af4930ec0c0879737eb710cc495`|655/655|subject 655|102|2|1|
|ORTHRUS 同名文件|`41b60345dcb551b5899b11fb116dc240493931a97ea3acd92c19d9a8a7730e88`|43/43|subject 24、file 13、netflow 6|43|5|5|

两表仅 **14 个 UUID 重合**，但数量差不能当作质量排序。REAPr [原发布方法说明](https://bitbucket.org/sts-lab/reapr-ground-truth/src/32babb5613f7d8c4c9f7ab0a0e602da64521f149/README.md)（固定提交 `32babb5613f7d8c4c9f7ab0a0e602da64521f149`，本机副本哈希与官方相同）以报告线索选根/影响节点，做 process-only 正向与反向图遍历，并经人工复核，输出攻击/污染进程标签。故其中一部分是**依赖遍历派生**的实体范围；PIDSMaker 这份三列导出没有保留逐行攻击/污染类别，不能把 655 行都称为逐事件恶意真值，更不能用相似遍历恢复它们来验证路径结构。原 REAPr 仓库本轮读取了本机保存的方法 README；**未证明 PIDSMaker 三列 CSV 与原仓库某个文件逐字节同版**。

ORTHRUS [论文](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang)明确称作者对文本报告与数据进行人工逐节点审查；[其公开仓库](https://github.com/ubc-provenance/ground-truth)说明这类 CSV 的三列是原始实体 UUID、属性、数据库 index_id。该 ORTHRUS CSV 已与 [独立官方标签库](https://github.com/ubc-provenance/ground-truth/tree/59d2d1a99ca8a6f36a893d3795d4760e6da79150) 提交 `59d2d1a99ca8a6f36a893d3795d4760e6da79150` 的同名文件逐字节比对，SHA-256 相同。PIDSMaker 的 [ORTHRUS 注释说明](https://github.com/ubc-provenance/PIDSMaker/blob/main/Ground_Truth/orthrus/readme.md)将 04-12 的 43 个节点纳入使用，并说明该次攻击部分成功。**人工节点判定不是人工事件对依赖判定**；个别正常但受到影响的实体是否被排除、每个节点的复核记录，当前未独立核实。ORTHRUS 原代码副本提交 `e7f25dfee1ddd182a955b88f8a90a8cbd4a8e543` 的 `src/labelling.py` 也只把 UUID 映射为数据库节点 ID。

两套标签共享 DARPA 攻击叙事与 CDM 图，且任务边界不同。REAPr 的图遍历与本轮溯源搜索存在**潜在循环评价**；ORTHRUS 较窄、覆盖文件和网络实体，但并未公开此案例的事件级结构关系表。因此本轮只做来源分开的攻击相关实体覆盖，不计算全体节点 Precision/F1，也不计算结构 Precision/Recall/F1。
