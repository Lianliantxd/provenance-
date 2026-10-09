# 执行与输入审计

本轮使用本机已有 [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker) 副本（`main`，提交 `438a05a7c55256f639e5b5945cf4828fe3ee078e`）中的 04-12 REAPr/ORTHRUS CSV；没有把它们视为两个独立标注者。原始 CDM 为本机已有 `ta1-cadets-e3-official-2.json.tar.gz`，SHA-256 `8d2f090d372cfb0d21bfb72dba6824884ce7870b5c8d24df34e9081b9b09c793`，只读取其中 `ta1-cadets-e3-official-2.json` 成员。该成员扫描 5,000,000 行、4,299,097,329 字节，**不解包整套数据，不运行日志命令或容器/虚拟机**。

攻击时段采用 PIDSMaker 配置的 2018-04-12 13:59–14:39 `US/Eastern`，对应 17:59–18:39 UTC；这只是发布配置的时区换算。按**时段和主机，不按标签**扫描该成员，得到 178,399 条事件、20,900 个被事件引用的实体 UUID。扫描后才以公开 UUID 表连接，得到并集 131 个被观察标签实体；再次只针对这 131 个 UUID 核查独立 CDM 实体定义，131/131 找到，类型冲突 0。这里的“未观察”只限**这个本机成员与冻结时段**，不能推断全套 E3 没有该实体。窗口索引只保留标签命中实体的计数及最多四条事件样本，未将 4.3 GB 原始数据上传。原始记录偏移和 SHA-256 可从 `outputs/bounded_window_index.json`、`outputs/entity_definition_checks.json` 回链。

既有 10 秒图位于 18:00:20–18:00:30 UTC：原抽取窗口 294 条事件，支持的操作 196 条，98 条操作未进入图；对应 `events.csv` SHA-256 `100538fcff4cdf48664a7605078a07c1cd371c89c69b0f802b71f7c962b7efe7`。这**不是完整 40 分钟攻击背景图**。既有候选池 SHA-256 `310409a19814a1a06009f9da059a5cb872c8fb2644a373896463b84f3ecef2f1`；旧运行已核验其中 162/162 条输出事件的原始偏移/哈希，本轮又核查完整输入档案哈希、标签定义和来源版本。这里复用已冻结查询，不宣称盲测。解析器、图代码、选择器哈希及 POI 见 `02_FROZEN_CASE_AND_QUERY.json`。

本轮实际命令、退出码和输出摘要记录在 `outputs/execution_log.jsonl`。`src/scan_cadets_window.py`、`src/verify_entity_defs.py` 只读原始归档；`src/run_baselines.py` 仅读 10 秒旧图与候选池；`src/evaluate.py` **在路径输出完成后**才读标签。未改旧结果，未训练模型、部署 VM/Docker、重开 B2 或执行攻击命令。
