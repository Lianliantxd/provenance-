# D0 资产与历史决策审计（2026-10-10）

本目录只记录新的独立案例资格审查。历史结论维持：B2 匹配目标后未优于 B1-Min；WS12 官方表只支持步骤，不提供合格跨操作内容流 GT；CADETS E3 04-12 的 37 条连接仅为同一长寿命 nginx 的模型可能状态传播，`METHOD_GAP_NOT_ESTABLISHED`；G0–G4 是 `NARROW`。没有重跑它们，也没有要求真人 Root 标注或部署虚拟机。

审查顺序是本机与授权服务器现有文件、官方仓库及论文、ATLAS 小包 ZIP 中央目录、必要的小标签成员和只读原始文本扫描。没有运行归档内代码或恶意样本，没有解压完整日志，没有上传原始日志。官方提交固定为 ATLAS `e46096d1947e4f059e73a0ac2b9a9707812fd4bc`，DARPA TC `244ae2401032ce92ac3b72f49b8039cae67d60d6`（`git ls-remote ... HEAD`）。

| 已核文件 | 事实与范围 |
|---|---|
| ATLAS `raw_logs/M1.zip` | 官方 Git blob 67,946,790 B；下载到临时目录的 SHA-256 `c804d393e49f170caeeff58ca0d6b5e9b43f8c14e2890ff779696761ed8add59`；中央目录仅两主机各 `dns`、`firefox.txt`、`security_events.txt`，合计解压后 851,265,944 B。 |
| ATLAS `paper_experiments/M1.zip` | 61,929,024 B；SHA-256 `dc23ac3fecca7e505f68ad7132ae5c9e75cd7d28328be3479ea885a4c04acd79`；有作者 `malicious_labels.txt`，也有实验输出，但没有发现独立的逐操作攻击报告。只读了目录与标签成员。 |
| ATLAS `raw_logs/S1.zip` | 33,563,971 B；SHA-256 `4af22286497d2ee85ff0a0518796cc67e73659307ff3b8e020e4eb4dedc1a6f4`；单主机三种日志，解压后 400,352,529 B。 |
| ATLAS `paper_experiments/S1.zip` | 13,735,107 B；SHA-256 `edd16ee4eca5e4c7634a286d5d9b4b4df4c6865cf014019262f8aeb46e2fad67`；测试标签只给三个实体名。 |
| E5 本地 TA5.1 报告 | `research/sources/PIDSMaker/Ground_Truth/TA51_Final_report_E5.pdf`，158 页，SHA-256 `aa12f7b93399159491f90fe036a88f1250c451809f686950e55edc0ee6a25d3b`；第 10.4 节描述 2019-05-17 CADETS Nginx Drakon 执行。它不是配套原始 CDM。 |
| 本机与服务器原始 E5 | 对本机 Documents 的 7 层文件名搜索、项目树的 `rg --files`、服务器授权 `code` 目录 7 层搜索，均未发现 E5 Avro/归档或 ATLAS 本地副本。此结论仅限上述路径和搜索模式，不等于官方数据不存在。 |

ATLAS M1 作者标签在 h1 包含 `0xalsaheel.com`、`192.168.223.3`、`payload.exe`、`aalsahee/index.html`，h2 为前三项；S1 为前三项。它们是**实体标签**，与 `evaluate.py` 要求手工整理、填回 `eval_**` 的预测列表不同；两类都不是逐边传播真值。论文 §6.1、表 2–3 声称 M1 有两主机、背景、251.6K 事件、28 个攻击实体；S1 有 95.0K 事件、22 个攻击实体。这是发布者统计，未被本轮独立重建为查询图。

审查文件：[`01_DATASET_CANDIDATE_GATE.csv`](01_DATASET_CANDIDATE_GATE.csv)、[`02_ATTACK_REPORT_AND_REFERENCE_ANCHORS.md`](02_ATTACK_REPORT_AND_REFERENCE_ANCHORS.md)、[`outputs/package_audit.json`](outputs/package_audit.json)。可复跑包审计：`python3 src/audit_zip.py M1_raw.zip M1_experiment.zip S1_raw.zip S1_experiment.zip > outputs/package_audit.json`。路径按命令参数传入，不依赖本机绝对位置。

来源：[ATLAS 仓库 README](https://github.com/purseclab/ATLAS/tree/e46096d1947e4f059e73a0ac2b9a9707812fd4bc)、[ATLAS 论文 §6.1、表 2–3](https://www.usenix.org/system/files/sec21-alsaheel.pdf)、[DARPA E5 发布说明](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)。
