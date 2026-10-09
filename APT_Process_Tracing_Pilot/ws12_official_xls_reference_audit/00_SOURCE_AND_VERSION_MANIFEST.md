# WS12 官方材料来源与版本审计

审计日期：2026-10-09（Asia/Shanghai）。官方入口为 [PKU-ASAL/Simulated-Data](https://github.com/PKU-ASAL/Simulated-Data)，查询时分支为 `main`，提交 `434dbe2d0be88bd034c4af0c819aed641d2b3758`。本机 `research/repos/nodlink/` 是无 `.git` 的文件副本，**不能**从它声称读到了 Git commit；本轮从上述提交的 raw URL 单独取得 1 个 XLS 与 7 个注释小文件，逐一与本机副本计算**文件内容 SHA-256**并比对，8/8 相同。未把 Git blob SHA 当 SHA-256，也未下载数据集归档。

|同提交文件|大小（字节）|SHA-256（文件内容）|
|---|---:|---|
|`doc/SimulatedWS12-attack/attack_analysis.xls`|22528|`394e31cd95f7ff1ab1ea4cae32d1f235169d955cb5f2a14cd63294f3a307850b`|
|`attack_annotation/A1.txt`|139|`75af4b52d76c7baacf8aeaed106191d7b29913b3fc9c189596d0bb8ce7b09936`|
|`attack_annotation/A2.txt`|345|`730e040bba1de43ab895bb5c699c3adcb1123a7c4bac68d84a76b6b59f555f7e`|
|`attack_annotation/A3.txt`|183|`5b5db45ab9ff9380f2ae4e3c84378cea0ddd82af677a997b74ac139caeb88742`|
|`attack_annotation/A4.txt`|680|`bec0bc533a9712bd0e94a5c7bd98dd9534d9c166506833b8b4ddf2601b0fdb35`|
|`attack_annotation/A5.txt`|163|`e3baaac69efda0c6a65119147b4d09802306b107ea446f158203daa83c8f3ce7`|
|`attack_annotation/A6.txt`|199|`463c93656dd30f5023d43490d473cb9e1411c84c7f6b21638c5cf404a46a5010`|
|`attack_annotation/A_alltime.txt`|104|`7e221709caafe7243bcda51381137c7c9d0bdc46de2ec7532f73599ad4edc15e`|

本机 ETW `anomaly.json` 为 369,184,761 字节，SHA-256 `7664b3f8a4f8ba4b374f63b0dc8f23f39772ea52eda8ff0e6a5ebd7844f0edce`。从本机 `hw20.zip` 流式提取该成员得到相同哈希；本机 ZIP 自身 SHA-256 为 `903962c7251c5b8a8232da0a13a73d5d6fd04eeb29524a9f0d256bd74079aa66`。**没有核对该 ZIP 与官方提交中大型数据归档的字节一致性**，故“官方 XLS/注释同提交”不等于“本机 ETW 一定同一发布版本”。只把可以实际回读的本机事件用于受限映射。

读取工具是隔离在 `/private/tmp/ws12-xlrd/` 的 `xlrd 2.0.2` 与 `olefile 0.47`；未改系统 Python。运行 `src/audit_sources.py` 与 `src/build_candidates.py` 只读来源，输出至本目录。`outputs/source_freeze.json` 记录官方提交、8 个文件哈希、本机原始日志与上一轮图/候选域版本、POI、时窗。`outputs/reference_freeze.json` 固定本轮参考表 SHA；WS12 早已是开发案例，不是盲测。本轮无合格官方事件对参考，因而没有启动新基线运行。

工作簿和注释中含模拟攻击命令及凭据字样。公开的本轮产物对凭据作了遮盖；原 XLS 和注释保留在原始本机位置，不随本轮文件再次上传。完整命令、退出码与输出哈希见 `execution_log.jsonl`。
