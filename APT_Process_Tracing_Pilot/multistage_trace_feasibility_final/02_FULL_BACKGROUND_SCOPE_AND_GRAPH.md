# 背景图范围和查询语义

从单个已有 CDM TAR 成员，按主机 `83C8ED1F-5045-DBCD-B39F-918F0DF4F851` 和 2018-04-12 17:59:00–18:39:00 UTC 流式抽取全部事件；**没有攻击标签预过滤**。共 178,399 条事件、356,281 条实体定义记录；其中 50,757 条记录具有受支持方向，127,642 条原样保留但不设分析方向。全背景事件压缩 CSV、定义压缩 CSV、82,976,768 字节的 SQLite 索引及构建清单位于 `outputs/`。索引有事件 UUID、subject/time、object/time、time；直接操作边另表，过程状态边按相邻严格时间组按需查询，不物化长进程全部两两边。

方向规则：READ/RECVFROM/EXECUTE 为 object→subject；WRITE/SENDTO/CONNECT/FORK 为 subject→object。它们是 `DIRECT_OPERATION`，只证明每条传感器操作本身。FORK/EXECUTE 可标为传感器记录的创建/执行事件，但未在本例跨事件路径中使用。其他类型保留为背景，不凭操作名生成直接方向。两个相邻、时间严格递增的同一 subject 时间组之间可产生 `MODEL_POSSIBLE_DEPENDENCY`；这是进程状态可能传播，绝非特定字节因果。同一纳秒组内 `ORDER_UNRESOLVED`，无严格边。不同 UUID 无可靠同一性材料时为 `IDENTITY_UNRESOLVED`；日志空白处为 `MISSING_OBSERVATION`。

**范围限制：**只有一个 40 分钟成员，不是整个 E3；按当前主机过滤。T1 实际查询只展开 B 所属 subject 的进程时间线，没有穷尽文件版本、网络流或其它实体分支。B0 因而是“同进程上游候选池”，不能宣称全图上游召回率。最早观察到的同进程事件仅是窗口边界，不是失陷 Root。

可重复命令：`python3 src/extract_background.py`（新目录中已有产物时不要覆盖）、`python3 src/build_index.py`、`python3 src/run_t1.py`、`python3 src/run_t2.py`、`python3 src/verify_raw.py`、`python3 -m unittest discover -s tests -v`。本轮对应命令退出码均为 0。背景扫描耗时 33.708 秒；查询在 SQLite 索引上完成，未创建大型进程两两边。哈希和原始引用见冻结 JSON 与各输出。
