# 攻击报告与参考锚点资格

**结论：本轮没有冻结合格的非输入上游参考。** 下表说明为什么“标签命中”不能代替独立攻击步骤。

| 候选 | 可独立支持的内容 | 原始映射检查 | 缺口 |
|---|---|---|---|
| M1 | [论文表 2](https://www.usenix.org/system/files/sec21-alsaheel.pdf)给出 strategic web compromise、CVE-2015-5122 及钓鱼链接、注入、信息收集、后门、横向移动、外传等**阶段类别**；§6.1 说明实验者知道攻击实体。实验包只列少数实体名。 | 对官方原始 ZIP 六个日志成员逐行做大小写不敏感字面扫描；`payload.exe` 在 h1/h2 security 日志分别命中 4,293/4,641 行，`0xalsaheel.com` 在 h1 Firefox 命中 886 行。`outputs/package_audit.json` 保存首个字面命中的成员、行号、解压后字节偏移和该**行**哈希。 | 无 M1 本次执行的逐步攻击记录、时间、具体进程实例和可唯一对齐的末端 B；多次命中不能按最易回溯者挑为真值。Firefox、DNS 和 Windows Security 时间格式不同，DNS 中还有明显早于本次主日志的记录，跨主机时钟不可据标签推断。 |
| S1 | 同一 [论文表 2](https://www.usenix.org/system/files/sec21-alsaheel.pdf)只列阶段类别。作者测试标签仅 `0xalsaheel.com`、`192.168.223.3`、`payload.exe`。 | 官方原始 ZIP 与实验 ZIP 均可读取，`security_events.txt` 样本显示 Windows 安全日志的时间、PID、进程名与文件名，但不含天然稳定事件 UUID。 | 三个标签不等于三个有出处、时间和实例的攻击阶段；域名与其 IP 尤其可能是同一解析事实。未找到两个非输入的逐步骤原始事件参考。 |
| E5 CADETS 2019-05-17 | 本地 TA5.1 报告 §10.4（PDF 101–106 页）给出 CADETS Nginx Drakon 行动、主机与多个时点；[DARPA README](https://github.com/darpa-i2o/Transparent-Computing/blob/244ae2401032ce92ac3b72f49b8039cae67d60d6/README.md)说明另有 ground truth、STARC 注释和分传感器 CDM。 | 未发现与该执行同版的原始 E5 CDM；本地 ORTHRUS/PIDSMaker 的 E5 节点 CSV、权重或脚本不是原始事件记录。 | 报告支持攻击步骤，但无法回链原始 event UUID/偏移、确认两进程实例及构建含背景图。不得把 E3 日志或二次实体标签套在 E5 报告上。 |

M1 首个 DNS 字面命中示例为 `M1/h1/logs/dns` 的物理第 3191 行、解压后偏移 952024，行 SHA-256 `8fdb0ab2df103045b569f94541b98bd299c178e96d0a6a07e90518334a60d7e6`。这**只证明字符串所在的行可回读**，并未证明它属于独立上游攻击步骤，也不是完整事件哈希、因果边或报告支持的攻击来源。M1 h1 DNS 首个相关行时间是 2018-11-02，而 h1 Firefox 首个相关行时间是 2018-12-21；未解决时钟/混合采集来源前不能把它们串成时间有序路径。

没有建立 `REFERENCE_ATTACK_STEPS.csv` 或 `PRESEARCH_CONTRACT.json`：硬门槛要求它们包含真实同版原始映射、至少两个非 POI 上游锚点和唯一晚期 B，而目前不满足。下游 T1/T2 因而没有运行。
