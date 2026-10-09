# G2–G4：执行对、观测与基线

## G2：冻结问题与真实观测

Q 是“保持控制字节和其他输入不变，改变本次 16 字节 payload 是否改变输出值”。它不是控制依赖、请求归属、文件版本或粗粒度可达。`02_PRE_REGISTERED_TASK_AND_CASES.json` 在正式运行前冻结了程序/可执行文件 SHA256、投影字段、12 次执行、干预、预算和停止条件。F1 是同一个 785,328 字节静态 ELF，命令行形态、输入/输出相对路径和环境哈希在 12 次中一致；控制字节仅在本地输入文件中。

四种历史 F_K、N_K、F_Z、N_Z 各重复三次。K 事实输入下 F 与 N 都输出 K×16；固定 F 控制字节把 payload 改成 Z×16 后输出变 Z×16；固定 N 控制字节做同样干预后输出仍为 K×16。冻结 C 源码语义与实际输出共同构成独立 oracle。12 个原始 `strace` 各有 6 个与两个本地对象相关的系统调用，均由非特权 Linux `strace -ttt -yy -s 256` 跟踪自建子进程。原始日志留在服务器私有 `raw_sensor/`，其逐文件 SHA256 和字节数在 `outputs/sensor_manifest.json`；不发布含个人绝对路径、输入控制字节和内存地址的原始文本。

冻结投影保留调用顺序、操作名、规范化对象、open flags、请求/返回字节数和单一进程实例 token；排除绝对 PID/FD、时间戳和读写缓冲区内容。**12 次投影完全相同，12 个完整原始 trace SHA256 全部不同。** 原生 trace 至少可见时间差，读缓冲区中还可见 F/N 控制字节和 payload；F_Z 的写缓冲区内容也不同。因此状态严格为 `PROJECTED_EQUIVALENT_PAIR_VERIFIED`，不是“完整 OS 日志相同”，也不是数学上对所有可能执行不可识别的证明。单次原始 trace 为 1,184 字节；投影内容见 `outputs/projected_observations/`。`strace` 12 次封装运行的中位 wall 为 3,866.088 μs；该数包含启动和追踪，不可与应用 CPU 成本等同。

## G3：补充观测的真实性

`M_VALUE_LINEAGE` 本轮只验证了**应用内读缓冲区地址与写源地址**的窄代理，而不是通用字节污点。另编译的插桩程序记录两处指针，不写 `is_flow`、模式标签或 oracle 判断；12 次中地址相等 6 次、不等 6 次，每次增加 64 字节原始观测。它需要源码修改和事前部署；无 root。未追踪运行中位 wall 由 535.506 μs 到 554.797 μs，差值 19.291 μs，仅为本次 12+12 小样本描述，不是稳健 CPU 开销或显著性结论。地址不等在一般程序里仍可能通过复制产生值依赖，因而固定规则只能在“相等”时对这个冻结程序给出确定依赖，其余拒答。其他三类候选只作机制/成本可行性审计，未在 F1 验证；详见 `04_MEASUREMENT_CATALOG.csv`。

G3 状态：`ACTIONABLE_MEASUREMENTS_AVAILABLE`，但仅为已知程序的事前应用插桩；同时触发 `TRIVIAL_FIELD_ADDITION`。F2 请求归属族未运行，因为 F1 已显示单一固定字段解决当前可确认的覆盖增益，且没有非平凡选择问题；F2 不计入样本和方法结论。

## G4：同任务、同预算对照

预算为一个已验证、可分享的补充机制（64 字节/执行）。无补充观测时粗可达仅允许候选关系，因此必须拒答。只有一个经实测可行的 F1 补采项，`RANDOM_SAME_BUDGET` 和全量可行基线退化为同一选择，不能夸大随机试验。穷举仅覆盖本轮冻结并验证的空集/单项集；在达到至少 6 个正确确定答案、0 错误断言的目标下，该单项是唯一最小组合，不是现实世界全局最优。

| 策略 | 正确确定/12 | 错误确定 | 拒答 | 补充字节总量 |
|---|---:|---:|---:|---:|
| COARSE_REACHABILITY | 0 | 0 | 12 | 0 |
| ALWAYS_ABSTAIN | 0 | 0 | 12 | 0 |
| FIXED_RULE_VALUE_LINEAGE / FIXED_LOW_COST | 6 | 0 | 6 | 768 |
| COLLECT_ALL_VALIDATED_FEASIBLE / RANDOM_SAME_BUDGET / EXHAUSTIVE_SUBSET_REFERENCE | 6 | 0 | 6 | 768 |

`SUPPORTED_NONDEPENDENCE` 没有从被动元数据或“不等指针”直接断言。`UNDETERMINED` 与无依赖是不同结果。程序把预测和 oracle 读取分为两个阶段；预测函数只用投影和地址相等字段。详表见 `outputs/g4_coverage_risk_cost.csv`。因固定规则已达到本轮全部已证实收益，未实现问题条件化选择原型，G4=`METHOD_GAP_NOT_ESTABLISHED`。这些是 12 次良性受控历史，不是 12 次独立 APT 攻击，也不支持显著性或跨软件普适性。
