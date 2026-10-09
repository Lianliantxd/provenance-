# G0–G4 最终博士研究决策

| 闸门 | 实际结果 | 判定 |
|---|---|---|
| G0 | 五篇指定原文均已核查；单元划分、运行期污点、因果 ID、身份恢复、低保真图降噪早有先行机制；仅“不同 Q 和成本下的观测组合选择”留条件性空间 | `G0_PASS_CONDITIONAL` |
| G1 | 普通用户在授权 Linux 服务器成功 `strace` 自建良性子进程；独立干预 oracle 可获得 | `EMPIRICAL_SENSOR_GATE_PASS` |
| G2 | 同一可执行文件 12 次；冻结元数据投影相同；完整原生 trace 不同；两种内部值依赖及干预响应实际成立 | `PROJECTED_EQUIVALENT_PAIR_VERIFIED` |
| G3 | 事前应用指针观测每次 64 字节，在本程序上可辨；其他候选未验证，不能声称通用值 lineage | `ACTIONABLE_MEASUREMENTS_AVAILABLE` + `TRIVIAL_FIELD_ADDITION` |
| G4 | 固定字段规则达到所有本轮经验证可行的覆盖增益；同预算没有问题条件化选择的额外正确覆盖或成本优势 | `METHOD_GAP_NOT_ESTABLISHED` |

**最终方向：`NARROW`。方法状态：`METHOD_GAP_NOT_ESTABLISHED`。** 可以保留“对指定溯源命题区分直接操作、可能依赖和观测缺口”的诊断与评价协议；当前证据不足以把它写成独立的第四项新算法。只加 `UNKNOWN`、请求 ID 或固定指针/lineage 字段都已被先行机制或简单规则覆盖。F1 受控执行不能代替真实 APT 因果 GT，不能声称历史 CADETS 的 37 段传播已验证。

**唯一后续动作：正式止损独立算法主张。** 保留可复核的 G0 文献矩阵、G2 投影对照和 G4 负结果，停止在同一良性程序上调字段/预算或训练复杂模型寻找优势。本结论不否认更广泛的问题可能存在，只说明本轮未通过方法差距闸门。

材料可复核性：`02_PRE_REGISTERED_TASK_AND_CASES.json` 为运行前冻结；`outputs/sensor_manifest.json` 保存 12 份原始 trace 的 SHA/字节数；原始 trace 仅在授权服务器私有目录，公开仓库只有匿名化投影、隔离 oracle 和汇总数据；`outputs/engineering_tests.txt` 有 16 项护栏测试结果。所有实验均为本地良性文件读写，不涉及真实凭据、外网或其他进程。
