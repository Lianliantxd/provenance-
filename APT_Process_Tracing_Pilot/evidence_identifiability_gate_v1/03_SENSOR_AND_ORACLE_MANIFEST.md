# G1：传感器和独立参考能力

- 本机：Darwin arm64、普通用户、Python 3.14.4、`/usr/bin/cc`，`strace` 不存在；不以 macOS 模拟冒充 OS 追踪。
- 授权服务器：Ubuntu Linux x86_64、普通用户 `uid=1004`、Python 3.12.3、`/usr/bin/cc`、`/usr/bin/strace`、目标 `/home` 分区约 19T 可用。目标目录的尾部空格经 `pwd` 与 `realpath` 核查；该目录不是 Git 工作树。
- 最小探针：普通用户运行 `strace -e trace=write /usr/bin/printf gate-probe`，退出码 0、输出 `gate-probe`、trace 2 行；仅自建子进程，无 sudo、无内核修改、无其他进程监听。
- F1 计划中的 `sensor/` 是 `strace` 对自建良性程序的真实系统调用外部观测；`oracle/` 是受控 payload 干预加冻结 C 语义的独立参考。原始传感器允许出现输入缓冲区内容，因此**不能**宣称原始 trace 不可区分；评价只针对预冻结的规范化投影。

G1 状态：`EMPIRICAL_SENSOR_GATE_PASS`。这仅确认可用非特权 OS 追踪，不预言 G2–G4 的结果。
