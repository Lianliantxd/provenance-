# 输入、报告与时间审计

- 直接可访问本机输入：`/Users/tianxd/Documents/Transparent Computing E3/CADETS/ta1-cadets-e3-official-2.json.tar.gz`，成员 `ta1-cadets-e3-official-2.json`；原归档预期 SHA256 `8d2f090d372cfb0d21bfb72dba6824884ce7870b5c8d24df34e9081b9b09c793`。此次流式扫描成员 4,299,097,329 字节，5,000,000 行。没有重新下载或启动虚拟机。
- 原报告：`/Users/tianxd/Documents/Transparent Computing E3/TC_Ground_Truth_Report_E3_Update.pdf`，SHA256 `021fc642e18544fdcc7bf0a79e2b5aae001f5717d3adbce16744b68934523599`，§3.13，PDF 第 26–28 页（印刷 23–25 页）。报告记载 14:00 nginx/Drakon 活动、14:02 `putfile tmux-1002`、14:37 micro 扫描。报告自身未明确时区；以 14:02→18:02:10 UTC 的多字段对应推断 EDT，仍保留时区不确定性。
- B 原始操作 `EVENT_WRITE`，UUID `58A15EC1-9BE9-5B97-9C54-1F5746A8AD2E`，UTC 18:02:10.376185722，offset `3098089940`，SHA256 `d218e1970b58cc654abddf0d7c37fe50bd1e5f8272ee24ac2cd5d623dd7b9fa8`。相同文件 UUID 的 `EVENT_OPEN` 路径 `/tmp/tmux-1002`，但两操作同一纳秒，不能声称严格先后。
- A 原始操作 `EVENT_CONNECT`，UUID `EBFB7595-F532-54F8-B51B-CE074AAAFE37`，UTC 18:00:23.166196193，offset `3089881394`，SHA256 `1f1af48eaedd0b47bc1cb9ace3b8b5f816eace1c5ec4ba6d9e4dc980815b01cf`；网络对象远端 `155.162.39.48:80`，符合报告 loaderDrakon 地址与 nginx 连接描述。
- 两个 offset/hash 已在重新打开原 TAR 成员后逐字节验证，见 `outputs/raw_anchor_verification.json`。原始存在和步骤匹配不证明 A 的字节导致 B。
- 备选排序在搜索前冻结：14:02 文件写入第一；14:37 目标端口扫描在相应分钟未找到报告目标 IP/22/6000 的 `EVENT_CONNECT`；`/tmp/test` 有四条 `EVENT_EXECUTE`，不具唯一性。
