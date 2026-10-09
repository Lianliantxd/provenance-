# `attack_analysis.xls` 内部工作表审计

文件是真实的 **OLE2/BIFF `.xls`**，不是改后缀的 `.xlsx`。`xlrd` 只读解出一个可见工作表 `Sheet1`；有效区域 `A1:D9`，9 行×4 列，26 个非空单元格。合并区（Excel 坐标）是 `A2:D2`、`A4:A5`、`B4:B5`。`A4:A5` 合并标签为 `A1`；第五行的 A2 动作在 `C5/D5`，不能把空白 `A5/B5` 误判为没有第二项。工作簿列标题在 `B3:D3`：`Attack phase`、`Attack command`、`Attack steps`。

|位置|原值或忠实摘录|仅可支持的解释|
|---|---|---|
|`Sheet1!A2`|`Attack description:` 后列出部署下载服务、phpstudy 漏洞、agent、WinBrute、3389、nbtscan、PAExec 等步骤（含模拟凭据，公开版遮盖）|攻击叙事和阶段；没有 ETW 事件 ID/依赖对|
|`Sheet1!C4:D4`|`whoami&arp -a&ipconfig&ping www.baidu.com -c 1`；`phpstudy backdoor utilization - execution of system commands for information gathering`|A1 命令与侦察步骤|
|`Sheet1!C5:D5`|`taskkill ... & certutil ... agent.exe & cmd /c start ... agent.exe -opid 2f9c7075-ec33-4a29-901a-8e383f395763 ...`；`phpstudy backdoor utilization - download the agent and go live`|A2 复合命令和意图；没有某次文件写入→读取/执行的事件对标注|
|`Sheet1!C6:D6`|注册表/3389 操作；`Open the 3389 and leave the shift backdoor`|持久化步骤|
|`Sheet1!C7:D7`|`WinBrute.exe administrator_pass.txt administrator`；`Winbrute blasts the local administrator password`|凭据攻击步骤|
|`Sheet1!C8:D8`|`nbtscan.exe 192.168.0.244/24`；`nbtscan scans`|发现步骤|
|`Sheet1!C9:D9`|`PAExec.exe` 横向移动命令（模拟密码遮盖）；`PAExec lateral movement`|横向移动步骤|

工作簿 `A6:A9` 标注分别为 `A7`、`A24`、`A25`、`A32`，**并非**注释文件 `A3.txt`–`A6.txt` 的同名 ID；只按命令/步骤语义对应，不按这些代码直接连接事件。七份注释中的 `A1`–`A6` 给出时间范围、主机、命令，部分给出路径；`A_alltime` 只给整体时间及两个主机 IP。注释没有原始 ETW 事件 UUID、字节哈希、文件版本、两个具体日志偏移或明确的 `wrote-data-consumed-by` 等事件对语义。其绝对时钟与 ETW 相对 `MSec` 的偏移仍是推定，不能独立证实。

隐藏/非单元格检查：该 OLE 文件有 `Workbook`、文档元数据、`CompObj` 与 682 字节 `ETExtData` 流；工作簿中 `BOUNDSHEET=1`、`BOF=2`，唯一 sheet 的 visibility=0（可见）。BIFF 完整遍历未见 `FORMULA`、`NOTE`、`OBJ`、`MSODRAWING`、`MSODRAWINGGROUP`、`TXO` 记录；`xlrd` 未报告批注或超链接。**`ETExtData` 的私有语义未解码**，所以不能声称二进制的每个扩展字节都已解释；但无证据表明它承载一个普通可见/隐藏工作表或逐事件依赖表。逐格只读值与精确坐标在 `outputs/workbook_inventory.json`，其中模拟凭据已遮盖，关键主张可用原始 XLS 哈希和上述坐标复核。
