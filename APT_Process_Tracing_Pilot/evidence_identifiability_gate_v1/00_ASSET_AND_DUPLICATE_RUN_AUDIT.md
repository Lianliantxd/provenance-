# 资产与重复运行审计

- 本机项目工作目录：`evidence_identifiability_gate_v1/` 在本轮开始前不存在；旧 `multistage_trace_feasibility_final/` 存在，只作为迁移参考，不冒充本轮实验。此工作目录是未提交的本地汇总，不是远端同步仓库。
- 已授权临时同步副本：检查时分支 `main`、HEAD `bbee4181299d22123aa7073da094d20c2405fc4a`、工作树干净，remote 为 `https://github.com/Lianliantxd/provenance-.git`。同目标新目录此前不存在。
- 服务器目标目录经 `pwd` 和 `realpath` 核查，目录名确有尾部空格，且自身不是 Git 工作树。本轮只同步新目录中的可公开分享审计材料；原始 `strace` 留在授权服务器私有目录，不上传个人绝对路径、真实凭据或大型归档。
- 既有 CADETS 04-12 实验结论 `MULTISTAGE_CANDIDATE_ONLY / METHOD_GAP_NOT_ESTABLISHED`，本轮不重跑旧回溯。
