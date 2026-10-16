本轮离线结项；不得启动模型或Controller。私有00_source_map_and_scope.json包含已冻结C15来源路径，公开包不含配置或数据。复算须具备原工件和配套Gold访问权限。

1. 在新私有目录保留来源配置/同版环境探针，用scripts/analyze_reflection_snapshots.py freeze冻结后验口径；先核验全部源hash。
2. Mac侧extract，按实际phase与ACK绑定PRE/POST/FINAL；只拷贝新增快照，不复制完整历史Prompt或Gold。
3. 原服务器既有评价解释器以-B运行evaluate，输入同一派生Input、Gold、作者评价器。重复执行已评分目录只读取检查点；若要真正重算，请使用新的输出目录，不能覆盖本轮封存。
4. 将新增评价结果逐文件SHA取回，用report-data生成三类差值与结构侧表。小型structural_closeout_adapter.py只用已存对象生成边/匹配身份聚合及图，不再评价。
5. tests/test_snapshot_boundaries.py为17项合成JSON边界检查，未调用模型或fake服务。

main入口冻结SHA见logs/analysis_contract_freeze.json；最终源码、适配器和所有来源依赖SHA见封存清单/00来源表。官方原源码及原C15不可写。公开仅聚合指标、通用无载荷代码、限制及图，不能独立代替私有实验输入。
