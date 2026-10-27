# 2026-10-27 研究增量同步

本目录汇总最近成功推送之后的本机研究交付，保留失败、NA、未准入和不确定性。
最近核实的既有推送：C22，`6f4f4b106e04cad26dbbfea52da38b2a90f0f84a`，分支 `codex/c22-source-admission-20261019`。
本发布从该提交建立新分支，不改旧结果。主分支较旧不表示后续分支没有推送。

- [证据语义实验与 SAGA r13–r19](reports/evidence_semantics_and_saga.md)
- [四方法复现交付](reports/four_methods.md)
- [ORTHRUS 上游恢复](reports/orthrus_recovery.md)
- [候选基线准入审查](reports/baseline_admission.md)
- [共同调查流程执行](reports/common_baseline_execution.md)
- [AIRTAG 补充边证据与结构审查](reports/airtag_edge_audit.md)
- `aggregates/`：从冻结结果选择的汇总列，未重新运行研究。
- `tools/`：无案例载荷的清单核验与多重有向图删除工具；不是新攻击重构模型。

完整研究交付物、预测、逐项证据、原生记录和私有对应关系只归档到授权服务器。
下载归档、已安装环境和缓存复用原位置，不作为新研究成果重复上传。
本目录不含原始日志、逐事件摘录、Gold 正文、提示/回复、私有路径、端点或访问密钥。
报告是公开编辑版，不能代替私有原始冻结文件；原始报告哈希见 `SOURCE_REPORT_HASHES.json`。
报告中“本轮未推送”等表述描述当时实验，当前发布由用户后续明确授权。

这些是探索性运行和工件审查。未建立独立过程参考的 Edge/Path F1 保持 NA，未完成的作者流程保持 NOT_RUN。
本次仅同步既有结果，无新增 LLM、GPU、训练、攻击程序、数据下载或实验重跑。
