# DiagChain C1 后续执行：本地真实通道与服务器GPU核查

结论：本机Ollama无害探针成功；作者原生控制器单案例首轮请求在180秒超时后按冻结预算停止。没有预测、没有Gold评价。失败证据完整保留，不能称为复现成功或方法失败。

- 本轮尝试：2次模型请求（1探针成功、1真实案例超时）；已知探针token35，真实案例token未知；外部API费用0。
- 配置：原始作者控制器 + ECRAG/Reflection/Typed/Memory等论文主配置，现有deepseek-r1:1.5b，本机CPU2/GPU0。更换模型及资源预算，不能严格数值比较。
- 服务器GPU：4×A40，首次利用率96/96/100/97%，第二次97/96/28/99%，均已有其他用户进程。服务器CPU/内存此次充足；没有启动服务器模型任务。
- 预测0，评价0，Reflection0，typed动作0；没有Gold语义访问。
- 核心公开证据：SUMMARY.json 和可审查的运行层源码。完整私有记录另行归档。
- GitHub仅发布经审查的代码/聚合摘要；本机完整请求及案例映射不公开。

Ollama API参数与用量字段依据：[官方API](https://docs.ollama.com/api/generate)、[官方options定义](https://github.com/ollama/ollama/blob/main/api/types.go)。CPU使用是本轮请求配置，不能仅凭配置宣称已独立验证硬件执行全过程。

公开脚本需要私有运行合同、已核验作者代码和数据路径；本导出是审查归档，不是零配置独立执行包。未提供Gold、oracle、真实案例名称/映射或任何原始模型请求/响应。
