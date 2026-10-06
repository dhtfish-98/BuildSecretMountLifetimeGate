# v0.1.0 验证边界

2026-10-06 02:39 UTC 的发布前冻结：[公开仓库](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate)提交 `39a003349fe3dfc641a6e59fa9fc3a543ae3eaa7` 的[主线 Linux BuildKit 运行](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate/actions/runs/37404999120)两个作业成功。真实 Docker 28.0.4、Buildx v0.37.1、BuildKit v0.33.1 环境中，故意弱化的 `ARG`→`ENV` 分支在镜像历史和 OCI 导出检出一次性合成值；secret mount 分支在镜像历史、OCI、文件、缓存、元数据和构建日志检查中未检出。回执记录构建器与原始输出已删除、运行目录权限 `0700`；原始导出按设计已销毁，事后不能独立重扫。此前失败的 GitHub 运行保留在历史中，不计为通过。

源码和安装包静态反例、TAR/OCI/元数据校验及 Python 3.12/3.14 各 17 项单测通过；独立复核回下载了上述主线运行的原生附件并核对 GitHub 摘要、回执字段及精确提交。此后任何文档或工作流修订会产生新提交；正式标签、Release 和附件须按最终提交另核，不由本冻结记录推定。

该实验仅覆盖自有 Dockerfile、固定基础镜像/frontend、一次性合成值和列出的导出器。secret mount 不能阻止恶意构建指令主动复制、打印或派生秘密；本结果不证明 BuildKit 上游漏洞、通用无泄漏、生产部署、真实授权任务、模型防护影响或 CVP 资格/审批。
