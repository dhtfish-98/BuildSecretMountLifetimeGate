# v0.1.1 验证边界

当前源码版本为 `0.1.1`。每个正式版本须以其精确提交、Linux 主线及标签运行、回下载的脱敏回执和 Release 附件共同核对；版本号、测试或上传本身不代表实际实验通过。当前公开发行状态见 [GitHub Releases](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate/releases)。

上一版 [v0.1.0](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate/releases/tag/v0.1.0) 的注释标签与主线对应提交 `36da957a5b0a4b7971d326191af692ecaa2c864f`，其[主线](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate/actions/runs/37405815167)和[标签](https://github.com/dhtfish-98/BuildSecretMountLifetimeGate/actions/runs/37406251640)两个作业均成功。真实 Docker 28.0.4、Buildx v0.37.1、BuildKit v0.33.1 中，自有弱侧 `ARG`→`ENV` 在镜像历史/OCI 等列明区域检出一次性合成值；secret mount 强侧在镜像历史、OCI、文件、缓存、元数据及构建日志中未检出。回执记录构建器和原始输出已删除，原始导出不能事后独立重扫。此前失败的运行保留在 GitHub 历史中，不计作通过。

本项目只覆盖自有 Dockerfile、固定基础镜像和 frontend、一次性合成值及列明导出器。secret mount 不能阻止恶意构建指令主动复制、打印或派生秘密；这些结果不证明 BuildKit 上游漏洞、通用无泄漏、生产部署、真实授权任务、模型防护影响或 CVP 资格/审批。第三方 BuildKit、运行镜像及相关组件的原权利说明保留在 [第三方说明](THIRD_PARTY_NOTICES.md)。
