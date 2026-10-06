# 验证门槛

1. 单元测试必须覆盖 tar/gzip/zlib 命中、普通文件和目录名、缺失/损坏/非预期压缩导出 fail-closed、OCI 描述符指向的配置历史阳性与阴性、未被索引引用的伪历史拒绝、空元数据与占位缓存拒绝、已识别 Buildx 元数据字段的错误类型或摘要拒绝、分段日志永不持久化。OCI 镜像与本地缓存的层必须按已验证描述符 `mediaType` 强制解析 TAR 或 gzip TAR；即使 TAR 首块 magic 与校验和同时损坏也应拒绝。未知和当前不支持的层类型，包括 zstd，须拒绝。它们只证明扫描代码按自建夹具工作。
2. 同一精确提交的 Linux Docker/Buildx/BuildKit 实验必须成功运行弱、强两侧。弱侧需在 OCI 配置 `history.created_by` 命中随机合成值；强侧当前 RUN 的 SHA-256 校验和下一条 RUN 的挂载消失均必须成功。
3. 强侧 OCI 导出、解压层、文件导出、本地缓存、元数据和原始日志均不得有该合成值字节。缺文件、无法完整展开或扫描超限均 FAIL。
4. 原始输出置于 `0700` 运行根并在本次运行结束后删除；只可发布不含合成值的回执。需要记录工作流运行、精确提交、可读的 Docker client/server、Buildx 与 BuildKit 版本、基础镜像/frontend 摘要、源 Dockerfile 摘要、元数据/缓存结构、结果及失败项目。未知格式或无法完整解析的导出须 FAIL。
5. 单次合成实验不等于生产构建验证。真实授权场景、相关模型防护影响和 CVP 资格均须独立证明。

当前本机只有 macOS arm64，未发现 Docker/Buildx/BuildKit 命令。上列第 2–4 项及公开发行仍 **OPEN**。

当前跟踪工作流的 PR 路径只做不导入代码的语法解析；PR 仍可改动工作流且托管 runner 可能提供 Docker/sudo，不应称其为安全沙箱。可信 ref 的真实实验也依赖管理员实际配置分支与标签保护，保护规则仍 OPEN。

参考：[Docker 构建密钥](https://docs.docker.com/build/building/secrets/)、[构建变量](https://docs.docker.com/build/building/variables/)、[本地缓存](https://docs.docker.com/build/cache/backends/local/)、[导出器](https://docs.docker.com/build/exporters/)、[OCI 层格式规范](https://github.com/opencontainers/image-spec/blob/main/layer.md)、[GitHub Ubuntu 24.04 runner 软件清单](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)。
