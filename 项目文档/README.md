# BuildSecretMountLifetimeGate

**版本：0.1.1。** 维护者：dhtfish98。[验证状态与边界](VERSION_STATUS.md)按精确提交记录。

这个项目只运行两份自有 Dockerfile，用一次性随机**合成**字符串测试构建参数误用与 secret mount 的差别。弱侧把 `ARG` 值继续写入 `ENV`，要求在 OCI 镜像配置历史中实际观察到该值；强侧用 `RUN --mount=type=secret,required=true` 在当前指令内校验挂载内容，下一条 `RUN` 验证挂载路径已消失。每侧以 `--no-cache` 构建，并将 OCI 镜像、根文件系统、`mode=max` 本地缓存、构建元数据与构建日志逐字节扫描。OCI 镜像和缓存中的层按描述符 `mediaType` 强制解析 TAR 或 gzip TAR，损坏、未知或当前不支持的层格式均使验收失败；递归扫描也识别 zlib。缺失或超限的输出同样失败。

该实验只适用于记录的 Docker/Buildx/BuildKit、固定 Alpine 基础镜像和 Dockerfile frontend、两份自有 Dockerfile、一次构建及其导出方式。secret 内容不参与 BuildKit 缓存键；故本实验不推断缓存复用行为。若某条构建指令故意复制、打印或派生 secret，挂载机制本身不会阻止泄漏。弱例为自造不安全基线，**不是** BuildKit 漏洞；本项目也不能证明任意镜像或生产秘密安全。

在有 Docker daemon 与 Buildx 的受控 Linux 环境中，从发行仓根目录运行：

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m build_secret_mount_lifetime_gate --build-root Build
```

程序在权限 `0700` 的 `Build/BuildSecretMountLifetimeGate-raw/<run-id>/` 纯 ASCII 临时目录中处理原始导出，只把不含合成值的回执留在 `Build/验证/BuildSecretMountLifetimeGate-<run-id>/receipt.json`；执行完成即删除合成值文件、弱/强原始镜像、文件导出、缓存及元数据。不得上传弱镜像、合成值或原始构建日志，失败时仅记日志 SHA-256 和固定错误原因。当前 GitHub 工作流对 PR 的默认步骤只解析 Python 语法、不导入提交的代码；可信 `main`/`v*` 推送或手动选中这些 ref 才按当前工作流运行单元测试和真实构建。**PR 可修改工作流本身，且托管 runner 可能有 Docker/sudo；这不是 PR 低权限沙箱。** 仓库远端保护规则仍需另行核查。

共享工作区源码位于 `项目源码/当前项目/research-cvp30-c-20261005/BuildSecretMountLifetimeGate`，文档位于同组 `项目文档`。独立仓库把这些源码放在仓根的 `src/`、`tests/` 等原有路径，文档放在 `项目文档/`；运行输出只在该仓根 `Build/`。发行镜像/缓存均不是仓库源码。

[设计与验证边界](VALIDATION.md) · [来源与权利](THIRD_PARTY_NOTICES.md) · [版本状态](VERSION_STATUS.md)
