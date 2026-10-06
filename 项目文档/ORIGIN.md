# 来源与自有范围

固定参考是 `moby/buildkit@106f55ce1f4a3ebb591780c7bcbb84a531f4395e`。本仓自写的 Python 扫描器、合成 Dockerfile 与工作流不复制、修改或替代上游 BuildKit 源码。维护者为 dhtfish98；上游 BuildKit 的作者与 Apache-2.0 权利保持原归属。

自建弱侧显式将 `ARG` 值写入 `ENV`，用作可复现的明文留存阳性对照；强侧只通过 `RUN` 的暂时挂载使用同一次性值。实验边界以 [VALIDATION](VALIDATION.md) 为准。
