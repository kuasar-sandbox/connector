[English](LICENSE_SCOPE.md) | [简体中文](LICENSE_SCOPE_zh.md)

# 许可证范围

除下述文件和产物外,本仓库中未另行声明许可证的项目原创内容适用根目录的 Apache License 2.0.

## eBPF 程序

- `bpf/switch_kern.c` 适用 GPL-2.0-only,其首行 SPDX 标识是权威声明.
- `pkg/internal/bpf/vswitch_arm64_bpfel.o` 和 `pkg/internal/bpf/vswitch_x86_bpfel.o` 由上述 GPL 源文件编译生成,在本仓库中按 GPL-2.0-only 标识.相邻的 `.license` 文件提供机器可读映射.
- 其余未另行声明许可证的项目原创 BPF 支持文件适用根目录的 Apache-2.0.这不改变包含 `switch_kern.c` 后生成的 BPF 对象的 GPL-2.0-only 标识.

GPL-2.0-only 全文见 [`LICENSES/GPL-2.0-only.txt`](LICENSES/GPL-2.0-only.txt).根目录 `LICENSE` 不会重新许可上述 GPL 文件或产物.

通过 Go module 引用但未复制进本仓库的依赖继续适用其各自的上游许可证.
