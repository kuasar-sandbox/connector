[English](LICENSE_SCOPE.md) | [简体中文](LICENSE_SCOPE_zh.md)

<a id="许可证范围"></a>

# License scope

Except for the files and artifacts below, project-original content in this repository without a separate license declaration uses the root Apache License 2.0.

<a id="ebpf-程序"></a>

## eBPF programs

- `bpf/switch_kern.c` uses GPL-2.0-only; its first-line SPDX identifier is the authoritative declaration.
- `pkg/internal/bpf/vswitch_arm64_bpfel.o` and `pkg/internal/bpf/vswitch_x86_bpfel.o` are compiled from that GPL source and identified as GPL-2.0-only in this repository. Adjacent `.license` files provide machine-readable mappings.
- Other project-original BPF support files without separate declarations use the root Apache-2.0 license. This does not change the GPL-2.0-only identification of BPF objects produced with `switch_kern.c`.

The full GPL-2.0-only text is in [LICENSES/GPL-2.0-only.txt](LICENSES/GPL-2.0-only.txt). The root `LICENSE` does not relicense these GPL files or artifacts.

Dependencies referenced through Go modules but not copied into this repository retain their respective upstream licenses.
