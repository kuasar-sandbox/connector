package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type mgmt_cidr -type exported_u32 -target amd64 vswitch ../../../bpf/switch_kern.c -- -I../../../bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type mgmt_cidr -type exported_u32 -target arm64 vswitch ../../../bpf/switch_kern.c -- -I../../../bpf
