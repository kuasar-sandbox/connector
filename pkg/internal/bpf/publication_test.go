package bpf

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// Verify the instructions, not just C source order. The publication load must
// reach every dependent address unchanged, and DNAT must load InnerIP afterwards.
// This check also runs against the kernel's rewritten instruction stream.
func checkPublicationDependencies(name string, insns asm.Instructions) error {
	want := map[string]int{"tc_ingress_nx": 1, "tc_ingress_mx": 2, "tc_ingress_transit": 1}[name]
	var gates []int
	for i, in := range insns {
		// New fetch-atomic operations must not raise the Linux 5.10 baseline.
		if (uint8(in.OpCode) == 0xc3 || uint8(in.OpCode) == 0xdb) && in.Constant != 0 {
			return fmt.Errorf("%s instruction %d needs post-5.10 BPF atomics", name, i)
		}
		if uint8(in.OpCode) == 0x61 && in.Offset == 60 && i+1 < len(insns) {
			mask := insns[i+1]
			if uint8(mask.OpCode) == 0x57 && mask.Dst == in.Dst && mask.Constant == 1 {
				gates = append(gates, i)
			}
		}
	}
	if len(gates) != want {
		return fmt.Errorf("%s: %d publication loads, want %d", name, len(gates), want)
	}
	for n, g := range gates {
		base, token := insns[g].Src, insns[g].Dst
		dep := -1
		branched := false
		for j := g + 2; j+1 < len(insns) && j <= g+12; j++ {
			in := insns[j]
			// The signed comparison refines [0,1] to [1,1] even on 5.10.
			if (uint8(in.OpCode) == 0xd5 && in.Dst == token && in.Constant == 0) ||
				(uint8(in.OpCode) == 0xc5 && in.Dst == token && in.Constant == 1) {
				branched = true
			}
			if uint8(in.OpCode) == 0x6d && in.Src == token && j > 0 {
				prev := insns[j-1]
				if uint8(prev.OpCode) == 0xb7 && prev.Dst == in.Dst && prev.Constant == 1 {
					branched = true
				}
			}
			if uint8(in.OpCode) == 0x0f && in.Dst == base && in.Src == token {
				next := insns[j+1]
				if uint8(next.OpCode) == 0x07 && next.Dst == base && next.Constant == -1 {
					dep = j + 1
					break
				}
			}
		}
		if !branched || dep < 0 {
			return fmt.Errorf("%s gate %d lost load/branch/address dependency", name, n)
		}
		if name == "tc_ingress_mx" && n == len(gates)-1 {
			fresh := false
			for j := dep + 1; j < len(insns) && j <= dep+16; j++ {
				in := insns[j]
				if uint8(in.OpCode) == 0x61 && in.Src == base && in.Offset == 4 {
					fresh = true
					break
				}
			}
			if !fresh {
				return fmt.Errorf("management DNAT lacks a dependent post-up InnerIP read")
			}
		}
		if name == "tc_ingress_nx" {
			// geneve_opts is a separate allocation: a slot-only dependency
			// cannot order its loads. It must use the same publication token.
			options := false
			for j := dep + 1; j+2 < len(insns); j++ {
				in, next := insns[j], insns[j+1]
				if uint8(in.OpCode) == 0x0f && in.Src == token && in.Dst == asm.R0 &&
					uint8(next.OpCode) == 0x07 && next.Dst == asm.R0 && next.Constant == -1 &&
					uint8(insns[j+2].OpCode) == 0x71 && insns[j+2].Src == asm.R0 {
					options = true
					break
				}
			}
			if !options {
				return fmt.Errorf("sandbox egress lacks dependent options-map reads")
			}
		}
	}
	return nil
}

func TestPublicationDependencyInstructions(t *testing.T) {
	spec, err := loadVswitch()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tc_ingress_nx", "tc_ingress_mx", "tc_ingress_transit"} {
		p := spec.Programs[name]
		if p == nil {
			t.Fatalf("missing %s", name)
		}
		if err := checkPublicationDependencies(name, p.Instructions); err != nil {
			t.Fatal(err)
		}
	}
}
