package bpf

import "testing"

// Packet tests validate stable configurations; inspect generated instructions as
// well so a compiler cannot silently reuse a pre-up InnerIP during A->B commit.
func TestPublicationAcquireInstructions(t *testing.T) {
	spec, err := loadVswitch()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"tc_ingress_nx": 1, "tc_ingress_mx": 2, "tc_ingress_transit": 1} {
		program := spec.Programs[name]
		if program == nil {
			t.Fatalf("missing %s", name)
		}
		var gates []int
		for i, in := range program.Instructions {
			// BPF_STX|BPF_ATOMIC|BPF_W, OR|FETCH, slot.flags offset 60.
			if uint8(in.OpCode) == 0xc3 && in.Constant == 0x41 && in.Offset == 60 {
				gates = append(gates, i)
			}
		}
		if len(gates) != want {
			t.Fatalf("%s has %d acquire publication gates; want %d", name, len(gates), want)
		}
		if name != "tc_ingress_mx" {
			continue
		}
		gate := gates[len(gates)-1]
		slotRegister := program.Instructions[gate].Dst
		reloaded := false
		for i := gate + 1; i < len(program.Instructions) && i <= gate+16; i++ {
			in := program.Instructions[i]
			// BPF_LDX|BPF_MEM|BPF_W loads the final InnerIP after flags acquire.
			if uint8(in.OpCode) == 0x61 && in.Src == slotRegister && in.Offset == 4 {
				reloaded = true
				break
			}
		}
		if !reloaded {
			t.Fatal("management DNAT lacks a fresh InnerIP read after the publication acquire")
		}
	}
}
