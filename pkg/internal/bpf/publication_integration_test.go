//go:build integration

package bpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// The verifier may rewrite pointer arithmetic. Require the actual loaded
// instruction stream to retain the dependency, not only the clang output.
func TestPublicationLoadedDependencies(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for loaded BPF instructions")
	}
	objs, err := LoadObjects()
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}
	defer objs.Close()
	for name, p := range map[string]*ebpf.Program{
		"tc_ingress_nx":      objs.Programs.IngressNX,
		"tc_ingress_mx":      objs.Programs.IngressMX,
		"tc_ingress_transit": objs.Programs.IngressTransit,
	} {
		info, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		insns, err := info.Instructions()
		if err != nil {
			t.Fatal(err)
		}
		if err := checkPublicationDependencies(name, insns); err != nil {
			t.Fatal(err)
		}
		// Optional evidence for native JIT inspection; never required in CI.
		if d := os.Getenv("CONNECTOR_PUBLICATION_DUMP"); d != "" {
			code, ok := info.JitedInsns()
			if !ok || len(code) == 0 {
				t.Fatal("JIT bytecode unavailable")
			}
			if err := os.MkdirAll(d, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d, name+".bin"), code, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
