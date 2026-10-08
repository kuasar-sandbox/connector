package vswitch

import (
	"errors"
	"github.com/kuasar-sandbox/connector/pkg/internal/bpf"
	"net"
	"sync/atomic"
	"testing"
)

func TestDeferredAttachAndSetPortUp(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{GenerationBits: 4}, true)
	var writes int
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, _ *GeneveOptsValue) error { writes++; return nil }
	out, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.1"), Generation: 3, AdminDown: true, SkipDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	if out.Port != 1 || atomic.LoadUint32(&slots.GetSlot(0).Flags) != 0 {
		t.Fatal("deferred attach not down")
	}
	before := slots.GetSlot(0).Generation
	if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
	if slots.GetInnerIP(0) != bpf.IPToUint32(net.ParseIP("10.0.0.2")) || slots.GetSlot(0).Flags != PortFUp {
		t.Fatal("final publication failed")
	}
	if slots.GetSlot(0).Generation != before || writes != 2 {
		t.Fatalf("identity changed or options not overwritten: gen=%d writes=%d", slots.GetSlot(0).Generation, writes)
	}
	if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.3")}); err == nil {
		t.Fatal("up port accepted second commit")
	}
	if err := s.Detach(DetachOptions{Port: 1, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
}
func TestSetPortUpFailureRemainsDownAndRetryable(t *testing.T) {
	defer resetDeps()
	s, slots := newGeneveAttachTestContext(&SwitchConfig{}, true)
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, _ *GeneveOptsValue) error { return nil }
	if _, err := s.Attach(AttachOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.1"), AdminDown: true, SkipDevice: true}); err != nil {
		t.Fatal(err)
	}
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, _ *GeneveOptsValue) error { return errors.New("injected failure") }
	if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2")}); err == nil {
		t.Fatal("expected failure")
	}
	if slots.GetInnerIP(0) != bpf.IPToUint32(net.ParseIP("10.0.0.1")) || slots.GetSlot(0).Flags != 0 {
		t.Fatal("failure published state")
	}
	writeGeneveOptsFn = func(_ BPFMap, _ uint32, _ *GeneveOptsValue) error { return nil }
	if err := s.SetPortUp(PortUpOptions{Port: 1, InnerIP: net.ParseIP("10.0.0.2")}); err != nil {
		t.Fatal(err)
	}
}
