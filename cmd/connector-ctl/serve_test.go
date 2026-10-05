package main

import "testing"

func TestServeExposesGenerationBitsFlag(t *testing.T) {
	f := serveCmd.Flags().Lookup("generation-bits")
	if f == nil || f.DefValue != "0" {
		t.Fatalf("generation-bits flag=%v", f)
	}
}
