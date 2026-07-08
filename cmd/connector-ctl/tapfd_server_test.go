package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuasar-sandbox/connector/pkg/tapfd"
)

func TestTapFDServerRejectsSwitchMismatch(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tapfd.sock")
	srv, err := startTapFDServer(context.Background(), sock, "sw0", nil)
	if err != nil {
		t.Fatalf("startTapFDServer: %v", err)
	}
	defer srv.Close()

	conn, err := tapfd.ConnectUnix(sock)
	if err != nil {
		t.Fatalf("ConnectUnix: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("TAPFD/1 OPEN switch=other port=1\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _, _, err = tapfd.RecvFdsWithNetns(conn)
	if err == nil || !strings.Contains(err.Error(), tapfd.ErrorCodeSwitchMismatch) {
		t.Fatalf("RecvFdsWithNetns error = %v, want switch mismatch", err)
	}
}

func TestTapFDServerRejectsMalformedRequest(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tapfd.sock")
	srv, err := startTapFDServer(context.Background(), sock, "sw0", nil)
	if err != nil {
		t.Fatalf("startTapFDServer: %v", err)
	}
	defer srv.Close()

	conn, err := tapfd.ConnectUnix(sock)
	if err != nil {
		t.Fatalf("ConnectUnix: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("bad request\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _, _, err = tapfd.RecvFdsWithNetns(conn)
	if err == nil || !strings.Contains(err.Error(), tapfd.ErrorCodeBadRequest) {
		t.Fatalf("RecvFdsWithNetns error = %v, want bad request", err)
	}
}

func TestPrepareTapFDListenPathRejectsNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tapfd.sock")
	if err := os.WriteFile(path, []byte("not socket"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := prepareTapFDListenPath(path); err == nil {
		t.Fatalf("prepareTapFDListenPath: want error for non-socket path")
	}
}
