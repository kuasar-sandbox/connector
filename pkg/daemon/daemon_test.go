package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// --- notify tests ---

func TestNotifyNoSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	// Should be a no-op, not panic
	NotifyReady()
	NotifyStatus("test")
	NotifyWatchdog()
}

func TestNotifyWithSocket(t *testing.T) {
	socketPath := fmt.Sprintf("%s/test-notify-%d.sock", t.TempDir(), os.Getpid())

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("NOTIFY_SOCKET", socketPath)

	NotifyReady()

	buf := make([]byte, 128)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from socket: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("got %q, want READY=1", got)
	}
}

func TestNotifyStatusMessage(t *testing.T) {
	socketPath := fmt.Sprintf("%s/test-status-%d.sock", t.TempDir(), os.Getpid())

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("NOTIFY_SOCKET", socketPath)

	NotifyStatus("healthy")

	buf := make([]byte, 128)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read from socket: %v", err)
	}
	if got := string(buf[:n]); got != "STATUS=healthy" {
		t.Errorf("got %q, want STATUS=healthy", got)
	}
}

// --- WatchdogEnabled tests ---

func TestWatchdogEnabled(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		wantInterval time.Duration
		wantOK       bool
	}{
		{"empty", "", 0, false},
		{"valid 60s", "60000000", 30 * time.Second, true},
		{"valid 2s", "2000000", 1 * time.Second, true},
		{"clamped to min", "100", 1 * time.Second, true},
		{"zero", "0", 0, false},
		{"negative", "-1", 0, false},
		{"invalid", "abc", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WATCHDOG_USEC", tt.envValue)
			interval, ok := WatchdogEnabled()
			if ok != tt.wantOK {
				t.Errorf("WatchdogEnabled() ok = %v, want %v", ok, tt.wantOK)
			}
			if interval != tt.wantInterval {
				t.Errorf("WatchdogEnabled() interval = %v, want %v", interval, tt.wantInterval)
			}
		})
	}
}

// --- RunWatchdog tests ---

func TestRunWatchdogSendsKeepalive(t *testing.T) {
	socketPath := fmt.Sprintf("%s/test-wd-%d.sock", t.TempDir(), os.Getpid())

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("WATCHDOG_USEC", "2000000") // 2s → keepalive every 1s
	t.Setenv("NOTIFY_SOCKET", socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWatchdog(ctx)
		close(done)
	}()

	// Wait for at least one WATCHDOG=1
	buf := make([]byte, 128)
	gotWatchdog := false
	for i := 0; i < 20; i++ {
		_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) == "WATCHDOG=1" {
			gotWatchdog = true
			break
		}
	}

	cancel()
	<-done

	if !gotWatchdog {
		t.Error("expected at least one WATCHDOG=1 notification")
	}
}

func TestRunWatchdogNoEnv(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		RunWatchdog(ctx)
		close(done)
	}()

	select {
	case <-done:
		// RunWatchdog returned immediately — correct
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunWatchdog should return immediately without WATCHDOG_USEC")
	}
}

func TestRunWatchdogStopsOnCancel(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "2000000")
	t.Setenv("NOTIFY_SOCKET", "")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		RunWatchdog(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("RunWatchdog did not stop after context cancel")
	}
}

func TestRunWatchdogCallbackErrorSkipsWatchdog(t *testing.T) {
	socketPath := fmt.Sprintf("%s/test-cb-%d.sock", t.TempDir(), os.Getpid())

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("WATCHDOG_USEC", "2000000") // 2s → keepalive every 1s
	t.Setenv("NOTIFY_SOCKET", socketPath)

	failingCallback := func() error {
		return errors.New("check failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWatchdog(ctx, failingCallback)
		close(done)
	}()

	// Read messages — should get STATUS but NOT WATCHDOG=1
	buf := make([]byte, 256)
	gotWatchdog := false
	gotStatus := false
	for i := 0; i < 20; i++ {
		_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			continue
		}
		msg := string(buf[:n])
		if msg == "WATCHDOG=1" {
			gotWatchdog = true
		}
		if msg == "STATUS=check failed" {
			gotStatus = true
			break
		}
	}

	cancel()
	<-done

	if gotWatchdog {
		t.Error("WATCHDOG=1 should not be sent when callback fails")
	}
	if !gotStatus {
		t.Error("expected STATUS=check failed notification")
	}
}

func TestRunWatchdogCallbackSuccessSendsWatchdog(t *testing.T) {
	socketPath := fmt.Sprintf("%s/test-cbok-%d.sock", t.TempDir(), os.Getpid())

	listener, err := net.ListenPacket("unixgram", socketPath)
	if err != nil {
		t.Skipf("cannot create unixgram socket: %v", err)
	}
	defer listener.Close()

	t.Setenv("WATCHDOG_USEC", "2000000")
	t.Setenv("NOTIFY_SOCKET", socketPath)

	okCallback := func() error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWatchdog(ctx, okCallback)
		close(done)
	}()

	buf := make([]byte, 128)
	gotWatchdog := false
	for i := 0; i < 20; i++ {
		_ = listener.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := listener.ReadFrom(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) == "WATCHDOG=1" {
			gotWatchdog = true
			break
		}
	}

	cancel()
	<-done

	if !gotWatchdog {
		t.Error("expected WATCHDOG=1 when callback succeeds")
	}
}
