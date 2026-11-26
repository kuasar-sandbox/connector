package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeStreamReplyFraming(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runner := newPipeRunner(client)
	go func() {
		reader := bufio.NewReader(server)
		for _, response := range []string{"{\"committed\":true}\n\x00", "\x00"} {
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
			for _, part := range strings.SplitAfter(response, "\n") {
				if _, err := io.WriteString(server, part); err != nil {
					return
				}
			}
		}
	}()
	reply, err := runner.Run(context.Background(), "egress-geneve commit")
	if err != nil || reply != "{\"committed\":true}" {
		t.Fatalf("reply=%q error=%v", reply, err)
	}
	reply, err = runner.Run(context.Background(), "egress-policy reset")
	if err != nil || reply != "" {
		t.Fatalf("empty acknowledgement=%q error=%v", reply, err)
	}
}

func TestNativeStreamLostAcknowledgementIsNotReused(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runner := newPipeRunner(client)
	read := make(chan struct{})
	go func() { _, _ = bufio.NewReader(server).ReadString('\n'); close(read) }()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-read; cancel() }()
	if _, err := runner.Run(ctx, "egress-geneve commit"); err == nil {
		t.Fatal("accepted an unacknowledged publication")
	}
	done := make(chan error, 1)
	go func() { _, err := runner.Run(context.Background(), "show egress-geneve"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reused an ambiguous stream")
		}
	case <-time.After(time.Second):
		t.Fatal("retry blocked on a poisoned stream")
	}
}

func TestNativeStreamRejectsInjectedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	runner := newPipeRunner(client)
	if _, err := runner.Run(context.Background(), "show version\nquit"); err == nil {
		t.Fatal("accepted multiple commands")
	}
}
