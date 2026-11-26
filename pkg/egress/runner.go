package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// pipeRunner owns an unnamed parent/child duplex stream, with no listener or
// filesystem endpoint. Native noninteractive CLI replies end with NUL.
type pipeRunner struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	failed error
}

func newPipeRunner(conn net.Conn) *pipeRunner {
	return &pipeRunner{conn: conn, reader: bufio.NewReader(conn)}
}
func (p *pipeRunner) Run(ctx context.Context, command string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed != nil {
		return "", p.failed
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.ContainsAny(command, "\r\n\x00") {
		return "", errors.New("invalid native command framing")
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.conn.SetDeadline(deadline); err != nil {
		p.failed = err
		return "", err
	}
	stop := context.AfterFunc(ctx, func() { p.conn.Close() })
	defer stop()
	if _, err := io.WriteString(p.conn, command+"\n"); err != nil {
		p.failed = err
		return "", err
	}
	text, err := p.reader.ReadString(0)
	if err != nil {
		p.failed = fmt.Errorf("native process stream: %w", err)
		return "", p.failed
	}
	return strings.TrimSpace(strings.TrimSuffix(text, "\x00")), nil
}

// Failure reports a permanently unusable stream, including failures from
// read-only diagnostics. A later command cannot resynchronize that stream.
func (p *pipeRunner) Failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failed
}
