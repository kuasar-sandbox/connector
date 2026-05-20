package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// MinWatchdogInterval is the minimum watchdog keepalive interval.
const MinWatchdogInterval = 1 * time.Second

// NotifyReady sends READY=1 to systemd (Type=notify service is ready).
func NotifyReady() {
	notify("READY=1")
}

// NotifyStatus sends STATUS=<msg> to systemd for display.
func NotifyStatus(msg string) {
	notify("STATUS=" + msg)
}

// NotifyWatchdog sends WATCHDOG=1 keepalive to systemd.
func NotifyWatchdog() {
	notify("WATCHDOG=1")
}

// WatchdogEnabled returns the watchdog keepalive interval and whether watchdog is enabled.
// Interval is WATCHDOG_USEC/2, clamped to MinWatchdogInterval.
func WatchdogEnabled() (interval time.Duration, ok bool) {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return 0, false
	}
	usec, err := strconv.Atoi(usecStr)
	if err != nil || usec <= 0 {
		return 0, false
	}
	interval = time.Duration(usec) * time.Microsecond / 2
	if interval < MinWatchdogInterval {
		interval = MinWatchdogInterval
	}
	return interval, true
}

// RunWatchdog runs the watchdog keepalive loop until ctx is cancelled.
// On each tick it calls optional callbacks first; only if all pass,
// sends WATCHDOG=1. If any callback returns error, reports via
// NotifyStatus but does NOT send WATCHDOG=1 (systemd will eventually restart).
// No callbacks = pure liveness (always sends WATCHDOG=1).
// No-op if WATCHDOG_USEC is not set.
func RunWatchdog(ctx context.Context, callbacks ...func() error) {
	interval, ok := WatchdogEnabled()
	if !ok {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			healthy := true
			for _, cb := range callbacks {
				if err := cb(); err != nil {
					NotifyStatus(err.Error())
					healthy = false
				}
			}
			if healthy {
				NotifyWatchdog()
			}
		}
	}
}

// notify sends a message to systemd via NOTIFY_SOCKET.
// No-op if NOTIFY_SOCKET is not set.
func notify(msg string) {
	socketAddr := os.Getenv("NOTIFY_SOCKET")
	if socketAddr == "" {
		return
	}
	conn, err := net.Dial("unixgram", socketAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] sd_notify failed: %v\n", err)
		return
	}
	defer conn.Close()
	if _, err = conn.Write([]byte(msg)); err != nil {
		fmt.Fprintf(os.Stderr, "[warn] sd_notify write failed: %v\n", err)
	}
}
