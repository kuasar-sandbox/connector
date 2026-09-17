#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=notify_helpers.sh
source "$SCRIPT_DIR/notify_helpers.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/connector-notify-test.XXXXXX")
receiver_pid=""
unrelated_pid=""
cleanup() {
    stop_owned_process "$receiver_pid"
    stop_owned_process "$unrelated_pid"
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

send() {
    python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(sys.argv[2].encode(), sys.argv[1])
PY
}

# A delayed bind proves the handshake blocks the sender until the socket exists.
start_notify_receiver "$tmp_dir/delayed.sock" "$tmp_dir/delayed.data" "$tmp_dir/delayed.ready" 0.2
receiver_pid=$NOTIFY_RECEIVER_PID
[ ! -e "$tmp_dir/delayed.ready" ]
wait_notify_receiver_ready "$tmp_dir/delayed.ready" "$receiver_pid" 2
send "$tmp_dir/delayed.sock" READY=1
sleep 0.1
has_single_ready_notification "$tmp_dir/delayed.data"
stop_owned_process "$receiver_pid"
receiver_pid=""

# Bind failure and a dead receiver must fail without waiting for the timeout.
mkdir "$tmp_dir/not-a-socket"
start_notify_receiver "$tmp_dir/not-a-socket" "$tmp_dir/fail.data" "$tmp_dir/fail.ready"
receiver_pid=$NOTIFY_RECEIVER_PID
if wait_notify_receiver_ready "$tmp_dir/fail.ready" "$receiver_pid" 2; then exit 1; fi
receiver_pid=""
(exit 1) & dead_pid=$!
wait "$dead_pid" || true
if wait_notify_receiver_ready "$tmp_dir/dead.ready" "$dead_pid" 2; then exit 1; fi

# STATUS does not satisfy READY, and duplicate READY notifications are rejected.
start_notify_receiver "$tmp_dir/data.sock" "$tmp_dir/data" "$tmp_dir/data.ready"
receiver_pid=$NOTIFY_RECEIVER_PID
wait_notify_receiver_ready "$tmp_dir/data.ready" "$receiver_pid" 2
send "$tmp_dir/data.sock" STATUS=waiting
sleep 0.1
if has_single_ready_notification "$tmp_dir/data"; then exit 1; fi
send "$tmp_dir/data.sock" READY=1
sleep 0.1
has_single_ready_notification "$tmp_dir/data"
send "$tmp_dir/data.sock" READY=1
sleep 0.1
if has_single_ready_notification "$tmp_dir/data"; then exit 1; fi

# Owned cleanup must not terminate an unrelated process or remove its resources.
sleep 30 & unrelated_pid=$!
touch "$tmp_dir/unrelated"
stop_owned_process "$receiver_pid"
receiver_pid=""
kill -0 "$unrelated_pid"
[ -e "$tmp_dir/unrelated" ]

# Signal handlers using the helper reap their owned child, preserve the shell's
# conventional status, and leave the unrelated process alone.
cat >"$tmp_dir/signal-fixture.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
sleep 30 & owned_pid=$!
echo "$owned_pid" >"$2"
trap 'stop_owned_process "$owned_pid"; exit 130' INT
trap 'stop_owned_process "$owned_pid"; exit 143' TERM
while :; do sleep 1; done
SH
python3 - "$tmp_dir/signal-fixture.sh" "$SCRIPT_DIR/notify_helpers.sh" "$tmp_dir" <<'PY'
import os
import signal
import subprocess
import sys
import time

fixture, helpers, tmp_dir = sys.argv[1:]
for sig, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
    pid_file = os.path.join(tmp_dir, f"owned.{sig.name}")
    process = subprocess.Popen(["bash", fixture, helpers, pid_file])
    deadline = time.monotonic() + 2
    while not os.path.exists(pid_file):
        if process.poll() is not None or time.monotonic() >= deadline:
            raise SystemExit("signal fixture did not start")
        time.sleep(0.01)
    process.send_signal(sig)
    if process.wait(timeout=2) != expected:
        raise SystemExit(f"wrong exit status for {sig.name}")
    owned_pid = int(open(pid_file, encoding="utf-8").read())
    try:
        os.kill(owned_pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise SystemExit(f"owned child survived {sig.name}")
PY
kill -0 "$unrelated_pid"

echo "notify helper tests: PASS"
