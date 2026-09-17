#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=notify_helpers.sh
source "$SCRIPT_DIR/notify_helpers.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/connector-notify-test.XXXXXX")
receiver_pid=""
unrelated_pid=""
cleanup() {
    stop_owned_process "$receiver_pid" || true
    stop_owned_process "$unrelated_pid" || true
    rm -rf "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

send() {
    python3 - "$1" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.sendto(sys.argv[2].encode(), sys.argv[1])
PY
}

wait_lines() {
    local output="$1" count="$2"
    for _ in $(seq 1 100); do
        if [ -f "$output" ] && [ "$(wc -l < "$output")" -ge "$count" ]; then return 0; fi
        sleep 0.02
    done
    echo "notification output did not reach $count datagrams" >&2
    return 1
}

# A delayed bind proves the handshake blocks the sender until the socket exists.
start_notify_receiver "$tmp_dir/delayed.sock" "$tmp_dir/delayed.data" "$tmp_dir/delayed.ready" 0.2
receiver_pid=$NOTIFY_RECEIVER_PID
[ ! -e "$tmp_dir/delayed.ready" ]
wait_notify_receiver_ready "$tmp_dir/delayed.ready" "$receiver_pid" 2
send "$tmp_dir/delayed.sock" READY=1
wait_lines "$tmp_dir/delayed.data" 1
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
wait_lines "$tmp_dir/data" 1
if has_single_ready_notification "$tmp_dir/data"; then exit 1; fi
send "$tmp_dir/data.sock" READY=1
wait_lines "$tmp_dir/data" 2
if has_single_ready_notification "$tmp_dir/data"; then exit 1; fi
send "$tmp_dir/data.sock" READY=1
wait_lines "$tmp_dir/data" 3
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

# Output failure must never publish readiness.
mkdir "$tmp_dir/output-is-directory"
start_notify_receiver "$tmp_dir/output-fail.sock" "$tmp_dir/output-is-directory" "$tmp_dir/output-fail.ready"
receiver_pid=$NOTIFY_RECEIVER_PID
if wait_notify_receiver_ready "$tmp_dir/output-fail.ready" "$receiver_pid" 2; then exit 1; fi
[ ! -e "$tmp_dir/output-fail.ready" ]
receiver_pid=""

# Preserve the complete stream: a late duplicate cannot pass the final check.
start_notify_receiver "$tmp_dir/final.sock" "$tmp_dir/final.data" "$tmp_dir/final.ready"
receiver_pid=$NOTIFY_RECEIVER_PID
wait_notify_receiver_ready "$tmp_dir/final.ready" "$receiver_pid" 2
send "$tmp_dir/final.sock" READY=1
wait_lines "$tmp_dir/final.data" 1
has_single_ready_notification "$tmp_dir/final.data"
send "$tmp_dir/final.sock" STATUS=ready
send "$tmp_dir/final.sock" READY=1
finish_notify_receiver "$tmp_dir/final.sock" "$receiver_pid"
receiver_pid=""
[ "$(wc -l < "$tmp_dir/final.data")" -eq 3 ]
if has_single_ready_notification "$tmp_dir/final.data"; then exit 1; fi

# A child refusing TERM is killed/reaped within the configured bound.
python3 - "$tmp_dir/stubborn.ready" <<'PY' &
import pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).touch()
while True: time.sleep(0.1)
PY
receiver_pid=$!
wait_notify_receiver_ready "$tmp_dir/stubborn.ready" "$receiver_pid" 2
if stop_owned_process "$receiver_pid"; then echo 'expected forced-shutdown failure' >&2; exit 1; fi
if kill -0 "$receiver_pid" 2>/dev/null; then exit 1; fi
receiver_pid=""

echo "notify helper tests: PASS"
