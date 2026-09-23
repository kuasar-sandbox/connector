#!/usr/bin/env bash

# Start a Unix datagram receiver. The ready file is created only after bind(2)
# succeeds, so callers can safely start a one-shot sd_notify sender afterwards.
start_notify_receiver() {
    local socket_path="$1" output_path="$2" ready_path="$3"
    local bind_delay="${4:-0}"

    python3 - "$socket_path" "$output_path" "$ready_path" "$bind_delay" <<'PY' &
import os
import json
import socket
import sys
import time

socket_path, output_path, ready_path, bind_delay = sys.argv[1:]
time.sleep(float(bind_delay))
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.bind(socket_path)
sock.settimeout(0.25)
try:
    with open(output_path, "a", encoding="utf-8") as output:
        with open(ready_path, "x"):
            pass
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            if data == b"\x00kuasar-notify-finished\x00":
                break
            output.write(json.dumps(data.decode(errors="replace")) + "\n")
            output.flush()
finally:
    sock.close()
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
PY
    # Public output used by the caller that owns and waits for this child.
    # shellcheck disable=SC2034
    NOTIFY_RECEIVER_PID=$!
}

# Wait at most timeout seconds for the post-bind marker, failing immediately if
# the receiver exits (for example because bind failed).
wait_notify_receiver_ready() {
    local ready_path="$1" receiver_pid="$2" timeout="${3:-5}"
    local deadline=$((SECONDS + timeout))

    while [ ! -e "$ready_path" ]; do
        if ! kill -0 "$receiver_pid" 2>/dev/null; then
            wait "$receiver_pid" 2>/dev/null || true
            return 1
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            return 1
        fi
        sleep 0.05
    done
    kill -0 "$receiver_pid" 2>/dev/null
}

# Wait for a known child only. Escalate after a bounded graceful shutdown.
wait_owned_process() {
    local pid="$1" status=0
    for _ in $(seq 1 100); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.02
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 1
    fi
    wait "$pid" 2>/dev/null || status=$?
    [ "$status" -eq 0 ] || [ "$status" -eq 143 ]
}

stop_owned_process() {
    local pid="${1:-}"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    wait_owned_process "$pid"
}

# Called only after the sender has exited, so the sentinel follows all its data.
finish_notify_receiver() {
    local socket_path="$1" receiver_pid="$2"
    python3 - "$socket_path" <<'PY'
import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
    sender.settimeout(2)
    sender.sendto(b"\x00kuasar-notify-finished\x00", sys.argv[1])
PY
    wait_owned_process "$receiver_pid"
}

has_single_ready_notification() {
    python3 - "$1" <<'PY'
import json, pathlib, sys
try:
    lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
    messages = [json.loads(line) for line in lines]
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if messages and messages[0] == "READY=1" and messages.count("READY=1") == 1 else 1)
PY
}
