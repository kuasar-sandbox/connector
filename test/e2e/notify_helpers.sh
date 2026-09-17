#!/usr/bin/env bash

# Start a Unix datagram receiver. The ready file is created only after bind(2)
# succeeds, so callers can safely start a one-shot sd_notify sender afterwards.
start_notify_receiver() {
    local socket_path="$1" output_path="$2" ready_path="$3"
    local bind_delay="${4:-0}"

    python3 - "$socket_path" "$output_path" "$ready_path" "$bind_delay" <<'PY' &
import os
import socket
import sys
import time

socket_path, output_path, ready_path, bind_delay = sys.argv[1:]
time.sleep(float(bind_delay))
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.bind(socket_path)
with open(ready_path, "x"):
    pass
sock.settimeout(0.25)
try:
    with open(output_path, "a", encoding="utf-8") as output:
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            output.write(data.decode(errors="replace") + "\n")
            output.flush()
finally:
    sock.close()
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass
PY
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

stop_owned_process() {
    local pid="${1:-}"
    [ -n "$pid" ] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

has_single_ready_notification() {
    local output_path="$1"
    [ -f "$output_path" ] && [ "$(grep -cFx 'READY=1' "$output_path" || true)" -eq 1 ]
}
