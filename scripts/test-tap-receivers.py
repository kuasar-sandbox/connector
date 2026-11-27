#!/usr/bin/env python3
"""Exercise the TAP case's real Bash children and local Unix sockets.

These controls need no network namespace or TAP device. The prepared E2E case
still proves a real TUNGETIFF/IFF_VNET_HDR descriptor and an ARP round-trip.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "test/e2e/cases/network.tap.sh"
HELPERS = ROOT / "test/e2e/lib/notify_helpers.sh"
SOURCE = CASE.read_text()


def function(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\n", SOURCE, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing TAP case function: {name}")
    return match.group()


FUNCTIONS = "\n".join(function(name) for name in (
    "stop_tap_receiver", "wait_tap_receiver_ready", "join_tap_receiver",
    "setup", "teardown", "spawn_fd_receiver", "spawn_connectivity_probe",
    "test_t4_open_port_scm_rights", "test_t7_attach_open_port_combined",
    "test_t11_tap_connectivity",
))
CASES = (
    ("test_t4_open_port_scm_rights", "spawn_fd_receiver",
     "tap_name=swtap-t1 is_tap=True has_vnet_hdr=True meta_port=1 "
     "meta_mac=02:00:00:00:80:01 meta_ip=169.254.1.1 meta_fd=1"),
    ("test_t7_attach_open_port_combined", "spawn_fd_receiver",
     "tap_name=swtap-t4 is_tap=True has_vnet_hdr=True meta_port=4 "
     "meta_mac=02:00:00:00:80:01 meta_ip=169.254.4.1"),
    ("test_t11_tap_connectivity", "spawn_connectivity_probe",
     "connectivity=OK frames=1 arp_op=2 reply_sip=169.254.169.254"),
)


class TapReceiverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="tap-control-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def shell(self, body: str, *, env: dict[str, str] | None = None,
              timeout: float = 15, expected: int = 0) -> subprocess.CompletedProcess[str]:
        bootstrap = f"""set -euo pipefail
source {shlex.quote(str(HELPERS))}
TAP_TMP_DIR={shlex.quote(str(self.root))}
TAP_RECEIVER_PID=""
SW_NAME=swtap
SWITCH_BIN=true
PASS=0
FAIL=0
pass() {{ printf 'PASS: %s\\n' "$1"; PASS=$((PASS + 1)); }}
fail() {{ printf 'FAIL: %s\\n' "$1"; FAIL=$((FAIL + 1)); }}
{FUNCTIONS}
trap 'stop_tap_receiver >/dev/null 2>&1 || true' EXIT
"""
        process = subprocess.Popen(
            ["bash", "-c", bootstrap + body], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, **(env or {})), start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # This process group is created by this fixture and contains only
            # its own Bash/Python children; no process-name matching is used.
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            self.fail(f"fixture exceeded {timeout}s:\n{stdout}\n{stderr}")
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_join_requires_successful_child_exit(self) -> None:
        for status in (0, 19, 143):
            with self.subTest(status=status):
                self.shell("""
(exit "$CHILD_STATUS") &
TAP_RECEIVER_PID=$!
pid=$TAP_RECEIVER_PID
actual=0
join_tap_receiver || actual=$?
[ "$actual" -eq "$EXPECTED" ]
[ -z "$TAP_RECEIVER_PID" ]
! kill -0 "$pid" 2>/dev/null
""", env={"CHILD_STATUS": str(status), "EXPECTED": "0" if status == 0 else "1"})

    def test_readiness_failure_reaps_its_child(self) -> None:
        self.shell("""
(exit 19) &
TAP_RECEIVER_PID=$!
pid=$TAP_RECEIVER_PID
if wait_tap_receiver_ready "$TAP_TMP_DIR/not-ready"; then exit 80; fi
[ -z "$TAP_RECEIVER_PID" ]
! kill -0 "$pid" 2>/dev/null
""")

    def test_post_listen_marker_and_missing_descriptor_fail(self) -> None:
        for spawn in ("spawn_fd_receiver", "spawn_connectivity_probe"):
            with self.subTest(spawn=spawn):
                self.shell(f"""
{spawn} "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"
pid=$TAP_RECEIVER_PID
[ -S "$TAP_TMP_DIR/receiver.sock" ] && [ -f "$TAP_TMP_DIR/result.ready" ]
python3 - "$TAP_TMP_DIR/receiver.sock" <<'PY'
import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    client.sendall(b'port=1\\0')
PY
if join_tap_receiver; then exit 81; fi
grep -Fxq 'ERR no_fd_received' "$TAP_TMP_DIR/result"
[ -z "$TAP_RECEIVER_PID" ]
! kill -0 "$pid" 2>/dev/null
""")
                for item in self.root.iterdir():
                    item.unlink()

    def test_real_scm_rights_with_non_tap_descriptor_fails(self) -> None:
        for spawn in ("spawn_fd_receiver", "spawn_connectivity_probe"):
            with self.subTest(spawn=spawn):
                self.shell(f"""
{spawn} "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"
pid=$TAP_RECEIVER_PID
python3 - "$TAP_TMP_DIR/receiver.sock" <<'PY'
import array, os, socket, sys
fd = os.open('/dev/null', os.O_RDONLY)
try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(sys.argv[1])
        client.sendmsg([b'port=1 mac=02:00:00:00:80:01 ip=169.254.1.1\\0'],
                       [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
finally:
    os.close(fd)
PY
if join_tap_receiver; then exit 82; fi
grep -Fq 'ERR OSError' "$TAP_TMP_DIR/result"
! kill -0 "$pid" 2>/dev/null
""")
                for item in self.root.iterdir():
                    item.unlink()

    def test_accept_without_sender_is_bounded(self) -> None:
        started = time.monotonic()
        result = self.shell("""
spawn_fd_receiver "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"
pid=$TAP_RECEIVER_PID
if join_tap_receiver; then exit 83; fi
! kill -0 "$pid" 2>/dev/null
""", timeout=12)
        self.assertIn("TimeoutError", result.stderr)
        self.assertLess(time.monotonic() - started, 12)

    def test_connected_sender_without_payload_is_bounded(self) -> None:
        result = self.shell("""
spawn_connectivity_probe "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"
pid=$TAP_RECEIVER_PID
python3 - "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/connected" <<'PY' &
import pathlib, socket, sys, time
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    pathlib.Path(sys.argv[2]).touch()
    time.sleep(30)
PY
sender=$!
while [ ! -f "$TAP_TMP_DIR/connected" ]; do sleep 0.01; done
actual=0
join_tap_receiver || actual=$?
kill -TERM "$sender"
wait "$sender" 2>/dev/null || true
[ "$actual" -ne 0 ]
! kill -0 "$pid" 2>/dev/null
""", timeout=12)
        self.assertIn("TimeoutError", result.stderr)

    def test_stale_paths_and_active_child_are_not_replaced(self) -> None:
        for spawn in ("spawn_fd_receiver", "spawn_connectivity_probe"):
            for suffix in ("receiver.sock", "result", "result.ready"):
                with self.subTest(spawn=spawn, stale=suffix):
                    stale = self.root / suffix
                    stale.write_text("owned canary\n")
                    self.shell(f"""
if {spawn} "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"; then exit 84; fi
[ -z "$TAP_RECEIVER_PID" ]
""")
                    self.assertEqual(stale.read_text(), "owned canary\n")
                    stale.unlink()
        self.shell("""
sleep 30 &
TAP_RECEIVER_PID=$!
pid=$TAP_RECEIVER_PID
if spawn_fd_receiver "$TAP_TMP_DIR/receiver.sock" "$TAP_TMP_DIR/result"; then exit 85; fi
[ "$TAP_RECEIVER_PID" = "$pid" ]
kill -0 "$pid"
stop_tap_receiver
""")

    def test_cases_require_exit_and_original_payload_assertions(self) -> None:
        for case, spawn, good in CASES:
            for status, payload, expected in ((0, good, 0), (19, good, 1),
                                              (143, good, 1), (0, "ERR wrong payload", 1)):
                with self.subTest(case=case, status=status, payload=payload):
                    self.shell(f"""
{spawn}() {{
    (printf '%s' "$PAYLOAD" > "$2"; exit "$CHILD_STATUS") &
    TAP_RECEIVER_PID=$!
}}
{case}
[ "$FAIL" -eq "$EXPECTED" ]
[ -z "$TAP_RECEIVER_PID" ]
""", env={"PAYLOAD": payload, "CHILD_STATUS": str(status), "EXPECTED": str(expected)})

    def test_cli_failure_stops_owned_receiver(self) -> None:
        for case, spawn, _ in CASES:
            with self.subTest(case=case):
                self.shell(f"""
{spawn}() {{
    sleep 30 &
    TAP_RECEIVER_PID=$!
    RECEIVER_PID=$TAP_RECEIVER_PID
}}
SWITCH_BIN=false
{case}
[ "$FAIL" -eq 1 ]
[ -z "$TAP_RECEIVER_PID" ]
! kill -0 "$RECEIVER_PID" 2>/dev/null
""")

    def test_forced_cleanup_fails_and_leaves_unrelated_child_alive(self) -> None:
        self.shell("""
sleep 30 &
canary=$!
python3 - "$TAP_TMP_DIR/ignoring-term" <<'PY' &
import pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).touch()
time.sleep(30)
PY
TAP_RECEIVER_PID=$!
pid=$TAP_RECEIVER_PID
while [ ! -f "$TAP_TMP_DIR/ignoring-term" ]; do sleep 0.01; done
actual=0
stop_tap_receiver || actual=$?
alive=0
kill -0 "$canary" || alive=$?
kill -TERM "$canary"
wait "$canary" 2>/dev/null || true
[ "$actual" -ne 0 ] && [ "$alive" -eq 0 ]
[ -z "$TAP_RECEIVER_PID" ]
! kill -0 "$pid" 2>/dev/null
""", timeout=8)

    def test_teardown_preserves_primary_failure_and_rejects_failed_cleanup(self) -> None:
        for primary, stop, expected in ((0, 0, 0), (19, 0, 19), (0, 1, 1), (19, 1, 19)):
            with self.subTest(primary=primary, stop=stop):
                self.shell("""
ip() { :; }
stop_tap_receiver() { return "$STOP_STATUS"; }
TAP_TMP_DIR=""
trap teardown EXIT
exit "$PRIMARY_STATUS"
""", env={"PRIMARY_STATUS": str(primary), "STOP_STATUS": str(stop)}, expected=expected)

    def test_private_directory_cleanup_does_not_delete_foreign_names(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="tap_test_recv_control_", suffix=".sock",
                                         dir="/tmp") as canary:
            result = self.shell("""
ip() { :; }
TAP_TMP_DIR=""
trap teardown EXIT
setup
printf 'OWNED_PATH=%s\n' "$TAP_TMP_DIR"
[ "$(stat -c %a "$TAP_TMP_DIR")" = 700 ]
printf receiver > "$TAP_TMP_DIR/fd-t4.txt"
""")
            owned = next(line.removeprefix("OWNED_PATH=") for line in result.stdout.splitlines()
                         if line.startswith("OWNED_PATH="))
            self.assertFalse(Path(owned).exists())
            self.assertTrue(Path(canary.name).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
