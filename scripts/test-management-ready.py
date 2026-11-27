#!/usr/bin/env python3
"""Run the actual management backend shell functions against loopback controls."""
from pathlib import Path
import os
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "test/e2e/cases/network.management.sh"
HELPERS = ROOT / "test/e2e/lib/notify_helpers.sh"


def function(name):
    text = CASE.read_text()
    start = text.index(name + "() {")
    end = text.index("\n}\n", start) + 3
    return text[start:end]


class ManagementReadyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="connector-management-source-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.ip = self.bin / "ip"
        self.ip.write_text("""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "netns exec" ]]; then
    shift 3
    if [[ "${BACKEND_CONTROL:-}" == "exit" ]]; then exit 23; fi
    if [[ "${BACKEND_CONTROL:-}" == "delayed" ]]; then sleep 0.15; fi
    if [[ "${BACKEND_CONTROL:-}" == "ignoreterm" ]]; then trap '' TERM; fi
    exec "$@"
fi
[[ "$1 $2" == "netns del" ]]
""")
        self.ip.chmod(0o755)

    def run_case(self, port, control="", failure=0):
        script = ("set -euo pipefail\n"
                  'source "$SOURCE_HELPERS"\n'
                  'SVC_PID=""; SVC_TMP_DIR=""; SWITCH_BIN=true; SW_NAME=sw1\n'
                  'SVC_TARGET=127.0.0.1; SVC_TARGET_PORT="$TEST_PORT"\n' +
                  function("start_service_backend") + "\n" + function("teardown") + "\n" +
                  'trap teardown EXIT\n'
                  'start_service_backend\n'
                  'printf "%s\\n" "$SVC_PID" > "$TEST_ROOT/pid"\n'
                  'printf "%s\\n" "$SVC_TMP_DIR" > "$TEST_ROOT/temporary"\n'
                  "python3 - \"$TEST_PORT\" <<'PY'\n"
                  "import socket,sys\n"
                  "with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=2) as s:\n"
                  " assert s.recv(3)==b'OK\\n'\n"
                  "PY\n"
                  f"exit {failure}\n")
        env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                   SOURCE_HELPERS=str(HELPERS), TEST_ROOT=str(self.root),
                   TEST_PORT=str(port), BACKEND_CONTROL=control, TMPDIR=str(self.root))
        result = subprocess.run(["bash", "-c", script], env=env,
                                text=True, capture_output=True, timeout=12)
        if (self.root / "pid").exists():
            pid = int((self.root / "pid").read_text())
            self.assertFalse(Path(f"/proc/{pid}").exists(), result.stderr)
        self.assertEqual(list(self.root.glob("connector-management.*")), [])
        return result

    def available_port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def test_real_post_listen_ready_and_owned_cleanup(self):
        result = self.run_case(self.available_port())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_delayed_child_still_uses_actual_readiness(self):
        result = self.run_case(self.available_port(), "delayed")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bind_collision_fails_instead_of_accepting_foreign_listener(self):
        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", 0))
            foreign.listen(1)
            result = self.run_case(foreign.getsockname()[1])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("management backend exited or did not listen", result.stderr)
            self.assertNotEqual(foreign.fileno(), -1)

    def test_child_exit_before_ready_fails(self):
        result = self.run_case(self.available_port(), "exit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("management backend exited or did not listen", result.stderr)

    def test_forced_cleanup_cannot_turn_a_case_green(self):
        result = self.run_case(self.available_port(), "ignoreterm")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("management backend did not exit cleanly", result.stderr)

    def test_cleanup_preserves_original_failure(self):
        result = self.run_case(self.available_port(), failure=19)
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
