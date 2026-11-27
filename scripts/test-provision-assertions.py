#!/usr/bin/env python3
"""Exercise the production provision assertions with explicit CLI outcomes."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "test/e2e/cases/network.provision.sh"


def function(name):
    source = CASE.read_text()
    start = source.index(name + "() {")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


class ProvisionAssertionTests(unittest.TestCase):
    def check(self, function_name, command, code, output, *, stop_code=0):
        with tempfile.TemporaryDirectory(prefix="connector-provision-assert-") as directory:
            root = Path(directory)
            cli = root / "vswitch"
            cli.write_text("""#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$TRACE"
if [[ "$1" == "stop" ]]; then exit "$STOP_CODE"; fi
[[ "$1" == "$EXPECTED_COMMAND" ]]
printf '%s\\n' "$OUTPUT"
exit "$CODE"
""")
            cli.chmod(0o755)
            script = ("set -euo pipefail\n"
                      'PASS=0; FAIL=0; SW_NAME=sw1; SWITCH_BIN="$FAKE_CLI"\n'
                      'pass() { echo "PASS: $*"; PASS=$((PASS+1)); }\n'
                      'fail() { echo "FAIL: $*"; FAIL=$((FAIL+1)); }\n'
                      'start_switch() { :; }; stop_switch() { :; }\n' +
                      function(function_name) + "\n" + function_name + "\n" +
                      '[ "$FAIL" -eq 0 ]\n')
            env = dict(os.environ, FAKE_CLI=str(cli), TRACE=str(root / "trace"),
                       EXPECTED_COMMAND=command, CODE=str(code), OUTPUT=output,
                       STOP_CODE=str(stop_code))
            result = subprocess.run(["bash", "-c", script], env=env,
                                    text=True, capture_output=True, timeout=3)
            self.assertIn(command, (root / "trace").read_text())
            return result

    def test_missing_port_requires_exit_one_and_its_actual_diagnostic(self):
        for code, output, accepted in [
            (1, "Error: --port is required\nUsage: reserve\n--port is required", True),
            (0, "--port is required", False),
            (1, "operation not permitted", False),
            (3, "--port is required", False),
            (42, "--port is required", False),
        ]:
            with self.subTest(code=code, output=output):
                result = self.check("test_c4_reserve_missing_port", "reserve", code, output)
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_stopped_status_requires_exact_exit_three(self):
        for code in (0, 1, 3, 4, 42):
            with self.subTest(code=code):
                result = self.check("test_d1_normal_stop", "status", code,
                                    "Switch sw1 is not running")
                self.assertEqual(result.returncode == 0, code == 3, result.stdout + result.stderr)

    def test_a_failed_stop_cannot_be_hidden_by_missing_status(self):
        result = self.check("test_d1_normal_stop", "status", 3,
                            "Switch sw1 is not running", stop_code=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("D1: stop failed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
