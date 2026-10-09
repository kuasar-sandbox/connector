#!/usr/bin/env python3
"""Check real source-gate selection and fail-closed privilege requirements."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceChecks(unittest.TestCase):
    def run_gate(self, arguments=(), uid="0", fail=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "calls.jsonl"
            for tool in ("go", "bash", "python3", "id"):
                path = root / tool
                path.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
if name == 'id':
    print(os.environ['TEST_UID'])
    raise SystemExit(0)
with open(os.environ['CALLS'], 'a') as log:
    print(json.dumps([name, sys.argv[1:], os.environ.get('CGO_ENABLED')]), file=log)
if os.environ.get('FAIL_MATCH') and os.environ['FAIL_MATCH'] in ' '.join(sys.argv):
    raise SystemExit(73)
''')
                path.chmod(0o755)
            result = subprocess.run(["/bin/bash", str(ROOT / "scripts/ci-source-checks.sh"), *arguments],
                                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                                             CALLS=str(log), TEST_UID=uid, FAIL_MATCH=fail),
                                    text=True, capture_output=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_split_preserves_every_default_check(self):
        result, complete = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        result, ordinary = self.run_gate(("--ordinary",))
        self.assertEqual(result.returncode, 0, result.stderr)
        result, privileged = self.run_gate(("--privileged",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(complete, ordinary + privileged)
        self.assertTrue(any(call[0] == "bash" and call[1] == ["scripts/test-notify-helpers.sh"] for call in ordinary))
        self.assertTrue(any(call[0] == "go" and call[1] == ["vet", "./..."] for call in ordinary))
        race = next(call for call in ordinary if call[0] == "go" and call[1][0] == "test")
        self.assertEqual(race[1], ["test", "-race", "-count=1", "./pkg/vswitch", "./pkg/internal/bpfmap"])
        self.assertEqual(race[2], "1")
        self.assertEqual(len(privileged), 1)
        self.assertEqual(privileged[0], ["go", ["test", "-race", "-tags=integration", "-count=1", "-v",
                         "-exec", "env REQUIRE_CONNECTOR_STATS=1", "-run",
                         "TestNativeStatsReal|TestVerifyCurrentSwitchWithRealPinnedMaps", "./pkg/vswitch"], "1"])

    def test_nonroot_retains_sudo_and_required_real_bpf(self):
        result, calls = self.run_gate(("--privileged",), uid="1001")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sudo -n env REQUIRE_CONNECTOR_STATS=1", calls[0][1])

    def test_failures_propagate_without_running_later_checks(self):
        result, calls = self.run_gate(fail="-race")
        self.assertEqual(result.returncode, 73)
        self.assertFalse(any(call[0] == "go" and call[1][0] == "vet" for call in calls))
        self.assertFalse(any("-tags=integration" in call[1] for call in calls))
        result, _ = self.run_gate(("--privileged",), fail="-tags=integration")
        self.assertEqual(result.returncode, 73)

    def test_invalid_selection_fails_before_any_check(self):
        for arguments in (("--unknown",), ("--ordinary", "--privileged")):
            result, calls = self.run_gate(arguments)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
