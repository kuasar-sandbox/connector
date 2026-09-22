#!/usr/bin/env python3
"""Release jobs consume the environment CLI without installing or selecting tools."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EnvironmentTools(unittest.TestCase):
    def cli_steps(self):
        steps = []
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            lines = workflow.read_text().splitlines()
            for index, line in enumerate(lines):
                if line.strip() != "- name: Check environment GitHub CLI":
                    continue
                self.assertEqual(lines[index + 1].strip(), "run: |")
                prefix = line[:len(line) - len(line.lstrip())] + "    "
                command = []
                for candidate in lines[index + 2:]:
                    if not candidate.startswith(prefix):
                        break
                    command.append(candidate[len(prefix):])
                steps.append("\n".join(command))
        self.assertTrue(steps, "release jobs must check their environment CLI")
        return set(steps)

    def test_cli_accepts_environment_versions_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "independent tools"
            tools.mkdir()
            cli = tools / "gh"
            for version in ("distro-build", "different-compatible-release"):
                cli.write_text("#!/bin/sh\n"
                               'if [ "$1:${2-}" = api:--help ]; then echo "  --slurp  collect pages"; exit 0; fi\n'
                               "echo " + version + "\n"
                               'printf "%s:%s\\n" "${GOTOOLCHAIN+x}" "${GOTOOLCHAIN-}" > "$OBSERVED"\n')
                cli.chmod(0o755)
                before = cli.read_bytes()
                for policy in (None, "local", "auto", "go1.99.1+path"):
                    env = dict(os.environ, PATH=str(tools), OBSERVED=str(root / "observed"),
                               GITHUB_PATH=str(root / "github-path"))
                    if policy is None:
                        env.pop("GOTOOLCHAIN", None)
                    else:
                        env["GOTOOLCHAIN"] = policy
                    for command in self.cli_steps():
                        result = subprocess.run([shutil.which("bash"), "-e", "-c", command],
                                                env=env, text=True, capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), version)
                    self.assertEqual((root / "observed").read_text().strip(),
                                     ":" if policy is None else "x:" + policy)
                    self.assertEqual(cli.read_bytes(), before)
                    self.assertFalse((root / "github-path").exists())

    def test_missing_cli_fails_without_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            for command in self.cli_steps():
                result = subprocess.run([shutil.which("bash"), "-e", "-c", command],
                                        env=dict(os.environ, PATH=directory),
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("gh", result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_incompatible_cli_fails_before_any_remote_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "gh"
            cli.write_text('#!/bin/sh\n'
                           'case "$1:${2-}" in --version:) echo old-distro-gh;; '
                           'api:--help) echo "  --paginate";; '
                           '*) echo REMOTE_OPERATION; exit 77;; esac\n')
            cli.chmod(0o755)
            for command in self.cli_steps():
                result = subprocess.run([shutil.which("bash"), "-e", "-c", command],
                                        env=dict(os.environ, PATH=directory),
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must support api --slurp", result.stderr)
                self.assertNotIn("REMOTE_OPERATION", result.stdout)

    def test_release_jobs_do_not_pin_toolchain_policy_or_install_cli(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            source = workflow.read_text()
            self.assertNotIn("install-gh-cli.sh", source)
            self.assertNotIn("GOTOOLCHAIN: local", source)
        for directory in ("scripts", "release"):
            self.assertFalse((ROOT / directory / "install-gh-cli.sh").exists())


class ReleaseGoHandoff(unittest.TestCase):
    def test_release_children_use_selected_go_and_preserve_policy(self):
        lines = (ROOT / ".github/workflows/release.yml").read_text().splitlines()
        index = next(i for i, line in enumerate(lines)
                     if line.strip() == "- name: Build and test connector")
        self.assertEqual(lines[index + 1].strip(), "run: |")
        prefix = " " * (len(lines[index]) - len(lines[index].lstrip()) + 4)
        command = []
        for line in lines[index + 2:]:
            if not line.startswith(prefix):
                self.assertEqual(line.strip(), "working-directory: src/connector")
                break
            command.append(line[len(prefix):])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "launcher"
            selected = root / "selected compiler" / "bin"
            stale = root / "stale inherited root"
            module = root / "module"
            for path in (tools, selected, stale, module):
                path.mkdir(parents=True)
            scripts = {
                tools / "taskset": "#!/bin/sh\nexit 0\n",
                tools / "go": '''#!/bin/sh
[ "$PWD" = "$EXPECTED_MODULE" ] || exit 62
[ "$*" = "env GOROOT" ] || { echo 'go: no such tool "covdata"' >&2; exit 1; }
[ "$GO_RESOLVE_EXIT" = 0 ] || exit "$GO_RESOLVE_EXIT"
printf '%s\n' "$SELECTED_ROOT"
''',
                selected / "go": '''#!/bin/sh
[ "$*" = "tool covdata" ] || exit 63
''',
                tools / "make": '''#!/bin/sh
set -e
go tool covdata
printf '%s|%s|%s|%s\n' "$*" "${GOTOOLCHAIN-unset}" "${GOROOT-unset}" "$GOENV" >> "$OBSERVED"
''',
            }
            for path, source in scripts.items():
                path.write_text(source)
                path.chmod(0o755)
            for inherited_goroot in (None, str(stale)):
                for policy in (None, "local", "auto", "go1.99.1+path"):
                    for resolve_exit in (0, 73):
                        observed = root / "observed"
                        observed.unlink(missing_ok=True)
                        env = dict(os.environ, PATH=str(tools), TARGET_ARCH="x86_64",
                                   KUASAR_BUILD_CPUS="0", EXPECTED_MODULE=str(module),
                                   SELECTED_ROOT=str(selected.parent), OBSERVED=str(observed),
                                   GOENV=str(root / "environment-owned-config"),
                                   GO_RESOLVE_EXIT=str(resolve_exit))
                        if inherited_goroot is None:
                            env.pop("GOROOT", None)
                        else:
                            env["GOROOT"] = inherited_goroot
                        if policy is None:
                            env.pop("GOTOOLCHAIN", None)
                        else:
                            env["GOTOOLCHAIN"] = policy
                        with self.subTest(goroot=inherited_goroot, policy=policy, resolve_exit=resolve_exit):
                            result = subprocess.run([shutil.which("bash"), "-e", "-c", "\n".join(command)],
                                                    cwd=module, env=env, text=True,
                                                    capture_output=True, timeout=10)
                            self.assertEqual(result.returncode, resolve_exit, result.stderr)
                            if resolve_exit:
                                self.assertFalse(observed.exists())
                            else:
                                self.assertEqual(observed.read_text().splitlines(), [
                                    target + "|" + (policy or "unset") + "|" + str(selected.parent)
                                    + "|" + env["GOENV"]
                                    for target in ("test", "vet", "build")])


if __name__ == "__main__":
    unittest.main()
