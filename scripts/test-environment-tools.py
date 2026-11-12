#!/usr/bin/env python3
"""Release jobs consume the environment CLI without installing or selecting tools."""
import json
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

    def test_local_release_selects_its_own_go_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipe = (ROOT/'Makefile').read_text().split('\nrelease:\n', 1)[1].split('\n\n', 1)[0]
            (root/'Makefile').write_text(
                "SHELL := /bin/bash\nGO := go\nBUILD_DIR := build\nTARGET_ARCH := x86_64\n"
                "release:\n" + recipe + "\n.PHONY: build\nbuild:\n"
                "\t@go env GOWORK > build-env\n\t@go build -o checked .\n")
            (root/'go.mod').write_text('module example.com/release-fixture\n\ngo 1.20\n')
            (root/'main.go').write_text('package main\nfunc main() {}\n')
            (root/'go.work').write_text('invalid workspace supplied by the caller\n')
            (root/'scripts').mkdir()
            (root/'scripts/release.sh').write_text(
                'set -eu\n./checked\ngo env GOWORK > package-env\n'
                'if [[ "$GOWORK" != off ]]; then go work edit -json "$GOWORK" > selected.json; fi\n')
            for cmd in (['init', '-q'], ['add', '.'],
                        ['-c','user.name=test','-c','user.email=test@example.invalid','commit','-qm','fixture']):
                subprocess.run(['git', *cmd], cwd=root, check=True, capture_output=True)
            for version in ('v0.1.1', 'v0.1.2-preview.20261112'):
                with self.subTest(version=version):
                    result = subprocess.run(['make', 'release', 'VERSION='+version,
                                             'GOWORK='+str(root/'go.work')], cwd=root,
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    selected = (root/'build-env').read_text().strip()
                    self.assertEqual((root/'package-env').read_text().strip(), selected)
                    if '-preview.' in version:
                        work = Path(selected)
                        self.assertFalse(work.exists())
                        doc = json.loads((root/'selected.json').read_text())
                        self.assertEqual([(work.parent / use['DiskPath']).resolve() for use in doc['Use']], [root])
                        self.assertFalse(doc.get('Replace'))
                    else:
                        self.assertEqual(selected, 'off')

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
                     if line.strip() == "- name: Build, test and package connector")
        self.assertEqual(lines[index + 1].strip(), "uses: ./trusted/platform/.github/actions/workbench")
        run_index = next(i for i in range(index, len(lines)) if lines[i].strip() == "run: |")
        prefix = " " * (len(lines[run_index]) - len(lines[run_index].lstrip()) + 2)
        command = []
        for line in lines[run_index + 1:]:
            if not line.startswith(prefix) or line.lstrip().startswith("VERSION="):
                break
            command.append(line[len(prefix):])
        self.assertIn("cd connector", command)

        real_go = shutil.which("go")
        self.assertIsNotNone(real_go, "release validation requires the environment Go launcher")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "environment tools"
            stale = root / "stale inherited root"
            module = root / "connector"
            for path in (tools, stale, module):
                path.mkdir(parents=True)
            (tools / "go").symlink_to(real_go)
            helper = root / "go_workspace.py"
            helper.write_text("import os, sys\nfrom pathlib import Path\n"
                              "assert Path(os.environ['GOROOT'], 'bin/go').is_file()\nassert sys.argv[1:] == "
                              "['--root', '/src', '--owners', 'connector', '--bound-release', '--version', 'v0.1.1']\n"
                              "print('off')\n")
            command = "\n".join(command).replace("/inputs/release/ci/integration/go_workspace.py", str(helper))
            command = command.replace("${{ needs.preflight.outputs.version }}", "v0.1.1")
            scripts = {
                tools / "make": '''#!/bin/sh
set -e
[ "$GOWORK" = off ] || exit 63
[ "$(go env GOROOT)" = "$GOROOT" ] || exit 64
go tool compile -V=full >/dev/null
printf '%s|%s|%s|%s\n' "$*" "${GOTOOLCHAIN-unset}" "${GOROOT-unset}" "$GOENV" >> "$OBSERVED"
''',
            }
            for path, source in scripts.items():
                path.write_text(source)
                path.chmod(0o755)
            (module / "go.mod").write_text("module example.com/releasehandoff\n\ngo 1.20\n")
            goenv = root / "environment-owned-config"
            goenv.write_text("")
            path = str(tools) + os.pathsep + os.environ.get("PATH", "")

            for inherited_goroot in (None, str(stale)):
                for policy in (None, "local", "auto"):
                    observed = root / "observed"
                    observed.unlink(missing_ok=True)
                    github_env = root / "github-env"
                    github_path = root / "github-path"
                    github_env.unlink(missing_ok=True)
                    github_path.unlink(missing_ok=True)
                    env = dict(os.environ, PATH=path, TARGET_ARCH="x86_64", GOWORK=str(root/"bad.work"),
                               OBSERVED=str(observed),
                               GOENV=str(goenv), GITHUB_ENV=str(github_env),
                               GITHUB_PATH=str(github_path))
                    if inherited_goroot is None:
                        env.pop("GOROOT", None)
                    else:
                        env["GOROOT"] = inherited_goroot
                    if policy is None:
                        env.pop("GOTOOLCHAIN", None)
                    else:
                        env["GOTOOLCHAIN"] = policy
                    probe_env = dict(env)
                    probe_env.pop("GOROOT", None)
                    probe_env["GOWORK"] = "off"
                    expected = subprocess.run([real_go, "env", "GOROOT"], cwd=module,
                                              env=probe_env, text=True, capture_output=True,
                                              timeout=10, check=True).stdout.strip()
                    with self.subTest(goroot=inherited_goroot, policy=policy):
                        result = subprocess.run([shutil.which("bash"), "-e", "-c", command],
                                                cwd=root, env=env, text=True,
                                                capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(observed.read_text().splitlines(), [
                            target + "|" + (policy or "unset") + "|" + expected
                            + "|" + str(goenv)
                            for target in ("test", "vet", "build")])
                        self.assertFalse(github_env.exists(), "candidate must not change host Go environment")
                        self.assertFalse(github_path.exists(), "candidate must not change host PATH")

            observed = root / "observed"
            observed.unlink(missing_ok=True)
            github_env = root / "github-env"
            github_path = root / "github-path"
            github_env.unlink(missing_ok=True)
            github_path.unlink(missing_ok=True)
            env = dict(os.environ, PATH=path, TARGET_ARCH="x86_64", GOWORK=str(root/"bad.work"),
                       OBSERVED=str(observed),
                       GOENV=str(goenv), GOROOT=str(stale),
                       GOTOOLCHAIN="go9.99.9+path", GITHUB_ENV=str(github_env),
                       GITHUB_PATH=str(github_path))
            result = subprocess.run([shutil.which("bash"), "-e", "-c", command],
                                    cwd=root, env=env, text=True,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(observed.exists())
            self.assertFalse(github_env.exists())
            self.assertFalse(github_path.exists())



if __name__ == "__main__":
    unittest.main()
