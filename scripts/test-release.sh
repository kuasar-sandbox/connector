#!/usr/bin/env bash

set -euo pipefail

# This suite compiles private synthetic modules; product source gates select
# their own verified workspace outside these standalone packaging fixtures.
export GOWORK=off

# Archive fixtures target x86_64 even when this gate runs on an ARM host.
# Validators run natively; payload fixtures are inspected, never executed.

# Keep this offline fixture's checksum routing and local-only Go isolation.
export GOSUMDB=sum.golang.google.cn GOTOOLCHAIN=local

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() {
  echo "test-release: $*" >&2
  exit 1
}

# shellcheck source=scripts/release-materials.sh
source "$ROOT/scripts/release-materials.sh"

bash "$ROOT/scripts/test-release-materials.sh"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test-selected-go-materials.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test-release-go-environment.py"
bash "$ROOT/scripts/test-release-license-traversal.sh"

init_fixture_repo() {
  local directory="$1"
  shift
  git -C "$directory" init -q
  git -C "$directory" config --local user.name "Chen Xiaohui"
  git -C "$directory" config --local user.email "graych@gmail.com"
  git -C "$directory" add -- "$@"
  git -C "$directory" commit -q -m "test: create release source fixture"
  git -C "$directory" rev-parse HEAD
}

mkdir -p "$TMP/git-source"
printf 'fixture license\n' > "$TMP/git-source/LICENSE"
fixture_git_sha="$(init_fixture_repo "$TMP/git-source" LICENSE)"
[ "$(release_materials_git_version "$TMP/git-source" v1.2.3 "$fixture_git_sha")" = "git:$fixture_git_sha" ] \
  || fail "untagged source was recorded as a component release"
git -C "$TMP/git-source" tag v1.2.3 "$fixture_git_sha"
[ "$(release_materials_git_version "$TMP/git-source" v1.2.3 "$fixture_git_sha")" = v1.2.3 ] \
  || fail "matching source tag was not retained"
if (release_materials_git_version "$TMP/git-source" v1.2.3 \
  0000000000000000000000000000000000000000 >/dev/null 2>&1); then
  fail "source version resolver accepted a tag for another commit"
fi
[ "$(release_materials_resolve_git_source "$TMP/git-source" "$fixture_git_sha" fixture)" = "$fixture_git_sha" ] \
  || fail "clean source worktree did not resolve to its selected commit"
if (release_materials_resolve_git_source "$TMP/git-source" \
  0000000000000000000000000000000000000000 fixture >/dev/null 2>&1); then
  fail "source resolver accepted a commit that differs from the selected commit"
fi
printf 'untracked source\n' > "$TMP/git-source/untracked.go"
if (release_materials_resolve_git_source "$TMP/git-source" "" fixture >/dev/null 2>&1); then
  fail "source resolver accepted a dirty source worktree"
fi
printf 'LICENSE.generated\n' > "$TMP/git-source/.git/info/exclude"
printf 'ignored material\n' > "$TMP/git-source/LICENSE.generated"
if (
  release_materials_init "$TMP/ignored-material/stage" "$TMP/ignored-material/work" fixture
  release_materials_copy_licenses "$TMP/git-source" project >/dev/null 2>&1
); then
  fail "license collection accepted material absent from the selected commit"
fi
# Package validation checks actual paths, permissions, notices and payloads.
material_root="$TMP/material-validation"
material_unit=validation
mkdir -p "$material_root/share/licenses/$material_unit/project" "$TMP/material-validation-work"
printf 'fixture license\n' > "$material_root/share/licenses/$material_unit/project/LICENSE"
find "$material_root/share" -type d -exec chmod 0755 {} +
find "$material_root/share" -type f -exec chmod 0644 {} +
WORK="$TMP/material-validation-work" release_materials_validate "$material_root" "$material_unit"
for mutation in parent-mode file-mode link fifo empty missing unsafe-path source-record; do
  altered="$TMP/material-$mutation"
  cp -a "$material_root" "$altered"
  license="$altered/share/licenses/$material_unit/project/LICENSE"
  case "$mutation" in
    parent-mode) chmod 0777 "$altered/share" ;;
    file-mode) chmod 0666 "$license" ;;
    link) rm "$license"; ln -s /etc/passwd "$license" ;;
    fifo) rm "$license"; mkfifo "$license" ;;
    empty) : > "$license" ;;
    missing) rm "$license" ;;
    unsafe-path) mv "$license" "${license} unsafe" ;;
    source-record) mkdir -p "$altered/share/sources/$material_unit"; printf 'retired\n' > "$altered/share/sources/$material_unit/SOURCES.tsv" ;;
  esac
  if (WORK="$TMP/material-validation-work" release_materials_validate "$altered" "$material_unit" >/dev/null 2>&1); then
    fail "license validator accepted $mutation"
  fi
done
if (WORK="$TMP/material-validation-work" release_materials_validate_go "$material_root" "$material_unit" bin/missing >/dev/null 2>&1); then
  fail "validator accepted missing Go binary"
fi

bash "$ROOT/scripts/test-preview-line.sh"
bash "$ROOT/scripts/test-delete-preview.sh"

# The component passes every input unchanged to the fixed trusted helper.
mkdir -p "$TMP/source-entry/trusted/platform/release"
cat > "$TMP/source-entry/trusted/platform/release/producer-inputs.py" <<'PYENTRY'
import os, sys
from pathlib import Path
unit = os.environ['ENTRY_UNIT']
prefix = unit + '-' if unit in ('runtime', 'vmlinux') else ''
assert sys.argv[1:] == ['admit', unit, 'release/v1.2.x', '1' * 40,
                       prefix + 'v1.2.3', os.environ['GITHUB_REPOSITORY'], 'producer-source.tar']
if os.environ.get('ENTRY_REJECT'): raise SystemExit(23)
Path('producer-source.tar').write_text('admitted fixture')
PYENTRY
(
  cd "$TMP/source-entry"
  export GITHUB_REPOSITORY=kuasar-sandbox/connector ENTRY_UNIT=connector
  bash "$ROOT/scripts/validate-release-source.sh" release/v1.2.x 1111111111111111111111111111111111111111 v1.2.3 connector
  [ -f producer-source.tar ] || fail "source admission was not preserved"
  rm producer-source.tar
  status=0
  ENTRY_REJECT=1 bash "$ROOT/scripts/validate-release-source.sh" release/v1.2.x 1111111111111111111111111111111111111111 v1.2.3 connector || status=$?
  [ "$status" -eq 23 ] || fail "source admission failure was not preserved"
  [ ! -e producer-source.tar ] || fail "rejected admission produced an artifact"
)
rm "$TMP/source-entry/trusted/platform/release/producer-inputs.py"
if (cd "$TMP/source-entry"; bash "$ROOT/scripts/validate-release-source.sh" main 1111111111111111111111111111111111111111 v1.2.3 connector) >/dev/null 2>&1; then
  fail "source validator accepted a missing trusted helper"
fi
bash -n "$ROOT/scripts/delete-preview.sh" "$ROOT/scripts/validate-release-source.sh"
grep -Fqx 'run-name: Release ${{ inputs.version }} @${{ inputs.source_sha }}' \
  "$ROOT/.github/workflows/release.yml" \
  || fail "release run identity does not pin source_sha"
workflow="$ROOT/.github/workflows/release.yml"
for workflow in release.yml delete-preview.yml; do
  [ "$(grep -Fc 'group: component-mutation-${{ github.repository }}-${{ inputs.version }}' \
    "$ROOT/.github/workflows/$workflow")" -eq 1 ] \
    || fail "$workflow does not hold exactly one full-workflow mutation lock"
done
[ ! -e "$ROOT/.github/workflows/reconcile-latest.yml" ] || fail "retired Latest writer remains"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/test-release-publisher.py"

expected_cases=(
  test/e2e/cases/network.geneve-ethernet.sh
  test/e2e/cases/network.geneve-ip.sh
  test/e2e/cases/network.management.sh
  test/e2e/cases/network.provision.sh
  test/e2e/cases/network.tap.sh
  test/e2e/cases/network.vswitch-cleanup.sh
)
mapfile -t actual_cases < <(git -C "$ROOT" ls-files -- 'test/e2e/cases/network.*.sh' | sort)
mapfile -t sorted_expected_cases < <(printf '%s\n' "${expected_cases[@]}" | sort)
[ "${#actual_cases[@]}" -eq "${#sorted_expected_cases[@]}" ] \
  || fail "unexpected number of connector network E2E cases"
for i in "${!sorted_expected_cases[@]}"; do
  [ "${actual_cases[$i]}" = "${sorted_expected_cases[$i]}" ] \
    || fail "connector network E2E case set differs from the six platform cases"
done
for case_path in "${expected_cases[@]}"; do
  [ "$(git -C "$ROOT" ls-files -s -- "$case_path" | awk '{print $1}')" = 100644 ] \
    || fail "$case_path must be a non-executable platform case file (100644)"
done
for entrypoint in examples/perf_bench.sh examples/start_perf_bench.sh; do
  [ "$(git -C "$ROOT" ls-files -s -- "$entrypoint" | awk '{print $1}')" = 100755 ] \
    || fail "$entrypoint is not executable in the Git index"
done
for retired in test/e2e/run_all.sh test/e2e/geneve_eth_test.sh \
  test/e2e/geneve_ip_test.sh test/e2e/mgmt_isolation_test.sh \
  test/e2e/provision_test.sh test/e2e/tap_test.sh; do
  if git -C "$ROOT" ls-files --error-unmatch -- "$retired" >/dev/null 2>&1; then
    fail "$retired is retired and must not remain in the source tree"
  fi
done

mkdir -p "$TMP/bin" "$TMP/src"
fixture_root="$TMP/project"
mkdir -p "$fixture_root/scripts"
install -m 0644 "$ROOT/LICENSE" "$fixture_root/LICENSE"
install -m 0644 "$ROOT/LICENSE_SCOPE.md" "$fixture_root/LICENSE_SCOPE.md"
install -m 0644 "$ROOT/LICENSE_SCOPE_zh.md" "$fixture_root/LICENSE_SCOPE_zh.md"
cp -a "$ROOT/LICENSES" "$fixture_root/LICENSES"
printf '/bin/\n/build/\n' > "$fixture_root/.gitignore"
install -m 0755 "$ROOT/scripts/release.sh" "$fixture_root/scripts/release.sh"
install -m 0755 "$ROOT/scripts/release-materials.sh" "$fixture_root/scripts/release-materials.sh"
install -m 0755 "$ROOT/scripts/publish-release.sh" "$fixture_root/scripts/publish-release.sh"
install -m 0644 "$ROOT/scripts/release-publisher.py" "$fixture_root/scripts/release-publisher.py"
printf 'module github.com/kuasar-sandbox/connector\n\ngo 1.24\n' > "$fixture_root/go.mod"
mkdir -p "$fixture_root/cmd/connector-ctl"
printf 'package main\nfunc main() {}\n' > "$fixture_root/cmd/connector-ctl/main.go"
mkdir -p "$fixture_root/."
cp -a "$ROOT/examples" "$fixture_root/examples"
# A second real main package in the same clean commit must not identify the CLI.
printf 'package main\nfunc main() {}\n' > "$fixture_root/examples/tapfd_receiver/main.go"
mkdir -p "$fixture_root/."
cp -a "$ROOT/dist" "$fixture_root/dist"
cat > "$fixture_root/Makefile" <<'EOF'
.PHONY: build
build:
	mkdir -p bin/x86_64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true -o bin/x86_64/connector-ctl ./cmd/connector-ctl
EOF
fixture_project_sha="$(init_fixture_repo "$fixture_root" LICENSE LICENSE_SCOPE.md LICENSE_SCOPE_zh.md LICENSES .gitignore scripts go.mod cmd examples dist Makefile)"
(cd "$fixture_root" && GOWORK=off GOOS=linux GOARCH=amd64 go build -buildvcs=true -o "$TMP/go-fixture" ./cmd/connector-ctl)
release_materials_require_go_revision "$TMP/go-fixture" "$fixture_project_sha"
printf '// dirty fixture\n' >> "$fixture_root/cmd/connector-ctl/main.go"
(cd "$fixture_root" && GOWORK=off GOOS=linux GOARCH=amd64 go build -buildvcs=true -o "$TMP/dirty-go-fixture" ./cmd/connector-ctl)
if (release_materials_require_go_revision "$TMP/dirty-go-fixture" "$fixture_project_sha" >/dev/null 2>&1); then
  fail "release accepted a binary built from dirty source"
fi
printf 'package main\nfunc main() {}\n' > "$fixture_root/cmd/connector-ctl/main.go"
if (release_materials_require_go_revision "$TMP/go-fixture" \
  0000000000000000000000000000000000000000 >/dev/null 2>&1); then
  fail "release accepted a binary built from another commit"
fi
GOWORK=off GO111MODULE=off go build -o "$TMP/unstamped-go-fixture" "$fixture_root/cmd/connector-ctl/main.go"
if (release_materials_require_go_revision "$TMP/unstamped-go-fixture" "$fixture_project_sha" >/dev/null 2>&1); then
  fail "release accepted a binary without source stamping"
fi
install -m 0755 "$TMP/go-fixture" "$TMP/bin/connector-ctl"

mkdir -p "$fixture_root/bin/x86_64"
install -m 0755 "$TMP/go-fixture" "$fixture_root/bin/x86_64/connector-ctl"
RELEASE_BIN_DIR="$TMP/bin" RELEASE_SOURCE_ROOT="$fixture_root" "$fixture_root/scripts/release.sh" package v1.2.3 x86_64 \
  "$TMP/prebuilt-override"
cmp "$TMP/bin/connector-ctl" "$fixture_root/bin/x86_64/connector-ctl"
SOURCE_DATE_EPOCH=1700000000 GH_TOKEN=fixture-private AWS_SECRET_ACCESS_KEY=fixture-private \
  RELEASE_SOURCE_ROOT="$fixture_root" "$fixture_root/scripts/release.sh" package v1.2.3 x86_64 "$TMP/bundle"
"$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/bundle"
# A current publication may bind its own binaries to its selected commit;
# standalone validation above does not require or query historical sources.
if SOURCE_SHA=0000000000000000000000000000000000000000 "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/bundle" > "$TMP/publication-source.log" 2>&1; then
  fail "publication accepted an owner binary built at another commit"
fi
grep -Fq 'Go payload must be built from the clean selected commit' "$TMP/publication-source.log" \
  || fail "publication source mismatch failed for an unrelated reason"

"$ROOT/scripts/test-publisher.sh" "$fixture_root/scripts/publish-release.sh" \
  "$TMP/bundle" kuasar-sandbox/connector v1.2.3 \
  "$fixture_project_sha" main
"$ROOT/scripts/test-publisher.sh" "$fixture_root/scripts/publish-release.sh" \
  "$TMP/bundle" kuasar-sandbox/connector v1.2.3 \
  "$fixture_project_sha" release/v1.2.x

archive="$TMP/bundle/assets/connector-v1.2.3-linux-x86_64.tar.gz"
go_toolchain="$(go version | awk '{print $3}')"
for path in ./bin/connector-ctl ./deploy/connector-vswitch.service \
  ./test/connector/perf_bench.sh \
  ./share/licenses/connector/project/LICENSE \
  ./share/licenses/connector/project/LICENSE_SCOPE.md \
  ./share/licenses/connector/project/LICENSES/GPL-2.0-only.txt \
  ./share/licenses/connector/go-toolchain/"$go_toolchain"/LICENSE; do
  tar -tzf "$archive" | grep -Fx "$path" >/dev/null || fail "archive is missing $path"
done
if tar -tzf "$archive" | grep -E '(^|/)sources/|SOURCES[.]tsv|GO-BUILD-INFO[.]tsv|GO-MODULES[.]tsv|MATERIALS[.]sha256|CLOUD-HYPERVISOR-Cargo.lock' >/dev/null; then
  fail "new archive includes historical source or build records"
fi
if tar -tzf "$archive" | grep -E '^\./(docs|test/e2e)(/|$)|^\./test/connector/(geneve_.*_test|mgmt_isolation_test|provision_test|tap_test)\.sh$' >/dev/null; then
  fail "component archive contains documentation or E2E sources"
fi
if tar -tzf "$archive" | grep -Fx './test/connector/manage_switch.sh' >/dev/null; then
  fail "archive contains the retired unsafe topology helper"
fi
if tar -tzf "$archive" | grep -E '(^|/)release\.json$|(^|/)release/[^/]+\.json$' >/dev/null; then
  fail "archive contains release metadata JSON"
fi

SOURCE_DATE_EPOCH=1700000000 \
  RELEASE_SOURCE_ROOT="$fixture_root" "$ROOT/scripts/release.sh" package v1.2.3 x86_64 "$TMP/reproducible"
cmp -s "$archive" "$TMP/reproducible/assets/connector-v1.2.3-linux-x86_64.tar.gz" \
  || fail "identical inputs did not produce an identical archive"

git clone --quiet --no-local "$fixture_root" "$TMP/target-source"
for target in darwin/amd64 linux/arm64; do
  (cd "$TMP/target-source" && GOWORK=off CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" \
    go build -buildvcs=true -o "$TMP/target-${target//\//-}" ./cmd/connector-ctl)
  candidate="$TMP/wrong-target-${target//\//-}"
  cp -a "$TMP/bundle" "$candidate"
  mkdir "$candidate/root"
  tar -xzf "$archive" -C "$candidate/root"
  install -m 0755 "$TMP/target-${target//\//-}" "$candidate/root/bin/connector-ctl"
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1700000000 \
    -czf "$candidate/assets/$(basename "$archive")" -C "$candidate/root" .
  if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$candidate" > "$candidate/result.log" 2>&1; then
    fail "validator accepted a $target payload with regenerated checksums"
  fi
  grep -Fq 'must target linux/amd64' "$candidate/result.log" || fail "$target failed for an unrelated reason"
done

mkdir -p "$TMP/arm-bin"
install -m 0755 "$TMP/target-linux-arm64" "$TMP/arm-bin/connector-ctl"
SOURCE_DATE_EPOCH=1700000000 RELEASE_BIN_DIR="$TMP/arm-bin" \
  RELEASE_SOURCE_ROOT="$fixture_root" "$fixture_root/scripts/release.sh" package v1.2.3 aarch64 "$TMP/arm-bundle"
# Assembly is offline. Satisfy the publisher's tool preflight while making any
# accidental API invocation fail, even on hosts without the GitHub CLI.
mkdir "$TMP/offline-publisher-bin"
printf '#!/bin/sh\necho "offline assembly invoked gh" >&2\nexit 97\n' > "$TMP/offline-publisher-bin/gh"
chmod 0755 "$TMP/offline-publisher-bin/gh"
PATH="$TMP/offline-publisher-bin:$PATH" GH_REPO=kuasar-sandbox/connector SOURCE_SHA="$fixture_project_sha" "$fixture_root/scripts/publish-release.sh" assemble \
  v1.2.3 "$TMP/bundle" "$TMP/arm-bundle" "$TMP/dual-bundle"
PUBLISHER_TEST_ARCH=all "$ROOT/scripts/test-publisher.sh" "$fixture_root/scripts/publish-release.sh" \
  "$TMP/dual-bundle" kuasar-sandbox/connector v1.2.3 "$fixture_project_sha" main
for arch in x86_64 aarch64; do
  original="$TMP/bundle"
  [ "$arch" != aarch64 ] || original="$TMP/arm-bundle"
  cmp "$original/assets/connector-v1.2.3-linux-$arch.tar.gz" \
    "$TMP/dual-bundle/assets/connector-v1.2.3-linux-$arch.tar.gz" \
    || fail 'dual publication rebuilt or changed a validated archive'
done
cp -a "$TMP/arm-bundle" "$TMP/arm-tampered"
printf 'tampered' >> "$TMP/arm-tampered/assets/connector-v1.2.3-linux-aarch64.tar.gz"
if PATH="$TMP/offline-publisher-bin:$PATH" GH_REPO=kuasar-sandbox/connector "$fixture_root/scripts/publish-release.sh" assemble v1.2.3 "$TMP/bundle" \
  "$TMP/arm-tampered" "$TMP/dual-tampered" >/dev/null 2>&1; then
  fail 'dual assembler accepted changed ARM bytes'
fi
if PATH="$TMP/offline-publisher-bin:$PATH" GH_REPO=kuasar-sandbox/connector "$fixture_root/scripts/publish-release.sh" assemble v1.2.3 "$TMP/bundle" \
  "$TMP/bundle" "$TMP/dual-wrong-target" >/dev/null 2>&1; then
  fail 'dual assembler accepted AMD64 as the missing ARM archive'
fi

for target_package in ./examples/tapfd_receiver command-line-arguments; do
  binary="$TMP/other-main-${target_package##*/}"
  if [ "$target_package" = command-line-arguments ]; then
    (cd "$TMP/target-source" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -buildvcs=true -o "$binary" ./cmd/connector-ctl/main.go)
  else
    (cd "$TMP/target-source" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=true -o "$binary" "$target_package")
    release_materials_require_go_revision "$binary" "$fixture_project_sha"
  fi
  candidate="$TMP/wrong-main-${target_package##*/}"
  cp -a "$TMP/bundle" "$candidate"
  mkdir "$candidate/root"
  tar -xzf "$archive" -C "$candidate/root"
  install -m 0755 "$binary" "$candidate/root/bin/connector-ctl"
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1700000000 \
    -czf "$candidate/assets/$(basename "$archive")" -C "$candidate/root" .
  if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$candidate" > "$candidate/result.log" 2>&1; then
    fail "validator accepted the $target_package main package with regenerated metadata and checksums"
  fi
  grep -Fq 'must be the connector-ctl main package' "$candidate/result.log" \
    || fail "wrong main package failed for an unrelated reason"
done

cp -a "$TMP/bundle" "$TMP/tampered"
printf 'tampered\n' >> "$TMP/tampered/assets/connector-v1.2.3-linux-x86_64.tar.gz"
if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/tampered" >/dev/null 2>&1; then
  fail "validator accepted a tampered archive"
fi

cp -a "$TMP/bundle" "$TMP/extra"
touch "$TMP/extra/assets/release.json"
if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/extra" >/dev/null 2>&1; then
  fail "validator accepted an extra asset"
fi

cp -a "$TMP/bundle" "$TMP/retired-helper"
retired_archive="$TMP/retired-helper/assets/connector-v1.2.3-linux-x86_64.tar.gz"
mkdir -p "$TMP/retired-stage"
tar -xzf "$retired_archive" -C "$TMP/retired-stage"
install -m 0755 /dev/null "$TMP/retired-stage/test/connector/manage_switch.sh"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@1700000000' \
  --pax-option=delete=atime,delete=ctime -czf "$retired_archive" -C "$TMP/retired-stage" .
if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/retired-helper" >/dev/null 2>&1; then
  fail "validator accepted a checksummed archive containing the retired topology helper"
fi

if RELEASE_BIN_DIR="$TMP/bin" RELEASE_SOURCE_ROOT="$fixture_root" "$fixture_root/scripts/release.sh" package 01.2.3 x86_64 \
  "$TMP/invalid-version" >/dev/null 2>&1; then
  fail "packager accepted an invalid version"
fi
if RELEASE_BIN_DIR="$TMP/bin" RELEASE_SOURCE_ROOT="$fixture_root" "$fixture_root/scripts/release.sh" package v1.2.3 aarch64 \
  "$TMP/invalid-arch" >/dev/null 2>&1; then
  fail "packager accepted x86_64 payloads as aarch64"
fi

for mutation in setuid setgid writable-directory writable-binary; do
  candidate="$TMP/unsafe-mode-$mutation"
  cp -a "$TMP/bundle" "$candidate"
  mkdir "$candidate/root"
  tar -xzf "$archive" -C "$candidate/root"
  case "$mutation" in
    setuid) chmod 4755 "$candidate/root/bin/connector-ctl" ;;
    setgid) chmod 2755 "$candidate/root/bin/connector-ctl" ;;
    writable-directory) chmod 0777 "$candidate/root/bin" ;;
    writable-binary) chmod 0777 "$candidate/root/bin/connector-ctl" ;;
  esac
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1700000000 \
    -czf "$candidate/assets/$(basename "$archive")" -C "$candidate/root" .
  if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$candidate" > "$candidate/result.log" 2>&1; then
    fail "validator accepted $mutation with regenerated checksums"
  fi
  grep -Fq 'unsafe type, mode or ownership' "$candidate/result.log" \
    || fail "$mutation was rejected for an unrelated reason"
done

cp -a "$TMP/bundle" "$TMP/nonroot-owner"
mkdir "$TMP/nonroot-owner/root"
tar -xzf "$archive" -C "$TMP/nonroot-owner/root"
tar --sort=name --owner=1234 --group=0 --numeric-owner --mtime=@1700000000 \
  -czf "$TMP/nonroot-owner/assets/$(basename "$archive")" -C "$TMP/nonroot-owner/root" .
if "$fixture_root/scripts/release.sh" validate v1.2.3 x86_64 "$TMP/nonroot-owner" >/dev/null 2>&1; then
  fail "validator accepted non-root numeric ownership with regenerated checksums"
fi

# Standalone validation must not need source checkouts, module downloads or a build.
mkdir -p "$TMP/standalone-tools" "$TMP/standalone-bin"
cp -a "$fixture_root/scripts" "$TMP/standalone-tools/scripts"
for command in git curl wget cargo make gcc; do
  printf '#!/bin/sh\nexit 97\n' > "$TMP/standalone-bin/$command"
  chmod 0755 "$TMP/standalone-bin/$command"
done
env PATH="$TMP/standalone-bin:$PATH" GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local \
  SOURCE_SHA="$fixture_project_sha" "$TMP/standalone-tools/scripts/release.sh" validate \
  v1.2.3 x86_64 "$TMP/bundle"
echo "test-release: standalone validation without checkouts/downloads/build PASS"

echo "test-release: PASS"
