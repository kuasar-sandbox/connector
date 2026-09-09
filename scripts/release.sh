#!/usr/bin/env bash

set -euo pipefail
umask 022

NAME=connector
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=scripts/release-materials.sh
source "$ROOT/scripts/release-materials.sh"

fail() {
  echo "release: $*" >&2
  exit 1
}

validate_version() {
  [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-preview\.[0-9]{8})?$ ]] \
    || fail "version must match vX.Y.Z or vX.Y.Z-preview.YYYYMMDD"
}

normalize_arch() {
  case "$1" in
    amd64|x86_64) printf 'x86_64\n' ;;
    *) fail "unsupported release architecture: $1; current release target is x86_64" ;;
  esac
}

archive_name() {
  local version="$1" arch
  validate_version "$version"
  arch="$(normalize_arch "$2")"
  printf '%s-%s-linux-%s.tar.gz\n' "$NAME" "$version" "$arch"
}

copy_file() {
  local source="$1" destination="$2"
  [ -f "$ROOT/$source" ] || fail "missing release input: $ROOT/$source"
  mkdir -p "$(dirname "$STAGE/$destination")"
  install -m 0644 "$ROOT/$source" "$STAGE/$destination"
}

copy_executable() {
  local source="$1" destination="$2"
  [ -x "$source" ] || fail "missing executable release input: $source"
  mkdir -p "$(dirname "$STAGE/$destination")"
  install -m 0755 "$source" "$STAGE/$destination"
}

copy_root_executable() {
  local source="$1" destination="$2"
  [ -x "$ROOT/$source" ] || fail "missing executable release input: $ROOT/$source"
  mkdir -p "$(dirname "$STAGE/$destination")"
  install -m 0755 "$ROOT/$source" "$STAGE/$destination"
}

check_go_binary() {
  local file="$1"
  go version -m "$file" >/dev/null 2>&1 \
    || fail "Go build info is missing from $file"
}

validate_archive_paths() {
  local archive="$1" listing="$WORK/listing"
  tar -tzf "$archive" > "$listing"
  awk '
    /^\// { exit 1 }
    { path=$0; sub(/^\.\//, "", path); if (path ~ /(^|\/)\.\.($|\/)/) exit 1 }
  ' "$listing" || fail "$archive contains an unsafe path"
  if grep -E '(^|/)release\.json$|(^|/)release/[^/]+\.json$' "$listing" >/dev/null; then
    fail "$archive contains release metadata JSON"
  fi
  local expected_files="$WORK/expected-archive-files" actual_files="$WORK/actual-archive-files"
  cat > "$expected_files" <<'EOF'
bin/connector-ctl
deploy/NetworkManager-connector.conf
deploy/connector-switch.conf
deploy/connector-vswitch.service
test/connector/perf_bench.sh
test/connector/start_perf_bench.sh
EOF
  awk '
    { path=$0; sub(/^\.\//, "", path) }
    path != "" && path !~ /\/$/ && path !~ /^share\/(licenses|sources)\/connector\// { print path }
  ' "$listing" | LC_ALL=C sort > "$actual_files"
  cmp -s "$expected_files" "$actual_files" \
    || { diff -u "$expected_files" "$actual_files" >&2 || true; fail "$archive does not match the exact connector release file set"; }

  # A name-only allowlist is insufficient: an archive could replace an allowed
  # path with a link and make extraction depend on content outside the bundle.
  # The release contract contains only directories and regular files.
  tar --numeric-owner -tvzf "$archive" | awk '
    $2 != "0/0" { exit 1 }
    $1 ~ /^d/ { if ($1 != "drwxr-xr-x") exit 1; next }
    $1 !~ /^-/ { exit 1 }
    {
      path=$6; sub(/^\.\//, "", path)
      expected=(path ~ /^(bin\/|test\/connector\/)/ ? "-rwxr-xr-x" : "-rw-r--r--")
      if ($1 != expected) exit 1
    }
  ' || fail "$archive contains an unsafe type, mode or ownership"
  awk '
    { path=$0; sub(/^\.\//, "", path) }
    path != "" && path !~ /\/$/ && path ~ /^share\// && path !~ /^share\/(licenses|sources)\/connector\// { exit 1 }
  ' "$listing" || fail "$archive contains another release unit's material namespace"
}

validate_bundle() {
  [ "$#" -eq 3 ] || fail "usage: release.sh validate <version> <arch> <bundle-dir>"
  local version="$1" arch archive bundle="$3"
  arch="$(normalize_arch "$2")"
  archive="$(archive_name "$version" "$arch")"
  [ -s "$bundle/release-notes.md" ] || fail "release-notes.md is missing"
  [ -d "$bundle/assets" ] || fail "assets directory is missing"

  local expected="$WORK/expected-assets" actual="$WORK/actual-assets"
  printf '%s\n' "$archive" SHA256SUMS | LC_ALL=C sort > "$expected"
  find "$bundle/assets" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort > "$actual"
  cmp -s "$expected" "$actual" \
    || { diff -u "$expected" "$actual" >&2 || true; fail "bundle contains an unexpected asset set"; }
  [ "$(grep -cve '^[[:space:]]*$' "$bundle/assets/SHA256SUMS")" -eq 1 ] \
    || fail "SHA256SUMS must contain exactly one entry"
  local digest listed extra
  read -r digest listed extra < "$bundle/assets/SHA256SUMS"
  listed="${listed#\*}"
  if ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]] \
    || [ "$listed" != "$archive" ] || [ -n "${extra:-}" ]; then
    fail "SHA256SUMS does not describe the expected archive"
  fi
  (cd "$bundle/assets" && sha256sum --quiet -c SHA256SUMS) \
    || fail "SHA256SUMS validation failed"

  validate_archive_paths "$bundle/assets/$archive"
  local extract="$WORK/extract"
  rm -rf "$extract"
  mkdir -p "$extract"
  tar -xzf "$bundle/assets/$archive" -C "$extract"
  release_materials_validate "$extract" "$NAME"
  release_materials_require_source "$extract" "$NAME" 'bin/*,deploy/*,test/connector/*' 'connector' "$version"
  release_materials_require_source "$extract" "$NAME" 'bin/connector-ctl' 'embedded-ebpf' "$version"
  release_materials_require_go "$extract" "$NAME" 'bin/connector-ctl'
  [ -x "$extract/bin/connector-ctl" ] \
    || fail "$archive is missing executable bin/connector-ctl"
  check_go_binary "$extract/bin/connector-ctl"
  local file
  for file in deploy/connector-vswitch.service deploy/connector-switch.conf \
    deploy/NetworkManager-connector.conf \
    test/connector/perf_bench.sh test/connector/start_perf_bench.sh; do
    [ -f "$extract/$file" ] || fail "$archive is missing $file"
  done
}

package_release() {
  [ "$#" -eq 3 ] || fail "usage: release.sh package <version> <arch> <output-dir>"
  local version="$1" arch output="$3" archive epoch bin_dir project_sha
  arch="$(normalize_arch "$2")"
  archive="$(archive_name "$version" "$arch")"
  if [ -z "$output" ] || [ "$output" = / ] || [ "$output" = . ]; then
    fail "unsafe output directory: $output"
  fi
  [ ! -e "$output" ] || fail "output already exists: $output"
  epoch="${SOURCE_DATE_EPOCH:-0}"
  [[ "$epoch" =~ ^[0-9]+$ ]] || fail "SOURCE_DATE_EPOCH must be an integer"

  STAGE="$WORK/stage"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  bin_dir="${RELEASE_BIN_DIR:-$ROOT/bin/$arch}"
  copy_executable "$bin_dir/connector-ctl" bin/connector-ctl
  check_go_binary "$STAGE/bin/connector-ctl"
  copy_root_executable examples/perf_bench.sh test/connector/perf_bench.sh
  copy_root_executable examples/start_perf_bench.sh test/connector/start_perf_bench.sh
  copy_file dist/connector-vswitch.service deploy/connector-vswitch.service
  copy_file dist/connector-switch.conf deploy/connector-switch.conf
  copy_file dist/NetworkManager-connector.conf deploy/NetworkManager-connector.conf

  project_sha="$(release_materials_resolve_git_source "$ROOT" "" connector)"
  release_materials_require_go_revision "$STAGE/bin/connector-ctl" "$project_sha"
  release_materials_init "$STAGE" "$WORK/materials" "$NAME"
  release_materials_copy_licenses "$ROOT" project
  release_materials_record_source 'bin/*,deploy/*,test/connector/*' connector "$version" \
    "https://github.com/kuasar-sandbox/connector/commit/$project_sha" \
    "git:$project_sha" project
  release_materials_record_source bin/connector-ctl embedded-ebpf "$version" \
    "https://github.com/kuasar-sandbox/connector/blob/$project_sha/bpf/switch_kern.c" \
    "git:$project_sha;spdx:GPL-2.0-only" project
  release_materials_add_go_binary "$STAGE/bin/connector-ctl" bin/connector-ctl
  release_materials_finish

  mkdir -p "$output/assets"
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
    --pax-option=delete=atime,delete=ctime -czf "$output/assets/$archive" -C "$STAGE" .
  (cd "$output/assets" && sha256sum "$archive" > SHA256SUMS)
  cat > "$output/release-notes.md" <<EOF
$NAME $version for Linux $arch.

Extract the archive into a Kuasar Sandbox deployment root and verify it with \`SHA256SUMS\`. Documentation and E2E suites from this exact tag are collected by the aggregate platform release.
EOF
  validate_bundle "$version" "$arch" "$output"
  echo "==> prepared $output for $version"
}

command -v go >/dev/null || fail "go is required"
case "${1:-}" in
  archive-name) shift; [ "$#" -eq 2 ] || fail "usage: release.sh archive-name <version> <arch>"; archive_name "$@" ;;
  package) shift; package_release "$@" ;;
  validate) shift; validate_bundle "$@" ;;
  *) fail "usage: release.sh <archive-name|package|validate> ..." ;;
esac
