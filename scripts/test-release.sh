#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "test-release: $*" >&2
  exit 1
}

mkdir -p "$TMP/bin"
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/connector-ctl"
chmod +x "$TMP/bin/connector-ctl"
cat > "$TMP/revisions.tsv" <<'EOF'
repository	requested_ref	resolved_sha	role
kuasar-sandbox/connector	main	1111111111111111111111111111111111111111	primary
EOF

env \
  RELEASE_BIN_DIR="$TMP/bin" \
  SOURCE_DATE_EPOCH=1700000000 \
  RELEASE_WORKFLOW_REPOSITORY=kuasar-sandbox/connector \
  RELEASE_WORKFLOW_RUN_ID=123 \
  RELEASE_WORKFLOW_RUN_ATTEMPT=1 \
  RELEASE_WORKFLOW_RUN_URL=https://github.com/kuasar-sandbox/connector/actions/runs/123 \
  "$ROOT/scripts/release.sh" package v1.2.3 x86_64 "$TMP/revisions.tsv" "$TMP/bundle"
"$ROOT/scripts/release.sh" validate "$TMP/bundle"

archive="$TMP/bundle/assets/connector-v1.2.3-linux-x86_64.tar.gz"
for path in \
  ./bin/connector-ctl \
  ./docs/connector.md \
  ./release/connector.json; do
  tar -tzf "$archive" | grep -Fx "$path" >/dev/null || fail "archive is missing $path"
done

cp -a "$TMP/bundle" "$TMP/tampered"
printf 'tampered\n' >> "$TMP/tampered/assets/connector-v1.2.3-linux-x86_64.tar.gz"
if "$ROOT/scripts/release.sh" validate "$TMP/tampered" >/dev/null 2>&1; then
  fail "validator accepted a tampered archive"
fi

if RELEASE_BIN_DIR="$TMP/bin" "$ROOT/scripts/release.sh" package 01.2.3 x86_64 \
  "$TMP/revisions.tsv" "$TMP/invalid" >/dev/null 2>&1; then
  fail "packager accepted an invalid version"
fi

echo "test-release: PASS"
