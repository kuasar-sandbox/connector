#!/usr/bin/env bash
# Staged native VPP dependency: fetch, patches-apply, patches-format, build.
# Source archives and patch development follow Sandboxer/Guest Runtime conventions.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$script_dir/../.." && pwd)
# shellcheck disable=SC1091
source "$script_dir/common.sh"

: "${STAGE:=build}"
: "${TARGET_ARCH:=$(uname -m)}"
case "$TARGET_ARCH" in
    amd64) TARGET_ARCH=x86_64 ;;
    arm64) TARGET_ARCH=aarch64 ;;
esac
case "$TARGET_ARCH" in
    x86_64) baseline=x86-64-v2 ;;
    aarch64) baseline=armv8-a+crc ;;
    *) die "unsupported TARGET_ARCH=$TARGET_ARCH; supported: x86_64, aarch64" ;;
esac
: "${BUILD_DIR:=$root/native-deps/build/$TARGET_ARCH}"
: "${BINDIR:=$root/bin/$TARGET_ARCH}"
: "${TARBALL_CACHE:=$root/native-deps/build/tarball}"
: "${VPP_BUILD_SRC:=$root/native-deps/build/src/vpp}"
: "${VPP_BUILD_OUT:=$BUILD_DIR/vpp}"
: "${VPP_PATCHES_DIR:=$script_dir/vpp-patches}"
: "${VPP_BASE_TAG:=vpp-patches-base}"
read -r revision version default_digest < <(python3 - "$script_dir/vpp-source.json" <<'PY'
import json, sys
source = json.load(open(sys.argv[1]))
print(source['commit'], source['version'], source['tarball_sha256'])
PY
)
: "${VPP_TARBALL:=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tarball"])' "$script_dir/vpp-source.json")}"
: "${VPP_TARBALL_SHA256:=$default_digest}"
[[ "$VPP_TARBALL_SHA256" =~ ^[0-9a-f]{64}$ ]] || die 'VPP_TARBALL_SHA256 must be a SHA256 digest'
src_dir=$VPP_BUILD_SRC
out_obj=$VPP_BUILD_OUT

check_import() {
    [ -d "$src_dir/.git" ] || die "no VPP source tree; run 'make vpp-fetch' first"
    git -C "$src_dir" rev-parse --verify "$VPP_BASE_TAG" >/dev/null 2>&1 \
        || die "source tree has no $VPP_BASE_TAG; refusing to overwrite it"
    python3 - "$src_dir/.git/vpp-source.json" "$revision" "$version" "$VPP_TARBALL_SHA256" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
expected = dict(commit=sys.argv[2], version=sys.argv[3], tarball_sha256=sys.argv[4])
if not path.is_file() or json.loads(path.read_text()) != expected:
    raise SystemExit('VPP source archive differs from the selected version; preserve work and select a fresh VPP_BUILD_SRC/VPP_BUILD_OUT')
PY
}

do_fetch() {
    if [ -d "$src_dir/.git" ]; then
        check_import
        log "$VPP_BASE_TAG exists at $src_dir, skipping fetch"
        return
    fi
    [ ! -e "$src_dir" ] || die "source directory already exists without a managed Git baseline: $src_dir"
    require_cmd git tar python3 sha256sum
    local tarball
    tarball=$(resolve_tarball "$VPP_TARBALL" "$VPP_TARBALL_SHA256")
    extract_tarball "$tarball" "$src_dir" >/dev/null
    # Upstream make-dist archives carry this file. GitHub archives do not.
    # The synthetic import has a different Git ID; retain the pinned VPP version.
    printf 'v%s-0-g%s\n' "$version" "$revision" > "$src_dir/src/scripts/.version"
    git -C "$src_dir" init -q
    printf '/src/plugins/egress_policy/\n/src/plugins/egress_geneve/\n/src/plugins/egress_packet/\n__pycache__/\n' >> "$src_dir/.git/info/exclude"
    git -C "$src_dir" add -A
    git -C "$src_dir" add -f src/scripts/.version
    GIT_AUTHOR_DATE="${GIT_AUTHOR_DATE:-@${SOURCE_DATE_EPOCH:-0} +0000}" \
        GIT_COMMITTER_DATE="${GIT_COMMITTER_DATE:-@${SOURCE_DATE_EPOCH:-0} +0000}" \
        git -C "$src_dir" -c user.name=deps -c user.email=deps@local \
        commit -qm "import ${tarball##*/}"
    git -C "$src_dir" tag "$VPP_BASE_TAG"
    # version still calls git describe when .version is present. Supply its
    # release label on the imported baseline; source identity is the archive SHA.
    GIT_COMMITTER_DATE="${GIT_COMMITTER_DATE:-@${SOURCE_DATE_EPOCH:-0} +0000}" \
        git -C "$src_dir" -c user.name=deps -c user.email=deps@local \
        tag -a "v$version" -m "VPP $version source archive" "$VPP_BASE_TAG"
    python3 - "$src_dir/.git/vpp-source.json" "$revision" "$version" "$VPP_TARBALL_SHA256" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps(dict(commit=sys.argv[2], version=sys.argv[3], tarball_sha256=sys.argv[4]), sort_keys=True) + '\n')
PY
}

require_clean_source() {
    git -C "$src_dir" diff --quiet && git -C "$src_dir" diff --cached --quiet \
        || die "VPP source has uncommitted changes; commit and run 'make vpp-patches-format' first"
    [ -z "$(git -C "$src_dir" ls-files --others --exclude-standard)" ] \
        || die "VPP source has untracked files; commit the intended changes before exporting patches"
}

# Compare actual trees, not only commit titles: changing a patch body must not
# silently reuse a source tree built with an earlier version of that patch.
verify_patch_tree() (
    local index expected actual
    index=$(mktemp "$src_dir/.git/vpp-index.XXXXXX")
    rm -f "$index"
    trap 'rm -f "$index"' EXIT
    export GIT_INDEX_FILE=$index
    git -C "$src_dir" read-tree "$VPP_BASE_TAG"
    shopt -s nullglob
    local patches=("$VPP_PATCHES_DIR"/*.patch)
    if [ "${#patches[@]}" -gt 0 ]; then
        git -C "$src_dir" apply --cached "${patches[@]}" \
            || die 'maintained VPP patches do not apply to the selected baseline'
    fi
    expected=$(git -C "$src_dir" write-tree)
    actual=$(git -C "$src_dir" rev-parse 'HEAD^{tree}')
    [ "$actual" = "$expected" ] \
        || die "VPP source differs from maintained patches; export committed work with 'make vpp-patches-format', or select a fresh source tree"
)

do_patches_apply() {
    check_import
    require_clean_source
    shopt -s nullglob
    local patches=("$VPP_PATCHES_DIR"/*.patch)
    if [ "$(git -C "$src_dir" rev-parse HEAD)" = "$(git -C "$src_dir" rev-parse "$VPP_BASE_TAG")" ] \
        && [ "${#patches[@]}" -gt 0 ]; then
        log "applying ${#patches[@]} VPP patch(es)"
        GIT_COMMITTER_DATE="${GIT_COMMITTER_DATE:-@${SOURCE_DATE_EPOCH:-0} +0000}" \
            git -C "$src_dir" -c user.name=deps -c user.email=deps@local am "${patches[@]}"
    fi
    verify_patch_tree
}

do_patches_format() {
    check_import
    require_clean_source
    local pending
    mkdir -p "$VPP_PATCHES_DIR"
    pending=$(mktemp -d "$VPP_PATCHES_DIR/.format.XXXXXX")
    if ! git -C "$src_dir" format-patch --no-signature "$VPP_BASE_TAG..HEAD" -o "$pending"; then
        rm -rf "$pending"
        die 'could not export VPP patches'
    fi
    rm -f "$VPP_PATCHES_DIR"/*.patch
    shopt -s nullglob
    local patches=("$pending"/*.patch)
    if [ "${#patches[@]}" -gt 0 ]; then
        mv "${patches[@]}" "$VPP_PATCHES_DIR/"
    fi
    rmdir "$pending"
    log "exported ${#patches[@]} VPP patch(es)"
}

do_build() {
    [ "$(uname -m)" = "$TARGET_ARCH" ] \
        || die "VPP requires a native $TARGET_ARCH builder; host is $(uname -m)"
    local jobs=${KUASAR_BUILD_JOBS:-$(nproc)}
    [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die 'KUASAR_BUILD_JOBS must be a positive integer'
    check_import
    require_clean_source
    verify_patch_tree
    require_cmd cmake ninja python3 readelf
    mkdir -p "$out_obj"
    # Keep this build-only Python dependency in the same verified download cache.
    local wheel
    wheel=$(resolve_tarball 'https://files.pythonhosted.org/packages/a3/58/35da89ee790598a0700ea49b2a66594140f44dec458c07e8e3d4979137fc/ply-3.11-py2.py3-none-any.whl' \
        '096f9b8350b65ebd2fd1346b12452efe5b9607f7482813ffca50c22722a807ce')
    export PYTHONPATH="$wheel${PYTHONPATH:+:$PYTHONPATH}"
    rm -f "$out_obj/build-inputs.json"
    python3 "$script_dir/stage-vpp.py" --record-inputs "$out_obj/build-inputs.pending.json"
    # Only these owned plugin directories are synchronized. Remove files which
    # disappeared from project inputs, so stale sources cannot survive a rebuild.
    python3 - "$root/egress/vpp/plugins" "$src_dir/src/plugins" <<'PY'
from pathlib import Path
import shutil, sys
source, dest = map(Path, sys.argv[1:])
for name in ('egress_policy', 'egress_geneve', 'egress_packet'):
    inputs = {p.relative_to(source/name): p for p in (source/name).rglob('*') if p.is_file()}
    target = dest/name
    target.mkdir(parents=True, exist_ok=True)
    for path in target.rglob('*'):
        if path.is_file() and path.relative_to(target) not in inputs:
            path.unlink()
    for relative, path in inputs.items():
        output = target/relative
        output.parent.mkdir(parents=True, exist_ok=True)
        if not output.is_file() or output.read_bytes() != path.read_bytes():
            shutil.copy2(path, output)
PY
    cmake -S "$src_dir/src" -B "$out_obj/obj" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR="lib/$TARGET_ARCH-linux-gnu" \
        -DVPP_RUNTIME_DIR=. \
        -DVPP_IP_FIB_MTRIE_16=OFF -DVPP_BUILD_NATIVE_ONLY=ON -DVPP_BUILD_NATIVE_ARCH="$baseline"
    cmake --build "$out_obj/obj" --parallel "$jobs" --target \
        vpp nat_plugin af_packet_plugin ping_plugin \
        egress_policy_plugin egress_geneve_plugin egress_packet_plugin
    require_clean_source
    verify_patch_tree
    mv "$out_obj/build-inputs.pending.json" "$out_obj/build-inputs.json"
    python3 "$script_dir/stage-vpp.py" --build "$out_obj" --source "$src_dir" \
        --arch "$TARGET_ARCH" --output "$BINDIR"
}

case "$STAGE" in
    fetch) do_fetch ;;
    patches-apply) do_patches_apply ;;
    patches-format) do_patches_format ;;
    build) do_build ;;
    *) die "unknown STAGE=$STAGE; use fetch, patches-apply, patches-format or build" ;;
esac
