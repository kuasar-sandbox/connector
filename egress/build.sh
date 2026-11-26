#!/usr/bin/env bash
# Builds the pinned VPP runtime; no host interfaces or system services are changed.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build=${EGRESS_BUILD_DIR:-"$root/build/egress"}
source_dir="$build/source"
revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$root/egress/vpp/source.json")
case $(uname -m) in
  x86_64) baseline=x86-64-v2 ;;
  aarch64) baseline=armv8-a+crc ;;
  *) echo 'Egress runtime requires native Linux x86_64 or aarch64' >&2; exit 1 ;;
esac
mkdir -p "$build"
if [[ ! -d "$source_dir/.git" ]]; then
  git init -q "$source_dir"
  git -C "$source_dir" remote add origin https://github.com/FDio/vpp.git
  git -C "$source_dir" fetch --depth=1 origin "$revision"
  git -C "$source_dir" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$source_dir" rev-parse HEAD) == "$revision" ]] || { echo 'Unexpected VPP revision' >&2; exit 1; }
# Applying the same patch again is safe. A different dirty tree is rejected.
patch="$root/egress/vpp/patches/native-policy.patch"
if git -C "$source_dir" apply --check "$patch" 2>/dev/null; then
  git -C "$source_dir" apply "$patch"
else
  git -C "$source_dir" apply --reverse --check "$patch"
fi
git -C "$source_dir" diff --cached --quiet
git -C "$source_dir" diff --binary --no-ext-diff | cmp -s "$patch" - || { echo 'Unrelated VPP source changes; use a clean build directory' >&2; exit 1; }
copy_changed() { cmp -s "$1" "$2" || cp "$1" "$2"; }
copy_changed "$root/egress/vpp/patches/nat44_ed_policy.h" "$source_dir/src/plugins/nat/nat44-ed/nat44_ed_policy.h"
for plugin in egress_policy egress_geneve egress_packet; do
  mkdir -p "$source_dir/src/plugins/$plugin"
  for file in "$root/egress/vpp/plugins/$plugin/"*; do
    copy_changed "$file" "$source_dir/src/plugins/$plugin/$(basename "$file")"
  done
done
cmake -S "$source_dir/src" -B "$build/obj" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DVPP_IP_FIB_MTRIE_16=OFF \
  -DVPP_BUILD_NATIVE_ONLY=ON -DVPP_BUILD_NATIVE_ARCH="$baseline"
cmake --build "$build/obj" --parallel "${JOBS:-4}" --target \
  vpp nat_plugin af_packet_plugin ping_plugin \
  egress_policy_plugin egress_geneve_plugin egress_packet_plugin
printf '%s\n' "$revision" > "$build/vpp-revision"
python3 - "$root/egress" "$build/build-inputs.json" <<'PY'
import hashlib,json,pathlib,sys
root,out=map(pathlib.Path,sys.argv[1:])
paths=[root/'build.sh',*sorted((root/'vpp').rglob('*'))]
inputs={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
out.write_text(json.dumps(inputs,sort_keys=True,indent=2)+'\n')
PY
