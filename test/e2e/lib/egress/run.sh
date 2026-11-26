#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run.sh connector-ctl runtime output-root' >&2; exit 2; }
[[ $EUID == 0 ]] || { echo 'Native acceptance requires an isolated root executor' >&2; exit 1; }
ctl=$(realpath "$1")
runtime=$(realpath "$2")
[[ -x $ctl && -x $runtime/connector-vpp && -f $runtime/vpp-runtime.json ]] || { echo 'Build the selected Connector static dataplane first' >&2; exit 1; }
mkdir -p "$3"
output=$(mktemp -d "$3/run-XXXXXXXX")
tests=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Verify the exact runtime bytes and source receipt before privileged traffic.
source_args=()
[[ -z ${EGRESS_SOURCE_ROOT:-} ]] || source_args=(--source "$EGRESS_SOURCE_ROOT")
python3 "$tests/runtime.py" validate --arch "$(uname -m)" --runtime "$runtime" "${source_args[@]}"
python3 "$tests/wire.py" --ctl "$ctl" --runtime "$runtime" --output "$output/wire-tlv" --locator tlv
python3 "$tests/wire.py" --ctl "$ctl" --runtime "$runtime" --output "$output/wire-port" --locator port
python3 "$tests/wire.py" --ctl "$ctl" --runtime "$runtime" --output "$output/scale-vni" --contexts 12288 --flows 16
for location in local remote; do
  options=()
  [[ $location != remote ]] || options+=(--remote)
  for locator in port vni tlv; do
    for encapsulation in ether ip; do
      python3 "$tests/e2e.py" --ctl "$ctl" --runtime "$runtime" \
        --output "$output/$location-$locator-$encapsulation" \
        --locator "$locator" --encap "$encapsulation" "${options[@]}"
    done
  done
done
python3 "$tests/e2e.py" --ctl "$ctl" --runtime "$runtime" --output "$output/legacy" --legacy
python3 - "$output" "$ctl" "$runtime" <<'PY'
import hashlib,json,pathlib,platform,sys
out,ctl,runtime=map(pathlib.Path,sys.argv[1:])
rows={str(p.relative_to(out)):json.loads(p.read_text()) for p in out.glob('*/result.json')}
assert len(rows)==16 and all(row['pass'] for row in rows.values())
result={'pass':True,'architecture':platform.machine(),'connector_ctl_sha256':hashlib.sha256(ctl.read_bytes()).hexdigest(),'runtime':json.loads((runtime/'vpp-runtime.json').read_text()),'cases':rows}
(out/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
print(out/'acceptance.json')
PY
