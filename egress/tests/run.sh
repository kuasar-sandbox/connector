#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'usage: run.sh connector-ctl runtime output-root' >&2; exit 2; }
[[ $EUID == 0 ]] || { echo 'Native acceptance requires an isolated root executor' >&2; exit 1; }
ctl=$(realpath "$1")
runtime=$(realpath "$2")
[[ -x $ctl && -x $runtime/bin/vpp && -f $runtime/runtime.json ]] || { echo 'Build and stage the selected native runtime first' >&2; exit 1; }
mkdir -p "$3"
output=$(mktemp -d "$3/run-XXXXXXXX")
tests=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for location in local remote; do
  options=()
  [[ $location != remote ]] || options+=(--remote)
  for locator in port vni tlv; do
    for encapsulation in ether ip; do
      python3 "$tests/e2e.py" --ctl "$ctl" --vpp-build "$runtime" \
        --output "$output/$location-$locator-$encapsulation" \
        --locator "$locator" --encap "$encapsulation" "${options[@]}"
    done
  done
done
python3 "$tests/e2e.py" --ctl "$ctl" --vpp-build "$runtime" --output "$output/legacy" --legacy
python3 "$tests/wire.py" --ctl "$ctl" --vpp-build "$runtime" --output "$output/wire-tlv" --locator tlv
python3 "$tests/wire.py" --ctl "$ctl" --vpp-build "$runtime" --output "$output/scale-vni" --contexts 4096 --flows 16
python3 - "$output" "$ctl" "$runtime" <<'PY'
import hashlib,json,pathlib,platform,sys
out,ctl,runtime=map(pathlib.Path,sys.argv[1:])
rows={str(p.relative_to(out)):json.loads(p.read_text()) for p in out.glob('*/result.json')}
assert len(rows)==15 and all(row['pass'] for row in rows.values())
result={'pass':True,'architecture':platform.machine(),'connector_ctl_sha256':hashlib.sha256(ctl.read_bytes()).hexdigest(),'runtime':json.loads((runtime/'runtime.json').read_text()),'cases':rows}
(out/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
print(out/'acceptance.json')
PY
