#!/usr/bin/env python3
"""Stage an owned native runtime; never install services or mutate networking."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile

PLUGINS = ('nat', 'af_packet', 'ping', 'egress_policy', 'egress_geneve', 'egress_packet')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    build = Path(args.build).resolve()
    output = Path(args.output).absolute()
    root = Path(__file__).resolve().parent
    built_inputs = json.loads((build/'build-inputs.json').read_text())
    paths = [root/'build.sh', *sorted((root/'vpp').rglob('*'))]
    selected_inputs = {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    if built_inputs != selected_inputs:
        raise SystemExit('Selected native inputs differ from the completed build; rebuild before staging')
    if output.exists():
        raise SystemExit('Output already exists; choose a new staging directory')
    triplet = {'x86_64': 'x86_64-linux-gnu', 'aarch64': 'aarch64-linux-gnu'}[platform.machine()]
    machine = {'x86_64': 62, 'aarch64': 183}[platform.machine()]
    baseline = {'x86_64': 'x86-64-v2', 'aarch64': 'armv8-a+crc'}[platform.machine()]
    cache = (build/'obj/CMakeCache.txt').read_text()
    if not re.search(r'^VPP_BUILD_NATIVE_ARCH:[^=]+='+re.escape(baseline)+r'$', cache, re.M):
        raise SystemExit('Runtime must use the documented portable CPU baseline')
    output.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix='.egress-runtime-', dir=output.parent))
    try:
        manifest = dict(product='connector-egress-native-runtime', schema=1,
                        architecture=platform.machine(), cpu_baseline=baseline,
                        vpp=json.loads((root/'vpp/source.json').read_text()), native_build_inputs=built_inputs, files={})
        inputs = [(build/'obj/bin'/name, Path('bin')/name) for name in ('vpp', 'vppctl')]
        lib = build/'obj/lib'/triplet
        inputs += [(path, Path('lib')/triplet/path.name) for path in sorted(lib.glob('lib*.so*'))]
        inputs += [(lib/'vpp_plugins'/(name+'_plugin.so'), Path('lib')/triplet/'vpp_plugins'/(name+'_plugin.so')) for name in PLUGINS]
        required = set()
        for source, relative in inputs:
            content = source.read_bytes()
            if content[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', content, 18)[0] != machine:
                raise SystemExit('Wrong architecture or invalid ELF: '+str(source))
            dest = staged/relative; dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content); dest.chmod(0o755 if relative.parts[0] == 'bin' else 0o644)
            needed = subprocess.check_output(['readelf', '-d', str(source)], text=True)
            required.update(re.findall(r'\(NEEDED\).*\[([^]]+)\]', needed))
        shipped = {relative.name for _, relative in inputs}
        manifest['required_system_libraries'] = sorted(required-shipped)
        licenses = staged/'share/licenses'; licenses.mkdir(parents=True)
        shutil.copy2(root.parent/'LICENSE', licenses/'CONNECTOR-LICENSE')
        shutil.copy2(build/'source/LICENSE', licenses/'VPP-LICENSE')
        # Retain upstream license files and embedded leading copyright/license
        # comments for the shipped core and plugins, without packaging sources.
        notice = []
        source_root = build/'source'
        for relative in ('src/vppinfra', 'src/vlib', 'src/vlibapi', 'src/vlibmemory', 'src/svm', 'src/vnet', 'src/plugins/nat', 'src/plugins/af_packet', 'src/plugins/ping'):
            for source in sorted((source_root/relative).rglob('*')):
                if not source.is_file():
                    continue
                if re.fullmatch(r'(LICENSE|COPYING|NOTICE)(\..*)?', source.name, re.I):
                    dest = licenses/'upstream'/source.relative_to(source_root)
                    dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, dest)
                if source.suffix in ('.c', '.h', '.S'):
                    data = source.read_text(errors='replace')
                    leading = re.match(r'(?:\s+|/\*[\s\S]*?\*/|//[^\n]*(?:\n|$))*', data).group()
                    if re.search(r'copyright|license|SPDX|redistribution', leading, re.I):
                        notice.append(str(source.relative_to(source_root))+'\n'+leading.strip())
        (licenses/'VPP-EMBEDDED-NOTICES').write_text('\n\n'.join(notice)+'\n')
        for path in sorted(staged.rglob('*')):
            if path.is_file():
                manifest['files'][str(path.relative_to(staged))] = hashlib.sha256(path.read_bytes()).hexdigest()
        (staged/'runtime.json').write_text(json.dumps(manifest, indent=2)+'\n')
        os.rename(staged, output)
        print(output)
    finally:
        if staged.exists():
            shutil.rmtree(staged)


if __name__ == '__main__':
    main()
