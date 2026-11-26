#!/usr/bin/env python3
"""Publish static connector-vpp into the shared architecture output directory."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('vpp_runtime', ROOT/'scripts/vpp-runtime.py')
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


def licenses(source, output):
    output.mkdir(parents=True)
    shutil.copy2(ROOT/'LICENSE', output/'CONNECTOR-LICENSE')
    shutil.copy2(source/'LICENSE', output/'VPP-LICENSE')
    notice = []
    for relative in ('src/vppinfra', 'src/vlib', 'src/vlibapi', 'src/vlibmemory',
                     'src/svm', 'src/vnet', 'src/plugins/nat',
                     'src/plugins/af_packet', 'src/plugins/ping'):
        for path in sorted((source/relative).rglob('*')):
            if not path.is_file():
                continue
            if re.fullmatch(r'(LICENSE|COPYING|NOTICE)(\..*)?', path.name, re.I):
                dest = output/'upstream'/path.relative_to(source)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)
            if path.suffix in ('.c', '.h', '.S'):
                data = path.read_text(errors='replace')
                leading = re.match(r'(?:\s+|/\*[\s\S]*?\*/|//[^\n]*(?:\n|$))*', data).group()
                if re.search(r'copyright|license|SPDX|redistribution', leading, re.I):
                    notice.append(str(path.relative_to(source))+'\n'+leading.strip())
    (output/'VPP-EMBEDDED-NOTICES').write_text('\n\n'.join(notice)+'\n')
    output.chmod(0o755)
    for path in output.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)


def check_output_path(output, relative=Path()):
    path = output
    if path.is_symlink():
        raise SystemExit('VPP output may not contain links: '+str(path))
    for part in relative.parts:
        path = path/part
        if path.is_symlink():
            raise SystemExit('VPP output may not contain links: '+str(path))


def stage(build, source, output, arch):
    built_inputs = json.loads((build/'build-inputs.json').read_text())
    if built_inputs != RUNTIME.native_inputs(ROOT):
        raise SystemExit('Selected native inputs differ from the completed build; rebuild before staging')
    metadata = RUNTIME.source_metadata(ROOT)
    imported = json.loads((source/'.git/vpp-source.json').read_text())
    if imported != {key: metadata[key] for key in ('commit', 'version', 'tarball_sha256')}:
        raise SystemExit('Built source archive differs from the selected VPP source lock')
    triplet = arch+'-linux-gnu'
    machine = {'x86_64': 62, 'aarch64': 183}[arch]
    baseline = {'x86_64': 'x86-64-v2', 'aarch64': 'armv8-a+crc'}[arch]
    cache = (build/'obj/CMakeCache.txt').read_text()
    if not re.search(r'^VPP_BUILD_NATIVE_ARCH:[^=]+='+re.escape(baseline)+r'$', cache, re.M):
        raise SystemExit('VPP must use the documented portable CPU baseline')
    if not re.search(r'^VPP_STATIC_EGRESS:BOOL=ON$', cache, re.M):
        raise SystemExit('connector-vpp must use the fixed static Egress build')
    check_output_path(output)
    output.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix='.vpp-', dir=output.parent))
    license_stage = Path(tempfile.mkdtemp(prefix='.licenses-', dir=build))
    try:
        manifest = dict(product='connector-egress-native-runtime', schema=1,
                        architecture=arch, cpu_baseline=baseline, vpp=metadata,
                        native_build_inputs=built_inputs, files={})
        inputs = [(build/'obj/connector-vpp', Path('connector-vpp'))]
        for path, relative in inputs:
            content = path.read_bytes()
            if len(content) < 20 or content[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', content, 18)[0] != machine:
                raise SystemExit('Wrong architecture or invalid ELF: '+str(path))
            dest = staged/relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            dest.chmod(0o755)
            manifest['files'][relative.as_posix()] = hashlib.sha256(content).hexdigest()
        manifest['required_system_libraries'] = []
        (staged/'vpp-runtime.json').write_text(json.dumps(manifest, indent=2)+'\n')
        (staged/'vpp-runtime.json').chmod(0o644)
        RUNTIME.inspect(staged, arch)
        # License materials follow the existing native dependency convention:
        # retain them with build outputs; the release package owns share/licenses.
        licenses(source, license_stage/'licenses')
        subprocess.run([
            sys.executable, str(ROOT/'native-deps/deps/static-libraries.py'),
            '--link-map', str(build/'obj/connector-vpp.map'),
            '--build-root', str(build/'obj'),
            '--output', str(license_stage/'licenses/system'),
            '--record', str(build/'static-libraries.json')], check=True)
        old = output/'vpp-runtime.json'
        check_output_path(output, Path('vpp-runtime.json'))
        previous = json.loads(old.read_text()) if old.is_file() else {'files': {}}
        old_files = previous.get('files')
        if not isinstance(old_files, dict):
            raise SystemExit('Existing VPP runtime manifest has no file inventory')
        for name in old_files:
            path = Path(name)
            if (path.is_absolute() or '..' in path.parts or
                    (name not in ('connector-vpp', 'vpp') and not name.startswith('lib/'+triplet+'/'))):
                raise SystemExit('Existing VPP manifest contains a path outside its owned files')
        for name in old_files.keys() | manifest['files'].keys():
            check_output_path(output, Path(name))
        for name in manifest['files']:
            dest = output/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged/name, dest)
        for name in old_files.keys() - manifest['files'].keys():
            (output/name).unlink(missing_ok=True)
        # Publish the completed manifest last; connector-ctl and other outputs
        # sharing this directory are never removed or replaced here.
        license_output = build/'licenses'
        if license_output.exists():
            shutil.rmtree(license_output)
        os.replace(license_stage/'licenses', license_output)
        os.replace(staged/'vpp-runtime.json', output/'vpp-runtime.json')
        print(output)
    finally:
        shutil.rmtree(staged)
        shutil.rmtree(license_stage)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--record-inputs', type=Path)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--arch', choices=('x86_64', 'aarch64'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.record_inputs:
        args.record_inputs.write_text(json.dumps(RUNTIME.native_inputs(ROOT), sort_keys=True, indent=2)+'\n')
        return
    if not all((args.build, args.source, args.arch, args.output)):
        parser.error('--build, --source, --arch and --output are required for staging')
    stage(args.build.resolve(), args.source.resolve(), args.output.absolute(), args.arch)


if __name__ == '__main__':
    main()
