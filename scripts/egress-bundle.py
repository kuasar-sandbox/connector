#!/usr/bin/env python3
"""Pack or validate the same-version native runtime without executing its code."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import tarfile

PLUGINS = {'nat', 'af_packet', 'ping', 'egress_policy', 'egress_geneve', 'egress_packet'}
ARCHES = {'x86_64': (62, 'x86_64-linux-gnu'), 'aarch64': (183, 'aarch64-linux-gnu')}


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(bundle, arch):
    require(arch in ARCHES, 'unsupported native architecture')
    machine, triplet = ARCHES[arch]
    with tarfile.open(bundle, 'r:') as archive:
        entries = {}
        total = 0
        for item in archive:
            name = item.name
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and str(path) == name
                    and '\\' not in name and name not in entries, 'unsafe or duplicate runtime path')
            require(item.isfile() and item.uid == item.gid == 0 and not item.pax_headers,
                    'runtime entries must be plain root-owned regular files')
            executable = name == 'bin/vpp'
            require(item.mode == (0o755 if executable else 0o644), 'unsafe runtime file mode')
            allowed = (name in ('runtime.json', 'bin/vpp')
                       or re.fullmatch(r'lib/'+triplet+r'/lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9.]+)?', name)
                       or name in {'lib/'+triplet+'/vpp_plugins/'+p+'_plugin.so' for p in PLUGINS}
                       or name.startswith('share/licenses/'))
            require(allowed, 'undeclared runtime file: '+name)
            total += item.size
            require(item.size <= 256*1024*1024 and total <= 1024*1024*1024 and len(entries) < 4096,
                    'invalid native archive size')
            entries[name] = item
        require('runtime.json' in entries and entries['runtime.json'].size < 1024*1024,
                'missing or oversized runtime manifest')
        manifest = json.load(archive.extractfile(entries['runtime.json']))
        require(manifest.get('schema') == 1 and manifest.get('product') == 'connector-egress-native-runtime'
                and manifest.get('architecture') == arch, 'runtime identity mismatch')
        require(set(entries) == set(manifest['files']) | {'runtime.json'}, 'runtime manifest file set mismatch')
        needed = {'bin/vpp', 'share/licenses/CONNECTOR-LICENSE', 'share/licenses/VPP-LICENSE',
                  'share/licenses/VPP-EMBEDDED-NOTICES'}
        needed.update('lib/'+triplet+'/vpp_plugins/'+p+'_plugin.so' for p in PLUGINS)
        require(needed <= set(entries), 'incomplete native runtime')
        for name, expected in manifest['files'].items():
            require(re.fullmatch('[0-9a-f]{64}', expected), 'invalid runtime digest')
            stream = archive.extractfile(entries[name])
            header = stream.read(20)
            if name.startswith(('bin/', 'lib/')):
                require(len(header) == 20 and header[:6] == b'\x7fELF\x02\x01'
                        and struct.unpack_from('<H', header, 18)[0] == machine, 'wrong native ELF: '+name)
            digest = hashlib.sha256(header)
            for block in iter(lambda: stream.read(1024*1024), b''):
                digest.update(block)
            require(digest.hexdigest() == expected, 'runtime digest mismatch: '+name)
        return manifest


def extract(bundle, output, arch):
    inspect(bundle, arch)
    require(not output.exists(), 'runtime extraction output already exists')
    output.mkdir(parents=True)
    try:
        with tarfile.open(bundle, 'r:') as archive:
            for item in archive:
                target = output/item.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, target.open('xb') as dest:
                    shutil.copyfileobj(source, dest)
                target.chmod(item.mode)
    except BaseException:
        shutil.rmtree(output)
        raise


def pack(runtime, output, arch):
    require(runtime.is_dir() and not runtime.is_symlink(), 'invalid staged runtime')
    require(not output.exists(), 'bundle output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(output, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(runtime.rglob('*')):
                require(not path.is_symlink(), 'runtime may not contain links')
                if path.is_dir():
                    continue
                require(path.is_file(), 'runtime contains a special file')
                item = tarfile.TarInfo(path.relative_to(runtime).as_posix())
                item.size = path.stat().st_size
                item.mode = 0o755 if item.name == 'bin/vpp' else 0o644
                with path.open('rb') as stream:
                    archive.addfile(item, stream)
        inspect(output, arch)
        output.chmod(0o644)
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('pack', 'validate', 'extract'))
    parser.add_argument('--arch', required=True, choices=ARCHES)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--runtime', type=Path)
    args = parser.parse_args()
    if args.command == 'validate':
        inspect(args.bundle, args.arch)
    else:
        require(args.runtime is not None, '--runtime is required')
        if args.command == 'pack':
            pack(args.runtime, args.bundle, args.arch)
        else:
            extract(args.bundle, args.runtime, args.arch)


if __name__ == '__main__':
    main()
