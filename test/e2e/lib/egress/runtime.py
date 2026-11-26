#!/usr/bin/env python3
"""Validate or copy Connector's native VPP files in a normal bin directory."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tarfile

MANIFEST = 'vpp-runtime.json'
PLUGINS = {'nat', 'af_packet', 'ping', 'egress_policy', 'egress_geneve', 'egress_packet'}
ARCHES = {'x86_64': (62, 'x86_64-linux-gnu'), 'aarch64': (183, 'aarch64-linux-gnu')}
BASELINES = {'x86_64': 'x86-64-v2', 'aarch64': 'armv8-a+crc'}


def require(value, message):
    if not value:
        raise ValueError(message)


def native_inputs(root):
    """Hash selected source files without executing code from that source tree."""
    root = Path(root)
    paths = [root / name for name in (
        'LICENSE', 'native-deps/Makefile', 'native-deps/deps/common.sh',
        'native-deps/deps/build-vpp.sh', 'native-deps/deps/stage-vpp.py',
        'native-deps/deps/vpp-source.json', 'scripts/vpp-runtime.py')]
    patches = root / 'native-deps/deps/vpp-patches'
    paths += sorted(path for path in patches.rglob('*')
                    if path.suffix in ('.patch', '.license'))
    paths += sorted(path for path in (root / 'egress/vpp/plugins').rglob('*')
                    if not path.is_dir())
    result = {}
    for path in paths:
        require(path.is_file() and not path.is_symlink(),
                'missing or invalid native source input: ' + str(path))
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def source_metadata(root):
    return json.loads((Path(root) / 'native-deps/deps/vpp-source.json').read_text())


def verify_source(manifest, source):
    require(manifest.get('native_build_inputs') == native_inputs(source),
            'native runtime inputs differ from the selected Connector source')
    require(manifest.get('vpp') == source_metadata(source),
            'native VPP source identity differs from selected source')


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate runtime manifest key: ' + key)
        value[key] = item
    return value


def _manifest(data, arch):
    require(arch in ARCHES, 'unsupported native architecture')
    require(len(data) < 1024 * 1024, 'oversized runtime manifest')
    manifest = json.loads(data, object_pairs_hook=_unique_object)
    require(isinstance(manifest, dict) and manifest.get('schema') == 1
            and manifest.get('product') == 'connector-egress-native-runtime'
            and manifest.get('architecture') == arch, 'runtime identity mismatch')
    require(manifest.get('cpu_baseline') == BASELINES[arch], 'runtime CPU baseline mismatch')
    files = manifest.get('files')
    require(isinstance(files, dict) and 0 < len(files) < 4096, 'invalid runtime file set')
    triplet = ARCHES[arch][1]
    plugins = {'lib/' + triplet + '/vpp_plugins/' + name + '_plugin.so'
               for name in PLUGINS}
    require({'vpp'} | plugins <= set(files), 'incomplete native runtime')
    for name, digest in files.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name
                and '\\' not in name, 'unsafe runtime path: ' + name)
        require(name == 'vpp' or name in plugins
                or re.fullmatch(r'lib/' + triplet + r'/lib[A-Za-z0-9_.+-]+\.so(?:\.[0-9.]+)?', name),
                'undeclared runtime file: ' + name)
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
                'invalid runtime digest: ' + name)
    return manifest


def _check_file(name, data, expected, arch):
    require(len(data) <= 256 * 1024 * 1024, 'oversized native file: ' + name)
    require(len(data) >= 20 and data[:6] == b'\x7fELF\x02\x01'
            and struct.unpack_from('<H', data, 18)[0] == ARCHES[arch][0],
            'wrong native ELF: ' + name)
    require(hashlib.sha256(data).hexdigest() == expected, 'runtime digest mismatch: ' + name)


def _regular(root, name, mode):
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        require(not path.is_symlink(), 'runtime may not contain links: ' + name)
    require(path.is_file(), 'missing or nonregular runtime file: ' + name)
    require(stat.S_IMODE(path.stat().st_mode) == mode, 'unsafe runtime file mode: ' + name)
    return path


def inspect(runtime, arch):
    runtime = Path(runtime)
    require(runtime.is_dir() and not runtime.is_symlink(), 'invalid runtime directory')
    manifest_file = _regular(runtime, MANIFEST, 0o644)
    require(manifest_file.stat().st_size < 1024 * 1024, 'oversized runtime manifest')
    manifest = _manifest(manifest_file.read_bytes(), arch)
    triplet = ARCHES[arch][1]
    lib = runtime / 'lib' / triplet
    actual = {'vpp'}
    if lib.exists():
        require(lib.is_dir() and not lib.is_symlink() and not lib.parent.is_symlink(),
                'invalid runtime library directory')
        for path in lib.rglob('*'):
            require(not path.is_symlink(), 'runtime may not contain links: ' + str(path))
            if path.is_dir():
                continue
            require(path.is_file(), 'runtime contains a special file: ' + str(path))
            actual.add(path.relative_to(runtime).as_posix())
    require(actual == set(manifest['files']), 'runtime manifest file set mismatch')
    total = 0
    for name, digest in manifest['files'].items():
        path = _regular(runtime, name, 0o755 if name == 'vpp' else 0o644)
        total += path.stat().st_size
        require(path.stat().st_size <= 256 * 1024 * 1024 and total <= 1024 * 1024 * 1024,
                'invalid native runtime size')
        _check_file(name, path.read_bytes(), digest, arch)
    return manifest


def copy(runtime, output, arch):
    """Copy only VPP-owned files; connector-ctl and other products are untouched."""
    runtime, output = Path(runtime), Path(output)
    manifest = inspect(runtime, arch)
    require(not output.is_symlink(), 'invalid runtime output directory')
    names = [*sorted(manifest['files']), MANIFEST]
    for name in names:
        path = output
        for part in PurePosixPath(name).parts:
            path = path / part
            require(not path.is_symlink(), 'runtime output may not contain links')
        require(not path.exists(), 'native output already exists: ' + name)
    output.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for name in names:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(runtime / name, target)
            created.append(target)
            target.chmod(0o755 if name == 'vpp' else 0o644)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return manifest


def inspect_archive(path, arch):
    """Validate VPP files directly in an ordinary Connector release archive."""
    with tarfile.open(path, 'r:*') as archive:
        entries = {}
        for item in archive:
            name = item.name.removeprefix('./').rstrip('/')
            if name in ('', '.'):
                continue
            require(name not in entries, 'duplicate archive path: ' + name)
            entries[name] = item
        manifest_name = 'bin/' + MANIFEST
        native = {name.removeprefix('bin/') for name in entries
                  if name == 'bin/vpp' or (name.startswith('bin/lib/') and not entries[name].isdir())}
        if manifest_name not in entries:
            require(not native, 'native files without runtime manifest')
            return None

        def read(name, limit, mode):
            item = entries.get(name)
            require(item is not None and item.isfile() and item.uid == item.gid == 0
                    and item.mode == mode and item.size <= limit,
                    'missing or invalid native archive file: ' + name)
            return archive.extractfile(item).read()

        manifest = _manifest(read(manifest_name, 1024 * 1024 - 1, 0o644), arch)
        require(native == set(manifest['files']), 'archive runtime file set mismatch')
        total = 0
        for name, digest in manifest['files'].items():
            data = read('bin/' + name, 256 * 1024 * 1024, 0o755 if name == 'vpp' else 0o644)
            total += len(data)
            require(total <= 1024 * 1024 * 1024, 'invalid native archive size')
            _check_file(name, data, digest, arch)
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('validate', 'copy', 'archive-files'))
    parser.add_argument('--arch', required=True, choices=ARCHES)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--source', type=Path, help='selected Connector repository for input binding')
    args = parser.parse_args()
    if args.command == 'archive-files':
        require(args.archive is not None, '--archive is required')
        manifest = inspect_archive(args.archive, args.arch)
        if manifest is not None:
            for name in sorted([*manifest['files'], MANIFEST]):
                print('bin/' + name)
        return
    require(args.runtime is not None, '--runtime is required')
    manifest = inspect(args.runtime, args.arch)
    if args.source is not None:
        verify_source(manifest, args.source)
    if args.command == 'copy':
        require(args.output is not None, '--output is required')
        copy(args.runtime, args.output, args.arch)


if __name__ == '__main__':
    main()
