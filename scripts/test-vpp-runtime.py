#!/usr/bin/env python3
"""Exercise direct native-directory delivery without executing fixture binaries."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('vpp_runtime', HERE / 'vpp-runtime.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def elf(machine=62, interpreter=False, needed=False, pie=False):
    """A bounded ELF fixture with a load segment and optional dynamic input."""
    payload = b'/lib/ld-linux.so.2\0' if interpreter else b''
    if needed:
        payload = struct.pack('<qQqQ', 1, 1, 0, 0)
    count = 2 if payload else 1
    offset = 64 + count * 56
    data = bytearray(offset + len(payload))
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     3 if pie else 2, machine, 1, 0x400000, 64, 0, 0,
                     64, 56, count, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0x400000,
                     len(data), len(data), 4096)
    if payload:
        struct.pack_into('<IIQQQQQQ', data, 120, 3 if interpreter else 2, 4,
                         offset, 0x400000 + offset, 0x400000 + offset,
                         len(payload), len(payload), 8)
        data[offset:] = payload
    return bytes(data)


class RuntimeAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.source = self.root / 'source'
        for name in ('LICENSE', 'native-deps/Makefile', 'native-deps/deps/common.sh',
                     'native-deps/deps/build-vpp.sh', 'native-deps/deps/stage-vpp.py',
                     'native-deps/deps/static-libraries.py',
                     'scripts/vpp-runtime.py', 'egress/vpp/plugins/egress_policy/policy.c',
                     'native-deps/deps/vpp-patches/0001-policy.patch.license'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture input: ' + name + '\n')
        self.patch = self.source / 'native-deps/deps/vpp-patches/0001-policy.patch'
        self.patch.write_text('Subject: [PATCH] native policy\n\n-old\n+first\n')
        metadata = {'version': '26.10', 'commit': '1' * 40,
                    'tarball': 'https://example.invalid/vpp.tar.gz', 'tarball_sha256': '2' * 64}
        (self.source / 'native-deps/deps/vpp-source.json').write_text(json.dumps(metadata))
        files = {runtime.BINARY: elf()}
        for name, content in files.items():
            path = self.bin / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o755)
        (self.bin / 'connector-ctl').write_bytes(b'neighbor control program\n')
        (self.bin / 'connector-ctl').chmod(0o755)
        self.manifest = {'schema': 1, 'product': 'connector-egress-native-runtime',
                         'architecture': 'x86_64', 'cpu_baseline': 'x86-64-v2',
                         'vpp': metadata, 'native_build_inputs': runtime.native_inputs(self.source),
                         'required_system_libraries': [],
                         'files': {name: hashlib.sha256(content).hexdigest()
                                   for name, content in files.items()}}
        self.write_manifest()

    def write_manifest(self):
        path = self.bin / runtime.MANIFEST
        path.write_text(json.dumps(self.manifest))
        path.chmod(0o644)

    def write_binary(self, data):
        (self.bin / runtime.BINARY).write_bytes(data)
        self.manifest['files'][runtime.BINARY] = hashlib.sha256(data).hexdigest()
        self.write_manifest()

    def archive(self, mutate=None):
        """Build an ordinary outer component archive, including an unrelated CLI."""
        entries = []
        for path in sorted(self.bin.rglob('*')):
            if path.is_file():
                info = tarfile.TarInfo('./bin/' + path.relative_to(self.bin).as_posix())
                info.mode = path.stat().st_mode & 0o777
                content = path.read_bytes()
                info.size = len(content)
                entries.append((info, content))
        if mutate:
            mutate(entries)
        result = self.root / 'connector-v1.2.3-linux-x86_64.tar.gz'
        with tarfile.open(result, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for info, content in entries:
                archive.addfile(info, io.BytesIO(content) if info.isfile() else None)
        return result

    def test_copy_preserves_adjacent_control_program_and_relative_layout(self):
        destination = self.root / 'destination'
        destination.mkdir()
        control = destination / 'connector-ctl'
        control.write_bytes(b'selected control program\n')
        control.chmod(0o755)
        runtime.copy(self.bin, destination, 'x86_64')
        self.assertEqual(control.read_bytes(), b'selected control program\n')
        self.assertEqual(runtime.inspect(destination, 'x86_64'), self.manifest)
        actual = {path.relative_to(destination).as_posix()
                  for path in destination.rglob('*') if path.is_file()}
        self.assertEqual(actual, set(self.manifest['files']) | {runtime.MANIFEST, 'connector-ctl'})
        self.assertEqual((destination / runtime.BINARY).stat().st_mode & 0o777, 0o755)
        self.assertFalse((destination / 'bin').exists())

    def test_copy_refuses_owned_file_collision_without_touching_existing_files(self):
        destination = self.root / 'destination'
        destination.mkdir()
        (destination / runtime.BINARY).write_bytes(b'existing VPP')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            runtime.copy(self.bin, destination, 'x86_64')
        self.assertEqual((destination / runtime.BINARY).read_bytes(), b'existing VPP')
        self.assertEqual(set(destination.iterdir()), {destination / runtime.BINARY})

    def test_copy_refuses_linked_output_parent(self):
        destination = self.root / 'destination'
        outside = self.root / 'outside'
        outside.mkdir()
        destination.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'output directory'):
            runtime.copy(self.bin, destination, 'x86_64')
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((destination / runtime.BINARY).exists())

    def test_changed_payload_requires_matching_digest(self):
        with (self.bin / runtime.BINARY).open('ab') as stream:
            stream.write(b'changed executable')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            runtime.inspect(self.bin, 'x86_64')

    def test_missing_binary_is_rejected_even_when_removed_from_manifest(self):
        (self.bin / runtime.BINARY).unlink()
        del self.manifest['files'][runtime.BINARY]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'must contain only'):
            runtime.inspect(self.bin, 'x86_64')

    def test_unrelated_libraries_are_not_claimed_or_copied(self):
        library = self.bin / 'lib/another-product.so'
        library.parent.mkdir()
        library.write_bytes(b'neighbor product')
        destination = self.root / 'destination'
        runtime.copy(self.bin, destination, 'x86_64')
        self.assertFalse((destination / 'lib').exists())
        self.assertEqual(library.read_bytes(), b'neighbor product')

    def test_dynamic_interpreter_and_dependencies_are_rejected(self):
        for content, message in ((elf(interpreter=True), 'dynamic interpreter'),
                                 (elf(needed=True), 'shared-library dependency')):
            with self.subTest(message=message):
                self.write_binary(content)
                with self.assertRaisesRegex(ValueError, message):
                    runtime.inspect(self.bin, 'x86_64')
                with self.assertRaisesRegex(ValueError, message):
                    runtime.inspect_archive(self.archive(), 'x86_64')

    def test_static_pie_is_accepted_and_system_library_claims_rejected(self):
        self.write_binary(elf(pie=True))
        runtime.inspect(self.bin, 'x86_64')
        self.manifest['required_system_libraries'] = ['libc.so.6']
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'must not require'):
            runtime.inspect(self.bin, 'x86_64')

    def test_malformed_program_headers_and_dynamic_tables_are_rejected(self):
        invalid = []
        missing = bytearray(elf())
        struct.pack_into('<H', missing, 56, 0)
        invalid.append(missing)
        missing_load = bytearray(elf())
        struct.pack_into('<I', missing_load, 64, 4)
        invalid.append(missing_load)
        truncated = bytearray(elf())
        struct.pack_into('<Q', truncated, 32, 1000)
        invalid.append(truncated)
        overflow = bytearray(elf())
        struct.pack_into('<Q', overflow, 96, len(overflow) + 1)
        invalid.append(overflow)
        unterminated = bytearray(elf(needed=True))
        struct.pack_into('<q', unterminated, 176, 2)
        struct.pack_into('<q', unterminated, 192, 2)
        invalid.append(unterminated)
        for index, content in enumerate(invalid):
            with self.subTest(case=index):
                self.write_binary(content)
                with self.assertRaises(ValueError):
                    runtime.inspect(self.bin, 'x86_64')

    def test_architecture_and_cpu_baseline_are_checked(self):
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            runtime.inspect(self.bin, 'aarch64')
        self.manifest['cpu_baseline'] = 'native'
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'CPU baseline mismatch'):
            runtime.inspect(self.bin, 'x86_64')
        self.manifest['cpu_baseline'] = 'x86-64-v2'
        content = bytearray((self.bin / runtime.BINARY).read_bytes())
        struct.pack_into('<H', content, 18, 183)
        self.write_binary(content)
        with self.assertRaisesRegex(ValueError, 'wrong native ELF'):
            runtime.inspect(self.bin, 'x86_64')

    def test_manifest_cannot_claim_control_program_or_escape_output(self):
        for name in ('connector-ctl', '../escape', '/escape', 'lib/../escape',
                     'lib/x86_64-linux-gnu/libvlib.so'):
            with self.subTest(path=name):
                self.manifest['files'][name] = '0' * 64
                self.write_manifest()
                with self.assertRaises(ValueError):
                    runtime.copy(self.bin, self.root / 'destination', 'x86_64')
                self.assertFalse((self.root / 'destination').exists())
                del self.manifest['files'][name]

    def test_links_and_unsafe_modes_are_rejected(self):
        for name in (runtime.MANIFEST, runtime.BINARY):
            with self.subTest(link=name):
                candidate = self.root / ('candidate-' + name.replace('/', '-'))
                shutil.copytree(self.bin, candidate)
                path = candidate / name
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                path.symlink_to(self.bin / name, target_is_directory=(self.bin / name).is_dir())
                with self.assertRaisesRegex(ValueError, 'links'):
                    runtime.inspect(candidate, 'x86_64')
        for name, mode in ((runtime.BINARY, 0o4755), (runtime.MANIFEST, 0o666)):
            with self.subTest(mode=name):
                path = self.bin / name
                original = path.stat().st_mode & 0o7777
                path.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'file mode'):
                    runtime.inspect(self.bin, 'x86_64')
                path.chmod(original)

    def test_duplicate_manifest_keys_are_rejected(self):
        path = self.bin / runtime.MANIFEST
        content = path.read_text().replace('"architecture": "x86_64"',
                                            '"architecture": "aarch64", "architecture": "x86_64"')
        path.write_text(content)
        with self.assertRaisesRegex(ValueError, 'duplicate runtime manifest key'):
            runtime.inspect(self.bin, 'x86_64')

    def test_outer_release_archive_contains_native_files_directly(self):
        archive = self.archive()
        self.assertEqual(runtime.inspect_archive(archive, 'x86_64'), self.manifest)
        with tarfile.open(archive) as stream:
            names = {info.name.removeprefix('./') for info in stream}
        self.assertIn('bin/' + runtime.BINARY, names)
        self.assertFalse(any(name.startswith('bin/lib/') for name in names))
        self.assertIn('bin/' + runtime.MANIFEST, names)
        self.assertIn('bin/connector-ctl', names)
        self.assertFalse(any(name.endswith('.bundle') for name in names))
        result = subprocess.run([sys.executable, str(HERE / 'vpp-runtime.py'), 'archive-files',
                                 '--arch', 'x86_64', '--archive', str(archive)],
                                check=True, capture_output=True, text=True)
        self.assertEqual(set(result.stdout.splitlines()),
                         {'bin/' + name for name in self.manifest['files']} | {'bin/' + runtime.MANIFEST})

    def test_archive_rejects_missing_manifest_links_and_duplicate_paths(self):
        def missing(entries):
            entries[:] = [(info, data) for info, data in entries
                          if info.name != './bin/' + runtime.MANIFEST]

        def link(entries):
            info = next(info for info, _ in entries if info.name == './bin/' + runtime.BINARY)
            info.type, info.linkname, info.size = tarfile.SYMTYPE, '/external/connector-vpp', 0

        def duplicate(entries):
            entries.append(entries[0])

        for mutation in (missing, link, duplicate):
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                runtime.inspect_archive(self.archive(mutation), 'x86_64')

    def test_source_receipt_tracks_patch_contents_and_all_native_sources(self):
        runtime.verify_source(self.manifest, self.source)
        for name in (self.patch, self.source / 'egress/vpp/plugins/egress_policy/policy.c',
                     self.source / 'native-deps/deps/build-vpp.sh'):
            with self.subTest(input=name.relative_to(self.source)):
                original = name.read_text()
                # The filename and patch Subject stay identical after this edit.
                name.write_text(original + '\n+changed implementation\n')
                with self.assertRaisesRegex(ValueError, 'inputs differ'):
                    runtime.verify_source(self.manifest, self.source)
                name.write_text(original)
        self.manifest['vpp'] = dict(self.manifest['vpp'], commit='3' * 40)
        with self.assertRaisesRegex(ValueError, 'source identity differs'):
            runtime.verify_source(self.manifest, self.source)

    def test_prepared_test_reader_matches_packaging_reader(self):
        self.assertEqual((HERE / 'vpp-runtime.py').read_bytes(),
                         (HERE.parent / 'test/e2e/lib/egress/runtime.py').read_bytes())


if __name__ == '__main__':
    unittest.main()
