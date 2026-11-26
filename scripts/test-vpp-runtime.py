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
        header = bytearray(64)
        header[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', header, 18, 62)
        self.library = 'lib/x86_64-linux-gnu/libvlib.so.0'
        self.plugin = 'lib/x86_64-linux-gnu/vpp_plugins/nat_plugin.so'
        files = {'vpp': bytes(header), self.library: bytes(header)}
        files.update({'lib/x86_64-linux-gnu/vpp_plugins/' + name + '_plugin.so': bytes(header)
                      for name in runtime.PLUGINS})
        for name, content in files.items():
            path = self.bin / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o755 if name == 'vpp' else 0o644)
        (self.bin / 'connector-ctl').write_bytes(b'neighbor control program\n')
        (self.bin / 'connector-ctl').chmod(0o755)
        self.manifest = {'schema': 1, 'product': 'connector-egress-native-runtime',
                         'architecture': 'x86_64', 'cpu_baseline': 'x86-64-v2',
                         'vpp': metadata, 'native_build_inputs': runtime.native_inputs(self.source),
                         'files': {name: hashlib.sha256(content).hexdigest()
                                   for name, content in files.items()}}
        self.write_manifest()

    def write_manifest(self):
        path = self.bin / runtime.MANIFEST
        path.write_text(json.dumps(self.manifest))
        path.chmod(0o644)

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
        self.assertEqual((destination / 'vpp').stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination / self.library).stat().st_mode & 0o777, 0o644)
        self.assertFalse((destination / 'bin').exists())

    def test_copy_refuses_owned_file_collision_without_touching_existing_files(self):
        destination = self.root / 'destination'
        destination.mkdir()
        (destination / 'vpp').write_bytes(b'existing VPP')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            runtime.copy(self.bin, destination, 'x86_64')
        self.assertEqual((destination / 'vpp').read_bytes(), b'existing VPP')
        self.assertEqual(set(destination.iterdir()), {destination / 'vpp'})

    def test_copy_refuses_linked_output_parent(self):
        destination = self.root / 'destination'
        destination.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (destination / 'lib').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'links'):
            runtime.copy(self.bin, destination, 'x86_64')
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((destination / 'vpp').exists())

    def test_changed_payload_requires_matching_digest(self):
        with (self.bin / self.library).open('ab') as stream:
            stream.write(b'changed library')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            runtime.inspect(self.bin, 'x86_64')

    def test_missing_plugin_is_rejected_even_when_removed_from_manifest(self):
        (self.bin / self.plugin).unlink()
        del self.manifest['files'][self.plugin]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'incomplete native runtime'):
            runtime.inspect(self.bin, 'x86_64')

    def test_undeclared_library_is_not_silently_copied(self):
        (self.bin / 'lib/x86_64-linux-gnu/unexpected.so').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'file set mismatch'):
            runtime.copy(self.bin, self.root / 'destination', 'x86_64')
        self.assertFalse((self.root / 'destination').exists())

    def test_architecture_and_cpu_baseline_are_checked(self):
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            runtime.inspect(self.bin, 'aarch64')
        self.manifest['cpu_baseline'] = 'native'
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'CPU baseline mismatch'):
            runtime.inspect(self.bin, 'x86_64')
        self.manifest['cpu_baseline'] = 'x86-64-v2'
        content = bytearray((self.bin / self.library).read_bytes())
        struct.pack_into('<H', content, 18, 183)
        (self.bin / self.library).write_bytes(content)
        self.manifest['files'][self.library] = hashlib.sha256(content).hexdigest()
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'wrong native ELF'):
            runtime.inspect(self.bin, 'x86_64')

    def test_manifest_cannot_claim_control_program_or_escape_output(self):
        for name in ('connector-ctl', '../escape', '/escape', 'lib/../escape'):
            with self.subTest(path=name):
                self.manifest['files'][name] = '0' * 64
                self.write_manifest()
                with self.assertRaises(ValueError):
                    runtime.copy(self.bin, self.root / 'destination', 'x86_64')
                self.assertFalse((self.root / 'destination').exists())
                del self.manifest['files'][name]

    def test_links_and_unsafe_modes_are_rejected(self):
        for name in (runtime.MANIFEST, 'vpp', self.library, 'lib',
                     'lib/x86_64-linux-gnu/vpp_plugins'):
            with self.subTest(link=name):
                candidate = self.root / ('candidate-' + name.replace('/', '-'))
                shutil.copytree(self.bin, candidate)
                path = candidate / name
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                path.symlink_to(self.bin / name, target_is_directory=(self.bin / name).is_dir())
                with self.assertRaisesRegex(ValueError, 'links|library directory'):
                    runtime.inspect(candidate, 'x86_64')
        for name, mode in (('vpp', 0o4755), (self.library, 0o755), (runtime.MANIFEST, 0o666)):
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
        self.assertIn('bin/vpp', names)
        self.assertIn('bin/' + self.library, names)
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
            info = next(info for info, _ in entries if info.name == './bin/vpp')
            info.type, info.linkname, info.size = tarfile.SYMTYPE, '/external/vpp', 0

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
