"""Verify VPP's ownership boundary in the shared executable output directory."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1]/'deps/stage-vpp.py'
SPEC = importlib.util.spec_from_file_location('stage_vpp', SCRIPT)
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


def elf(machine=62):
    value = bytearray(120)
    value[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', value, 16,
                     2, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', value, 64, 1, 5, 0, 0, 0, 120, 120, 4096)
    return bytes(value)


class VPPStagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpp-staging-')
        self.root = Path(self.temp.name)
        self.build = self.root/'build'
        self.source = self.root/'source'
        self.output = self.root/'bin/x86_64'
        (self.build/'obj').mkdir(parents=True)
        (self.build/'obj/connector-vpp').write_bytes(elf())
        (self.build/'obj/CMakeCache.txt').write_text(
            'VPP_BUILD_NATIVE_ARCH:STRING=x86-64-v2\nVPP_STATIC_EGRESS:BOOL=ON\n')
        (self.build/'build-inputs.json').write_text(json.dumps(STAGE.RUNTIME.native_inputs(STAGE.ROOT)))
        (self.source/'.git').mkdir(parents=True)
        metadata = STAGE.RUNTIME.source_metadata(STAGE.ROOT)
        (self.source/'.git/vpp-source.json').write_text(json.dumps({
            key: metadata[key] for key in ('commit', 'version', 'tarball_sha256')}))
        (self.source/'LICENSE').write_text('Upstream license fixture\n')
        self.output.mkdir(parents=True)
        (self.output/'connector-ctl').write_bytes(b'preserve this command')

    def tearDown(self):
        self.temp.cleanup()

    def stage(self):
        with mock.patch.object(STAGE.subprocess, 'run'):
            STAGE.stage(self.build, self.source, self.output, 'x86_64')

    def test_rebuild_preserves_sibling_tool_and_removes_retired_library(self):
        old = self.output/'lib/x86_64-linux-gnu/libretired.so'
        old.parent.mkdir(parents=True)
        old.write_bytes(elf())
        (self.output/'vpp').write_bytes(elf())
        (self.output/'vpp-runtime.json').write_text(json.dumps({'files': {
            'vpp': 'old', 'lib/x86_64-linux-gnu/libretired.so': 'old'}}))
        self.stage()
        self.assertEqual((self.output/'connector-ctl').read_bytes(), b'preserve this command')
        self.assertFalse(old.exists())
        self.assertFalse((self.output/'vpp').exists())
        manifest = STAGE.RUNTIME.inspect(self.output, 'x86_64')
        self.assertEqual(set(manifest['files']), {'connector-vpp'})
        self.assertEqual(manifest['required_system_libraries'], [])
        self.assertTrue((self.build/'licenses/VPP-LICENSE').is_file())
        self.assertFalse((self.output/'share').exists())

    def test_wrong_architecture_does_not_replace_existing_runtime(self):
        self.stage()
        before = (self.output/'vpp-runtime.json').read_bytes()
        (self.build/'obj/connector-vpp').write_bytes(elf(183))
        with self.assertRaisesRegex(SystemExit, 'Wrong architecture'):
            self.stage()
        self.assertEqual((self.output/'vpp-runtime.json').read_bytes(), before)
        STAGE.RUNTIME.inspect(self.output, 'x86_64')

    def test_dynamic_interpreter_does_not_replace_existing_runtime(self):
        self.stage()
        before = (self.output/'vpp-runtime.json').read_bytes()
        dynamic = bytearray(elf())
        struct.pack_into('<I', dynamic, 64, 3)
        (self.build/'obj/connector-vpp').write_bytes(dynamic)
        with self.assertRaisesRegex(ValueError, 'dynamic interpreter'):
            self.stage()
        self.assertEqual((self.output/'vpp-runtime.json').read_bytes(), before)
        STAGE.RUNTIME.inspect(self.output, 'x86_64')

    def test_nonstatic_build_is_rejected_before_staging(self):
        cache = self.build/'obj/CMakeCache.txt'
        cache.write_text(cache.read_text().replace('VPP_STATIC_EGRESS:BOOL=ON',
                                                   'VPP_STATIC_EGRESS:BOOL=OFF'))
        with self.assertRaisesRegex(SystemExit, 'fixed static Egress build'):
            self.stage()
        self.assertFalse((self.output/'connector-vpp').exists())

    def test_archive_override_cannot_claim_locked_source_identity(self):
        path = self.source/'.git/vpp-source.json'
        metadata = json.loads(path.read_text())
        metadata['tarball_sha256'] = '0'*64
        path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(SystemExit, 'archive differs'):
            self.stage()
        self.assertFalse((self.output/'connector-vpp').exists())

    def test_symlink_library_directory_cannot_write_outside_output(self):
        outside = self.root/'outside'
        outside.mkdir()
        (self.output/'lib').symlink_to(outside, target_is_directory=True)
        (self.output/'vpp-runtime.json').write_text(json.dumps({'files': {
            'lib/x86_64-linux-gnu/retired.so': 'old'}}))
        with self.assertRaisesRegex(SystemExit, 'may not contain links'):
            self.stage()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.output/'connector-vpp').exists())

    def test_modes_are_normalized_with_restrictive_umask(self):
        (self.source/'LICENSE').chmod(0o664)
        old_umask = os.umask(0o077)
        try:
            self.stage()
        finally:
            os.umask(old_umask)
        STAGE.RUNTIME.inspect(self.output, 'x86_64')
        for path in (self.build/'licenses').rglob('*'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)


if __name__ == '__main__':
    unittest.main()
