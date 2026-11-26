"""Exercise the source/patch lifecycle without downloading or compiling VPP."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import unittest

DEPS = Path(__file__).resolve().parents[1]/'deps'


class VPPWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpp-workflow-')
        self.root = Path(self.temp.name)
        deps = self.root/'native-deps/deps'
        deps.mkdir(parents=True)
        for name in ('common.sh', 'build-vpp.sh'):
            shutil.copy2(DEPS/name, deps/name)
        source = self.root/'upstream'
        (source/'src/scripts').mkdir(parents=True)
        (source/'src/scripts/version').write_text('#!/bin/sh\ncat "$(dirname "$0")/.version"\n')
        (source/'source.txt').write_text('base\n')
        self.archive = self.root/'source.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as archive:
            archive.add(source, arcname='vpp-test')
        lock = json.loads((DEPS/'vpp-source.json').read_text())
        self.version = lock['version']
        lock.update(tarball=str(self.archive), tarball_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest())
        (deps/'vpp-source.json').write_text(json.dumps(lock))
        self.script = deps/'build-vpp.sh'
        self.source = self.root/'managed-source'
        self.patches = self.root/'patches'
        self.patches.mkdir()
        self.env = dict(os.environ, VPP_BUILD_SRC=str(self.source),
                        VPP_BUILD_OUT=str(self.root/'objects'),
                        VPP_PATCHES_DIR=str(self.patches),
                        TARBALL_CACHE=str(self.root/'tarballs'),
                        BUILD_DIR=str(self.root/'build'), BINDIR=str(self.root/'bin'),
                        TARGET_ARCH=platform.machine(), SOURCE_DATE_EPOCH='0',
                        GIT_AUTHOR_NAME='Test', GIT_AUTHOR_EMAIL='test@example.invalid',
                        GIT_COMMITTER_NAME='Test', GIT_COMMITTER_EMAIL='test@example.invalid',
                        GIT_AUTHOR_DATE='2000-01-01T00:00:00+0000',
                        GIT_COMMITTER_DATE='2000-01-01T00:00:00+0000')
        self.run_stage('fetch')
        (self.source/'source.txt').write_text('first\n')
        self.git('add', 'source.txt')
        self.git('commit', '-qm', 'Change source')
        self.run_stage('patches-format')
        self.git('reset', '--hard', 'vpp-patches-base')

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), *args],
                                       env=self.env, text=True, stderr=subprocess.STDOUT)

    def run_stage(self, stage, ok=True, **extra):
        env = dict(self.env, STAGE=stage, **extra)
        result = subprocess.run(['bash', str(self.script)], env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout

    def test_repeated_fetch_and_apply_preserve_source(self):
        self.run_stage('patches-apply')
        head = self.git('rev-parse', 'HEAD')
        self.run_stage('fetch')
        self.run_stage('patches-apply')
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual((self.source/'source.txt').read_text(), 'first\n')
        self.assertTrue((self.source/'src/scripts/.version').read_text().startswith('v'+self.version+'-0-g'))

    def test_changed_patch_body_with_same_subject_is_rejected(self):
        self.run_stage('patches-apply')
        patch = next(self.patches.glob('*.patch'))
        patch.write_text(patch.read_text().replace('+first\n', '+second\n'))
        output = self.run_stage('patches-apply', ok=False)
        self.assertIn('source differs from maintained patches', output)
        self.assertEqual((self.source/'source.txt').read_text(), 'first\n')

    def test_uncommitted_work_is_preserved(self):
        self.run_stage('patches-apply')
        (self.source/'source.txt').write_text('uncommitted\n')
        output = self.run_stage('patches-apply', ok=False)
        self.assertIn('uncommitted changes', output)
        self.assertEqual((self.source/'source.txt').read_text(), 'uncommitted\n')

    def test_format_and_apply_roundtrip(self):
        self.run_stage('patches-apply')
        (self.source/'source.txt').write_text('second\n')
        self.git('add', 'source.txt')
        self.git('commit', '-qm', 'Change again')
        (self.patches/'README.md').write_text('Keep documentation\n')
        self.run_stage('patches-format')
        self.assertEqual(len(list(self.patches.glob('*.patch'))), 2)
        expected = self.git('rev-parse', 'HEAD^{tree}')
        self.git('reset', '--hard', 'vpp-patches-base')
        self.run_stage('patches-apply')
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), expected)
        self.assertEqual((self.patches/'README.md').read_text(), 'Keep documentation\n')

    def test_changed_archive_identity_does_not_reuse_old_source(self):
        output = self.run_stage('fetch', ok=False, VPP_TARBALL_SHA256='0'*64)
        self.assertIn('source archive differs', output)
        self.assertEqual((self.source/'source.txt').read_text(), 'base\n')

    def test_wrong_archive_checksum_rejects_fresh_import(self):
        fresh = self.root/'fresh-source'
        output = self.run_stage('fetch', ok=False, VPP_BUILD_SRC=str(fresh),
                                VPP_TARBALL_SHA256='0'*64)
        self.assertIn('sha256 mismatch', output)
        self.assertFalse(fresh.exists())

    def test_foreign_source_tree_is_not_removed(self):
        foreign = self.root/'foreign-source'
        foreign.mkdir()
        (foreign/'work.txt').write_text('preserve me')
        self.run_stage('fetch', ok=False, VPP_BUILD_SRC=str(foreign))
        self.assertEqual((foreign/'work.txt').read_text(), 'preserve me')

    def test_build_rejects_other_arch_before_compiling(self):
        other = 'aarch64' if platform.machine() == 'x86_64' else 'x86_64'
        output = self.run_stage('build', ok=False, TARGET_ARCH=other)
        self.assertIn('requires a native', output)


if __name__ == '__main__':
    unittest.main()
