#!/usr/bin/env python3
"""Exercise archive admission before any native product can be extracted."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bundle',HERE/'egress-bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)

class BundleAdmission(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.runtime=self.root/'runtime';self.runtime.mkdir()
        elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',elf,18,62)
        files={'bin/vpp':bytes(elf)}
        for plugin in bundle.PLUGINS:files['lib/x86_64-linux-gnu/vpp_plugins/'+plugin+'_plugin.so']=bytes(elf)
        for name in ['CONNECTOR-LICENSE','VPP-LICENSE','VPP-EMBEDDED-NOTICES']:files['share/licenses/'+name]=b'license\n'
        for name,data in files.items():
            target=self.runtime/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        manifest={'schema':1,'product':'connector-egress-native-runtime','architecture':'x86_64',
                  'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
        (self.runtime/'runtime.json').write_text(json.dumps(manifest))
        self.archive=self.root/'runtime.bundle';bundle.pack(self.runtime,self.archive,'x86_64')
    def altered(self,mutation):
        target=self.root/'altered.bundle'
        with tarfile.open(self.archive) as source,tarfile.open(target,'w',format=tarfile.USTAR_FORMAT) as output:
            rows=[(m,source.extractfile(m).read()) for m in source]
            mutation(rows)
            for m,data in rows:output.addfile(m,io.BytesIO(data) if m.isfile() else None)
        return target
    def test_valid_bundle_is_extracted_with_native_modes(self):
        dest=self.root/'extracted';bundle.extract(self.archive,dest,'x86_64')
        self.assertEqual((dest/'bin/vpp').stat().st_mode&0o777,0o755)
        self.assertEqual((dest/'runtime.json').stat().st_mode&0o777,0o644)
    def test_rejects_traversal_links_duplicates_and_wrong_architecture(self):
        def name(rows):rows[0][0].name='../escape'
        def link(rows):rows[0][0].type=tarfile.SYMTYPE;rows[0][0].linkname='/etc/passwd';rows[0][0].size=0
        def duplicate(rows):rows.append(rows[0])
        def mode(rows):rows[0][0].mode=0o4755
        for change in [name,link,duplicate,mode]:
            with self.subTest(change=change.__name__),self.assertRaises(ValueError):
                bundle.extract(self.altered(change),self.root/'bad','x86_64')
            self.assertFalse((self.root/'bad').exists())
        with self.assertRaises(ValueError):bundle.inspect(self.archive,'aarch64')
    def test_rejects_corruption_or_missing_plugin_even_with_consistent_manifest(self):
        (self.runtime/'bin/vpp').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):bundle.pack(self.runtime,self.root/'corrupt.bundle','x86_64')
        def omit(rows):
            plugin='lib/x86_64-linux-gnu/vpp_plugins/nat_plugin.so'
            rows[:]=[(m,data) for m,data in rows if m.name!=plugin]
            for i,(m,data) in enumerate(rows):
                if m.name=='runtime.json':
                    value=json.loads(data);del value['files'][plugin];data=json.dumps(value).encode();m.size=len(data);rows[i]=(m,data)
        with self.assertRaises(ValueError):bundle.inspect(self.altered(omit),'x86_64')
    def test_prepared_test_reader_matches_packaging_reader(self):
        self.assertEqual((HERE/'egress-bundle.py').read_bytes(),(HERE.parent/'test/e2e/lib/egress/bundle.py').read_bytes())

if __name__=='__main__':unittest.main()
