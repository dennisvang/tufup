import gzip
import logging
import pathlib
import struct
import tarfile
import time

import bsdiff4
from packaging.version import Version

from tests import TempDirTestCase
from tufup.common import Patcher, TargetMeta


class TestTargetMeta(TempDirTestCase):
    def test_init_whitespace(self):
        for kwargs in [
            dict(target_path='w h i t e s p a c e-1.2.3.tar.gz'),
            dict(name='w h i t e s p a c e'),
        ]:
            with self.subTest(msg=kwargs):
                with self.assertLogs(level=logging.CRITICAL):
                    TargetMeta(**kwargs)

    def test_eq_ne(self):
        target_meta = TargetMeta()
        self.assertEqual(target_meta, TargetMeta())
        self.assertNotEqual(target_meta, TargetMeta(target_path='something'))
        # two ways to initialize a TargetMeta instance:
        self.assertEqual(
            TargetMeta(target_path='my-app-1.2.3a0.patch'),
            TargetMeta(name='my-app', version='1.2.3a0', is_archive=False),
        )

    def test_repr(self):
        # https://docs.python.org/3/reference/datamodel.html#object.__repr__
        target_meta = TargetMeta(target_path='some.file')
        # the input to eval is known and trusted, so that should be safe, right?
        self.assertEqual(eval(repr(target_meta)), target_meta)

    def test_str(self):
        # see issue #3
        for target_path in ['str_path', pathlib.Path('pathlib_path')]:
            with self.subTest(msg=target_path):
                self.assertIsInstance(
                    TargetMeta(target_path=target_path).__str__(), str
                )

    def test_hashable(self):
        obj = TargetMeta()
        self.assertEqual(obj.__hash__(), hash(tuple(vars(obj).items())))
        # we can use the obj as a set member or as dict key
        self.assertEqual({obj, obj}, {obj})

    def test_sortable(self):
        version_1 = TargetMeta(target_path='my-app-win-1.0.tar.gz')
        version_2 = TargetMeta(target_path='my-app-win-2.0.tar.gz')
        info_list = [version_2, version_1]
        self.assertEqual([version_1, version_2], sorted(info_list))

    def test_filename(self):
        target_path = 'url/path/somefile'
        target_meta = TargetMeta(target_path=target_path)
        self.assertEqual('somefile', target_meta.filename)

    def test_name(self):
        target_meta = TargetMeta(target_path='url/path/my-app-1.0.tar.gz')
        self.assertEqual('my-app', target_meta.name)

    def test_version(self):
        for version_str in ['1.2.3a4', '']:
            expected = Version(version_str) if version_str else None
            with self.subTest(msg=version_str):
                target_meta = TargetMeta(target_path=f'x-{version_str}.tar.gz')
                self.assertEqual(expected, target_meta.version)

    def test_suffix(self):
        valid_suffixes = ['.tar.gz', '.patch']
        for suffix in ['', '.zip', '.tar.gz', '.patch']:
            with self.subTest(msg=suffix):
                target_meta = TargetMeta(target_path=f'my-app-1.2.3a4{suffix}')
                if suffix in valid_suffixes:
                    self.assertEqual(suffix, target_meta.suffix)
                else:
                    self.assertIsNone(target_meta.suffix)

    def test_is_archive(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.tar.gz').is_archive)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.patch').is_archive)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.zip').is_archive)

    def test_is_patch(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.patch').is_patch)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.tar.gz').is_patch)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.zip').is_patch)

    def test_is_other(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.zip').is_other)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.patch').is_other)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.tar.gz').is_other)

    def test_parse_filename(self):
        cases = [
            # PEP440 versions are allowed (we do not parse them here...)
            ('app-1.patch', ('app', '1', '.patch')),
            ('app-1.tar.gz', ('app', '1', '.tar.gz')),
            ('app-1.2.tar.gz', ('app', '1.2', '.tar.gz')),
            ('app-1.2.3.tar.gz', ('app', '1.2.3', '.tar.gz')),
            ('app-1a.tar.gz', ('app', '1a', '.tar.gz')),
            ('app-1b.tar.gz', ('app', '1b', '.tar.gz')),
            ('app-1rc.tar.gz', ('app', '1rc', '.tar.gz')),
            ('app-1rc0.tar.gz', ('app', '1rc0', '.tar.gz')),
            ('app-2022.0.tar.gz', ('app', '2022.0', '.tar.gz')),
            # we don't impose a specific version format at this point (that
            # is deferred to packaging.Version)
            ('app-invalidversion.tar.gz', ('app', 'invalidversion', '.tar.gz')),
            # underscores, dashes, capitals, etc.
            ('app-name---1.tar.gz', ('app-name--', '1', '.tar.gz')),
            ('CAPS-1.tar.gz', ('CAPS', '1', '.tar.gz')),
            ('un_der_scores-1.0.tar.gz', ('un_der_scores', '1.0', '.tar.gz')),
            # invalid filenames
            ('sp ac es-1.zip', ()),
            ('app-1.gz', ()),
            ('app-1.xz', ()),
            ('anything', ()),
        ]
        for filename, expected in cases:
            match_dict = TargetMeta.parse_filename(filename=filename)
            with self.subTest(msg=filename):
                self.assertEqual(expected, tuple(match_dict.values()))

    def test_compose_filename(self):
        filename = TargetMeta.compose_filename(
            name='app', version='1.0', is_archive=True
        )
        self.assertEqual('app-1.0.tar.gz', filename)


class PatcherTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.file_paths = dict()
        self.tar_paths = dict()
        self.gz_paths = dict()
        # The gzip header contains an mtime field [1], and we need to make sure we
        # can set this field properly. However, the resolution of os.stat.mtime
        # depends on the operating system and file system, e.g. Windows/FAT32 has a 2
        # sec resolution [2], so to check for inequality of the *default* mtime in
        # the gzip header, we would need to force a delay on the order of seconds in
        # our tests. To work around this, we override the mtime field for test files.
        # [1]: https://datatracker.ietf.org/doc/html/rfc1952#page-5
        # [2]: https://docs.python.org/3.12/library/os.html#os.stat_result
        mtimes = dict(
            old=time.time() - 100,  # some arbitrary time in the past [seconds]
            new=None,  # i.e. just use the default mtime (current time)
        )
        for key, mtime in mtimes.items():
            # create dummy file
            file_path = self.temp_dir_path / key
            file_path.write_text(key)
            # create .tar archive from dummy file
            tar_path = file_path.with_suffix('.tar')
            with tarfile.open(tar_path, 'w') as tar:
                tar.add(file_path)
            # compress .tar file using gzip (without filename in header)
            gz_path = tar_path.with_suffix('.tar.gz')
            gz_path.write_bytes(gzip.compress(data=tar_path.read_bytes(), mtime=mtime))
            # keep reference
            self.file_paths[key] = file_path
            self.tar_paths[key] = tar_path
            self.gz_paths[key] = gz_path
        # expected patch data
        self.expected_patch_bytes = bsdiff4.diff(
            src_bytes=self.tar_paths['old'].read_bytes(),
            dst_bytes=self.tar_paths['new'].read_bytes(),
        )

    def test_gzip_header(self):
        # see gzip header definition in RFC 1952
        # byte order: little endian
        # https://datatracker.ietf.org/doc/html/rfc1952#page-4
        gzip_header_bytes = 10  # "basic" header size
        # make dummy data
        expected_mtime = 123
        gz_bytes = gzip.compress(data=b'dummy', mtime=expected_mtime)
        # read basic header (variable names from RFC 1952)
        (ID1, ID2, CM, FLG, MTIME, XFL, OS) = struct.unpack(
            '<BBBBIBB', gz_bytes[:gzip_header_bytes]
        )
        # extract flags (variable names from RFC 1952)
        (FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT) = (FLG & 1 << i for i in range(5))
        # verify that we don't have a filename, and mtime matches expectation
        self.assertEqual(expected_mtime, MTIME)
        self.assertFalse(FNAME)

    def test_gzip_compress_reproducibility(self):
        # verify that different mtimes lead to differences in the gz file
        not_repr_gz_path = Patcher.gzip(
            src_path=self.tar_paths['old'],
            dst_path=self.temp_dir_path / 'not-reproducible.tar.gz',
        )
        self.assertNotEqual(
            self.gz_paths['old'].read_bytes(), not_repr_gz_path.read_bytes()
        )
        # verify that we can override the mtime to remove these differences
        repr_gz_path = Patcher.gzip(
            src_path=self.tar_paths['old'],
            dst_path=self.temp_dir_path / 'reproducible.tar.gz',
            mtime=0,
        )
        self.assertEqual(self.gz_paths['old'].read_bytes(), repr_gz_path.read_bytes())

    def test_gzip_compress(self):
        # prepare
        src_path = self.tar_paths['old']
        # test gzip compression
        with self.assertLogs(level='DEBUG') as logs:
            for dst_path in [None, self.temp_dir_path / 'compressed.tar.gz']:
                with self.subTest(msg=dst_path):
                    gz_path = Patcher.gzip(src_path=src_path, dst_path=dst_path)
                    self.assertTrue(gz_path.exists())
        self.assertEqual(2, sum(1 for msg in logs.output if 'compress' in msg))
        # note these are not byte-for-byte equal, because of the default mtime

    def test_gzip_decompress(self):
        src_path = self.gz_paths['old']
        with self.assertLogs(level='DEBUG') as logs:
            for dst_path in [None, self.temp_dir_path / 'decompressed.tar']:
                with self.subTest(msg=str(dst_path)):
                    tar_path = Patcher.gzip(src_path=src_path, dst_path=dst_path)
                    self.assertTrue(tar_path.exists())
        self.assertEqual(2, sum(1 for msg in logs.output if 'decompress' in msg))
        self.assertEqual(self.tar_paths['old'].read_bytes(), tar_path.read_bytes())

    def test_create_patch(self):
        # test
        patch_path = Patcher.create_patch(
            src_path=self.gz_paths['old'], dst_path=self.gz_paths['new']
        )
        self.assertTrue(patch_path.exists())
        self.assertEqual(self.expected_patch_bytes, patch_path.read_bytes())

    def test_apply_patch(self):
        # write dummy patch file
        name = 'latest'
        patch_path = self.temp_dir_path / (name + '.patch')
        patch_path.write_bytes(self.expected_patch_bytes)
        # test
        new_gz_path = Patcher.apply_patch(
            src_path=self.gz_paths['old'], patch_path=patch_path
        )
        self.assertEqual(name + '.tar.gz', new_gz_path.name)
        self.assertTrue(new_gz_path.exists())
