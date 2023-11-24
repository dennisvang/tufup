import gzip
import logging
import pathlib
import struct
import sys
import tarfile

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
        for key in ['old', 'new']:
            # create dummy file
            file_path = self.temp_dir_path / key
            file_path.write_text(key)
            # create .tar archive from dummy file
            tar_path = file_path.with_suffix('.tar')
            with tarfile.open(tar_path, 'w') as tar:
                tar.add(file_path)
            # compress .tar file using gzip (without filename and timestamp in header)
            # "MTIME = 0 means no time stamp is available."
            # https://datatracker.ietf.org/doc/html/rfc1952#page-7
            gz_path = tar_path.with_suffix('.tar.gz')
            gz_path.write_bytes(gzip.compress(data=tar_path.read_bytes(), mtime=0))
            # set OS field to 255 "unknown" in gzip header (for python >3.10)
            with gz_path.open(mode='r+b') as gz_file:
                gz_file.seek(9)  # 10th byte is OS field
                gz_file.write(b'\xff')  # value 255 "unknown"
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
        # byte order: little endian (format '<', relevant for MTIME)
        # https://datatracker.ietf.org/doc/html/rfc1952#page-4
        gzip_header_size = 10  # "basic" header size in bytes
        # make dummy data
        expected_mtime = 0  # "MTIME = 0 means no time stamp is available."
        gz_bytes = gzip.compress(data=b'dummy', mtime=expected_mtime)
        # read basic header (variable names from RFC 1952)
        (ID1, ID2, CM, FLG, MTIME, XFL, OS) = struct.unpack(
            '<BBBBLBB', gz_bytes[:gzip_header_size]
        )
        # extract flags (variable names from RFC 1952)
        (FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT) = (FLG & 1 << i for i in range(5))
        # verify that we don't have a filename, and mtime matches expectation
        self.assertEqual(expected_mtime, MTIME)
        self.assertFalse(FNAME)
        self.assertEqual(8, CM)  # "deflate method"
        self.assertEqual(2, XFL)  # "maximum compression"
        # https://github.com/python/cpython/issues/112346
        if sys.version_info[1] < 11:
            self.assertEqual(255, OS)  # "unknown"
        else:
            self.assertIn(
                OS,
                [
                    3,
                ],
            )  # unix, windows, macOS, unknown

    def test__fix_gzip_header(self):
        gz_bytes = gzip.compress(data=b'dummy', mtime=0)
        gz_path = self.temp_dir_path / 'test.gz'
        gz_path.write_bytes(gz_bytes)
        offset = 9
        desired_value = b'\xff'
        old_value = gz_bytes[offset : offset + 1]  # slice to keep bytes
        if sys.version_info[1] > 10:
            self.assertNotEqual(desired_value, old_value)
        Patcher._fix_gzip_header(gz_path)
        new_value = gz_path.read_bytes()[offset : offset + 1]  # slice to keep bytes
        self.assertEqual(desired_value, new_value)

    def test_gzip_compress_default(self):
        self.assertEqual(
            self.gz_paths['old'], Patcher.gzip(src_path=self.tar_paths['old'])
        )

    def test_gzip_decompress_default(self):
        self.assertEqual(
            self.tar_paths['old'], Patcher.gzip(src_path=self.gz_paths['old'])
        )

    def test_gzip_compress(self):
        # prepare
        src_path = self.tar_paths['old']
        dst_path = self.temp_dir_path / 'compressed.tar.gz'
        # test gzip compression
        with self.assertLogs(level='DEBUG') as logs:
            gz_path = Patcher.gzip(src_path=src_path, dst_path=dst_path, mtime=0)
        self.assertTrue(gz_path.exists())
        self.assertIn(' compress', logs.output[0])  # keep whitespace
        # check reproducibilty
        self.assertEqual(self.gz_paths['old'].read_bytes(), gz_path.read_bytes())

    def test_gzip_decompress(self):
        # prepare
        src_path = self.gz_paths['old']
        dst_path = self.temp_dir_path / 'decompressed.tar'
        # test gzip decompression
        with self.assertLogs(level='DEBUG') as logs:
            tar_path = Patcher.gzip(src_path=src_path, dst_path=dst_path)
        self.assertTrue(tar_path.exists())
        self.assertIn('decompress', logs.output[0])
        # check reproducibilty
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
        self.assertEqual(self.gz_paths['new'].read_bytes(), new_gz_path.read_bytes())
