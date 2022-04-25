import bsdiff4
from packaging.version import Version

from notsotuf.common import Patcher, TargetMeta
from tests import TempDirTestCase


class TestTargetMeta(TempDirTestCase):
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
            ('app-1.patch', ('app', '1', '.patch')),
            ('app-1.tar.gz', ('app', '1', '.tar.gz')),
            ('app-1.2.tar.gz', ('app', '1.2', '.tar.gz')),
            ('app-1.2.3.tar.gz', ('app', '1.2.3', '.tar.gz')),
            ('app-1a.tar.gz', ('app', '1a', '.tar.gz')),
            ('app-1b.tar.gz', ('app', '1b', '.tar.gz')),
            ('app-1rc.tar.gz', ('app', '1rc', '.tar.gz')),
            ('app-1rc0.tar.gz', ('app', '1rc0', '.tar.gz')),
            ('app-2022.0.tar.gz', ('app', '2022.0', '.tar.gz')),
            ('app-name---1.tar.gz', ('app-name--', '1', '.tar.gz')),
            ('CAPS-1.tar.gz', ('CAPS', '1', '.tar.gz')),
            ('un_der-1.tar.gz', ('un_der', '1', '.tar.gz')),
            # we don't impose a specific version format at this point (that
            # is deferred to packaging.Version)
            ('app-invalidversion.tar.gz', ('app', 'invalidversion', '.tar.gz')),
            ('sp ac es-1.zip', ()),
            ('app-1.gz', ()),
            ('app-1.xz', ()),
            ('anything', ()),
        ]
        for filename, expected in cases:
            match_dict = TargetMeta.parse_filename(filename=filename)
            self.assertEqual(expected, tuple(match_dict.values()))

    def test_compose_filename(self):
        filename = TargetMeta.compose_filename(
            name='app', version='1.0', is_archive=True
        )
        self.assertEqual('app-1.0.tar.gz', filename)


class PatcherTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # dummy paths
        self.old_archive_path = self.temp_dir_path / 'my_app-1.0.tar.gz'
        self.new_archive_path = self.temp_dir_path / 'my_app-2.0.tar.gz'
        self.new_patch_path = self.temp_dir_path / 'my_app-2.0.patch'
        # write dummy archive data to files
        self.old_archive_path.write_bytes(b'old archive data')
        self.new_archive_data = b'new archive data'
        self.new_archive_path.write_bytes(self.new_archive_data)
        # create patch file (see Patcher.create_patch)
        bsdiff4.file_diff(
            src_path=self.old_archive_path,
            dst_path=self.new_archive_path,
            patch_path=self.new_patch_path,
        )
        self.new_patch_data = self.new_patch_path.read_bytes()

    def test_create_patch(self):
        # remove existing patch file, just to be sure
        self.new_patch_path.unlink()
        # test
        new_patch_path = Patcher.create_patch(
            src_path=self.old_archive_path, dst_path=self.new_archive_path
        )
        self.assertTrue(new_patch_path.exists())
        self.assertEqual(self.new_patch_data, new_patch_path.read_bytes())

    def test_apply_patch(self):
        # remove existing "new archive" file, just to be sure
        self.new_archive_path.unlink()
        # test
        new_archive_path = Patcher.apply_patch(
            src_path=self.old_archive_path, patch_path=self.new_patch_path
        )
        self.assertTrue(new_archive_path.exists())
        self.assertEqual(self.new_archive_data, new_archive_path.read_bytes())
