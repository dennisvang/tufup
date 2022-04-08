import bsdiff4

from notsotuf.common import Patcher
from tests import TempDirTestCase


class PatcherTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # dummy paths
        self.old_archive_path = self.temp_dir_path / 'my_app-1.0.gz'
        self.new_archive_path = self.temp_dir_path / 'my_app-2.0.gz'
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
