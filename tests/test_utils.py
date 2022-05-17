from notsotuf.utils import remove_path
from tests import TempDirTestCase


class RemovePathTests(TempDirTestCase):
    def test_remove_path(self):
        # create a directory and subdirectory with dummy files
        dir_path = self.temp_dir_path / 'dir'
        subdir_path = dir_path / 'subdir'
        subdir_path.mkdir(parents=True)
        for file in [dir_path / 'file.in.dir', subdir_path / 'file.in.subdir']:
            file.touch()
        self.assertEqual(2, len(list(dir_path.iterdir())))
        self.assertEqual(1, len(list(subdir_path.iterdir())))
        # test
        self.assertTrue(remove_path(path=dir_path))
        self.assertFalse(dir_path.exists())
