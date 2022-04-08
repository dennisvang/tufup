import gzip

from notsotuf.client import shutil
from tests import TempDirTestCase


class UnpackGzipTests(TempDirTestCase):
    def test_unpack_gzip(self):
        # create dummy gzip archive
        archive_path = self.temp_dir_path / 'archive.gz'
        with gzip.open(archive_path, 'wb') as gzfile:
            gzfile.write(b'some data')
        # the following should work if the function was registered successfully
        shutil.unpack_archive(filename=archive_path, extract_dir=self.temp_dir_path)
        expected_file_path = self.temp_dir_path / archive_path.stem
        self.assertTrue(expected_file_path.exists())