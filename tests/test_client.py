import gzip
import pathlib

from notsotuf.client import Client, shutil
from tests import TempDirTestCase

BASE_DIR = pathlib.Path(__file__).resolve().parent


class UnpackTests(TempDirTestCase):
    def test_unpack_gzip(self):
        # create dummy gzip archive
        archive_path = self.temp_dir_path / 'archive.gz'
        with gzip.open(archive_path, 'wb') as gzfile:
            gzfile.write(b'some data')
        # the following should work if the function was registered successfully
        shutil.unpack_archive(filename=archive_path, extract_dir=self.temp_dir_path)
        expected_file_path = self.temp_dir_path / archive_path.stem
        self.assertTrue(expected_file_path.exists())


class ClientTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client_kwargs = dict(
            app_name='test_app',
            current_version='1.0.0a0',
            metadata_dir=self.temp_dir_path / 'metadata',
            metadata_base_url='http://localhost:8000/metadata/',
            target_dir=self.temp_dir_path / 'targets',
            target_base_url='http://localhost:8000/targets/',
        )

    def test_init(self):
        # client does not create any directories
        with self.assertRaises(FileNotFoundError):
            Client(**self.client_kwargs)
        # directories must be created by parent application
        for key in ['metadata_dir', 'target_dir']:
            self.client_kwargs[key].mkdir()
        # parent application must be shipped with root metadata
        shutil.copy(
            src=BASE_DIR / 'data/repository/metadata/root.json',
            dst=self.client_kwargs['metadata_dir'] / 'root.json',
        )
        # now we can initialize the Client
        client = Client(**self.client_kwargs)
        # Client is a subclass of tuf.ngclient.Updater, so it automatically
        # loads, and verifies, local metadata, if available
        self.assertTrue(client._trusted_set.root)
        # other metadata is not available yet
        for role_name in ['targets', 'snapshot', 'timestamp']:
            self.assertIsNone(getattr(client._trusted_set, role_name))
