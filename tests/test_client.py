import gzip
import pathlib

from notsotuf.client import Client, shutil
from tests import TempDirTestCase

BASE_DIR = pathlib.Path(__file__).resolve().parent
TEST_REPO_DIR = BASE_DIR / 'data' / 'repository'
ROOT_FILENAME = 'root.json'


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
        # directories must be created by parent application
        self.metadata_dir = self.temp_dir_path / 'metadata'
        self.target_dir = self.temp_dir_path / 'targets'
        self.metadata_dir.mkdir()
        self.target_dir.mkdir()
        # parent application must be shipped with root metadata, and must
        # ensure it is placed in the metadata_dir
        shutil.copy(
            src=TEST_REPO_DIR / 'metadata' / ROOT_FILENAME,
            dst=self.metadata_dir / ROOT_FILENAME,
        )
        # kwargs for client initializer
        self.client_kwargs = dict(
            app_name='test_app',
            current_version='1.0.0a0',
            metadata_dir=self.metadata_dir,
            metadata_base_url='http://localhost:8000/metadata/',
            target_dir=self.target_dir,
            target_base_url='http://localhost:8000/targets/',
        )

    def test_init_no_metadata(self):
        # cannot initialize without root metadata file
        (self.metadata_dir / ROOT_FILENAME).unlink()
        with self.assertRaises(FileNotFoundError):
            Client(**self.client_kwargs)

    def test_init(self):
        client = Client(**self.client_kwargs)
        # Client is a subclass of tuf.ngclient.Updater, so it automatically
        # loads, and verifies, local metadata (if the files are available)
        self.assertTrue(client._trusted_set.root)
        # other metadata is not available yet
        for role_name in ['targets', 'snapshot', 'timestamp']:
            self.assertIsNone(getattr(client._trusted_set, role_name))

    def test_trusted_target_paths(self):
        pass
