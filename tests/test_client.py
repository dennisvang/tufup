import gzip
import pathlib
from unittest.mock import Mock, patch

import tuf.api.exceptions
from tuf.api.metadata import TargetFile

from notsotuf.client import Client, shutil
from notsotuf.common import TargetPath
from tests import TempDirTestCase

BASE_DIR = pathlib.Path(__file__).resolve().parent
TEST_REPO_DIR = BASE_DIR / 'data' / 'repository'
ROOT_FILENAME = 'root.json'
TARGETS_FILENAME = 'targets.json'
SNAPSHOT_FILENAME = 'snapshot.json'
TIMESTAMP_FILENAME = 'timestamp.json'


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
            app_name='example_app',
            current_version='1.0',
            metadata_dir=self.metadata_dir,
            metadata_base_url='http://localhost:8000/metadata/',
            target_dir=self.target_dir,
            target_base_url='http://localhost:8000/targets/',
        )

    def mock_download_metadata(self, rolename: str, *args, **kwargs) -> bytes:
        if rolename == 'root':
            # indicate current root is newest version
            raise tuf.api.exceptions.DownloadHTTPError(status_code=404, message='')
        file_path = self.metadata_dir / f'{rolename}.json'
        return file_path.read_bytes()

    def get_refreshed_client(self):
        # make sure all metadata files are present (these would normally be
        # downloaded from the update server)
        for filename in [TARGETS_FILENAME, SNAPSHOT_FILENAME, TIMESTAMP_FILENAME]:
            shutil.copy(
                src=TEST_REPO_DIR / 'metadata' / filename,
                dst=self.metadata_dir / filename,
            )
        # refresh to load targets metadata (mock to prevent actual download)
        client = Client(**self.client_kwargs)
        with patch.object(client, '_download_metadata', self.mock_download_metadata):
            client.refresh()
        return client

    def test_init_no_metadata(self):
        # cannot initialize without root metadata file
        (self.metadata_dir / ROOT_FILENAME).unlink()
        with self.assertRaises(FileNotFoundError):
            Client(**self.client_kwargs)

    def test_init(self):
        client = Client(**self.client_kwargs)
        # Client is a subclass of tuf.ngclient.Updater, so it automatically
        # loads and verifies the local root metadata file
        self.assertTrue(client._trusted_set.root)
        # other metadata is not available yet
        for role_name in ['targets', 'snapshot', 'timestamp']:
            self.assertIsNone(getattr(client._trusted_set, role_name))

    def test_trusted_target_paths(self):
        client = self.get_refreshed_client()
        self.assertTrue(client.trusted_target_paths)

    def test_get_targetinfo(self):
        client = self.get_refreshed_client()
        target_path_str = 'example_app-1.0.gz'
        target_path_obj = TargetPath(target_path=target_path_str)
        for target_path in [target_path_str, target_path_obj]:
            target_info = client.get_targetinfo(target_path=target_path)
            with self.subTest(msg=target_path):
                self.assertIsInstance(target_info, TargetFile)

    def test_update(self):
        # just for completeness...
        mock_true = Mock(return_value=True)
        with patch.multiple(
                Client,
                _check_updates=mock_true,
                _download_updates=mock_true,
                _apply_updates=mock_true
        ):
            client = self.get_refreshed_client()
            client.update()
        self.assertEqual(3, mock_true.call_count)

    def test__check_updates(self):
        # expectations (based on targets in tests/data/repository):
        # - pre=None: only full releases are included, so finds 2.0 patch
        # - pre='a': finds all, but total patch size exceeds archive size
        # - pre='b': there is no 'b' release, so this finds same as 'rc'
        # - pre='rc': finds 2.0 and 3.0rc0, total patch size smaller than archive
        client = self.get_refreshed_client()
        with patch.object(client, 'refresh', Mock()):
            for pre, expected in [(None, 1), ('a', 1), ('b', 2), ('rc', 2)]:
                with self.subTest(msg=pre):
                    self.assertTrue(client._check_updates(pre=pre))
                    self.assertEqual(expected, len(client.new_targets))
                    if pre == 'a':
                        self.assertTrue(all(
                            item.is_archive for item in
                            client.new_targets.keys())
                        )
                    else:
                        self.assertTrue(all(
                            item.is_patch for item in client.new_targets.keys())
                        )

    def test__download_updates(self):
        client = Client(**self.client_kwargs)
        client.new_targets = {Mock(): Mock()}
        for cached_path, downloaded_path in [('cached', None), (None, 'downloaded')]:
            with patch.multiple(
                    client,
                    find_cached_target=Mock(return_value=cached_path),
                    download_target=Mock(return_value=downloaded_path),
            ):
                self.assertTrue(client._download_updates())
                local_path = next(iter(client.downloaded_target_files.values()))
                if cached_path:
                    self.assertEqual(cached_path, str(local_path))
                else:
                    self.assertEqual(downloaded_path, str(local_path))
