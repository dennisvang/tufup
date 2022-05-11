import pathlib
import shutil
from typing import Optional
import unittest
from unittest.mock import Mock, patch

from requests.auth import HTTPBasicAuth
import tuf.api.exceptions
from tuf.api.metadata import TargetFile

from notsotuf.client import AuthRequestsFetcher, Client
from notsotuf.common import TargetMeta
from tests import TempDirTestCase, TEST_REPO_DIR

ROOT_FILENAME = 'root.json'
TARGETS_FILENAME = 'targets.json'
SNAPSHOT_FILENAME = 'snapshot.json'
TIMESTAMP_FILENAME = 'timestamp.json'


class ClientTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # directory where the parent application is installed (e.g.
        # %PROGRAMFILES%\MyApp or %LOCALAPPDATA%\Programs\MyApp on Windows 10)
        # https://docs.microsoft.com/en-us/windows/win32/msi/installation-context
        self.app_install_dir = self.temp_dir_path / 'programs' / 'example'
        self.app_install_dir.mkdir(parents=True)
        # directories must be created by parent application
        self.metadata_dir = self.temp_dir_path / 'metadata'
        self.target_dir = self.temp_dir_path / 'targets'
        self.metadata_dir.mkdir()
        self.target_dir.mkdir()
        # parent application must be shipped with root metadata, and must
        # ensure it is placed in the metadata_dir (without version in filename)
        shutil.copy(
            src=TEST_REPO_DIR / 'metadata' / ('1.' + ROOT_FILENAME),
            dst=self.metadata_dir / ROOT_FILENAME,
        )
        # kwargs for client initializer
        self.client_kwargs = dict(
            app_name='example_app',
            app_install_dir=self.app_install_dir,
            current_version='1.0',
            metadata_dir=self.metadata_dir,
            metadata_base_url='http://localhost:8000/metadata/',
            target_dir=self.target_dir,
            target_base_url='http://localhost:8000/targets/',
            session_auth={'http://localhost:8000': ('username', 'password')}
        )

    def mock_download_metadata(
            self, rolename: str, length: int, version: Optional[int] = None
    ) -> bytes:
        if rolename == 'root':
            # indicate current root is newest version
            raise tuf.api.exceptions.DownloadHTTPError(status_code=404, message='')
        # read from the test repo dir, instead of actually downloading
        filename = f'{rolename}.json'
        if version:
            filename = f'{version}.{filename}'
        file_path = TEST_REPO_DIR / 'metadata' / filename
        return file_path.read_bytes()

    def get_refreshed_client(self):
        # refresh to load targets metadata (mock to prevent actual download)
        client = Client(**self.client_kwargs)
        with patch.object(client, '_download_metadata', self.mock_download_metadata):
            client.refresh()
        # ensure current archive exists (dummy)
        shutil.copy(
            src=TEST_REPO_DIR / 'targets' / client.current_archive.path.name,
            dst=client.current_archive_local_path,
        )
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

    def test_trusted_target_metas(self):
        client = self.get_refreshed_client()
        self.assertTrue(client.trusted_target_metas)

    def test_get_targetinfo(self):
        client = self.get_refreshed_client()
        target_path_str = 'example_app-1.0.tar.gz'
        target_meta = TargetMeta(target_path=target_path_str)
        for target_path in [target_path_str, target_meta]:
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

    def test__check_updates_already_up_to_date(self):
        self.client_kwargs['current_version'] = '4.0a0'
        client = self.get_refreshed_client()
        with patch.object(client, 'refresh', Mock()):
            self.assertFalse(client._check_updates(pre='a'))

    def test__check_updates_current_archive_missing(self):
        client = self.get_refreshed_client()
        # remove current archive dummy
        client.current_archive_local_path.unlink()
        with patch.object(client, 'refresh', Mock()):
            for pre in [None, 'a', 'b', 'rc']:
                self.assertTrue(client._check_updates(pre=pre))
                target_meta = next(iter(client.new_targets.keys()))
                self.assertTrue(target_meta.is_archive)

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

    def test__apply_updates(self):
        client = self.get_refreshed_client()
        # directly use target files from test repo as downloaded files
        client.downloaded_target_files = {
            target_meta: TEST_REPO_DIR / 'targets' / str(target_meta)
            for target_meta in client.trusted_target_metas
            if target_meta.is_patch
            and str(target_meta.version) in ['2.0', '3.0rc0']
        }
        # specify new archive (normally done in _check_updates)
        archives = [
            tp for tp in client.trusted_target_metas
            if tp.is_archive and str(tp.version) == '3.0rc0'
        ]
        client.new_archive_info = client.get_targetinfo(archives[-1])
        client.new_archive_local_path = pathlib.Path(
            client.target_dir, client.new_archive_info.path
        )
        # test
        mock_move = Mock()
        with patch('builtins.input', Mock(return_value='y')):
            client._apply_updates(move_and_exit=mock_move)
        self.assertTrue(any(client.extract_dir.iterdir()))
        self.assertTrue(mock_move.called)


class AuthRequestsFetcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session_auth = {
            'https://example.net': None,
            'https://example.com': ('username', 'password'),
            'https://example.org': HTTPBasicAuth(username='name', password='pw'),
        }

    def test_init(self):
        # drop-in replacement for default RequestsFetcher, without args
        self.assertTrue(AuthRequestsFetcher())
        # if authentication is required, specify arg
        fetcher = AuthRequestsFetcher(session_auth=self.session_auth)
        self.assertEqual(self.session_auth, fetcher.session_auth)

    def test__get_session(self):
        fetcher = AuthRequestsFetcher(session_auth=self.session_auth)
        for url, auth in self.session_auth.items():
            with self.subTest(msg=url):
                session = fetcher._get_session(url=url)
                self.assertEqual(auth, session.auth)
