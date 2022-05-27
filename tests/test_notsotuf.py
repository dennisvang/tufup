import argparse
import unittest
from unittest.mock import Mock, patch

import notsotuf
import notsotuf.repo
import notsotuf.utils
from tests import TempDirTestCase


class ParserTests(unittest.TestCase):
    def test__get_parser(self):
        parser = notsotuf._get_parser()
        for cmd in [
            'init',
            'targets -a 1.0 bundle-dir'
            'targets -r',
            'keys -c key-name',
            'keys -a key-path',
            'keys -r key-name',
        ]:
            options = parser.parse_args(cmd.split())
            self.assertTrue(options.func)


class CommandTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.config = dict(
            app_name='my-app',
            repo_dir=self.temp_dir_path / 'repo',
            keys_dir=self.temp_dir_path / 'keys',
            key_map=notsotuf.repo.DEFAULT_KEY_MAP,
            encrypted_keys=[],
            expiration_days=notsotuf.repo.DEFAULT_EXPIRATION_DAYS,
        )
        mock_return_config = Mock(return_value=self.config)
        mock_repo = Mock()
        mock_repo.save_config = Mock()
        mock_repo.initialize = Mock()
        mock_repo.add_bundle = Mock()
        mock_repo.remove_latest_bundle = Mock()
        MockRepository = Mock(return_value=mock_repo)  # noqa
        MockRepository.load_config = mock_return_config
        MockRepository.from_config = Mock(return_value=mock_repo)
        self.mock_repo = mock_repo
        self.mock_repo_class = MockRepository

    def test__cmd_init(self):
        with patch('notsotuf.Repository', self.mock_repo_class):
            with patch('notsotuf.input_bool', Mock(return_value=True)):
                with patch(
                        'notsotuf.get_config_from_user',
                        self.mock_repo_class.load_config,
                ):
                    notsotuf._cmd_init(options=argparse.Namespace())
        self.mock_repo.initialize.assert_called()

    def test__cmd_keys(self):
        # todo
        options = argparse.Namespace(add=None, create=None, revoke=None)
        notsotuf._cmd_keys(options=options)

    def test__cmd_targets_add(self):
        version = '1.0'
        bundle_dir = 'dummy'
        options = argparse.Namespace(add=[version, bundle_dir], remove=False)
        with patch('notsotuf.Repository', self.mock_repo_class):
            notsotuf._cmd_targets(options=options)
        self.mock_repo.add_bundle.assert_called_with(
            new_version=version, new_bundle_dir=bundle_dir
        )

    def test__cmd_targets_remove(self):
        options = argparse.Namespace(add=None, remove=True)
        with patch('notsotuf.Repository', self.mock_repo_class):
            notsotuf._cmd_targets(options=options)
        self.mock_repo.remove_latest_bundle.assert_called()
