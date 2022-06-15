import argparse
import unittest
from unittest.mock import Mock, patch

import notsotuf
import notsotuf.repo.cli
import notsotuf.utils
from tests import TempDirTestCase


class ParserTests(unittest.TestCase):
    def test__get_parser(self):
        parser = notsotuf.repo.cli.get_parser()
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
        with patch('notsotuf.repo.cli.Repository', self.mock_repo_class):
            with patch('notsotuf.repo.cli.input_bool', Mock(return_value=True)):
                with patch(
                        'notsotuf.repo.cli._get_config_from_user',
                        self.mock_repo_class.load_config,
                ):
                    notsotuf.repo.cli._cmd_init(options=argparse.Namespace())
        self.mock_repo.initialize.assert_called()

    def test__cmd_keys(self):
        # todo
        options = argparse.Namespace(add=None, create=None, revoke=None)
        notsotuf.repo.cli._cmd_keys(options=options)

    def test__cmd_targets_add(self):
        version = '1.0'
        bundle_dir = 'dummy'
        options = argparse.Namespace(add=[version, bundle_dir], remove=False)
        with patch('notsotuf.repo.cli.Repository', self.mock_repo_class):
            notsotuf.repo.cli._cmd_targets(options=options)
        self.mock_repo.add_bundle.assert_called_with(
            new_version=version, new_bundle_dir=bundle_dir
        )

    def test__cmd_targets_remove(self):
        options = argparse.Namespace(add=None, remove=True)
        with patch('notsotuf.repo.cli.Repository', self.mock_repo_class):
            notsotuf.repo.cli._cmd_targets(options=options)
        self.mock_repo.remove_latest_bundle.assert_called()

    def test__get_config_from_user_no_kwargs(self):
        default = ''
        yes = 'y'
        no = 'n'
        user_inputs = iter(
            [
                'my-app',  # app name
                'my_app.__version__',  # app version
                'repo/dir',  # repo dir
                'keys/dir',  # keys dir
                yes,  # keep default root key name
                yes,  # add another root key name
                'root-2',  # key name
                no,  # add another root key name
                default,  # encrypt 'root' key
                yes,  # encrypt 'root-2' key
                '365',  # expiration days
                '2',  # signature threshold
                default,  # keep default targets key name
                default,  # add another targets key name
                default,  # encrypt 'targets' key
                '30',  # expiration days
                '1',  # signature threshold
                default,  # keep default snapshot key name
                default,  # add another snapshot key name
                default,  # encrypt 'snapshot' key
                '7',  # expiration days
                '1',  # signature threshold
                default,  # keep default timestamp key name
                default,  # add another timestamp key name
                default,  # encrypt 'timestamp' key
                '1',  # expiration days
                '1',  # signature threshold
            ]
        )
        with patch('builtins.input', lambda *_, **__: next(user_inputs)):
            config_kwargs = notsotuf.repo.cli._get_config_from_user()
        self.assertTrue(config_kwargs)

    def test__get_config_from_user_with_kwargs(self):
        original_kwargs = dict(
            app_name='my-app',
            app_version_attr='my_app.__version__',
            repo_dir='repo/dir',
            keys_dir='keys/dir',
            key_map=notsotuf.repo.DEFAULT_KEY_MAP,
            encrypted_keys=['root'],
            expiration_days=notsotuf.repo.DEFAULT_EXPIRATION_DAYS,
            thresholds=notsotuf.repo.DEFAULT_THRESHOLDS,
        )
        default = ''
        with patch('builtins.input', Mock(return_value=default)):
            config_kwargs = notsotuf.repo.cli._get_config_from_user(
                **original_kwargs
            )
        self.assertEqual(config_kwargs, original_kwargs)
