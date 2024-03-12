import argparse
import json
import unittest
from unittest.mock import Mock, patch

import tufup
import tufup.repo.cli
import tufup.utils
from tests import TempDirTestCase


class ParserTests(unittest.TestCase):
    def test_get_parser(self):
        parser = tufup.repo.cli.get_parser()
        for cmd in [
            '--version',
            'init',
            'init --debug',
            'targets add 1.0 c:\\my_bundle_dir c:\\private_keys',
            'targets -d add 1.0 c:\\my_bundle_dir c:\\private_keys',
            'targets -d add -r 1.0 c:\\my_bundle_dir c:\\private_keys',
            'targets -d add -s 1.0 c:\\my_bundle_dir c:\\private_keys',
            'targets remove-latest c:\\private_keys',
            'keys my-key-name',  # todo: doesn't do anything... use subcommand?
            'keys my-key-name -c -e',
            'keys my-key-name add root c:\\private_keys d:\\more_private_keys',
            'keys my-key-name -c -e add root c:\\private_keys',
            'keys my-key-name replace old-key-name c:\\private_keys',
            'keys my-key-name -c -e replace old-key-name c:\\private_keys',
            'sign root c:\\private_keys d:\\other_private_keys',
            'sign root c:\\private_keys -e',
            'sign root c:\\private_keys -e 100',
        ]:
            with self.subTest(msg=cmd):
                args = cmd.split()
                options = parser.parse_args(args)
                expected_func_name = '_cmd_' + args[0]
                if args[0] in ['targets', 'keys']:
                    self.assertTrue(hasattr(options, 'subcommand'))
                if args[:2] == ['targets', 'add']:
                    self.assertTrue(hasattr(options, 'meta'))
                if args[0] == '--version':
                    self.assertTrue(options.version)
                else:
                    self.assertFalse(options.version)
                    self.assertEqual(expected_func_name, options.func.__name__)

    def test_get_parser_incomplete_commands(self):
        parser = tufup.repo.cli.get_parser()
        for cmd in [
            'targets',
            'targets add',
            'targets remove-latest',
            'keys',
            'keys my-key-name add',
            'keys my-key-name replace',
            'sign',
        ]:
            with self.subTest(msg=cmd):
                args = cmd.split()
                with self.assertRaises(SystemExit):
                    parser.parse_args(args)

    def test_get_parser_meta_json(self):
        parser = tufup.repo.cli.get_parser()
        args = 'targets add 1.0 c:\\my_bundle_dir c:\\private_keys'.split()
        with self.subTest(msg='no metadata'):
            self.assertIsNone(parser.parse_args(args).meta)
        json_object = '{"changes": ["line 1", "line2"]}'
        with self.subTest(msg='valid json object'):
            options = parser.parse_args(args + ['-m', json_object])
            self.assertEqual(json.loads(json_object), options.meta)
        with self.subTest(msg='invalid json'):
            with self.assertRaises(SystemExit):
                parser.parse_args(args + ['-m', '{'])
        with self.subTest(msg='valid json but not an object'):
            with self.assertRaises(SystemExit):
                parser.parse_args(args + ['-m', '["item 1", "item 2"]'])


class CommandTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        role_names = ['root', 'targets', 'snapshot', 'timestamp']
        self.config = dict(
            app_name='my-app',
            repo_dir=self.temp_dir_path / 'repo',
            keys_dir=self.temp_dir_path / 'keys',
            key_map={name: [name] for name in role_names},
            encrypted_keys=[],
            expiration_days={name: 1 for name in role_names},
        )
        mock_return_config = Mock(return_value=self.config)
        mock_keys = Mock()
        mock_keys.create_key_pair = Mock()
        mock_repo = Mock(keys=mock_keys, **self.config)
        mock_repo.save_config = Mock()
        mock_repo.initialize = Mock()
        mock_repo.add_bundle = Mock()
        mock_repo.remove_latest_bundle = Mock()
        mock_repo.add_key = Mock()
        mock_repo.replace_key = Mock()
        mock_repo.refresh_expiration_date = Mock()
        mock_repo.threshold_sign = Mock()
        mock_repo.publish_changes = Mock()
        MockRepository = Mock(return_value=mock_repo)  # noqa
        MockRepository.load_config = mock_return_config
        MockRepository.from_config = Mock(return_value=mock_repo)
        self.mock_repo = mock_repo
        self.mock_repo_class = MockRepository

    def test__cmd_init(self):
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            with patch('tufup.repo.cli.input_bool', Mock(return_value=True)):
                with patch(
                    'tufup.repo.cli._get_config_from_user',
                    self.mock_repo_class.load_config,
                ):
                    tufup.repo.cli._cmd_init(options=argparse.Namespace())
        self.mock_repo.initialize.assert_called()

    def test__cmd_keys_create(self):
        options = argparse.Namespace(
            subcommand=None, new_key_name='test', encrypted=True, create=True
        )
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_keys(options=options)
        self.mock_repo.keys.create_key_pair.assert_called()

    def test__cmd_keys_create_and_add_key(self):
        options = argparse.Namespace(
            subcommand='add',
            create=True,
            encrypted=True,
            key_dirs=['c:\\my_private_keys'],
            new_key_name='test',
            role_name='root',
        )
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_keys(options=options)
        self.mock_repo.keys.create_key_pair.assert_called()
        self.mock_repo.add_key.assert_called()
        self.mock_repo.publish_changes.assert_called()

    def test__cmd_keys_replace_key(self):
        options = argparse.Namespace(
            subcommand='replace',
            create=True,
            encrypted=False,
            key_dirs=['c:\\my_private_keys'],
            new_key_name='some new key to be created',
            old_key_name='some old key name',
        )
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_keys(options=options)
        self.mock_repo.replace_key.assert_called()
        self.mock_repo.keys.create_key_pair.assert_called()
        self.mock_repo.publish_changes.assert_called()

    def test__cmd_targets_add(self):
        kwargs = dict(
            subcommand='add',
            app_version='1.0',
            bundle_dir='dummy',
            key_dirs=['c:\\my_private_keys'],
            skip_patch=True,
            required=False,
            meta=dict(),
        )
        options = argparse.Namespace(**kwargs)
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_targets(options=options)
        self.mock_repo.add_bundle.assert_called_with(
            new_version=kwargs['app_version'],
            new_bundle_dir=kwargs['bundle_dir'],
            skip_patch=kwargs['skip_patch'],
            required=kwargs['required'],
            custom_metadata=kwargs['meta'],
        )
        self.mock_repo.publish_changes.assert_called_with(
            private_key_dirs=kwargs['key_dirs']
        )

    def test__cmd_targets_remove_latest(self):
        kwargs = dict(subcommand='remove-latest', key_dirs=['c:\\my_private_keys'])
        options = argparse.Namespace(**kwargs)
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_targets(options=options)
        self.mock_repo.remove_latest_bundle.assert_called()

    def test__cmd_sign_threshold(self):
        role_name = 'root'
        key_dirs = ['c:\\my_private_keys']
        options = argparse.Namespace(
            role_name=role_name, key_dirs=key_dirs, expiration_days=None
        )
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_sign(options=options)
        self.mock_repo.threshold_sign.assert_called_with(
            role_name=role_name, private_key_dirs=key_dirs
        )

    def test__cmd_sign_expired(self):
        role_name = 'root'
        key_dirs = ['c:\\my_private_keys']
        options = argparse.Namespace(
            role_name=role_name,
            key_dirs=key_dirs,
            expiration_days='default',  # i.e. specify -e without a value
        )
        with patch('tufup.repo.cli.Repository', self.mock_repo_class):
            tufup.repo.cli._cmd_sign(options=options)
        self.mock_repo.refresh_expiration_date.assert_called_with(
            role_name=role_name, days=self.config['expiration_days'][role_name]
        )
        self.mock_repo.publish_changes.assert_called_with(private_key_dirs=key_dirs)

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
            config_kwargs = tufup.repo.cli._get_config_from_user()
        self.assertTrue(config_kwargs)

    def test__get_config_from_user_with_kwargs(self):
        role_names = ['root', 'targets', 'snapshot', 'timestamp']
        original_kwargs = dict(
            app_name='my-app',
            app_version_attr='my_app.__version__',
            repo_dir='repo/dir',
            keys_dir='keys/dir',
            key_map={name: [name] for name in role_names},
            encrypted_keys=['root'],
            expiration_days={name: 1 for name in role_names},
            thresholds={name: 1 for name in role_names},
        )
        default = ''
        with patch('builtins.input', Mock(return_value=default)):
            config_kwargs = tufup.repo.cli._get_config_from_user(**original_kwargs)
        self.assertEqual(config_kwargs, original_kwargs)
