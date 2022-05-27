import pathlib
import unittest
from unittest.mock import Mock, patch

import notsotuf.utils
from tests import TempDirTestCase


class RemovePathTests(TempDirTestCase):
    def test_remove_path(self):
        for arg_type in [str, pathlib.Path]:
            # create a directory and subdirectory with dummy files
            dir_path = self.temp_dir_path / 'dir'
            subdir_path = dir_path / 'subdir'
            subdir_path.mkdir(parents=True)
            for file in [dir_path / 'file.in.dir', subdir_path / 'file.in.subdir']:
                file.touch()
            # just to be sure
            self.assertEqual(2, len(list(dir_path.iterdir())))
            self.assertEqual(1, len(list(subdir_path.iterdir())))
            # test
            with self.subTest(msg=arg_type):
                self.assertTrue(
                    notsotuf.utils.remove_path(path=arg_type(dir_path))
                )
                self.assertFalse(dir_path.exists())


class InputTests(unittest.TestCase):
    def test_input_bool(self):
        inputs = [('', None), ('y', True), ('n', False), ('anything', False)]
        for default in [True, False]:
            for user_input, expected in inputs:
                if expected is None:
                    expected = default
                with patch('builtins.input', Mock(return_value=user_input)):
                    self.assertEqual(
                        expected,
                        notsotuf.utils.input_bool(prompt='', default=default),
                    )

    def test_input_list(self):
        default = ['existing item']
        item_default = 'default item'
        new_item = 'new item'
        bool_inputs = iter([True, True, True, False])
        text_inputs = iter(['', new_item])
        # we use iterators to simulate sequences of user inputs
        with patch.object(
                notsotuf.utils, 'input_bool', lambda *_, **__: next(bool_inputs)
        ):
            with patch.object(
                    notsotuf.utils,
                    'input_text',
                    lambda *_, **__: next(text_inputs) or item_default,
            ):
                expected = default + [item_default, new_item]
                self.assertEqual(
                    expected,
                    notsotuf.utils.input_list(
                        prompt='', default=default, item_default=item_default
                    )
                )

    def test_input_numeric(self):
        default = 1
        answer = 0
        user_inputs = iter(['not numeric', str(answer)])
        # we use an iterator to simulate a sequence of user inputs,
        # and return '' instead of raising StopIteration
        with patch('builtins.input', lambda *_: next(user_inputs, '')):
            self.assertEqual(
                answer, notsotuf.utils.input_numeric(prompt='', default=default)
            )
            # iterator exhausted, so next user input is ''
            self.assertEqual(
                default, notsotuf.utils.input_numeric(prompt='', default=default)
            )

    def test_input_text(self):
        answer = 'something'
        user_inputs = iter(['', answer])
        with patch('builtins.input', lambda *_: next(user_inputs, '')):
            # this should iterate until we get a non-empty answer
            self.assertEqual(
                answer, notsotuf.utils.input_text(prompt='', default='')
            )
            # iterator exhausted, so next user input is ''
            self.assertEqual(
                answer, notsotuf.utils.input_text(prompt='', default=answer)
            )

    def test_input_text_optional(self):
        with patch('builtins.input', Mock(return_value='')):
            self.assertIsNone(
                notsotuf.utils.input_text(
                    prompt='', default=None, optional=True
                )
            )

    def test_get_config_from_user_no_kwargs(self):
        default = ''
        yes = 'y'
        no = 'n'
        user_inputs = iter(
            [
                'my-app',
                'my_app.__version__',
                'repo/dir',
                'keys/dir',
                default,
                yes,
                '365',
                default,
                no,
                '7',
                default,
                no,
                '7',
                default,
                no,
                '1',
            ]
        )
        with patch('builtins.input', lambda *_, **__: next(user_inputs)):
            config_kwargs = notsotuf.get_config_from_user()
        self.assertTrue(config_kwargs)

    def test_get_config_from_user_with_kwargs(self):
        original_kwargs = dict(
            app_name='my-app',
            app_version_attr='my_app.__version__',
            repo_dir='repo/dir',
            keys_dir='keys/dir',
            key_map=notsotuf.repo.DEFAULT_KEY_MAP,
            encrypted_keys=['root'],
            expiration_days=notsotuf.repo.DEFAULT_EXPIRATION_DAYS,
        )
        default = ''
        with patch('builtins.input', Mock(return_value=default)):
            config_kwargs = notsotuf.get_config_from_user(**original_kwargs)
        self.assertEqual(config_kwargs, original_kwargs)
