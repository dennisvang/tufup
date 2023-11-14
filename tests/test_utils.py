import os
import pathlib
import unittest
from unittest.mock import Mock, patch

import tufup.utils
from tufup.utils.platform_specific import ON_WINDOWS
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
                self.assertTrue(tufup.utils.remove_path(path=arg_type(dir_path)))
                self.assertFalse(dir_path.exists())

    def test_remove_dir_for_readonly_file(self):
        """
        on linux: a readonly file does not prevent deletion of the file, nor does it
        prevent deletion of the parent directory

        on windows: a readonly file prevents both file deletion and deletion of the
        parent directory
        """
        # prepare readonly file
        dir_path = self.temp_dir_path / 'dir'
        file_path = dir_path / 'readonly.file'
        dir_path.mkdir()
        file_path.touch(mode=0o444)
        # test
        self.assertEqual(not ON_WINDOWS, tufup.utils.remove_path(dir_path))
        if ON_WINDOWS:
            self.assertTrue(tufup.utils.remove_path(dir_path, remove_readonly=True))


    def test_remove_dir_for_readonly_dir(self):
        """
        on linux: a readonly directory prevents both file deletion and deletion of
        the directory itself

        on windows: a "readonly" directory does *not* prevent file deletion, but it
        does prevent deletion of the directory, even though some sources suggest "the
        Read-only attribute for a folder is typically ignored by Windows" [1]

        [1]: https://support.microsoft.com/en-gb/topic/you-cannot-view-or-change-the-read-only-or-the-system-attributes-of-folders-in-windows-server-2003-in-windows-xp-in-windows-vista-or-in-windows-7-55bd5ec5-d19e-6173-0df1-8f5b49247165
        """
        # prepare readonly directory
        dir_path = self.temp_dir_path / 'readonly_dir'
        file_path = dir_path / 'dummy.file'
        dir_path.mkdir()
        file_path.touch()
        dir_path.chmod(0o555)  # dir must have execution permission
        # test
        self.assertFalse(tufup.utils.remove_path(dir_path))
        self.assertTrue(tufup.utils.remove_path(dir_path, remove_readonly=True))


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
                        tufup.utils.input_bool(prompt='', default=default),
                    )

    def test_input_list(self):
        default = ['existing item']
        item_default = 'default item'
        new_item = 'new item'
        bool_inputs = iter([True, True, True, False])
        text_inputs = iter(['', new_item])
        # we use iterators to simulate sequences of user inputs
        with patch.object(
            tufup.utils, 'input_bool', lambda *_, **__: next(bool_inputs)
        ):
            with patch.object(
                tufup.utils,
                'input_text',
                lambda *_, **__: next(text_inputs) or item_default,
            ):
                expected = default + [item_default, new_item]
                self.assertEqual(
                    expected,
                    tufup.utils.input_list(
                        prompt='', default=default, item_default=item_default
                    ),
                )

    def test_input_numeric(self):
        default = 1
        answer = 0
        user_inputs = iter(['not numeric', str(answer)])
        # we use an iterator to simulate a sequence of user inputs,
        # and return '' instead of raising StopIteration
        with patch('builtins.input', lambda *_: next(user_inputs, '')):
            self.assertEqual(
                answer, tufup.utils.input_numeric(prompt='', default=default)
            )
            # iterator exhausted, so next user input is ''
            self.assertEqual(
                default, tufup.utils.input_numeric(prompt='', default=default)
            )

    def test_input_text(self):
        answer = 'something'
        user_inputs = iter(['', answer])
        with patch('builtins.input', lambda *_: next(user_inputs, '')):
            # this should iterate until we get a non-empty answer
            self.assertEqual(answer, tufup.utils.input_text(prompt='', default=''))
            # iterator exhausted, so next user input is ''
            self.assertEqual(answer, tufup.utils.input_text(prompt='', default=answer))

    def test_input_text_optional(self):
        with patch('builtins.input', Mock(return_value='')):
            self.assertIsNone(
                tufup.utils.input_text(prompt='', default=None, optional=True)
            )
