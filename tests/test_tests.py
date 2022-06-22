import pathlib
from unittest import TestCase

from tests import _create_cwd_change_generator, TempDirTestCase


class CreateToggleGeneratorTests(TestCase):
    def test__create_toggle_cwd_generator(self):
        original_cwd = pathlib.Path.cwd()
        toggle_generator = _create_cwd_change_generator()
        # switch to temporary dir
        temp_dir = next(toggle_generator)
        self.assertNotEqual(original_cwd, temp_dir)
        self.assertNotEqual(original_cwd, pathlib.Path.cwd())
        self.assertTrue(pathlib.Path(temp_dir).exists())
        # switch back to original dir
        try:
            next(toggle_generator)
        except StopIteration:
            pass
        self.assertEqual(original_cwd, pathlib.Path.cwd())
        self.assertFalse(pathlib.Path(temp_dir).exists())


class TempDirTestCaseTests(TempDirTestCase):
    def setUp(self) -> None:
        self.original_cwd = pathlib.Path.cwd()
        super().setUp()

    def test_temporary_cwd(self):
        current_cwd = pathlib.Path.cwd()
        self.assertNotIn('tests', str(current_cwd))
        self.assertNotEqual(self.original_cwd, current_cwd)
        self.assertEqual(self.temp_dir_path.resolve(), current_cwd.resolve())
