import pathlib
from tempfile import TemporaryDirectory
import unittest

BASE_DIR = pathlib.Path(__file__).resolve().parent
TEST_REPO_DIR = BASE_DIR / 'data' / 'repository'


class TempDirTestCase(unittest.TestCase):
    """Provides a temporary directory with pathlib Path, for convenience."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.temp_dir_path = pathlib.Path(self.temp_dir.name)

    def tearDown(self) -> None:
        # Note that cleanup is not strictly necessary for TemporaryDirectory.
        self.temp_dir.cleanup()
        self.temp_dir = None
        self.temp_dir_path = None

    def mock_cwd(self):
        return self.temp_dir_path
