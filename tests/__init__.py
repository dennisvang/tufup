import logging
import os
import pathlib
import sys
from tempfile import TemporaryDirectory
import unittest

logger = logging.getLogger(__name__)

BASE_DIR = pathlib.Path(__file__).resolve().parent
TEST_REPO_DIR = BASE_DIR / 'data' / 'repository'

# facilitate running tests from command line using `python -m unittest`
sys.path.append(str(BASE_DIR.parent / 'src'))


def _create_cwd_change_generator():
    """
    Returns a generator that creates a temporary directory and makes it the
    current working directory.

    TemporaryDirectory can also be used without context management, as it is
    cleaned up automatically. Nevertheless, it is neater to use an explicit
    context manager here.

    Also see example in docs:
    https://docs.python.org/3/library/contextlib.html#contextlib.contextmanager
    """
    # based on the pytest cleandir trick
    original_cwd = os.getcwd()
    with TemporaryDirectory() as temp_dir:
        os.chdir(temp_dir)
        logger.debug(f'cwd changed temporarily to {temp_dir}')
        yield temp_dir
        # the first time next() is called, we stop here, so the temp dir will
        # remain in context until the second call to next(), which will raise
        # StopIteration
        os.chdir(original_cwd)
        logger.debug(f'cwd changed back to {original_cwd}')


class TempDirTestCase(unittest.TestCase):
    """
    Creates a temporary directory for the duration of each test.

    The temporary directory becomes the current working directory (cwd),
    and it is accessible as a pathlib.Path, for convenience.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.change_cwd = _create_cwd_change_generator()

    def setUp(self) -> None:
        self.temp_dir = next(self.change_cwd)
        self.temp_dir_path = pathlib.Path(self.temp_dir)

    def tearDown(self) -> None:
        try:
            next(self.change_cwd)
        except StopIteration:
            pass
        self.temp_dir = None
        self.temp_dir_path = None
