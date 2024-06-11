import pathlib
from getpass import getuser
import os
import subprocess
import sys
import tempfile
import textwrap
from time import sleep
import unittest
from unittest.mock import patch

from tests import BASE_DIR, TempDirTestCase
import tufup.utils.platform_specific as ps
from tufup.utils.platform_specific import (
    ON_MAC,
    ON_WINDOWS,
    PLATFORM_SUPPORTED,
    run_bat_as_admin,
    WIN_BATCH_PREFIX,
    WIN_BATCH_SUFFIX,
)

_reason_platform_not_supported = (
    'install_update() is only actively supported on windows and mac'
)

DUMMY_APP_CONTENT = f"""
import subprocess
import sys
sys.path.append('{(BASE_DIR.parent / 'src').as_posix()}')
from tufup.utils.platform_specific import install_update
install_update(src_dir=sys.argv[1], dst_dir=sys.argv[2], {{extra_kwargs_str}})
"""

ON_GITHUB = os.getenv('GITHUB_ACTIONS')
TEST_RUNAS = os.getenv('TEST_RUNAS')


class UtilsTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # create src dir with dummy app file, and dst dir with stale subdir
        # and a file that must be excluded from purge
        test_dir = self.temp_dir_path / 'tufup_tests'
        self.src_dir = test_dir / 'src'
        self.src_subdir = self.src_dir / 'new'
        self.src_subdir.mkdir(parents=True)
        self.dst_dir = test_dir / 'dst'
        self.dst_subdir = self.dst_dir / 'stale'
        self.dst_subdir.mkdir(parents=True)
        (self.dst_subdir / 'stale.file').touch()
        self.keep_file_path = self.dst_dir / 'keep.file'
        self.keep_file_path.touch()
        self.keep_file_str = str(self.keep_file_path).replace('\\', '\\\\')
        self.src_file_name = 'dummy_app.py'
        self.src_file_path = self.src_dir / self.src_file_name

    def run_dummy_app(self, extra_kwargs_strings):
        # write dummy app content to file
        dummy_app_content = DUMMY_APP_CONTENT.format(
            extra_kwargs_str=', '.join(extra_kwargs_strings),
        )
        print(dummy_app_content)
        self.src_file_path.write_text(dummy_app_content)
        # run the dummy app in a separate process, which, in turn, will run
        # another process that moves the file
        completed_process = subprocess.run(
            [sys.executable, self.src_file_path, self.src_dir, self.dst_dir]
        )
        print(sys.executable)
        completed_process.check_returncode()
        if ON_WINDOWS:
            # allow some time for the batch file to complete (the batch file
            # waits a few seconds, so we have to wait longer)
            sleep(3)

    @unittest.skipIf(
        condition=ON_GITHUB or not TEST_RUNAS or not ON_WINDOWS,
        reason='windows only, requires user interaction',
    )
    def test_run_bat_as_admin(self):
        output_path = self.temp_dir_path / 'output.txt'
        bat_path = self.temp_dir_path / 'tell_me_who_i_am.bat'
        bat_path.write_text(f'whoami > "{output_path}"\ntimeout /t -1')
        # NOTE: this will open a UAC prompt (User Access Control)
        self.assertTrue(run_bat_as_admin(file_path=bat_path))
        # doesn't block, so we'll pause for a while
        sleep(1)
        self.assertTrue(output_path.exists())
        output = output_path.read_text()
        current_user = getuser()
        print(f'bat file runs as: {output}')
        print(f'current user: {current_user}')
        self.assertTrue(len(output))
        self.assertNotIn(current_user, output)

    @unittest.skipIf(condition=not ON_MAC, reason='macOS only')
    def test_install_update_macos_symlinks(self):
        with patch.object(ps, '_install_update_mac') as mock_install_update_mac:
            ps.install_update(src_dir='', dst_dir='')
            self.assertNotIn('symlinks', mock_install_update_mac.call_args.kwargs)
            ps.install_update(src_dir='', dst_dir='', symlinks=True)
            self.assertTrue(mock_install_update_mac.call_args.kwargs['symlinks'])

    @unittest.skipIf(
        condition=not PLATFORM_SUPPORTED, reason=_reason_platform_not_supported
    )
    def test_install_update_no_purge(self):
        extra_kwargs_strings = []
        if ON_WINDOWS:
            extra_kwargs_strings.extend(
                # unknown_kwarg reproduces issue #126
                ['as_admin=False', 'log_file_name=None', 'unknown_kwarg=True']
            )
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # ensure file has been moved from src to dst
        self.assertTrue(any(self.dst_dir.iterdir()))
        self.assertTrue((self.dst_dir / self.src_file_name).exists())
        # new empty subdir has been moved as well
        self.assertTrue((self.dst_dir / self.src_subdir.name).exists())
        # original src file no longer exists
        self.assertFalse(self.src_file_path.exists())
        # stale dst content must still be present
        self.assertTrue(self.dst_subdir.exists())
        # file to keep must still be present
        self.assertTrue(self.keep_file_path.exists())
        # the batch file itself should have been removed
        self.assertFalse(batch_file_exists())

    @unittest.skipIf(
        condition=not PLATFORM_SUPPORTED, reason=_reason_platform_not_supported
    )
    def test_install_update_purge(self):
        extra_kwargs_strings = [
            'purge_dst_dir=True',
            f'exclude_from_purge=["{self.keep_file_str}"]',
        ]
        if ON_WINDOWS:
            extra_kwargs_strings.extend(['as_admin=False', 'log_file_name=None'])
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # ensure file has been moved from src to dst
        self.assertTrue(any(self.dst_dir.iterdir()))
        self.assertTrue((self.dst_dir / self.src_file_name).exists())
        # new empty subdir has been moved as well
        self.assertTrue((self.dst_dir / self.src_subdir.name).exists())
        # original src file no longer exists
        self.assertFalse(self.src_file_path.exists())
        # stale dst content has been removed (robocopy /purge)
        self.assertFalse(self.dst_subdir.exists())
        # file to keep must still be present
        self.assertTrue(self.keep_file_path.exists())

    @unittest.skipIf(condition=not ON_WINDOWS, reason='robocopy is windows only')
    def test_install_update_robocopy_options_override(self):
        extra_kwargs_strings = [
            'as_admin=False',
            'log_file_name=None',
            'robocopy_options_override=[]',
        ]
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # ensure file has been copied from src to dst
        self.assertTrue(any(self.dst_dir.iterdir()))
        self.assertTrue((self.dst_dir / self.src_file_name).exists())
        # new subdir has not been copied
        self.assertFalse((self.dst_dir / self.src_subdir.name).exists())
        # original src file still exists
        self.assertTrue(self.src_file_path.exists())
        # stale dst content must still be present
        self.assertTrue(self.dst_subdir.exists())
        # file to keep must still be present
        self.assertTrue(self.keep_file_path.exists())

    @unittest.skipIf(
        condition=not ON_WINDOWS, reason='install.log file is windows only'
    )
    def test_install_update_log_file(self):
        log_file_name = 'install.log'
        extra_kwargs_strings = [
            'as_admin=False',
            f'log_file_name="{log_file_name}"',
            'robocopy_options_override=[]',
        ]
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # a log file should exist
        log_file_path = self.dst_dir / log_file_name
        self.assertTrue(log_file_path.exists())
        log_file_content = log_file_path.read_text()
        self.assertTrue(log_file_content)

    @unittest.skipIf(
        condition=not ON_WINDOWS, reason='process_creation_flags is for windows only'
    )
    def test_install_update_process_creation_flags(self):
        # the log file is only used to verify that the batch file has run successfully
        log_file_name = 'install.log'
        extra_kwargs_strings = [
            'process_creation_flags=subprocess.CREATE_NO_WINDOW',
            f'log_file_name="{log_file_name}"',
        ]
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # a log file should exist
        log_file_path = self.dst_dir / log_file_name
        self.assertTrue(log_file_path.read_text())

    @unittest.skipIf(
        condition=not ON_WINDOWS, reason='windows batch files are windows only'
    )
    def test_install_update_custom_batch_template(self):
        custom_content = 'some custom text'
        custom_file_path = self.temp_dir_path / 'test.txt'
        # a custom batch template that ignores most of the default template
        # variables and adds some custom variables
        custom_batch_template = textwrap.dedent(
            """
            echo {custom_content}> "{custom_file_path}"
            {delete_self}
            """
        )
        extra_kwargs_strings = [
            f'batch_template="""{custom_batch_template}"""',
            f'batch_template_extra_kwargs=dict(custom_content="{custom_content}", custom_file_path=r"{custom_file_path}")',
        ]
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # batch file should have created a file with specified content
        self.assertTrue(custom_file_path.exists())
        custom_file_content = custom_file_path.read_text()
        self.assertIn(custom_content, custom_file_content)
        # the batch file itself should have been removed
        self.assertFalse(batch_file_exists())


def batch_file_exists():
    """
    Checks if any tufup batch files remain in the system temporary directory.

    BEWARE: If a batch file does not remove itself successfully even once,
    this function will keep returning True, until the batch file is removed
    manually from the system temp dir (see print statement below). Windows
    does not clear the temp dirs automatically.
    """
    system_temp_dir = pathlib.Path(tempfile.gettempdir())
    print(f'system temp dir: {system_temp_dir}')
    return any(
        path.name.startswith(WIN_BATCH_PREFIX) and path.name.endswith(WIN_BATCH_SUFFIX)
        for path in system_temp_dir.iterdir()
        if path.is_file()
    )
