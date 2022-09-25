from getpass import getuser
import os
import subprocess
import sys
from time import sleep
import unittest

from tests import BASE_DIR, TempDirTestCase
from tufup.utils.platform_specific import (
    ON_WINDOWS,
    PLATFORM_SUPPORTED,
    run_bat_as_admin,
)

_reason_platform_not_supported = (
    "install_update() is only actively supported on windows and mac"
)

DUMMY_APP_CONTENT = f"""
import sys
sys.path.append('{(BASE_DIR.parent / 'src').as_posix()}')
from tufup.utils.platform_specific import install_update
install_update(src_dir=sys.argv[1], dst_dir=sys.argv[2], {{extra_kwargs_str}})
"""

ON_GITHUB = os.getenv("GITHUB_ACTIONS")
TEST_RUNAS = os.getenv("TEST_RUNAS")


class UtilsTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # create src dir with dummy app file, and dst dir with stale subdir
        # and a file that must be excluded from purge
        test_dir = self.temp_dir_path / "tufup_tests"
        self.src_dir = test_dir / "src"
        self.src_subdir = self.src_dir / "new"
        self.src_subdir.mkdir(parents=True)
        self.dst_dir = test_dir / "dst"
        self.dst_subdir = self.dst_dir / "stale"
        self.dst_subdir.mkdir(parents=True)
        (self.dst_subdir / "stale.file").touch()
        self.keep_file_path = self.dst_dir / "keep.file"
        self.keep_file_path.touch()
        self.keep_file_str = str(self.keep_file_path).replace("\\", "\\\\")
        self.src_file_name = "dummy_app.py"
        self.src_file_path = self.src_dir / self.src_file_name

    def run_dummy_app(self, extra_kwargs_strings):
        # write dummy app content to file
        dummy_app_content = DUMMY_APP_CONTENT.format(
            extra_kwargs_str=", ".join(extra_kwargs_strings),
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
        reason="windows only, requires user interaction",
    )
    def test_run_bat_as_admin(self):
        output_path = self.temp_dir_path / "output.txt"
        bat_path = self.temp_dir_path / "tell_me_who_i_am.bat"
        bat_path.write_text(f'whoami > "{output_path}"\ntimeout /t -1')
        # NOTE: this will open a UAC prompt (User Access Control)
        self.assertTrue(run_bat_as_admin(file_path=bat_path))
        # doesn't block, so we'll pause for a while
        sleep(1)
        self.assertTrue(output_path.exists())
        output = output_path.read_text()
        current_user = getuser()
        print(f"bat file runs as: {output}")
        print(f"current user: {current_user}")
        self.assertTrue(len(output))
        self.assertNotIn(current_user, output)

    @unittest.skipIf(
        condition=not PLATFORM_SUPPORTED, reason=_reason_platform_not_supported
    )
    def test_install_update_no_purge(self):
        extra_kwargs_strings = []
        if ON_WINDOWS:
            extra_kwargs_strings.extend(["as_admin=False", "log_file_name=None"])
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

    @unittest.skipIf(
        condition=not PLATFORM_SUPPORTED, reason=_reason_platform_not_supported
    )
    def test_install_update_purge(self):
        extra_kwargs_strings = [
            "purge_dst_dir=True",
            f'exclude_from_purge=["{self.keep_file_str}"]',
        ]
        if ON_WINDOWS:
            extra_kwargs_strings.extend(["as_admin=False", "log_file_name=None"])
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

    @unittest.skipIf(condition=not ON_WINDOWS, reason="robocopy is windows only")
    def test_install_update_robocopy_options_override(self):
        extra_kwargs_strings = [
            "as_admin=False",
            "log_file_name=None",
            "robocopy_options_override=[]",
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
        condition=not ON_WINDOWS, reason="install.log file is windows only"
    )
    def test_install_update_log_file(self):
        log_file_name = "install.log"
        extra_kwargs_strings = [
            "as_admin=False",
            f'log_file_name="{log_file_name}"',
            "robocopy_options_override=[]",
        ]
        # run the dummy app in a separate process
        self.run_dummy_app(extra_kwargs_strings=extra_kwargs_strings)
        # a log file should exist
        log_file_path = self.dst_dir / log_file_name
        self.assertTrue(log_file_path.exists())
        log_file_content = log_file_path.read_text()
        self.assertTrue(log_file_content)
