from getpass import getuser
import os
import subprocess
import sys
from time import sleep
import unittest

from tests import BASE_DIR, TempDirTestCase
from tufup.utils.platform_specific import (
    ON_WINDOWS, PLATFORM_SUPPORTED, run_bat_as_admin
)

DUMMY_APP_CONTENT = f"""
import sys
sys.path.append('{(BASE_DIR.parent / 'src').as_posix()}')
from tufup.utils.platform_specific import install_update
install_update(
    src_dir=sys.argv[1], 
    dst_dir=sys.argv[2],
    purge_dst_dir={{purge}},
    exclude_from_purge=["{{keep_file_str}}"], 
    {{extra_kwargs_str}}
)
"""

ON_GITHUB = os.getenv('GITHUB_ACTIONS')
TEST_RUNAS = os.getenv('TEST_RUNAS')


class UtilsTests(TempDirTestCase):
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

    @unittest.skipIf(
        condition=not PLATFORM_SUPPORTED,
        reason='install_update() is only actively supported on windows and mac',
    )
    def test_install_update_purge(self):
        # create src dir with dummy app file, and dst dir with stale subdir
        test_dir = self.temp_dir_path / 'tufup_tests'
        src_dir = test_dir / 'src'
        src_dir.mkdir(parents=True)
        dst_dir = test_dir / 'dst'
        dst_subdir = dst_dir / 'stale'
        dst_subdir.mkdir(parents=True)
        (dst_subdir / 'stale.file').touch()
        src_file_name = 'dummy_app.py'
        src_file_path = src_dir / src_file_name
        keep_file_path = dst_dir / 'keep.file'
        keep_file_path.touch()
        keep_file_str = str(keep_file_path).replace('\\', '\\\\')
        # write dummy app content to file
        extra_kwargs_str = ''
        if ON_WINDOWS:
            extra_kwargs_str = 'as_admin=False, debug=False'
        dummy_app_content = DUMMY_APP_CONTENT.format(
            purge=True,
            keep_file_str=keep_file_str,
            extra_kwargs_str=extra_kwargs_str,
        )
        print(dummy_app_content)
        src_file_path.write_text(dummy_app_content)
        # run the dummy app in a separate process, which, in turn, will run
        # another process that moves the file
        completed_process = subprocess.run(
            [sys.executable, src_file_path, src_dir, dst_dir]
        )
        print(sys.executable)
        completed_process.check_returncode()
        # allow some time for the batch file to complete (it also waits a few
        # seconds, so we have to wait longer)
        sleep(3)
        # ensure file has been moved from src to dst
        self.assertTrue(any(dst_dir.iterdir()))
        self.assertTrue((dst_dir / src_file_name).exists())
        # original src file no longer exists
        self.assertFalse(src_file_path.exists())
        # stale dst content has been removed (robocopy /purge)
        self.assertFalse(dst_subdir.exists())
        # file to keep must still be present
        self.assertTrue(keep_file_path.exists())
