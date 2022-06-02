import subprocess
import sys
from time import sleep

from tests import BASE_DIR, TempDirTestCase

DUMMY_APP_CONTENT = f"""
import sys
sys.path.append('{(BASE_DIR.parent / 'src').as_posix()}')
from notsotuf.utils.platform_specific import install_update
install_update(src_dir=sys.argv[1], dst_dir=sys.argv[2])
"""


class UtilsTests(TempDirTestCase):
    def test_install_update(self):
        # create src dir with dummy app file, and dst dir with stale subdir
        test_dir = self.temp_dir_path / 'notsotuf_tests'
        src_dir = test_dir / 'src'
        src_dir.mkdir(parents=True)
        dst_dir = test_dir / 'dst'
        dst_subdir = dst_dir / 'stale'
        dst_subdir.mkdir(parents=True)
        (dst_subdir / 'stale.file').touch()
        src_file_name = 'dummy_app.py'
        src_file_path = src_dir / src_file_name
        src_file_path.write_text(DUMMY_APP_CONTENT)
        # run the dummy app in a separate process, which, in turn, will run
        # another process that moves the file
        completed_process = subprocess.run(
            [sys.executable, src_file_path, src_dir, dst_dir]
        )
        print(sys.executable)
        completed_process.check_returncode()
        # allow some time for the batch file to complete
        sleep(1)
        # ensure file has been moved from src to dst
        self.assertTrue(any(dst_dir.iterdir()))
        self.assertTrue((dst_dir / src_file_name).exists())
        # original src file no longer exists
        self.assertFalse(src_file_path.exists())
        # stale dst content has been removed (robocopy /purge)
        self.assertFalse(dst_subdir.exists())
