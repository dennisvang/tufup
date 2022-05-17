import logging
import pathlib
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile
from typing import Union
import platform
from notsotuf.utils import remove_path

logger = logging.getLogger(__name__)

def handle_update(
        src_dir: Union[pathlib.Path, str], dst_dir: Union[pathlib.Path, str]
):
    if platform.system() == "Windows":
        return _start_script_and_exit_win(src_dir, dst_dir)
    if platform.system() == "Darwin":
        return _start_script_and_exit_mac(src_dir, dst_dir)
    else:
        raise RuntimeError("This platform is not supported!")

MOVE_FILES_BAT = """@echo off
rem /e: include subdirs, /move: move files and dirs, /v: verbose, /purge: delete stale files and dirs in destination folder
echo Moving app files...
robocopy {src} {dst} /e /move /v /purge
echo Done.
rem Delete self (https://stackoverflow.com/a/20333575)
(goto) 2>nul & del "%~f0"
"""


def _start_script_and_exit_win(
        src_dir: Union[pathlib.Path, str], dst_dir: Union[pathlib.Path, str]
):
    """
    Create a batch script that moves files from src to dst, then run the
    script in a new console, and exit the current process.

    The script is created in a default temporary directory, and deletes
    itself when done.
    """
    script_content = MOVE_FILES_BAT.format(src=src_dir, dst=dst_dir)
    logger.debug(f'writing windows batch script:\n{script_content}')
    with NamedTemporaryFile(
            mode='w', prefix='notsotuf', suffix='.bat', delete=False
    ) as temp_file:
        temp_file.write(script_content)
    print(f'Temporary batch script created: {temp_file.name}')
    script_path = pathlib.Path(temp_file.name).resolve()
    logger.debug(f'starting script in new console: {script_path}')
    subprocess.Popen([script_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
    logger.debug('exiting')
    sys.exit(0)

def _start_script_and_exit_mac(
        src_dir: Union[pathlib.Path, str], dst_dir: Union[pathlib.Path, str]
):
    logger.debug(f"Moving content of {src_dir} to {dst_dir}.")
	remove_path(dst_dir)
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    logger.debug(f"Restarting application, running {sys.executable}.")
    subprocess.Popen(sys.executable, shell=True) # nosec
    sys.exit(0)
