import logging
import pathlib
import subprocess
import sys
from tempfile import NamedTemporaryFile

logger = logging.getLogger(__name__)

BAT_TEMPLATE = """@echo off
rem /e: include subdirs, /move: move files and dirs, /v: verbose, /purge: delete stale files and dirs in destination folder
echo Moving app files...
robocopy {src} {dst} /e /move /v /purge
echo Done.
rem delete self (https://stackoverflow.com/a/20333575)
(goto) 2>nul & del "%~f0" & pause
"""


def start_script_and_exit(src_dir: pathlib.Path, dst_dir: pathlib.Path):
    script_content = BAT_TEMPLATE.format(src=src_dir, dst=dst_dir)
    logger.debug(f'writing windows batch script:\n{script_content}')
    with NamedTemporaryFile(mode='w', prefix='notsotuf', suffix='.bat', delete=False) as temp_file:
        temp_file.write(script_content)
    script_path = pathlib.Path(temp_file.name).resolve()
    logger.debug(f'starting script in new console: {script_path}')
    subprocess.Popen([script_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
    logger.debug('exiting')
    sys.exit(0)
