import logging
import pathlib
import platform
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile
from typing import List, Union

from tufup.utils import remove_path

logger = logging.getLogger(__name__)

CURRENT_PLATFORM = platform.system()
ON_WINDOWS = CURRENT_PLATFORM == 'Windows'
ON_MAC = CURRENT_PLATFORM == 'Darwin'
PLATFORM_SUPPORTED = ON_WINDOWS or ON_MAC


def install_update(
        src_dir: Union[pathlib.Path, str],
        dst_dir: Union[pathlib.Path, str],
        **kwargs,
):
    if ON_WINDOWS:
        return _install_update_win(src_dir=src_dir, dst_dir=dst_dir, **kwargs)
    if ON_MAC:
        return _install_update_mac(src_dir=src_dir, dst_dir=dst_dir, **kwargs)
    raise RuntimeError('This platform is not supported.')


WIN_DEBUG_LINES = """
rem wait for user confirmation (allow user to read any error messages)
timeout /t -1
"""

WIN_DEFAULT_ROBOCOPY_OPTIONS = (
    '/e',  # include subdirs
    '/move',  # move files and dirs
    '/v',  # verbose
    '/purge',  # delete stale files and dirs in destination folder
)

# https://stackoverflow.com/a/20333575
WIN_MOVE_FILES_BAT = """@echo off
echo Moving app files...
rem wait a few seconds for caller to relinquish locks etc. 
timeout /t 2
robocopy "{src}" "{dst}" {options}
echo Done.
{debug_lines}
rem Delete self
(goto) 2>nul & del "%~f0"
"""


def run_bat_as_admin(file_path: Union[pathlib.Path, str]):
    """
    Request elevation for windows command interpreter (opens UAC prompt) and
    then run the specified .bat file.

    Returns True if successfully started, does not block, can continue after
    calling process exits.
    """
    from ctypes import windll
    # https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew
    result = windll.shell32.ShellExecuteW(
        None,  # handle to parent window
        'runas',  # verb
        'cmd.exe',  # file on which verb acts
        ' '.join(['/c', str(file_path)]),  # parameters
        None,  # working directory (default is cwd)
        1,  # show window normally
    )
    return result > 32


def _install_update_win(
        src_dir: Union[pathlib.Path, str],
        dst_dir: Union[pathlib.Path, str],
        as_admin: bool = False,
        debug: bool = False,
        extra_robocopy_options: List[str] = None,
):
    """
    Create a batch script that moves files from src to dst, then run the
    script in a new console, and exit the current process.

    The script is created in a default temporary directory, and deletes
    itself when done.

    Extra options for [robocopy][1] can be specified as a list of strings.
    For example, to exlude files from being purged:

        extra_robocopy_options=['/xf', 'path\\to\\file1', r'"path to\file2"']

    [1]: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
    """
    options = list(WIN_DEFAULT_ROBOCOPY_OPTIONS)
    if extra_robocopy_options:
        options.extend(extra_robocopy_options)
    options_str = ' '.join(options)
    debug_lines = ''
    if debug:
        debug_lines = WIN_DEBUG_LINES
    script_content = WIN_MOVE_FILES_BAT.format(
        src=src_dir, dst=dst_dir, options=options_str, debug_lines=debug_lines
    )
    logger.debug(f'writing windows batch script:\n{script_content}')
    with NamedTemporaryFile(
            mode='w', prefix='tufup', suffix='.bat', delete=False
    ) as temp_file:
        temp_file.write(script_content)
    logger.debug(f'temporary batch script created: {temp_file.name}')
    script_path = pathlib.Path(temp_file.name).resolve()
    logger.debug(f'starting script in new console: {script_path}')
    if as_admin:
        run_bat_as_admin(file_path=script_path)
    else:
        subprocess.Popen(
            [script_path], creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    logger.debug('exiting')
    sys.exit(0)


def _install_update_mac(
        src_dir: Union[pathlib.Path, str],
        dst_dir: Union[pathlib.Path, str],
        **kwargs,
):
    # todo: implement as_admin and debug kwargs for mac
    logger.debug(f'kwargs not used: {kwargs}')
    logger.debug(f'Moving content of {src_dir} to {dst_dir}.')
    remove_path(pathlib.Path(dst_dir))
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
    logger.debug(f'Removing src directory {src_dir}.')
    remove_path(pathlib.Path(src_dir))
    logger.debug(f'Restarting application, running {sys.executable}.')
    subprocess.Popen(sys.executable, shell=True)  # nosec
    sys.exit(0)
