import logging
import pathlib
import platform
import shutil
import subprocess
import sys
from tempfile import NamedTemporaryFile
from typing import List, Optional, Union

from tufup.utils import remove_path

logger = logging.getLogger(__name__)

CURRENT_PLATFORM = platform.system()
ON_WINDOWS = CURRENT_PLATFORM == 'Windows'
ON_MAC = CURRENT_PLATFORM == 'Darwin'
PLATFORM_SUPPORTED = ON_WINDOWS or ON_MAC


def install_update(
    src_dir: Union[pathlib.Path, str],
    dst_dir: Union[pathlib.Path, str],
    purge_dst_dir: bool = False,
    exclude_from_purge: Optional[List[Union[pathlib.Path, str]]] = None,
    **kwargs,
):
    """
    Installs update files using platform specific installation script. The
    actual installation script copies the files and folders from `src_dir` to
    `dst_dir`.

    If `purge_dst_dir` is `True`, *ALL* files and folders are deleted from
    `dst_dir` before copying.

    **DANGER**:

    ONLY use `purge_dst_dir=True` if your app is properly installed in its
    own *separate* directory, such as %PROGRAMFILES%\MyApp.

    DO NOT use `purge_dst_dir=True` if your app executable is running
    directly from a folder that also contains unrelated files or folders,
    such as the Desktop folder or the Downloads folder, because this
    unrelated content would be then also be deleted.

    Individual files and folders can be excluded from purge using e.g.

        exclude_from_purge=['path\\to\\file1', r'"path to\file2"', ...]

    If `purge_dst_dir` is `False`, the `exclude_from_purge` argument is
    ignored.
    """
    if ON_WINDOWS:
        _install_update = _install_update_win
    elif ON_MAC:
        _install_update = _install_update_mac
    else:
        raise RuntimeError('This platform is not supported.')
    return _install_update(
        src_dir=src_dir,
        dst_dir=dst_dir,
        purge_dst_dir=purge_dst_dir,
        exclude_from_purge=exclude_from_purge,
        **kwargs,
    )


# Note that robocopy itself also has an option to create a log file,
# viz. `/log:<filename>`, as well as a `/tee` option, but we want to log *all*
# output from the batch file, not just output from the robocopy command.
WIN_LOG_LINES = """
call :log > "{log_file_path}" 2>&1
:log
"""
WIN_ROBOCOPY_OVERWRITE = (
    '/e',  # include subdirectories, even if empty
    '/move',  # deletes files and dirs from source dir after they've been copied
    '/v',  # verbose (show what is going on)
    '/w:2',  # set retry-timeout (default is 30 seconds)
)
WIN_ROBOCOPY_PURGE = '/purge'  # delete all files and dirs in destination folder
WIN_ROBOCOPY_EXCLUDE_FROM_PURGE = '/xf'  # exclude specified paths from purge
# makes batch file delete itself when done (https://stackoverflow.com/a/20333575)
WIN_BATCH_DELETE_SELF = '(goto) 2>nul & del "%~f0"'

# _install_update_win makes sure the following variables are available for
# batch templates:
# {log_lines}, {src_dir}, {dst_dir}, {robocopy_options}, {delete_self}
WIN_BATCH_TEMPLATE = """@echo off
{log_lines}
echo Moving app files...
robocopy "{src_dir}" "{dst_dir}" {robocopy_options}
echo Done.
{delete_self}
"""
WIN_BATCH_PREFIX = 'tufup'
WIN_BATCH_SUFFIX = '.bat'


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
        ' '.join(['/c', f'"{file_path}"']),  # parameters
        None,  # working directory (default is cwd)
        1,  # show window normally
    )
    success = result > 32
    if not success:
        logger.error(
            f'failed to run batch script as admin (ShellExecuteW returned {result})'
        )
    return success


def _install_update_win(
    src_dir: Union[pathlib.Path, str],
    dst_dir: Union[pathlib.Path, str],
    purge_dst_dir: bool,
    exclude_from_purge: List[Union[pathlib.Path, str]],
    as_admin: bool = False,
    batch_template: str = WIN_BATCH_TEMPLATE,
    batch_template_extra_kwargs: Optional[dict] = None,
    log_file_name: Optional[str] = None,
    robocopy_options_override: Optional[List[str]] = None,
    process_creation_flags=None,
    **kwargs,  # noqa
):
    """
    Create a batch script that moves files from src to dst, then run the
    script in a new console, and exit the current process.

    The script is created in a default temporary directory, and deletes
    itself when done.

    The `as_admin` options allows installation as admin (opens UAC dialog).

    The `batch_template` option allows specification of custom batch-file
    content. This may be in the form of a template string, as in the default
    `WIN_BATCH_TEMPLATE`, or it may be a ready-made string without any
    template variables. The following default template variables are
    available for use in the custom template, although their use is optional:
    {log_lines}, {src_dir}, {dst_dir}, {robocopy_options}, {delete_self}.
    Custom template variables can be used as well, in which case you'll need
    to specify `batch_template_extra_kwargs`.

    The `batch_template_extra_kwargs` options allows specification of
    *custom* template variables (in addition to the default ones, which are
    always available). It accepts a dict, with keys matching the *custom*
    template variable names specified in the `batch_template`.

    The `log_file_name` option will log the output of the install script to a
    file in the `dst_dir`.

    The `robocopy_options_override` option allows options for [robocopy][1]
    to be overridden completely. It accepts a list of option strings. This
    will cause the purge arguments to be ignored as well.

    The `process_creation_flags` option allows users to override creation flags for
    the subprocess call that runs the batch script. For example, one could specify
    `subprocess.CREATE_NO_WINDOW` to prevent a window from opening. See [2] and [3]
    for details.

    [1]: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
    [2]: https://docs.python.org/3/library/subprocess.html#windows-constants
    [3]: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    """
    if batch_template_extra_kwargs is None:
        batch_template_extra_kwargs = dict()
    # collect robocopy options
    if robocopy_options_override is None:
        robocopy_options = list(WIN_ROBOCOPY_OVERWRITE)
        if purge_dst_dir:
            robocopy_options.append(WIN_ROBOCOPY_PURGE)
            if exclude_from_purge:
                robocopy_options.append(WIN_ROBOCOPY_EXCLUDE_FROM_PURGE)
                robocopy_options.extend(exclude_from_purge)
    else:
        # empty list [] simply clears all options
        robocopy_options = robocopy_options_override
    options_str = ' '.join(robocopy_options)
    # handle batch file output logging
    log_lines = ''
    if log_file_name:
        log_file_path = pathlib.Path(dst_dir) / log_file_name
        log_lines = WIN_LOG_LINES.format(log_file_path=log_file_path)
        logger.info(f'logging install script output to {log_file_path}')
    # write temporary batch file (NOTE: The file is placed in the system
    # default temporary dir, but the file is not removed automatically. So,
    # either the batch file should self-delete when done, or it should be
    # deleted by some other means, because windows does not clean the temp
    # dir automatically.)
    script_content = batch_template.format(
        src_dir=src_dir,
        dst_dir=dst_dir,
        robocopy_options=options_str,
        log_lines=log_lines,
        delete_self=WIN_BATCH_DELETE_SELF,
        **batch_template_extra_kwargs,
    )
    logger.debug(f'writing windows batch script:\n{script_content}')
    with NamedTemporaryFile(
        mode='w', prefix=WIN_BATCH_PREFIX, suffix=WIN_BATCH_SUFFIX, delete=False
    ) as temp_file:
        temp_file.write(script_content)
    logger.debug(f'temporary batch script created: {temp_file.name}')
    script_path = pathlib.Path(temp_file.name).resolve()
    logger.debug(f'starting script in new console: {script_path}')
    # start the script in a separate process, non-blocking
    if as_admin:
        logger.debug('as admin')
        run_bat_as_admin(file_path=script_path)
    else:
        # by default we create a new console with window, but user can override this
        # using the process_creation_flags argument
        if process_creation_flags is None:
            process_creation_flags = subprocess.CREATE_NEW_CONSOLE
        else:
            logger.debug('using custom process creation flags')
        # we use Popen() instead of run(), because the latter blocks execution
        subprocess.Popen([script_path], creationflags=process_creation_flags)
    logger.debug('exiting')
    # exit current process
    sys.exit(0)


def _install_update_mac(
    src_dir: Union[pathlib.Path, str],
    dst_dir: Union[pathlib.Path, str],
    purge_dst_dir: bool,
    exclude_from_purge: List[Union[pathlib.Path, str]],
    symlinks: bool = False,
    **kwargs,
):
    """
    The symlinks arg is passed on to shutil.copytree()

    [1]: https://docs.python.org/3/library/shutil.html#shutil.copytree
    """
    # todo: implement as_admin and debug kwargs for mac
    logger.debug(f'Kwargs not used: {kwargs}')
    if purge_dst_dir:
        exclude_from_purge = (
            [  # enforce path objects
                pathlib.Path(item) for item in exclude_from_purge
            ]
            if exclude_from_purge
            else []
        )
        logger.debug(f'Purging content of {dst_dir}')
        for path in pathlib.Path(dst_dir).iterdir():
            if path not in exclude_from_purge:
                remove_path(path=path)
    logger.debug(f'Moving content of {src_dir} to {dst_dir}.')
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True, symlinks=symlinks)
    # Note: the src_dir is typically a temporary directory, but we'll clear
    # it anyway just to be consistent with the windows implementation
    for path in pathlib.Path(src_dir).iterdir():
        remove_path(path=path)
    logger.debug(f'Restarting application, running {sys.executable}.')
    subprocess.Popen(sys.executable, shell=True)  # nosec
    sys.exit(0)


def _patched_resolve(path: pathlib.Path):
    """
    this is a rather crude workaround for cpython issue #82852,
    where Path.resolve() yields a relative path, on windows, if the target
    does not exist yet

    https://github.com/python/cpython/issues/82852

    todo: remove this as soon as support for python 3.9 is dropped
    """
    if ON_WINDOWS and sys.version_info[:2] < (3, 10):
        logger.warning('using patched path for cpython #82852')
        if not path.is_absolute():
            path = pathlib.Path.cwd() / path
    return path.resolve()
