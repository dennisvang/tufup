import logging
import pathlib
import shutil
import sys
from typing import List, Optional, Union

utils_logger = logging.getLogger(__name__)

_INPUT_SEPARATOR = ' '


def remove_path(path: Union[pathlib.Path, str]) -> bool:
    """
    Recursively remove directory or file at specified path.

    If you want to remove directory contents but keep the directory itself:

        for path in my_dir_path.iterdir():
            remove_path(path)
    """
    # enforce pathlib.Path
    path = pathlib.Path(path)
    try:
        if path.is_dir():
            shutil.rmtree(path=path)
            utils_logger.debug(f'Removed directory {path}')
        elif path.is_file():
            path.unlink()
            utils_logger.debug(f'Removed file {path}')
    except Exception as e:
        utils_logger.error(f'Failed to remove {path}: {e}')
        return False
    return True


def log_print(message: str, logger: logging.Logger, level: int = logging.INFO):
    """
    Log message with specified level.

    Print message too, if logger is not enabled for specified level,
    or if logger does not have a handler that streams to stdout.
    """
    # log normally
    logger.log(level=level, msg=message)
    # print if necessary
    message_logged_to_stdout = False
    current_logger = logger
    while current_logger and not message_logged_to_stdout:
        is_enabled = current_logger.isEnabledFor(level)
        logs_to_stdout = any(
            getattr(handler, 'stream', None) == sys.stdout
            for handler in current_logger.handlers
        )
        message_logged_to_stdout = is_enabled and logs_to_stdout
        if not current_logger.propagate:
            current_logger = None
        else:
            current_logger = current_logger.parent
    if not message_logged_to_stdout:
        print(message)


def input_bool(prompt: str, default: bool) -> bool:
    true_inputs = ['y']
    default_str = ' (y/[n])'
    if default:
        default_str = ' ([y]/n)'
        true_inputs.append('')
    prompt += default_str + _INPUT_SEPARATOR
    answer = input(prompt)
    utils_logger.debug(f'{prompt}: {answer}')
    return answer in true_inputs


def input_list(
    prompt: str, default: List[str], item_default: Optional[str] = None
) -> List[str]:
    new_list = []
    log_print(message=prompt, level=logging.DEBUG, logger=utils_logger)
    # handle existing items
    for existing_item in default or []:
        if input_bool(f'{existing_item}\nKeep this item?', default=True):
            new_list.append(existing_item)
    # add new items
    while input_bool(prompt='Add a new item?', default=False):
        new_list.append(input_text(prompt='Enter item:', default=item_default))
    # return unique list (use dict keys instead of set(), to preserve order)
    return list(dict.fromkeys(new_list))


def input_numeric(prompt: str, default: int) -> int:
    answer = 'not empty, not numeric'
    default_str = f' (default: {default})'
    prompt += default_str + _INPUT_SEPARATOR
    while answer and not answer.isnumeric():
        answer = input(prompt)
        utils_logger.debug(f'{prompt}: {answer}')
    if answer:
        return int(answer)
    else:
        return default


def input_text(
    prompt: str, default: Optional[str], optional: bool = False
) -> Optional[str]:
    answer = None
    prompt += f' (default: {default})'
    prompt += ' [optional]' if optional else ''
    prompt += _INPUT_SEPARATOR
    while not answer:
        answer = input(prompt) or default
        utils_logger.debug(f'{prompt}: {answer}')
        if optional:
            break
    return answer
