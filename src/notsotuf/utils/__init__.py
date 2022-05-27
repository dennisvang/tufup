import logging
import pathlib
import shutil
from typing import List, Optional, Union

logger = logging.getLogger(__name__)

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
            logger.debug(f'Removed directory {path}')
        elif path.is_file():
            path.unlink()
            logger.debug(f'Removed file {path}')
    except Exception as e:
        logger.error(f'Failed to remove {path}: {e}')
        return False
    return True


def input_bool(prompt: str, default: bool) -> bool:
    true_inputs = ['y']
    default_str = ' (y/[n])'
    if default:
        default_str = ' ([y]/n)'
        true_inputs.append('')
    return input(prompt + default_str + _INPUT_SEPARATOR) in true_inputs


def input_list(
        prompt: str, default: List[str], item_default: Optional[str] = None
) -> List[str]:
    new_list = []
    print(prompt)
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
    while answer and not answer.isnumeric():
        answer = input(prompt + default_str + _INPUT_SEPARATOR)
    if answer:
        return int(answer)
    else:
        return default


def input_text(prompt: str, default: str) -> str:
    answer = ''
    default_str = f' (default: {default})'
    while not answer:
        answer = input(prompt + default_str + _INPUT_SEPARATOR) or default
    return answer
