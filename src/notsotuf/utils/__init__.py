import logging
import pathlib
import shutil

logger = logging.getLogger(__name__)


def remove_path(path: pathlib.Path) -> bool:
    """
    Recursively remove directory or file at specified path.

    If you want to remove directory contents but keep the directory itself:

        for path in my_dir_path.iterdir():
            remove_path(path)
    """
    try:
        if path.is_dir():
            shutil.rmtree(path=path)
            logger.debug(f"Removed directory {path}")
        elif path.is_file():
            path.unlink()
            logger.debug(f"Removed file {path}")
    except Exception as e:
        logger.error(f"Failed to remove {path}: {e}")
        return False
    return True
