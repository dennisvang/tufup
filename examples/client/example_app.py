import logging
import pathlib
import shutil

import bsdiff4

from tufup.client import Client
from tufup.common import BinaryDiff

logger = logging.getLogger(__name__)

# To get started, create a local example repository by running the
# repo_workflow_example.py script. Then serve the repo content directory on
# localhost:
#
#   python -m http.server -d examples/repo/content

# App info
APP_NAME = 'example_app'  # BEWARE: app name cannot contain whitespace
CURRENT_VERSION = '1.0'

# For this example, all files are stored in the tufup/examples/client
# directory. On Windows 10, a typical location for the BASE_DIR would be
# %PROGRAMDATA%\MyApp (per-machine), or %LOCALAPPDATA%\MyApp (per-user).
BASE_DIR = pathlib.Path(__file__).resolve().parent

# For this example, we copy the trusted root metadate directly from the repo dir
REPO_METADATA_DIR = BASE_DIR.parent / 'repo' / 'content' / 'metadata'

# On Windows 10, typical app installation locations are %PROGRAMFILES%\MyApp
# (per-machine) or %LOCALAPPDATA%\Programs\MyApp (per-user). Also see:
# https://docs.microsoft.com/en-us/windows/win32/msi/installation-context
APP_INSTALL_DIR = BASE_DIR / 'programs' / APP_NAME

# App directories
CACHE_DIR = BASE_DIR / 'cache'
METADATA_DIR = CACHE_DIR / 'metadata'
TARGET_DIR = CACHE_DIR / 'targets'

# Update-server urls
METADATA_BASE_URL = 'http://localhost:8000/metadata/'
TARGET_BASE_URL = 'http://localhost:8000/targets/'


# By default, tufup uses bsdiff4 to create patches, but we can override that.
# Here's a dummy example (just extending bsdiff4).
# You do not need to do this if you're happy with the default bsdiff4.
class CustomBinaryDiff(BinaryDiff):
    diff = bsdiff4.diff

    @staticmethod
    def patch(*, src_bytes: bytes, patch_bytes: bytes) -> bytes:
        logger.info('this is a custom patch, but we still use bsdiff4 for convenience')
        return bsdiff4.patch(src_bytes=src_bytes, patch_bytes=patch_bytes)


def main():
    # The app must ensure dirs exist
    for dir_path in [APP_INSTALL_DIR, METADATA_DIR, TARGET_DIR]:
        dir_path.mkdir(exist_ok=True, parents=True)

    # The app must be shipped with a trusted "root.json" metadata file (
    # created using tools.repo), and must ensure this file can found in the
    # specified metadata_dir. The root metadata file lists all trusted keys
    # and TUF roles. In this example we copy the root.json file from the
    # repo, but normally it would be included in the app distribution.
    source_path = REPO_METADATA_DIR / 'root.json'
    destination_path = METADATA_DIR / 'root.json'
    if not destination_path.exists():
        shutil.copy(src=source_path, dst=destination_path)
        logger.info('Trusted root metadata copied to cache.')

    # Create update client
    client = Client(
        app_name=APP_NAME,
        app_install_dir=APP_INSTALL_DIR,
        current_version=CURRENT_VERSION,
        metadata_dir=METADATA_DIR,
        metadata_base_url=METADATA_BASE_URL,
        target_dir=TARGET_DIR,
        target_base_url=TARGET_BASE_URL,
        refresh_required=False,
        binary_diff=CustomBinaryDiff,
    )

    # Perform update
    if client.check_for_updates():
        client.download_and_apply_update()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
