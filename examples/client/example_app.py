import logging
import pathlib
import shutil

from notsotuf.tools.client import Client

# This example stores all files in the notsotuf/examples/client directory
BASE_DIR = pathlib.Path(__file__).resolve().parent

# App info
APP_NAME = 'example_app'
CURRENT_VERSION = '1.0'
# App directories
CACHE_DIR = BASE_DIR / 'cache'
METADATA_DIR = CACHE_DIR / 'metadata'
TARGET_DIR = CACHE_DIR / 'target'
# Update-server urls
METADATA_BASE_URL = 'http://localhost:8000/metadata/'
TARGET_BASE_URL = 'http://localhost:8000/targets/'


def main():
    # The app must ensure dirs exist
    for dir_path in [METADATA_DIR, TARGET_DIR]:
        dir_path.mkdir(exist_ok=True, parents=True)

    # The app must be shipped with a trusted "root.json" metadata file (
    # created using tools.repo), and must ensure this file can found in the
    # specified metadata_dir. The root metadata file lists all trusted keys
    # and TUF roles.
    source_path = BASE_DIR / 'trusted_root.json'
    destination_path = METADATA_DIR / 'root.json'
    if not destination_path.exists():
        shutil.copy(src=source_path, dst=destination_path)
        print('trusted root metadata copied to cache')

    # Create update client
    client = Client(
        app_name=APP_NAME,
        current_version=CURRENT_VERSION,
        metadata_dir=METADATA_DIR,
        metadata_base_url=METADATA_BASE_URL,
        target_dir=TARGET_DIR,
        target_base_url=TARGET_BASE_URL,
        refresh_required=False,
    )

    # Perform update
    client.update()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
