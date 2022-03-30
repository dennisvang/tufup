import pathlib
from notsotuf.tools.client import Client


METADATA_DIR = pathlib.Path.cwd() / 'metadata'
TARGET_DIR = pathlib.Path.cwd() / 'target'
METADATA_BASE_URL = 'http://localhost:8000/metadata/'
TARGET_BASE_URL = 'http://localhost:8000/targets/'


def main():
    # ensure dirs exist
    for dir_path in [METADATA_DIR, TARGET_DIR]:
        dir_path.mkdir(exist_ok=True, parents=True)

    # create update client
    client = Client(
        metadata_dir=str(METADATA_DIR),
        target_dir=str(TARGET_DIR),
        metadata_base_url=METADATA_BASE_URL,
        target_base_url=TARGET_BASE_URL,
    )

    # do update
    client.update()


if __name__ == '__main__':
    main()
