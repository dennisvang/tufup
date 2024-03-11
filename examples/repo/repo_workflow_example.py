import copy
import logging
import os
import pathlib
import secrets  # from python 3.9+ we can use random.randbytes
import shutil
import tempfile

from tufup.repo import (
    DEFAULT_KEY_MAP,
    DEFAULT_KEYS_DIR_NAME,
    DEFAULT_META_DIR_NAME,
    DEFAULT_REPO_DIR_NAME,
    DEFAULT_TARGETS_DIR_NAME,
    Repository,
)

"""

This script was based on the python-tuf basic repo example [1]. The script generates a 
complete example repository, including key pairs and example data. It illustrates 
some common repository operations.

NOTE: This script creates subdirectories and files in the tufup/examples/repo directory.

NOTE: This script was also used to generate the test data in tests/data.

NOTE: The repo content can be served for local testing as follows:

    python -m http.server -d examples/repo/repository

NOTE: When running this script in PyCharm, ensure "Emulate terminal in output 
console" is enabled in the run configuration, otherwise the encryption passwords 
cannot be entered.

[1]: https://github.com/theupdateframework/python-tuf/blob/develop/examples/manual_repo/basic_repo.py
"""

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

APP_NAME = 'example_app'

# Default base directory
EXAMPLE_DIR = pathlib.Path(__file__).resolve().parent
BASE_DIR = EXAMPLE_DIR

# This script is also used to create/update test data, in which case we need to
# override some variables. Everything related to _UPDATE_TEST_DATA can be ignored for
# normal use.
_UPDATE_TEST_DATA = os.getenv('UPDATE_TEST_DATA')  # see dirs_to_clean for values
TEST_DATA_EXPIRATION_DAYS = None
if _UPDATE_TEST_DATA is not None:
    TEST_DATA_EXPIRATION_DAYS = 10000
    PROJECT_DIR = EXAMPLE_DIR.parent.parent
    BASE_DIR = PROJECT_DIR / 'tests' / 'data'
    logger.warning(f'updating test data in {BASE_DIR}')

# Specify local example paths
KEYS_DIR = BASE_DIR / DEFAULT_KEYS_DIR_NAME
ONLINE_DIR = KEYS_DIR / 'online_secrets'
OFFLINE_DIR_1 = KEYS_DIR / 'offline_secrets_1'
OFFLINE_DIR_2 = KEYS_DIR / 'offline_secrets_2'
REPO_DIR = BASE_DIR / DEFAULT_REPO_DIR_NAME
META_DIR = REPO_DIR / DEFAULT_META_DIR_NAME
TARGETS_DIR = REPO_DIR / DEFAULT_TARGETS_DIR_NAME

if _UPDATE_TEST_DATA is not None:
    # start with clean slate
    dirs_to_clean = dict(
        keys=[KEYS_DIR, META_DIR],  # metadata depends on keys, so remove both
        metadata=[META_DIR],
        targets=[TARGETS_DIR, META_DIR],  # metadata depends on targets, so remove both
        all=[KEYS_DIR, META_DIR, TARGETS_DIR],
    )
    for dir_path in dirs_to_clean.get(_UPDATE_TEST_DATA, []):
        for path in dir_path.iterdir():
            if path.suffix in ['.gz', '.patch', '.json']:
                path.unlink()

# Settings
EXPIRATION_DAYS = dict(
    root=TEST_DATA_EXPIRATION_DAYS or 365,
    targets=TEST_DATA_EXPIRATION_DAYS or 100,
    snapshot=TEST_DATA_EXPIRATION_DAYS or 7,
    timestamp=TEST_DATA_EXPIRATION_DAYS or 1,
)
THRESHOLDS = dict(root=2, targets=1, snapshot=1, timestamp=1)
KEY_MAP = copy.deepcopy(DEFAULT_KEY_MAP)
KEY_MAP['root'].append('root_two')  # use two keys for root
ENCRYPTED_KEYS = ['root', 'root_two', 'targets']

# Custom metadata (for example, a list of changes)
DUMMY_METADATA = dict(changes=['this has changed', 'that has changed', '...'])

# Create repository instance
repo = Repository(
    app_name=APP_NAME,
    repo_dir=REPO_DIR,
    keys_dir=KEYS_DIR,
    key_map=KEY_MAP,
    expiration_days=EXPIRATION_DAYS,
    encrypted_keys=ENCRYPTED_KEYS,
    thresholds=THRESHOLDS,
)

# Save configuration (JSON file)
repo.save_config()

# Initialize repository (creates keys and root metadata, if necessary)
repo.initialize()

# The keys are initially created in the same dir, but the private keys must
# remain secret, so we typically want to move them to different locations.
# Disclaimer: This is just an example, *NOT* a guideline.
for private_key_name, dst_dir in [
    ('root', OFFLINE_DIR_1),
    ('root_two', OFFLINE_DIR_2),
    ('targets', OFFLINE_DIR_1),
    ('snapshot', ONLINE_DIR),
    ('timestamp', ONLINE_DIR),
]:
    private_key_path = KEYS_DIR / private_key_name
    if private_key_path.exists():
        dst_dir.mkdir(exist_ok=True)
        private_key_path.rename(dst_dir / private_key_name)

# Create dummy application bundle (e.g. a PyInstaller bundle)
TARGETS_DIR.mkdir(exist_ok=True)
temp_dir = tempfile.TemporaryDirectory()  # no need for context manager
dummy_bundle_dir = pathlib.Path(temp_dir.name)
# include the root metadata file with the bundle (e.g. when using PyInstaller
# this could be automated using the .spec file)
shutil.copy(src=repo.roles.file_path(role_name='root'), dst=dummy_bundle_dir)
# create initial dummy app file
dummy_file_size = int(1e5)  # bytes
dummy_delta_size = int(1e2)  # bytes
dummy_file_content = secrets.token_bytes(dummy_file_size)
dummy_file_path = dummy_bundle_dir / 'dummy.exe'
dummy_file_path.write_bytes(dummy_file_content)

# Create archive from app bundle and register metadata
repo.add_bundle(new_version='1.0', new_bundle_dir=dummy_bundle_dir)
repo.publish_changes(private_key_dirs=[OFFLINE_DIR_1, ONLINE_DIR])

# threshold signing (assuming we are on the other key owner's system)
repo.threshold_sign(role_name='root', private_key_dirs=[OFFLINE_DIR_2])

# register additional target files (as updates become available over time)
new_versions = ['2.0', '3.0rc0', '4.0a0']
for new_version in new_versions:
    # Time goes by
    ...

    # Initialize repo from config
    repo = Repository.from_config()

    # Create dummy content for new update
    if new_version == new_versions[-1]:
        # large change (total patch size will be larger than full archive size)
        dummy_file_content = secrets.token_bytes(dummy_file_size)
    else:
        # small change
        dummy_file_content += secrets.token_bytes(dummy_delta_size)
    dummy_file_path.write_bytes(dummy_file_content)

    # Create archive and patch and register the new update (here we sign everything
    # at once, for convenience)
    repo.add_bundle(
        new_version=new_version,
        new_bundle_dir=dummy_bundle_dir,
        # example of optional custom metadata
        custom_metadata=DUMMY_METADATA.copy(),
        # "required" updates are exceptional and should be avoided if possible,
        # but we include one here just for completeness
        required=new_version == '2.0',
    )
    repo.publish_changes(private_key_dirs=[OFFLINE_DIR_1, OFFLINE_DIR_2, ONLINE_DIR])

# Time goes by
...

# Initialize repo from config
repo = Repository.from_config()

# Re-sign expired roles (downstream roles are refreshed automatically)
repo.refresh_expiration_date(role_name='snapshot', days=9)
repo.publish_changes(private_key_dirs=[ONLINE_DIR])

# Time goes by
...

# Rotate root key (new key is not encrypted, for convenience only)
new_private_key_path = OFFLINE_DIR_2 / 'root_three'
repo = Repository.from_config()
new_public_key_path = repo.keys.create_key_pair(
    private_key_path=new_private_key_path, encrypted=False
)
repo.replace_key(
    old_key_name='root_two',
    new_public_key_path=new_public_key_path,
    new_private_key_encrypted=False,
)
repo.publish_changes(private_key_dirs=[OFFLINE_DIR_1, OFFLINE_DIR_2, ONLINE_DIR])

# restore example config if necessary (ignore for normal use)
if _UPDATE_TEST_DATA:
    repo.keys_dir = EXAMPLE_DIR / DEFAULT_KEYS_DIR_NAME
    repo.repo_dir = EXAMPLE_DIR / DEFAULT_REPO_DIR_NAME
    repo.save_config()
