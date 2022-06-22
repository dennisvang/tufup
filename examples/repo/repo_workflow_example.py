import logging
import pathlib
import secrets  # from python 3.9+ we can use random.randbytes
import shutil
import tempfile

from notsotuf.repo import (
    DEFAULT_KEY_MAP,
    DEFAULT_KEYS_DIR_NAME,
    DEFAULT_META_DIR_NAME,
    DEFAULT_REPO_DIR_NAME,
    DEFAULT_TARGETS_DIR_NAME,
    Repository,
)

"""

NOTE: The repo content can be served for local testing as follows:

    python -m http.server -d examples/repo/content

NOTE: This script creates subdirectories and files in the 
notsotuf/examples/repo directory. 

NOTE: When running this script in PyCharm, ensure "Emulate terminal in output 
console" is enabled in the run configuration, otherwise the encryption 
passwords cannot be entered. 

"""

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

APP_NAME = 'example_app'

# Specify local paths
BASE_DIR = pathlib.Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / DEFAULT_KEYS_DIR_NAME
ONLINE_DIR = KEYS_DIR / 'online_secrets'
OFFLINE_DIR_1 = KEYS_DIR / 'offline_secrets_1'
OFFLINE_DIR_2 = KEYS_DIR / 'offline_secrets_2'
REPO_DIR = BASE_DIR / DEFAULT_REPO_DIR_NAME
META_DIR = REPO_DIR / DEFAULT_META_DIR_NAME
TARGETS_DIR = REPO_DIR / DEFAULT_TARGETS_DIR_NAME

# Settings
EXPIRATION_DAYS = dict(root=365, targets=100, snapshot=7, timestamp=1)
THRESHOLDS = dict(root=2, targets=1, snapshot=1, timestamp=1)
KEY_MAP = DEFAULT_KEY_MAP.copy()
KEY_MAP['root'].append('root_two')  # use two keys for root
ENCRYPTED_KEYS = ['root', 'root_two', 'targets']

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

    # Create archive and patch and register the new update (here we sign
    # everything at once, for convenience)
    repo.add_bundle(new_version=new_version, new_bundle_dir=dummy_bundle_dir)
    repo.publish_changes(
        private_key_dirs=[OFFLINE_DIR_1, OFFLINE_DIR_2, ONLINE_DIR]
    )

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
repo.publish_changes(
    private_key_dirs=[OFFLINE_DIR_1, OFFLINE_DIR_2, ONLINE_DIR]
)
