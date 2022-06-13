import logging
import pathlib
import secrets  # from python 3.9+ we can use random.randbytes
import shutil
import tempfile

from notsotuf.repo import (
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
REPO_DIR = BASE_DIR / DEFAULT_REPO_DIR_NAME
META_DIR = REPO_DIR / DEFAULT_META_DIR_NAME
TARGETS_DIR = REPO_DIR / DEFAULT_TARGETS_DIR_NAME

# Settings
EXPIRATION_DAYS = dict(root=365, targets=100, snapshot=7, timestamp=1)
ENCRYPTED_KEYS = ['root', 'targets']

# Create repository instance
repo = Repository(
    app_name=APP_NAME,
    repo_dir=REPO_DIR,
    keys_dir=KEYS_DIR,
    key_map=None,  # use default key map
    expiration_days=EXPIRATION_DAYS,
    encrypted_keys=ENCRYPTED_KEYS,
)

# Save configuration (JSON file)
repo.save_config()

# Initialize repository (creates keys and root metadata, if necessary)
repo.initialize()

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

    # Create archive and patch and register the new update
    repo.add_bundle(new_version=new_version, new_bundle_dir=dummy_bundle_dir)

# Time goes by
...

# Initialize repo from config
repo = Repository.from_config()

# Re-sign expired timestamp
repo.sign(
    role_name='timestamp',
    private_key_path=KEYS_DIR / 'timestamp',
    expiration_days=1,
)
