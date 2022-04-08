import gzip
import logging
import pathlib

from notsotuf.tools.common import Patcher, TargetPath
from notsotuf.tools.repo import Keys, Roles, ROOT, TARGETS

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
KEYS_DIR = BASE_DIR / 'keystore'
CONTENT_DIR = BASE_DIR / 'content'
META_DIR = CONTENT_DIR / 'metadata'
TARGETS_DIR = CONTENT_DIR / 'targets'

# Create key pairs for the top level tuf roles
keys = Keys(dir_path=KEYS_DIR, encrypted=[ROOT, TARGETS])
if keys.root is None:
    # create key pair files and save to disk
    keys.create()

# Initialize top level tuf roles
roles = Roles(dir_path=META_DIR)
if roles.root is None:
    # initialize metadata
    roles.initialize(keys=keys)
    # save root metadata file
    roles.publish_root(keys_dirs=[KEYS_DIR])

# Create dummy initial target file (normally using e.g. PyInstaller and gzip)
TARGETS_DIR.mkdir(exist_ok=True)
initial_archive_path = TARGETS_DIR / TargetPath.compose_filename(
    name=APP_NAME, version='1.0', is_archive=True
)
if not initial_archive_path.exists():
    # Note: for multi-file archives, we could use e.g. shutil.make_archive
    with gzip.open(initial_archive_path, 'wb') as gz_file:
        gz_file.write(b'dummy archive content')

# Register the initial target file
roles.add_or_update_target(local_path=initial_archive_path)
roles.publish_targets(keys_dirs=[KEYS_DIR])

# Time goes by
...

# Create target files for first update
new_archive_path = TARGETS_DIR / TargetPath.compose_filename(
    name=APP_NAME, version='2.0', is_archive=True
)
if not new_archive_path.exists():
    with gzip.open(new_archive_path, 'wb') as gz_file:
        gz_file.write(b'dummy archive content updated')
new_patch_path = Patcher.create_patch(
    src_path=initial_archive_path, dst_path=new_archive_path
)

# Register the update files
roles.add_or_update_target(local_path=new_archive_path)
roles.add_or_update_target(local_path=new_patch_path)
roles.publish_targets(keys_dirs=[KEYS_DIR])
