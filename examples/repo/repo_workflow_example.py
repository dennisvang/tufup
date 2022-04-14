import gzip
import logging
import pathlib
import secrets  # from python 3.9+ we can use random.randbytes

from notsotuf.common import Patcher, TargetPath
from notsotuf.repo import Keys, Roles, in_

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
keys = Keys(dir_path=KEYS_DIR, encrypted=['root', 'targets'])
if keys.root is None:
    # create key pair files and save to disk
    keys.create()

# Initialize top level tuf roles
roles = Roles(dir_path=META_DIR)
if roles.root is None:
    # initialize metadata
    roles.initialize(keys=keys)
    # save root metadata file
    print('signing initial root metadata')
    roles.publish_root(keys_dirs=[KEYS_DIR], expires=in_(365))

# Create dummy initial target file (normally using e.g. PyInstaller and gzip)
TARGETS_DIR.mkdir(exist_ok=True)
initial_archive_path = TARGETS_DIR / TargetPath.compose_filename(
    name=APP_NAME, version='1.0', is_archive=True
)
# To illustrate patch updates vs full updates, the size of the dummy archive
# is chosen here so that two consecutive patches are smaller, but three
# consecutive patches are larger than the full update.
number_of_bytes = 400
dummy_archive_content = secrets.token_bytes(number_of_bytes)
if not initial_archive_path.exists():
    # Note: for multi-file archives, we could use e.g. shutil.make_archive
    with gzip.open(initial_archive_path, 'wb') as gz_file:
        gz_file.write(dummy_archive_content)

# Register the initial target file
roles.add_or_update_target(local_path=initial_archive_path)
print('signing initial targets metadata')
expires = dict(targets=in_(7), snapshot=in_(7), timestamp=in_(1))
roles.publish_targets(keys_dirs=[KEYS_DIR], expires=expires)

# register additional target files (as updates become available over time)
for version, modified_content in [
    ('2.0', dummy_archive_content + b'2'),
    ('3.0rc0', dummy_archive_content + b'3rc'),
    ('4.0a0', dummy_archive_content + b'4a'),
]:
    # Time goes by
    ...

    # Create target files for new update
    new_archive_path = TARGETS_DIR / TargetPath.compose_filename(
        name=APP_NAME, version=version, is_archive=True
    )
    if not new_archive_path.exists():
        with gzip.open(new_archive_path, 'wb') as gz_file:
            gz_file.write(modified_content)
    new_patch_path = Patcher.create_patch(
        src_path=initial_archive_path, dst_path=new_archive_path
    )

    # Register the new update files
    roles.add_or_update_target(local_path=new_archive_path)
    roles.add_or_update_target(local_path=new_patch_path)
    print(f'signing updated metadata for version {version}')
    roles.publish_targets(keys_dirs=[KEYS_DIR], expires=expires)

# Time goes by
...

# Re-sign roles, before they expire
roles.sign_role(
    role_name='timestamp',
    expires=in_(1),
    private_key_path=KEYS_DIR / 'timestamp',
)
