import logging
import pathlib
import secrets  # from python 3.9+ we can use random.randbytes
import shutil
import tempfile

from notsotuf.common import Patcher
from notsotuf.repo import Keys, Roles, in_, make_gztar_archive

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
    roles.publish_root(
        private_key_paths=[keys.private_key_path('root')],
        expires=in_(365),
    )

# Create dummy initial target file (normally a gzipped PyInstaller bundle)
TARGETS_DIR.mkdir(exist_ok=True)
temp_dir = tempfile.TemporaryDirectory()  # no need for context manager
dummy_bundle_dir = pathlib.Path(temp_dir.name)
# include the root metadata file with the bundle (this is normally done
# using the pyinstaller .spec file)
shutil.copy(src=roles.file_path(role_name='root'), dst=dummy_bundle_dir)
# create dummy app file
dummy_file_size = int(1e5)  # bytes
dummy_delta_size = int(1e2)  # bytes
dummy_file_content = secrets.token_bytes(dummy_file_size)
dummy_file_path = dummy_bundle_dir / 'dummy.exe'
dummy_file_path.write_bytes(dummy_file_content)
# create archive
current_archive_path = make_gztar_archive(
    src_dir=dummy_bundle_dir,
    dst_dir=TARGETS_DIR,
    app_name=APP_NAME,
    version='1.0',
)

# Register the initial target file
roles.add_or_update_target(local_path=current_archive_path)
print('signing initial targets metadata')
expires = dict(targets=in_(100), snapshot=in_(7), timestamp=in_(1))
private_key_paths = {
    role_name: [keys.private_key_path(key_name=role_name)]
    for role_name in expires.keys()
}
roles.publish_targets(
    private_key_paths=private_key_paths, expires=expires
)

# register additional target files (as updates become available over time)
new_versions = ['2.0', '3.0rc0', '4.0a0']
for new_version in new_versions:
    # Time goes by
    ...

    # Create target files (archive and patch) for new update
    if new_version == new_versions[-1]:
        # large change (total patch size will be larger than full archive size)
        dummy_file_content = secrets.token_bytes(dummy_file_size)
    else:
        # small change
        dummy_file_content += secrets.token_bytes(dummy_delta_size)
    dummy_file_path.write_bytes(dummy_file_content)
    new_archive_path = make_gztar_archive(
        src_dir=dummy_bundle_dir,
        dst_dir=TARGETS_DIR,
        app_name=APP_NAME,
        version=new_version,
    )
    new_patch_path = Patcher.create_patch(
        src_path=current_archive_path, dst_path=new_archive_path
    )
    # Register the new update files
    roles.add_or_update_target(local_path=new_archive_path)
    roles.add_or_update_target(local_path=new_patch_path)
    print(f'signing updated metadata for version {new_version}')
    roles.publish_targets(private_key_paths=private_key_paths, expires=expires)
    # next
    current_archive_path = new_archive_path

# Time goes by
...

# Re-sign roles, before they expire
roles.sign_role(
    role_name='timestamp',
    expires=in_(2),
    private_key_path=keys.private_key_path(key_name='timestamp'),
)
roles.persist_role(role_name='timestamp')
