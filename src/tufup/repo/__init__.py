from copy import deepcopy
from datetime import datetime, timedelta
import inspect
import json
import logging
import pathlib

try:
    # workaround for PyInstaller issue 6911 (setuptools issue 3089)
    import setuptools.config.expand  # noqa
except AssertionError:
    pass  # assuming we are on the client side...
import shutil
import tarfile
from typing import Any, Dict, Iterable, List, Optional, TypedDict, Union

from securesystemslib.exceptions import CryptoError
from securesystemslib.interface import (
    generate_and_write_ed25519_keypair_with_prompt,
    generate_and_write_unencrypted_ed25519_keypair,
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file,
)

# SSlibKey see: https://github.com/secure-systems-lab/securesystemslib/pull/456
from securesystemslib.signer import SSlibKey, SSlibSigner
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

from tufup.common import (
    CustomMetadataDict,
    KEY_REQUIRED,
    Patcher,
    SUFFIX_PATCH,
    TargetMeta,
)
from tufup.utils.platform_specific import _patched_resolve

logger = logging.getLogger(__name__)

"""

https://github.com/theupdateframework/python-tuf/blob/develop/examples/repo_example/basic_repo.py

"""

__all__ = [
    'DEFAULT_KEY_MAP',
    'DEFAULT_KEYS_DIR_NAME',
    'DEFAULT_META_DIR_NAME',
    'DEFAULT_REPO_DIR_NAME',
    'DEFAULT_TARGETS_DIR_NAME',
    'in_',
    'Keys',
    'make_gztar_archive',
    'Repository',
    'Roles',
    'SUFFIX_JSON',
    'SUFFIX_PUB',
    'TOP_LEVEL_ROLE_NAMES',
]

# copied from python-tuf basic_repo.py
SPEC_VERSION = '.'.join(SPECIFICATION_VERSION)


# copied from python-tuf basic_repo.py
def in_(days: float) -> datetime:
    """Returns a timestamp for the specified number of days from now."""
    return datetime.utcnow().replace(microsecond=0) + timedelta(days=days)


def make_gztar_archive(
    src_dir: Union[pathlib.Path, str],
    dst_dir: Union[pathlib.Path, str],
    app_name: str,
    version: str,
    tar_format: int = tarfile.PAX_FORMAT,
) -> Optional[TargetMeta]:
    """
    Create a gzipped tar archive in the dst_dir, based on content of src_dir.

    The PAX_FORMAT is currently the default tar format [1] used by the tarfile
    module. For improved portability [2] and reproducibility [3], this can be changed
    e.g. to USTAR_FORMAT.

    [1]: https://www.gnu.org/software/tar/manual/html_node/Formats.html#Formats
    [2]: https://www.gnu.org/software/tar/manual/html_node/Portability.html#Portability
    [3]: https://www.gnu.org/software/tar/manual/html_node/Reproducibility.html#Reproducibility
    """
    # ensure paths
    src_dir = pathlib.Path(src_dir)
    dst_dir = pathlib.Path(dst_dir)
    # compose archive path and check existence
    archive_filename = TargetMeta.compose_filename(
        name=app_name, version=version, is_archive=True
    )
    archive_path = dst_dir / archive_filename
    if archive_path.exists():
        if input(f'Found existing archive: {archive_path}.\nOverwrite? [n]/y') != 'y':
            print('Using existing archive.')
            return TargetMeta(archive_path)
    # Make gzipped tar archive. Note that TarFile.add() sorts members by filename, see:
    # https://github.com/python/cpython/blob/64c9fcc8930f927f5fa903b9d6d442af85a101d1/Lib/tarfile.py#L2162
    with tarfile.open(archive_path, mode='w:gz', format=tar_format) as tar:
        # the filter arg could be used in future versions to modify the tarinfo objects
        tar.add(name=src_dir, arcname='.', recursive=True, filter=None)
    return TargetMeta(target_path=archive_path)


class RolesDict(TypedDict):
    root: Any
    targets: Any
    snapshot: Any
    timestamp: Any


DEFAULT_REPO_DIR_NAME = 'repository'
DEFAULT_KEYS_DIR_NAME = 'keystore'
DEFAULT_META_DIR_NAME = 'metadata'
DEFAULT_TARGETS_DIR_NAME = 'targets'
DEFAULT_KEY_MAP = RolesDict((key, [key]) for key in TOP_LEVEL_ROLE_NAMES)  # noqa
DEFAULT_EXPIRATION_DAYS = RolesDict(root=365, targets=7, snapshot=7, timestamp=1)
DEFAULT_THRESHOLDS = RolesDict(root=1, targets=1, snapshot=1, timestamp=1)
SUFFIX_JSON = '.json'
SUFFIX_PUB = '.pub'
FILENAME_ROOT = Root.type + SUFFIX_JSON
FILENAME_TARGETS = Targets.type + SUFFIX_JSON
FILENAME_SNAPSHOT = Snapshot.type + SUFFIX_JSON
FILENAME_TIMESTAMP = Timestamp.type + SUFFIX_JSON


class Base(object):
    def __init__(self, dir_path: Union[pathlib.Path, str, None]):
        """
        dir_path: directory where all key files are stored
        encrypted: names of the keys that are (to be) encrypted
        key_map: maps top-level role names to lists of key names
        """
        if dir_path is None:
            dir_path = pathlib.Path.cwd()
        # enforce pathlib.Path
        self.dir_path = pathlib.Path(dir_path)
        if not self.dir_path.exists():
            if input(f'Create directory {self.dir_path}? [y]/n') in ['y', '']:
                self.dir_path.mkdir(parents=True)
                print(f'Directory created: {self.dir_path}')


class Keys(Base):
    filename_pattern = '{key_name}'

    def __init__(
        self,
        dir_path: Union[pathlib.Path, str, None] = None,
        encrypted: Optional[List[str]] = None,
        key_map: Optional[RolesDict] = None,
        thresholds: Optional[RolesDict] = None,
    ):
        if dir_path is None:
            dir_path = pathlib.Path.cwd() / DEFAULT_KEYS_DIR_NAME
        super().__init__(dir_path=dir_path)
        if encrypted is None:
            encrypted = []
        if key_map is None:
            key_map = deepcopy(DEFAULT_KEY_MAP)
        if thresholds is None:
            thresholds = DEFAULT_THRESHOLDS.copy()
        self.encrypted = encrypted
        self.key_map = key_map
        self.thresholds = thresholds
        # top-level roles
        self.root: List[Dict[str, Any]] = []
        self.targets: List[Dict[str, Any]] = []
        self.snapshot: List[Dict[str, Any]] = []
        self.timestamp: List[Dict[str, Any]] = []
        # import public keys from dir_path, if it exists
        self.import_all_public_keys()

    def import_all_public_keys(self):
        for role_name, key_list in self.key_map.items():
            for key_name in key_list:
                self.import_public_key(role_name=role_name, key_name=key_name)

    def import_public_key(self, role_name: str, key_name: Optional[str] = None):
        """Import public key for specified role."""
        if key_name is None:
            key_name = role_name
        public_key_path = self.public_key_path(key_name=key_name)
        if public_key_path.exists():
            ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
            getattr(self, role_name).append(ssl_key)
            logger.debug(f'public key imported: {public_key_path}')
        else:
            logger.debug(f'file does not exist: {public_key_path}')

    def create(self):
        all_key_names = []
        for key_list in self.key_map.values():
            all_key_names.extend(key_list)
        unique_key_names = set(all_key_names)
        logger.debug(f'creating key-pairs: {unique_key_names}')
        for key_name in unique_key_names:
            default_private_key_path = self.private_key_path(key_name=key_name)
            self.create_key_pair(
                private_key_path=default_private_key_path,
                encrypted=key_name in self.encrypted,
            )
        # import the newly created public keys
        self.import_all_public_keys()

    @staticmethod
    def create_key_pair(
        private_key_path: pathlib.Path, encrypted: bool
    ) -> pathlib.Path:
        if encrypted:
            # encrypt private key
            logger.debug('set encryption password for private key')
            generate_keypair = generate_and_write_ed25519_keypair_with_prompt
        else:
            # do not encrypt private key (for automated signing)
            generate_keypair = generate_and_write_unencrypted_ed25519_keypair
        public_key_path = private_key_path.with_suffix(SUFFIX_PUB)
        proceed = True
        if public_key_path.exists():
            logger.warning(f'Public key already exists: {public_key_path}')
            proceed = input('Overwrite key pair? [n]/y') == 'y'
        if proceed:
            file_path_str = generate_keypair(filepath=str(private_key_path))
            logger.info(f'key-pair created: {file_path_str}, {public_key_path}')
        return public_key_path

    def private_key_path(self, key_name: str) -> pathlib.Path:
        return self.dir_path / self.filename_pattern.format(key_name=key_name)

    def public_key_path(self, key_name: str) -> pathlib.Path:
        return self.private_key_path(key_name=key_name).with_suffix(SUFFIX_PUB)

    def public(self):
        # return a dict that maps key ids to *public* key objects
        return {
            ssl_key['keyid']: SSlibKey.from_securesystemslib_key(key_dict=ssl_key)
            for attr_name, ssl_keys in vars(self).items()
            if attr_name in TOP_LEVEL_ROLE_NAMES
            for ssl_key in ssl_keys
        }

    def roles(self):
        # return a dict that maps role names to key ids and key thresholds
        roles_map = dict()
        for role_name in TOP_LEVEL_ROLE_NAMES:
            ssl_keys = getattr(self, role_name)
            role_keys = None
            if ssl_keys:
                unique_key_ids = list(set(ssl_key['keyid'] for ssl_key in ssl_keys))
                role_keys = Role(
                    keyids=unique_key_ids, threshold=self.thresholds[role_name]
                )
            roles_map[role_name] = role_keys
        return roles_map

    @classmethod
    def find_private_key(
        cls, key_name: str, key_dirs: List[Union[pathlib.Path, str]]
    ) -> Optional[pathlib.Path]:
        """
        recursively search key_dirs for a private key with specified key_name

        returns path to first matching file (or None)
        """
        private_key_filename = cls.filename_pattern.format(key_name=key_name)
        for key_dir in key_dirs:
            key_dir = pathlib.Path(key_dir)  # ensure Path
            for path in key_dir.iterdir():
                if path.is_file() and path.name == private_key_filename:
                    # base case
                    return path
                elif path.is_dir():
                    # recursive case
                    private_key_path = cls.find_private_key(
                        key_name=key_name, key_dirs=[path]
                    )
                    if private_key_path:
                        return private_key_path


class Roles(Base):
    filename_pattern = '{version}{role_name}{suffix}'

    def __init__(self, dir_path: Union[pathlib.Path, str, None] = None):
        """
        TUF roles

        - root metadata tells us:
            + all the known keys (key id and public key value)
            + which keys belong to each role
            + how many signatures are needed for each role
        - targets metadata tells us:
            + which target files are available (filename, size, hash)
        - snapshots metatadata tells us:
            + which version of the targets-metadata file to expect
        - timestamp metadata tells us:
            + which version of the snapshot-metadata file to expect

        """
        if dir_path is None:
            dir_path = pathlib.Path.cwd() / DEFAULT_META_DIR_NAME
        super().__init__(dir_path=dir_path)
        # top-level roles
        self.root: Optional[Metadata[Root]] = None
        self.targets: Optional[Metadata[Targets]] = None
        self.snapshot: Optional[Metadata[Snapshot]] = None
        self.timestamp: Optional[Metadata[Timestamp]] = None
        # import roles from dir_path, if it exists
        self._import_roles(role_names=TOP_LEVEL_ROLE_NAMES)

    def _import_roles(self, role_names: Iterable[str]):
        """Import roles from metadata files."""
        file_paths = []
        if self.dir_path.exists():
            file_paths = [p for p in self.dir_path.iterdir() if p.is_file()]
        for role_name in role_names:
            # exclude (root) filenames starting with a version
            role_paths = [p for p in file_paths if p.name.startswith(role_name)]
            if role_paths:
                # there should be only one for each role
                setattr(self, role_name, Metadata.from_file(str(role_paths[0])))

    def initialize(self, keys: Keys, expiration_days: Optional[RolesDict] = None):
        if expiration_days is None:
            expiration_days = DEFAULT_EXPIRATION_DAYS.copy()
        # based on python-tuf basic_repo.py
        common_kwargs = dict(version=1, spec_version=SPEC_VERSION)
        # role-specific kwargs
        initial_data = {
            Root: dict(
                expires=in_(expiration_days['root']),
                keys=keys.public(),
                roles=keys.roles(),
                # repo is relatively static, no need for consistent snapshots
                consistent_snapshot=False,
            ),
            Targets: dict(
                expires=in_(expiration_days['targets']),
                targets=dict(),
            ),
            Snapshot: dict(
                expires=in_(expiration_days['snapshot']),
                meta={FILENAME_TARGETS: MetaFile(version=1)},
            ),
            Timestamp: dict(
                expires=in_(expiration_days['timestamp']),
                snapshot_meta=MetaFile(version=1),
            ),
        }
        for role_class, role_kwargs in initial_data.items():
            attr_name = role_class.type
            if getattr(self, attr_name) is None:
                # intialize role only if there is no role yet
                setattr(
                    self,
                    attr_name,
                    Metadata(
                        signed=role_class(**common_kwargs, **role_kwargs),
                        signatures=dict(),
                    ),
                )

    def add_or_update_target(
        self,
        local_path: Union[pathlib.Path, str],
        url_path_segments: Optional[List[str]] = None,
        custom: Optional[CustomMetadataDict] = None,
    ):
        # based on python-tuf basic_repo.py
        local_path = pathlib.Path(local_path)
        # build url path
        url_path_segments = url_path_segments or []
        url_path_segments.append(local_path.name)
        url_path = '/'.join(url_path_segments)
        # create targetfile instance
        target_file_info = TargetFile.from_file(
            target_file_path=url_path, local_path=str(local_path)
        )
        if custom:
            # todo: handle creation of patch metadata here?
            # todo: should we verify that custom is a dict?
            target_file_info.unrecognized_fields['custom'] = custom
        # note we assume self.targets has been initialized
        self.targets.signed.targets[url_path] = target_file_info

    def remove_target(self, local_path: Union[pathlib.Path, str]) -> bool:
        removed = False
        targets_dict = self.targets.signed.targets
        for target_url in targets_dict:
            # assume target filenames only occur once
            if target_url.endswith(local_path.name):
                removed = targets_dict.pop(target_url, None) is not None
                break
        if removed:
            local_path.unlink()
        return removed

    def add_public_key(self, role_name: str, public_key_path: Union[pathlib.Path, str]):
        """Import a public key from file and add it to the specified role."""
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
        self.root.signed.add_key(
            role=role_name, key=SSlibKey.from_securesystemslib_key(ssl_key)
        )

    def set_signature_threshold(self, role_name: str, threshold: int):
        self.root.signed.roles[role_name].threshold = threshold

    def set_expiration_date(self, role_name: str, days: int):
        role = getattr(self, role_name)
        if hasattr(role, 'signed'):
            role.signed.expires = in_(days)

    def sign_role(self, role_name: str, private_key_path: Union[pathlib.Path, str]):
        """
        Sign role using specified private key.

        We sign off on the role.signed part, and the signature is added to
        the role.signatures list.
        """
        # based on python-tuf basic_repo.py
        try:
            # assume unencrypted
            ssl_key = import_ed25519_privatekey_from_file(
                filepath=str(private_key_path), prompt=False
            )
        except CryptoError as e:
            # possibly encrypted: try to import with password
            logger.debug(f'private key import attempt without password failed: {e}')
            ssl_key = import_ed25519_privatekey_from_file(
                filepath=str(private_key_path), prompt=True
            )
        signer = SSlibSigner(ssl_key)
        getattr(self, role_name).sign(signer, append=True)

    def file_path(self, role_name: str, version: Optional[int] = None):
        version_str = ''
        if role_name == Root.type and version is not None:
            # "... all released versions of root metadata files MUST always
            # be provided so that outdated clients can update to the latest
            # available root."
            # https://theupdateframework.github.io/specification/latest/#writing-consistent-snapshots
            version_str = f'{version}.'
        return self.dir_path / self.filename_pattern.format(
            version=version_str, role_name=role_name, suffix=SUFFIX_JSON
        )

    def file_exists(self, role_name: str):
        """
        Return True if any metadata file exists for the specified role,
        ignoring any versions in the filename.
        """
        return any(
            path.exists()
            for path in self.dir_path.iterdir()
            if path.is_file() and role_name in path.name
        )

    def persist_role(self, role_name: str):
        """
        Save specified role to corresponding metadata file.

        In case of root, make sure "root.json" always represents the latest
        version (in addition to x.root.json).
        """
        # based on python-tuf basic_repo.py (but without consistent snapshots)
        role = getattr(self, role_name)
        file_path = self.file_path(role_name=role_name, version=role.signed.version)
        role.to_file(filename=str(file_path), serializer=JSONSerializer(compact=False))
        if role_name == Root.type:
            # Copy the latest root metadata to 'root.json' (without version),
            # to use as trusted root metadata for distribution with the
            # client. This is convenient, otherwise we would need to modify
            # the version in the filename every time root is updated.
            # Moreover, we can now easily access the latest root metadata,
            # without having to check the version in the filename.
            client_root_file_path = self.file_path(role_name=Root.type)
            client_root_file_path.unlink(missing_ok=True)
            shutil.copy(src=file_path, dst=client_root_file_path)

    def get_latest_archive(self) -> Optional[TargetMeta]:
        """
        Returns TargetMeta for latest archive.

        Note that all pre-release versions are always included: On the repo
        side, there is no difference between final releases an pre-releases.
        Pre-release specifiers are only used on the Client side, to filter
        available updates).
        """
        # Note this is similar to the logic in Client._check_updates, but not
        # exactly the same. Merging the implementations would overcomplicate
        # things.
        latest_archive = None
        # sort by version
        signed_targets = self.targets.signed.targets if self.targets else dict()
        targets = sorted(TargetMeta(key) for key in signed_targets.keys())
        # extract only the archives
        archives = [target for target in targets if target.is_archive]
        if archives:
            latest_archive = archives[-1]
        return latest_archive


class Repository(object):
    """High-level tools for repository management."""

    config_filename = '.tufup-repo-config'

    def __init__(
        self,
        app_name: str,
        app_version_attr: Optional[str] = None,
        repo_dir: Union[pathlib.Path, str, None] = None,
        keys_dir: Union[pathlib.Path, str, None] = None,
        key_map: Optional[RolesDict] = None,
        encrypted_keys: Optional[List[str]] = None,
        expiration_days: Optional[RolesDict] = None,
        thresholds: Optional[RolesDict] = None,
    ):
        if repo_dir is None:
            repo_dir = DEFAULT_REPO_DIR_NAME
        if keys_dir is None:
            keys_dir = DEFAULT_KEYS_DIR_NAME
        if key_map is None:
            key_map = deepcopy(DEFAULT_KEY_MAP)
        if encrypted_keys is None:
            encrypted_keys = []
        if expiration_days is None:
            expiration_days = DEFAULT_EXPIRATION_DAYS.copy()
        if thresholds is None:
            thresholds = DEFAULT_THRESHOLDS.copy()
        self.app_name = app_name
        self.app_version_attr = app_version_attr
        # force path object and resolve, in case of relative paths
        self.repo_dir = _patched_resolve(pathlib.Path(repo_dir))
        self.keys_dir = _patched_resolve(pathlib.Path(keys_dir))
        self.key_map = key_map
        self.encrypted_keys = encrypted_keys
        self.expiration_days = expiration_days
        self.thresholds = thresholds
        # keys and roles
        self.keys: Optional[Keys] = None
        self.roles: Optional[Roles] = None
        self.revoked_key_names = []

    @property
    def config_dict(self):
        """dict to be saved to configuration file."""
        # attributes matching __init__ arguments are stored as configuration
        config_items = inspect.signature(self.__init__).parameters.keys()
        return {item: getattr(self, item) for item in config_items}

    @property
    def metadata_dir(self) -> pathlib.Path:
        return self.repo_dir / DEFAULT_META_DIR_NAME

    @property
    def targets_dir(self) -> pathlib.Path:
        return self.repo_dir / DEFAULT_TARGETS_DIR_NAME

    @property
    def app_version(self) -> str:
        # read version from specified module attribute without importing
        version = ''
        if self.app_version_attr:
            version = str(
                setuptools.config.expand.read_attr(self.app_version_attr)  # noqa
            )
        return version

    @classmethod
    def get_config_file_path(cls) -> pathlib.Path:
        # config must be stored in current working directory
        return pathlib.Path.cwd() / cls.config_filename

    def save_config(self):
        """Save current configuration."""
        config_file_path = self.get_config_file_path()
        # make paths relative to current working directory (cwd),
        # if possible, otherwise keep absolute paths (see #50)
        # (note, to avoid confusion, using paths other than cwd is discouraged)
        # also enforce posix paths on windows (see #147)
        temp_config_dict = self.config_dict  # note self.config_dict is a property
        for key in ['repo_dir', 'keys_dir']:
            try:
                temp_config_dict[key] = temp_config_dict[key].relative_to(
                    # resolve() is necessary on windows, to handle "short"
                    # path components (a.k.a. "8.3 filename" or "8.3 alias"),
                    # which are truncated with a tilde,
                    # e.g. c:\Users\RUNNER~1\...
                    pathlib.Path.cwd().resolve()
                ).as_posix()
            except ValueError:
                logger.warning(
                    f'Saving *absolute* path to config, because the path'
                    f' ({temp_config_dict[key]}) is not relative to cwd'
                    f' ({pathlib.Path.cwd()})'
                )
                temp_config_dict[key] = temp_config_dict[key].as_posix()
        # write file
        config_file_path.write_text(
            data=json.dumps(temp_config_dict, default=str, sort_keys=True, indent=4),
            encoding='utf-8',
        )

    @classmethod
    def load_config(cls) -> dict:
        """Load configuration dict from file."""
        file_path = cls.get_config_file_path()
        config_dict = dict()
        try:
            config_dict = json.loads(file_path.read_text())
        except FileNotFoundError:
            logger.warning(f'config file not found: {file_path}')
        except json.JSONDecodeError:
            logger.warning(f'config file invalid: {file_path}')
        # enforce posix paths (for legacy windows configs loaded on linux, see #147)
        for key in ['repo_dir', 'keys_dir']:
            value = config_dict.get(key)
            if value:
                # interpret the value as a windows path (\\ or /) then enforce posix (/)
                config_dict[key] = pathlib.PureWindowsPath(value).as_posix()
        return config_dict

    @classmethod
    def from_config(cls):
        """Create Repository instance from configuration file."""
        instance = cls(**cls.load_config())
        instance._load_keys_and_roles(create_keys=False)
        return instance

    def initialize(self, extra_key_dirs: Optional[List[pathlib.Path]] = None):
        """
        Initialize (or update) the local repository.

        This includes:

        - create directories if they do not exist
        - import public keys from existing files, or create new key pairs
        - import roles from existing metadata files
        - create root metadata file if it does not exist

        Safe to call for existing keys and roles.
        """
        extra_key_dirs = extra_key_dirs or []

        # Ensure dirs exist
        for path in [self.keys_dir, self.metadata_dir, self.targets_dir]:
            path.mkdir(parents=True, exist_ok=True)

        # Load keys and roles
        self._load_keys_and_roles(create_keys=True)

        # Publish root metadata (save 1.root.json and copy to root.json)
        if not self.roles.file_path('root').exists():
            self.publish_changes(private_key_dirs=[self.keys_dir] + extra_key_dirs)

    def refresh_expiration_date(self, role_name: str, days: Optional[int] = None):
        if days is None:
            days = self.expiration_days.get(role_name)
        self.roles.set_expiration_date(role_name=role_name, days=days)

    def replace_key(
        self,
        old_key_name: str,
        new_public_key_path: Union[pathlib.Path, str],
        new_private_key_encrypted: bool,
    ):
        """
        Replace an existing key by a new one, e.g. after a key compromise.

        Note the changes are not published yet: call publish_changes() for that.
        """
        self.revoked_key_names = []
        # Load old public key from file to obtain its key_id
        public_key_path = self.keys.public_key_path(key_name=old_key_name)
        old_key_id = import_ed25519_publickey_from_file(filepath=str(public_key_path))[
            'keyid'
        ]
        # Get new key name from public key path
        new_public_key_path = pathlib.Path(new_public_key_path)  # force path
        # A key may be used for multiple roles, so we check the key id for
        # all roles.
        for role_name in TOP_LEVEL_ROLE_NAMES:
            try:
                # remove old key_id from roles dict, if found, and remove key
                # from keys dict if it is no longer used by any roles
                self.roles.root.signed.revoke_key(role=role_name, keyid=old_key_id)
                # move old key name from key_map to revoked_key_map
                self.key_map[role_name].remove(old_key_name)
                # to ensure continuity, changes to root must be signed both
                # with the new key and the old key (in addition to unmodified
                # keys), so we keep track of revoked keys until signed
                self.revoked_key_names.append(old_key_name)
                logger.debug(f'Key revoked for {role_name}: {old_key_name}')
            except ValueError:
                logger.debug(f'{role_name} does not have key {old_key_name}')
            else:
                # add new key_id
                self.add_key(
                    role_name=role_name,
                    public_key_path=new_public_key_path,
                    encrypted=new_private_key_encrypted,
                )

    def add_key(
        self,
        role_name: str,
        public_key_path: Union[pathlib.Path, str],
        encrypted: bool,
    ):
        """
        Register a new public key for the specified role.

        Note the changes are not published yet: call publish_changes() for that.
        """
        public_key_path = pathlib.Path(public_key_path)
        # add new key to metadata
        self.roles.add_public_key(role_name=role_name, public_key_path=public_key_path)
        # add new key to key map
        key_name = public_key_path.with_suffix('').name
        if key_name not in self.key_map[role_name]:
            self.key_map[role_name].append(key_name)
        # add new key to encrypted keys if necessary
        already_present = key_name in self.encrypted_keys
        if encrypted and not already_present:
            self.encrypted_keys.append(key_name)

    def add_bundle(
        self,
        new_bundle_dir: Union[pathlib.Path, str],
        new_version: Optional[str] = None,
        skip_patch: bool = False,
        custom_metadata: Optional[dict] = None,  # archive only
        required: bool = False,
    ):
        """
        Adds a new application bundle to the local repository.

        An archive file is created from the app bundle, and this file is
        added to the tuf repository. If a previous archive version is found,
        a patch file is also created and added to the repository, unless
        `skip_patch` is True.

        Optional `custom_metadata` can be specified as a dictionary.

        If `required=True` (default is `False`), this release will always be
        installed, even if newer releases are available. For example, suppose
        an app is running at version 1.0, and version 2.0 is required, but version
        3.0 is also available, then tufup will first update to version 2.0,
        before updating to 3.0 on the next run.

        Note the changes are not published yet: call `publish_changes()` for
        that.
        """
        # enforce path object
        new_bundle_dir = pathlib.Path(new_bundle_dir)
        # determine new version
        if new_version is None:
            # todo: should we check for a valid version string?
            new_version = self.app_version
        # create archive from latest app bundle
        logger.info(f'Creating new archive from bundle: {new_bundle_dir}')
        new_archive = make_gztar_archive(
            src_dir=new_bundle_dir,
            dst_dir=self.targets_dir,
            app_name=self.app_name,
            version=new_version,
        )
        logger.info(f'Archive ready: {new_archive}')
        # check latest archive before registering the new one
        latest_archive = self.roles.get_latest_archive()
        if not latest_archive or latest_archive.version < new_archive.version:
            # register new archive
            self.roles.add_or_update_target(
                local_path=new_archive.path,
                # separate user-specified metadata from tufup-internal metadata
                custom=dict(user=custom_metadata, tufup={KEY_REQUIRED: required}),
            )
            # create patch, if possible, and register that too
            if latest_archive and not skip_patch:
                src_path = self.targets_dir / latest_archive.path
                dst_path = self.targets_dir / new_archive.path
                patch_path = dst_path.with_suffix('').with_suffix(SUFFIX_PATCH)
                # create patch
                dst_size_and_hash = Patcher.diff_and_hash(
                    src_path=src_path, dst_path=dst_path, patch_path=patch_path
                )
                # register patch (size and hash are used by the client to verify the
                # integrity of the patched archive)
                self.roles.add_or_update_target(
                    local_path=patch_path,
                    custom=dict(user=None, tufup=dst_size_and_hash),
                )
        else:
            logger.warning(
                f'bundle not added: version {new_archive.version} must be greater than'
                f'that of latest archive ({latest_archive.version})'
            )

    def remove_latest_bundle(self):
        """
        Removes the *latest* app bundle from the local repository.

        This deletes the bundle's archive file and corresponding patch file
        from the targets directory, and updates the tuf repository metadata
        accordingly.

        Note the changes are not published yet: call publish_changes() for that
        """
        # Get latest archive
        latest_archive = self.roles.get_latest_archive()
        if latest_archive:
            # remove latest archive and corresponding patch
            archive_path = self.targets_dir / latest_archive.target_path_str
            patch_path = archive_path.with_suffix('').with_suffix(SUFFIX_PATCH)
            for target_path in [archive_path, patch_path]:
                removed = self.roles.remove_target(local_path=target_path)
                logger.info(
                    f'target {"removed" if removed else "not found"}: {target_path}'
                )

    def publish_changes(self, private_key_dirs: List[Union[pathlib.Path, str]]):
        """
        Publish all modified roles. That is, if a role has changed w.r.t. to
        the version on disk:

        - update expiration date (if not yet updated)
        - bump version (if not yet bumped)
        - sign
        - save to disk

        If a role has not been modified, it is skipped.
        """
        # todo: implement custom Metadata subclass with extra methods:
        #  modified, set_expiration_date, sign, persist, etc. So we can do
        #  e.g role.set_expiration_date(days=1) instead of passing the
        #  role_name around
        for role_name in ['root', 'targets', 'snapshot', 'timestamp']:
            role = getattr(self.roles, role_name)
            # filename without version is always the latest version
            latest_file_path = self.roles.file_path(role_name=role_name, version=None)
            # if the file does not exist yet, the role is considered modified,
            # and we don't want to bump version and expiration date again
            modified = True
            expires_bumped = True
            version_bumped = True
            if latest_file_path.exists():
                latest_role = Metadata.from_file(filename=str(latest_file_path))
                modified = role.signed != latest_role.signed
                expires_bumped = role.signed.expires != latest_role.signed.expires
                version_bumped = role.signed.version > latest_role.signed.version
            if modified:
                # set new expiration date
                if not expires_bumped:
                    self.roles.set_expiration_date(
                        role_name=role_name,
                        days=self.expiration_days.get(role_name),
                    )
                # bump version
                if not version_bumped:
                    role.signed.version += 1
                # sign metadata and persist changes
                role.signatures.clear()
                self.threshold_sign(
                    role_name=role_name, private_key_dirs=private_key_dirs
                )
                # update version in dependent metadata
                dependent = None
                if role_name == 'root':
                    # Not all changes to root require a re-sign of the other
                    # metadata files (e.g. we could just add some additional
                    # valid keys). However, to be on the safe side,
                    # we'll force a re-sign cascade by bumping the targets
                    # version. Note this may cause a double version bump for
                    # targets, but that should not matter.
                    if self.roles.file_path(role_name='targets', version=None).exists():
                        self.roles.targets.signed.version += 1
                elif role_name == 'targets':
                    dependent = self.roles.snapshot.signed.meta[FILENAME_TARGETS]
                elif role_name == 'snapshot':
                    dependent = self.roles.timestamp.signed.snapshot_meta
                if dependent:
                    dependent.version = role.signed.version
                logger.info(f'Published changes for {role_name}.')
            else:
                logger.info(f'No changes detected for {role_name}.')
                # Check if signature count meets threshold
                threshold = self.roles.root.signed.roles[role_name].threshold
                if len(role.signatures) < threshold:
                    logger.info(f'{role_name} threshold not met. Trying to sign...')
                    signature_count = self.threshold_sign(
                        role_name=role_name, private_key_dirs=private_key_dirs
                    )
                    logger.info(f'Added {signature_count} signatures.')
        # update config if key_map has changed
        if self.config_dict != self.load_config():
            self.save_config()
            logger.info('Config file updated.')

    def threshold_sign(
        self,
        role_name: str,
        private_key_dirs: List[Union[pathlib.Path, str]],
    ) -> int:
        """
        Sign the metadata file for a specific role, and save changes to disk.

        Use this to sign and save without making any changes to the actual
        signed metadata.

        In case of root key rotation, both the old private key and the new
        private key are required.

        Returns the number of signatures created.
        """
        signature_count = 0
        # sign role with all required keys that can be found
        key_names = set(self.key_map.get(role_name, []))
        if role_name == 'root':
            # set ensures uniqueness
            key_names = key_names.union(self.revoked_key_names)
        for key_name in key_names:
            private_key_path = self.keys.find_private_key(
                key_name=key_name, key_dirs=private_key_dirs
            )
            if private_key_path:
                self.roles.sign_role(
                    role_name=role_name,
                    private_key_path=private_key_path,
                )
                signature_count += 1
                if key_name in self.revoked_key_names:
                    self.revoked_key_names.remove(key_name)
                    if key_name in self.encrypted_keys:
                        self.encrypted_keys.remove(key_name)
            else:
                logger.warning(f'Private key not found: {key_name}')
        if not signature_count:
            raise Exception(f'No private keys found for {role_name}.')
        # save changes to disk
        self.roles.persist_role(role_name=role_name)
        return signature_count

    def _load_keys_and_roles(self, create_keys: bool = False):
        # todo: make public, rename load_keys_and_metadata
        # todo: check import success (now says "metadata imported" even if files not found)
        if self.keys is None:
            logger.info('Importing public keys...')
            self.keys = Keys(
                dir_path=self.keys_dir,
                encrypted=self.encrypted_keys,
                key_map=self.key_map,
                thresholds=self.thresholds,
            )
            if create_keys:
                # safe to call if keys exist
                self.keys.create()
            logger.info('Public keys imported.')
        if self.roles is None:
            logger.info('Importing metadata...')
            self.roles = Roles(dir_path=self.metadata_dir)
            self.roles.initialize(keys=self.keys, expiration_days=self.expiration_days)
            logger.info('Metadata imported.')
