from datetime import datetime, timedelta
import logging
import pathlib
import re
import shutil
from typing import Any, Dict, Iterable, List, Optional, Union

from securesystemslib.interface import (
    generate_and_write_ed25519_keypair_with_prompt,
    generate_and_write_unencrypted_ed25519_keypair,
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file,
)
from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    Key,
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

from notsotuf.common import TargetMeta, SUFFIX_ARCHIVE

logger = logging.getLogger(__name__)

"""

https://github.com/theupdateframework/python-tuf/blob/develop/examples/repo_example/basic_repo.py

"""

__all__ = [
    'in_',
    'Keys',
    'make_gztar_archive',
    'Roles',
    'SUFFIX_JSON',
    'SUFFIX_PUB',
    'TOP_LEVEL_ROLE_NAMES',
]

# copied from python-tuf basic_repo.py
SPEC_VERSION = ".".join(SPECIFICATION_VERSION)


# copied from python-tuf basic_repo.py
def in_(days: float) -> datetime:
    """Returns a timestamp for the specified number of days from now."""
    return datetime.utcnow().replace(microsecond=0) + timedelta(days=days)


def make_gztar_archive(
        src_dir: Union[pathlib.Path, str],
        dst_dir: Union[pathlib.Path, str],
        app_name: str,
        version: str,
        **kwargs,  # allowed kwargs are passed on to shutil.make_archive
) -> Optional[TargetMeta]:
    # remove disallowed kwargs
    for key in ['base_name', 'root_dir', 'format']:
        if kwargs.pop(key, None):
            logger.warning(f'{key} ignored: using default')
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
    # make archive
    base_name = str(dst_dir / archive_filename.replace(SUFFIX_ARCHIVE, ''))
    archive_path_str = shutil.make_archive(
        base_name=base_name,  # archive file path, no suffix
        root_dir=str(src_dir),  # paths in archive will be relative to root_dir
        format='gztar',
        **kwargs,
    )
    return TargetMeta(target_path=archive_path_str)


DEFAULT_KEYS_DIR_NAME = 'keystore'
DEFAULT_META_DIR_NAME = 'metadata'
DEFAULT_TARGETS_DIR_NAME = 'targets'
SUFFIX_JSON = '.json'
SUFFIX_PUB = '.pub'
FILENAME_ROOT = Root.type + SUFFIX_JSON
FILENAME_TARGETS = Targets.type + SUFFIX_JSON
FILENAME_SNAPSHOT = Snapshot.type + SUFFIX_JSON
FILENAME_TIMESTAMP = Timestamp.type + SUFFIX_JSON


class Base(object):
    dir_path = pathlib.Path.cwd()
    encrypted = [Root.type, Targets.type]

    def __init__(self, dir_path: Union[pathlib.Path, str], encrypted: List[str]):
        if dir_path is not None:
            self.__class__.dir_path = pathlib.Path(dir_path)
        if encrypted is not None:
            self.__class__.encrypted = encrypted
        if not self.dir_path.exists():
            if input(f'Create directory {self.dir_path}? [y]/n') in ['y', '']:
                self.dir_path.mkdir(parents=True)
                print(f'Directory created: {self.dir_path}')


class Keys(Base):
    dir_path = pathlib.Path.cwd() / DEFAULT_KEYS_DIR_NAME
    encrypted = [Root.type, Targets.type]
    filename_pattern = '{key_name}'

    def __init__(
            self,
            dir_path: Union[pathlib.Path, str, None] = None,
            encrypted: Optional[List[str]] = None,
    ):
        super().__init__(dir_path=dir_path, encrypted=encrypted)
        # default roles
        self.root: Optional[Dict[str, Any]] = None
        self.targets: Optional[Dict[str, Any]] = None
        self.snapshot: Optional[Dict[str, Any]] = None
        self.timestamp: Optional[Dict[str, Any]] = None
        # import public keys from dir_path, if it exists
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.import_public_key(role_name=role_name)

    def import_public_key(self, role_name: str, key_name: Optional[str] = None):
        """Import public key for specified role."""
        if key_name is None:
            key_name = role_name
        public_key_path = self.public_key_path(key_name=key_name)
        if public_key_path.exists():
            ssl_key = import_ed25519_publickey_from_file(
                filepath=str(public_key_path)
            )
            setattr(self, role_name, ssl_key)
            logger.debug(f'public key imported: {public_key_path}')
        else:
            logger.debug(f'file does not exist: {public_key_path}')

    def create(
            self,
            role_names: Optional[Iterable[str]] = None,
            private_key_path: Optional[pathlib.Path] = None,
    ):
        if role_names is None:
            role_names = TOP_LEVEL_ROLE_NAMES
        logger.debug(f'creating key-pairs for roles: {role_names}')
        for role_name in role_names:
            default_private_key_path = self.private_key_path(role_name)
            self.create_key_pair(
                private_key_path=private_key_path or default_private_key_path,
                encrypted=role_name in self.encrypted,
            )
        # import the newly created public keys
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.import_public_key(role_name=role_name)

    @staticmethod
    def create_key_pair(
            private_key_path: pathlib.Path, encrypted: bool
    ) -> pathlib.Path:
        if encrypted:
            # encrypt private key
            logger.debug(f'set encryption password for private key')
            generate_keypair = generate_and_write_ed25519_keypair_with_prompt
        else:
            # do not encrypt private key (for automated signing)
            generate_keypair = generate_and_write_unencrypted_ed25519_keypair
        file_path_str = generate_keypair(filepath=str(private_key_path))
        public_key_path = private_key_path.with_suffix(SUFFIX_PUB)
        logger.info(f'key-pair created: {file_path_str}, {public_key_path}')
        return public_key_path

    def private_key_path(self, key_name: str) -> pathlib.Path:
        return self.dir_path / self.filename_pattern.format(key_name=key_name)

    def public_key_path(self, key_name: str) -> pathlib.Path:
        return self.private_key_path(key_name=key_name).with_suffix(SUFFIX_PUB)

    def public(self):
        # return a dict mapping key ids to *public* key objects
        return {
            ssl_key['keyid']: Key.from_securesystemslib_key(key_dict=ssl_key)
            for ssl_key in vars(self).values() if ssl_key is not None
        }

    def roles(self):
        # return a dict mapping role names to key ids and key thresholds
        return {
            role_name: Role(keyids=[ssl_key['keyid']], threshold=1)
            if ssl_key is not None else None
            for role_name, ssl_key in vars(self).items()
        }

    @classmethod
    def find_private_key(cls, role_name: str, key_dirs: List[Union[pathlib.Path, str]]):
        private_key_path = None
        private_key_filename = cls.filename_pattern.format(key_name=role_name)
        for key_dir in key_dirs:
            key_dir = pathlib.Path(key_dir)  # ensure Path
            for path in key_dir.iterdir():
                if path.is_file() and path.name == private_key_filename:
                    private_key_path = path
                    break
        return private_key_path


class Roles(Base):
    dir_path = pathlib.Path.cwd() / DEFAULT_META_DIR_NAME
    filename_pattern = '{version}{role_name}{suffix}'

    def __init__(
            self,
            dir_path: Union[pathlib.Path, str, None] = None,
            encrypted: Optional[List[str]] = None,
    ):
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
        super().__init__(dir_path=dir_path, encrypted=encrypted)
        self.root: Optional[Metadata[Root]] = None
        self.targets: Optional[Metadata[Targets]] = None
        self.snapshot: Optional[Metadata[Snapshot]] = None
        self.timestamp: Optional[Metadata[Timestamp]] = None
        # import roles from dir_path, if it exists
        self._import_roles(role_names=TOP_LEVEL_ROLE_NAMES)
        # flags
        self.root_modified = False
        self.targets_modified = False

    def _import_roles(self, role_names: Iterable[str]):
        """Import roles from metadata files."""
        file_paths = []
        if self.dir_path.exists():
            file_paths = [p for p in self.dir_path.iterdir() if p.is_file()]
        for role_name in role_names:
            role_paths = [p for p in file_paths if role_name in p.name]
            if role_name != 'timestamp':
                # sort by file version, ascending
                role_paths = sorted(
                    role_paths, key=lambda path: int(path.name.split('.')[0])
                )
            # import latest version for this role
            if role_paths:
                setattr(self, role_name, Metadata.from_file(str(role_paths[-1])))

    def initialize(self, keys: Keys):
        # based on python-tuf basic_repo.py
        common_kwargs = dict(version=1, spec_version=SPEC_VERSION)
        # role-specific kwargs
        initial_data = {
            Root: dict(
                expires=in_(0),
                keys=keys.public(),
                roles=keys.roles(),
                consistent_snapshot=False,
            ),
            Targets: dict(expires=in_(0), targets=dict()),
            Snapshot: dict(
                expires=in_(0), meta={FILENAME_TARGETS: MetaFile(version=1)}
            ),
            Timestamp: dict(expires=in_(0), snapshot_meta=MetaFile(version=1)),
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
                if attr_name == 'root':
                    self.root_modified = True
                else:
                    self.targets_modified = True

    def add_or_update_target(
            self,
            local_path: Union[pathlib.Path, str],
            url_path_segments: Optional[List[str]] = None,
    ):
        # based on python-tuf basic_repo.py
        local_path = pathlib.Path(local_path)
        # build url path
        url_path_segments = url_path_segments or []
        url_path_segments.append(local_path.name)
        url_path = '/'.join(url_path_segments)
        target_file_info = TargetFile.from_file(
            target_file_path=url_path, local_path=str(local_path)
        )
        existing_target_file_info = self.targets.signed.targets.get(url_path)
        self.targets.signed.targets[url_path] = target_file_info
        if existing_target_file_info != target_file_info:
            self.targets_modified = True

    def add_public_key(
            self, role_name: str, public_key_path: Union[pathlib.Path, str]
    ):
        """Import a public key from file and add it to the specified role."""
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
        self.root.signed.add_key(
            role=role_name, key=Key.from_securesystemslib_key(ssl_key)
        )
        self.root_modified = True

    def set_signature_threshold(self, role_name: str, threshold: int):
        self.root.signed.roles[role_name].threshold = threshold
        self.root_modified = True

    def sign_role(
            self,
            role_name: str,
            private_key_path: Union[pathlib.Path, str],
            expires: datetime,
            encrypted: bool = False,
    ):
        # set new expiration date
        getattr(self, role_name).signed.expires = expires
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_privatekey_from_file(
            filepath=str(private_key_path), prompt=encrypted
        )
        signer = SSlibSigner(ssl_key)
        getattr(self, role_name).sign(signer, append=True)

    def file_path(self, role_name: str, version: int):
        version = f'{version}.'
        if role_name == Timestamp.type:
            # timestamp file has no version
            version = ''
        return self.dir_path / self.filename_pattern.format(
            version=version, role_name=role_name, suffix=SUFFIX_JSON
        )

    def file_exists(self, role_name: str):
        """
        Return True if any metadata file exists for the specified role,
        ignoring version.
        """
        return any(
            path.exists() for path in self.dir_path.iterdir()
            if path.is_file() and role_name in path.name
        )

    def persist_role(self, role_name: str):
        # based on python-tuf basic_repo.py (but without consistent snapshots)
        role = getattr(self, role_name)
        role.to_file(
            filename=str(
                self.file_path(
                    role_name=role.signed.type, version=role.signed.version
                )
            ),
            serializer=JSONSerializer(compact=False),
        )

    def publish_root(
            self,
            private_key_paths: List[Union[pathlib.Path, str]],
            expires: datetime,
    ):
        """Call this whenever root has been modified (should be rare)."""
        if self.root_modified:
            # root content has changed, so increment version (if not initial)
            if self.file_exists(role_name=Root.type):
                self.root.signed.version += 1
            # sign and save
            self._publish_metadata(
                private_key_paths={Root.type: private_key_paths},
                expires={Root.type: expires},
            )
            self.root_modified = False

    def publish_targets(
            self,
            private_key_paths: Dict[str, List[Union[pathlib.Path, str]]],
            expires: Dict[str, datetime],
    ):
        """Call this whenever new targets have been added."""
        if self.targets_modified:
            # targets content has changed, so increment version
            if self.file_exists(role_name=Targets.type):
                self.targets.signed.version += 1
            # update snapshot content and increment version
            self.snapshot.signed.meta[FILENAME_TARGETS].version = self.targets.signed.version
            if self.file_exists(role_name=Snapshot.type):
                self.snapshot.signed.version += 1
            # update timestamp content and increment version
            self.timestamp.signed.snapshot_meta.version = self.snapshot.signed.version
            if self.file_exists(role_name=Timestamp.type):
                self.timestamp.signed.version += 1
            # sign and save
            self._publish_metadata(
                private_key_paths=private_key_paths, expires=expires
            )
            self.targets_modified = False

    def _publish_metadata(
            self,
            private_key_paths: Dict[str, List[Union[pathlib.Path, str]]],
            expires: Dict[str, datetime],
    ):
        # sign the metadata files and save to disk
        for role_name, role_private_key_paths in private_key_paths.items():
            # sign with each specified key
            for private_key_path in role_private_key_paths:
                self.sign_role(
                    role_name=role_name,
                    private_key_path=private_key_path,
                    expires=expires[role_name],
                    encrypted=role_name in self.encrypted,
                )
            self.persist_role(role_name=role_name)

    def replace_key(
            self,
            old_key_id: str,
            old_private_key_path: Union[pathlib.Path, str],
            new_private_key_path: Union[pathlib.Path, str],
            new_public_key_path: Union[pathlib.Path, str],
            root_expires: datetime,
    ):
        """Based on root key rotation example from tuf basic_repo.py."""
        # a key may be used for multiple roles, so we check the key id for
        # all roles
        for role_name in TOP_LEVEL_ROLE_NAMES:
            try:
                # key id is removed from roles dict, if found, and key is
                # removed from keys dict if it is no longer used by any roles
                self.root.signed.remove_key(role=role_name, keyid=old_key_id)
            except ValueError:
                logger.debug(f'{role_name} does not have key {old_key_id}')
            else:
                # add the new key
                self.add_public_key(
                    role_name=role_name, public_key_path=new_public_key_path
                )
        # publish new version of root, sign with both old key and new key
        self.publish_root(
            private_key_paths=[old_private_key_path, new_private_key_path],
            expires=root_expires,
        )

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
        targets = sorted(
            TargetMeta(key) for key in signed_targets.keys()
        )
        # extract only the archives
        archives = [target for target in targets if target.is_archive]
        if archives:
            latest_archive = archives[-1]
        return latest_archive
