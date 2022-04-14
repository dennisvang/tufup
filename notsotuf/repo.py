from datetime import datetime, timedelta
import logging
import pathlib
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

logger = logging.getLogger(__name__)

"""

https://github.com/theupdateframework/python-tuf/blob/develop/examples/repo_example/basic_repo.py

"""

__all__ = [
    'Keys', 'Roles', 'in_', 'TOP_LEVEL_ROLE_NAMES', 'SUFFIX_PUB', 'SUFFIX_JSON'
]

# copied from python-tuf basic_repo.py
SPEC_VERSION = ".".join(SPECIFICATION_VERSION)


# copied from python-tuf basic_repo.py
def in_(days: float) -> datetime:
    """Returns a timestamp for the specified number of days from now."""
    return datetime.utcnow().replace(microsecond=0) + timedelta(days=days)


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
    filename_pattern = '{role_name}_key'

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
        self._import_public(role_names=TOP_LEVEL_ROLE_NAMES)

    def _import_public(self, role_names: Iterable[str]):
        for role_name in role_names:
            public_key_path = self.public_key_path(role_name)
            if public_key_path.exists():
                ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
                setattr(self, role_name, ssl_key)
                logger.debug(f'public key imported: {public_key_path}')
            else:
                logger.debug(f'file does not exist: {public_key_path}')

    def create(self, role_names: Optional[Iterable[str]] = None):
        if role_names is None:
            role_names = TOP_LEVEL_ROLE_NAMES
        logger.debug(f'creating key-pairs for roles: {role_names}')
        for role_name in role_names:
            private_key_path = self.private_key_path(role_name)
            if role_name in self.encrypted:
                # encrypt private key
                logger.debug(f'set encryption password for {role_name} private key')
                generate_and_write_ed25519_keypair_with_prompt(
                    filepath=str(private_key_path))
            else:
                # do not encrypt private key (for automated signing)
                generate_and_write_unencrypted_ed25519_keypair(
                    filepath=str(private_key_path))
            logger.debug(f'key-pair created: {private_key_path}')
        # import the newly created public keys
        self._import_public(role_names=role_names)

    def private_key_path(self, role_name: str) -> pathlib.Path:
        return self.dir_path / self.filename_pattern.format(role_name=role_name)

    def public_key_path(self, role_name: str) -> pathlib.Path:
        return self.private_key_path(role_name=role_name).with_suffix(SUFFIX_PUB)

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
            for role_name, ssl_key in vars(self).items() if ssl_key is not None
        }

    @classmethod
    def find_private(cls, role_name: str, key_dirs: List[Union[pathlib.Path, str]]):
        private_key_path = None
        private_key_filename = cls.filename_pattern.format(role_name=role_name)
        for key_dir in key_dirs:
            key_dir = pathlib.Path(key_dir)  # ensure Path
            for path in key_dir.iterdir():
                if path.is_file() and path.name == private_key_filename:
                    private_key_path = path
                    break
        return private_key_path


class Roles(Base):
    dir_path = pathlib.Path.cwd() / DEFAULT_META_DIR_NAME
    filename_pattern = '{role_name}' + SUFFIX_JSON

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

    def _import_roles(self, role_names: Iterable[str]):
        """Import roles from metadata files."""
        if self.dir_path.exists():
            for path in self.dir_path.iterdir():
                if path.is_file() and path.stem in role_names:
                    setattr(self, path.stem, Metadata.from_file(str(path)))

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
            # intialize role
            setattr(
                self,
                role_class.type,
                Metadata(
                    signed=role_class(**common_kwargs, **role_kwargs),
                    signatures=dict(),
                ),
            )

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
        self.targets.signed.targets[url_path] = target_file_info

    def add_public_key(
            self, role_name: str, public_key_path: Union[pathlib.Path, str]
    ):
        """Import a public key from file and add it to the specified role."""
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
        self.root.signed.add_key(
            role=role_name, key=Key.from_securesystemslib_key(ssl_key)
        )

    def set_signature_threshold(self, role_name: str, threshold: int):
        self.root.signed.roles[role_name].threshold = threshold

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
        getattr(self, role_name).sign(signer)

    def persist_role(self, role_name: str):
        # based on python-tuf basic_repo.py (but without consistent snapshots)
        role = getattr(self, role_name)
        file_path = self.dir_path / self.filename_pattern.format(
            role_name=role.signed.type
        )
        role.to_file(filename=str(file_path), serializer=JSONSerializer(compact=False))

    def publish_root(
            self, keys_dirs: List[Union[pathlib.Path, str]], expires: datetime
    ):
        """Call this whenever root has been modified (should be rare)."""
        # todo: handle initial case, as we cannot set version=0
        # root content has changed, so increment version
        self.root.signed.version += 1
        # sign and save
        self._publish_metadata(
            role_names=[Root.type], keys_dirs=keys_dirs, expires=dict(root=expires)
        )

    def publish_targets(
            self,
            keys_dirs: List[Union[pathlib.Path, str]],
            expires: Dict[str, datetime],
    ):
        """Call this whenever new targets have been added."""
        # targets content has changed, so increment version
        self.targets.signed.version += 1
        # update snapshot content and increment version
        self.snapshot.signed.meta[FILENAME_TARGETS].version = self.targets.signed.version
        self.snapshot.signed.version += 1
        # update timestamp content and increment version
        self.timestamp.signed.snapshot_meta.version = self.snapshot.signed.version
        self.timestamp.signed.version += 1
        # sign and save
        self._publish_metadata(
            role_names=[Targets.type, Snapshot.type, Timestamp.type],
            keys_dirs=keys_dirs,
            expires=expires,
        )

    def _publish_metadata(
            self,
            role_names: List[str],
            keys_dirs: List[Union[pathlib.Path, str]],
            expires: Dict[str, datetime],
    ):
        # sign the metadata files and save to disk
        for role_name in role_names:
            private_key_path = Keys.find_private(
                role_name=role_name, key_dirs=keys_dirs
            )
            self.sign_role(
                role_name=role_name,
                private_key_path=private_key_path,
                expires=expires[role_name],
                encrypted=role_name in self.encrypted,
            )
            self.persist_role(role_name=role_name)
