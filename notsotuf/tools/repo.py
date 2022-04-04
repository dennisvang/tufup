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

# copied from python-tuf basic_repo.py
SPEC_VERSION = ".".join(SPECIFICATION_VERSION)


# copied from python-tuf basic_repo.py
def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.utcnow().replace(microsecond=0) + timedelta(days=days)


ROOT = 'root'
TARGETS = 'targets'
SNAPSHOT = 'snapshot'
TIMESTAMP = 'timestamp'
DEFAULT_ROLE_NAMES = [ROOT, TARGETS, SNAPSHOT, TIMESTAMP]

DEFAULT_KEYS_DIR_NAME = 'keystore'
DEFAULT_META_DIR_NAME = 'metadata'
DEFAULT_TARGETS_DIR_NAME = 'targets'
SUFFIX_JSON = '.json'
SUFFIX_PUB = '.pub'
FILENAME_ROOT = ROOT + SUFFIX_JSON
FILENAME_TARGETS = TARGETS + SUFFIX_JSON
FILENAME_SNAPSHOT = SNAPSHOT + SUFFIX_JSON
FILENAME_TIMESTAMP = TIMESTAMP + SUFFIX_JSON


class Keys(object):
    dir_path = pathlib.Path.cwd() / DEFAULT_KEYS_DIR_NAME
    filename_pattern = '{role_name}_key'
    encrypted = [ROOT, TARGETS]

    def __init__(
            self,
            dir_path: Union[pathlib.Path, str, None] = None,
            encrypted: Optional[List[str]] = None,
    ):
        if dir_path is not None:
            Keys.dir_path = pathlib.Path(dir_path)
        if encrypted is not None:
            Keys.encrypted = encrypted
        # default roles
        self.root: Optional[Dict[str, Any]] = None
        self.targets: Optional[Dict[str, Any]] = None
        self.snapshot: Optional[Dict[str, Any]] = None
        self.timestamp: Optional[Dict[str, Any]] = None
        # initialize if necessary
        if not self.dir_path.exists():
            # create dir path
            self.dir_path.mkdir(parents=True)
            # initialize keys for default top-level roles
            self._generate_and_write(role_names=DEFAULT_ROLE_NAMES, encrypted=encrypted)
        # import public keys from dir_path
        self._import_public(role_names=DEFAULT_ROLE_NAMES)

    def private_key_path(self, role_name: str) -> pathlib.Path:
        return self.dir_path / self.filename_pattern.format(role_name=role_name)

    def public_key_path(self, role_name: str) -> pathlib.Path:
        return self.private_key_path(role_name=role_name).with_suffix(SUFFIX_PUB)

    def public(self):
        # return a dict mapping key ids to *public* key objects
        return {
            ssl_key['keyid']: Key.from_securesystemslib_key(key_dict=ssl_key)
            for ssl_key in vars(self).values()
        }

    def roles(self):
        # return a dict mapping role names to key ids and key thresholds
        return {
            role_name: Role(keyids=[ssl_key['keyid']], threshold=1)
            for role_name, ssl_key in vars(self).items()
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

    def _generate_and_write(self, role_names: Iterable[str], encrypted: List[str]):
        # create keys for specified roles
        for role_name in role_names:
            private_key_path = self.private_key_path(role_name)
            if role_name in encrypted:
                # encrypt private key
                generate_and_write_ed25519_keypair_with_prompt(
                    filepath=str(private_key_path))
            else:
                # do not encrypt private key (for automated signing)
                generate_and_write_unencrypted_ed25519_keypair(
                    filepath=str(private_key_path))

    def _import_public(self, role_names: Iterable[str]):
        for role_name in role_names:
            public_key_path = self.public_key_path(role_name)
            if public_key_path.exists():
                ssl_key = import_ed25519_publickey_from_file(
                    filepath=str(public_key_path))
                setattr(self, role_name, ssl_key)


class Roles(object):
    dir_path = pathlib.Path.cwd() / DEFAULT_META_DIR_NAME
    encrypted = [ROOT, TARGETS]

    def __init__(self, keys: Keys, dir_path: Union[pathlib.Path, str, None] = None):
        if dir_path is not None:
            Roles.dir_path = pathlib.Path(dir_path)
        self.root: Optional[Metadata[Root]] = None
        self.targets: Optional[Metadata[Targets]] = None
        self.snapshot: Optional[Metadata[Snapshot]] = None
        self.timestamp: Optional[Metadata[Timestamp]] = None
        if self.dir_path.exists():
            # import roles from metadata files
            for path in self.dir_path.iterdir():
                if path.is_file() and path.stem in DEFAULT_ROLE_NAMES:
                    setattr(self, path.stem, Metadata.from_file(str(path)))
        else:
            # create dir
            self.dir_path.mkdir(parents=True)
            # initialize top level roles
            self.create(keys=keys)

    def create(self, keys: Keys):
        # based on python-tuf basic_repo.py
        self.root = Metadata(
            signed=Root(version=1, spec_version=SPEC_VERSION, expires=_in(365), keys=keys.public(), roles=keys.roles(), consistent_snapshot=False),
            signatures={},
        )
        self.targets = Metadata(
            signed=Targets(version=1, spec_version=SPEC_VERSION, expires=_in(7), targets={}),
            signatures={},
        )
        self.snapshot = Metadata(
            signed=Snapshot(version=1, spec_version=SPEC_VERSION, expires=_in(7), meta={FILENAME_TARGETS: MetaFile(version=1)}),
            signatures={},
        )
        self.timestamp = Metadata(
            signed=Timestamp(version=1, spec_version=SPEC_VERSION, expires=_in(1), snapshot_meta=MetaFile(version=1)),
            signatures={},
        )

    def add_or_update_target(self, local_path: Union[pathlib.Path, str]):
        # based on python-tuf basic_repo.py
        local_path = pathlib.Path(local_path)
        target_url_path = '/'.join([DEFAULT_TARGETS_DIR_NAME, local_path.name])
        target_file_info = TargetFile.from_file(target_file_path=target_url_path, local_path=str(local_path))
        self.targets.signed.targets[target_url_path] = target_file_info

    def add_public_key(self, role_name: str, public_key_path: Union[pathlib.Path, str], increment_threshold=False):
        """Import a public key from file and add it to the specified role."""
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_publickey_from_file(filepath=str(public_key_path))
        self.root.signed.add_key(role=role_name, key=Key.from_securesystemslib_key(ssl_key))
        if increment_threshold:
            self.root.signed.roles[role_name].threshold += 1

    def sign_role(self, role_name: str, private_key_path: Union[pathlib.Path, str], encrypted: bool = False):
        # based on python-tuf basic_repo.py
        ssl_key = import_ed25519_privatekey_from_file(filepath=str(private_key_path), prompt=encrypted)
        signer = SSlibSigner(ssl_key)
        getattr(self, role_name).sign(signer)

    def persist_role(self, role_name: str):
        # based on python-tuf basic_repo.py (but without consistent snapshots)
        role = getattr(self, role_name)
        file_path = self.dir_path / (role.signed.type + SUFFIX_JSON)
        role.to_file(filename=str(file_path), serializer=JSONSerializer(compact=False))

    def publish_updated_targets(self, keys_dirs: List[Union[pathlib.Path, str]]):
        # based on python-tuf basic_repo.py

        # targets role has been updated, so we need to increment its version
        self.targets.signed.version += 1
        # update snapshot content and increment version
        self.snapshot.signed.meta[FILENAME_TARGETS].version = self.targets.signed.version
        self.snapshot.signed.version += 1
        # update timestamp content and increment version
        self.timestamp.signed.snapshot_meta.version = self.snapshot.signed.version
        self.timestamp.signed.version += 1
        # sign the modified metadate files
        for role_name in [TARGETS, SNAPSHOT, TIMESTAMP]:
            private_key_path = Keys.find_private(role_name=role_name, key_dirs=keys_dirs)
            self.sign_role(role_name=role_name, private_key_path=private_key_path, encrypted=role_name in self.encrypted)
            self.persist_role(role_name=role_name)
