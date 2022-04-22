from datetime import datetime, timedelta
import json
import pathlib
from unittest.mock import patch, Mock

from securesystemslib.interface import generate_and_write_unencrypted_ed25519_keypair
from tuf.api.metadata import (
    Metadata,
    Role,
    Root,
    Targets,
    Snapshot,
    Timestamp,
    TargetFile,
    TOP_LEVEL_ROLE_NAMES
)

import notsotuf.repo  # for patching
from notsotuf.repo import Base, Keys, Roles, in_, SUFFIX_PUB, make_gztar_archive
from tests import TempDirTestCase


mock_input = Mock(return_value='')

DUMMY_SSL_KEY = {
    'keytype': 'ed25519',
    'scheme': 'ed25519',
    'keyid': '22f7c6046e29cfb0205a1c07941a5a57da39a6859b844f8c347f622a57ff82c8',
    'keyid_hash_algorithms': ['sha256', 'sha512'],
    'keyval': {'public': '93032b5804ba40a725145171193782bdfa30038584715546aea3228ea8018e46'},
}
DUMMY_ROOT = Root(
    version=1,
    spec_version='1.0',
    expires=datetime.now() + timedelta(days=1),
    keys=dict(),
    roles={
        role_name: Role(keyids=[], threshold=1)
        for role_name in TOP_LEVEL_ROLE_NAMES
    },
    consistent_snapshot=False,
)
DUMMY_EXPIRES = dict(
    root=in_(0), targets=in_(0), snapshot=in_(0), timestamp=in_(0)
)
DUMMY_PRIVATE_KEY_PATHS = dict(
    (role_name, [pathlib.Path('dummy', role_name)])
    for role_name in TOP_LEVEL_ROLE_NAMES
)


class ModuleTests(TempDirTestCase):
    def test_in_(self):
        self.assertIsInstance(in_(days=1), datetime)

    def test_make_gztar_archive(self):
        app_name = 'test'
        version = '1.2.3'
        # prepare
        sub_dir = self.temp_dir_path / 'sub'
        sub_file = sub_dir / 'sub.txt'
        root_file = self.temp_dir_path / 'root.txt'
        sub_dir.mkdir()
        sub_file.touch()
        root_file.touch()
        # archive already exists (to test overwrite confirmation)
        existing_archive = self.temp_dir_path / f'{app_name}-{version}.tar.gz'
        existing_archive.touch()
        # test
        mock_input_yes = Mock(return_value='y')
        with patch('builtins.input', mock_input_yes):
            archive_path = make_gztar_archive(
                src_dir=self.temp_dir_path,
                dst_dir=self.temp_dir_path,
                app_name=app_name,
                version=version,
                base_dir='.',  # this kwarg is allowed
                root_dir='some path',  # this kwarg is removed
            )
        self.assertTrue(archive_path.exists())
        self.assertTrue(mock_input_yes.called)
        self.assertTrue(app_name in str(archive_path))
        self.assertTrue(version in str(archive_path))


class BaseTests(TempDirTestCase):
    def test_init(self):
        with patch('builtins.input', mock_input):
            # dir exists
            base = Base(dir_path=self.temp_dir_path, encrypted=[])
            self.assertTrue(base.dir_path.exists())
            # dir does not exist yet
            base = Base(dir_path=self.temp_dir_path / 'new', encrypted=[])
            self.assertTrue(base.dir_path.exists())
            self.assertFalse(base.encrypted)


class KeysTests(TempDirTestCase):
    def test_init_no_key_files(self):
        # no public key files exist yet
        keys = Keys(dir_path=self.temp_dir_path)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsNone(getattr(keys, role_name))

    def test_init_import_existing_public_keys(self):
        # create some key files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            private_key_filename = Keys.filename_pattern.format(key_name=role_name)
            file_path = self.temp_dir_path / private_key_filename
            generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        # test
        keys = Keys(dir_path=self.temp_dir_path)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name), dict)

    def test_import_public_key(self):
        # create dummy key with name differing from role name
        key_name = 'test'
        role_name = 'targets'
        private_key_filename = Keys.filename_pattern.format(key_name=key_name)
        file_path = self.temp_dir_path / private_key_filename
        generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        # test
        keys = Keys(dir_path=self.temp_dir_path)
        keys.import_public_key(role_name=role_name, key_name=key_name)
        self.assertTrue(keys.targets)

    def test_create(self):
        with patch('getpass.getpass', mock_input):
            keys = Keys(dir_path=self.temp_dir_path)
            keys.create()
            # key pair files should now exist
            filenames = [item.name for item in keys.dir_path.iterdir()]
            for role_name in TOP_LEVEL_ROLE_NAMES:
                private_key_filename = Keys.filename_pattern.format(key_name=role_name)
                public_key_filename = private_key_filename + SUFFIX_PUB
                self.assertIn(private_key_filename, filenames)
                self.assertIn(public_key_filename, filenames)
            # and the public keys should have been imported
            self.assertTrue(all(getattr(keys, n) for n in TOP_LEVEL_ROLE_NAMES))

    def test_create_key_pair(self):
        public_key_path = Keys.create_key_pair(
            private_key_path=self.temp_dir_path / 'key_name', encrypted=False
        )
        self.assertTrue(public_key_path.exists())

    def test_public(self):
        keys = Keys(dir_path=self.temp_dir_path)
        # test empty
        self.assertFalse(keys.public())
        # set a dummy key value
        keys.root = DUMMY_SSL_KEY
        # test
        self.assertIn(DUMMY_SSL_KEY['keyid'], keys.public().keys())

    def test_roles(self):
        keys = Keys(dir_path=self.temp_dir_path)
        # test empty
        self.assertSetEqual(set(TOP_LEVEL_ROLE_NAMES), set(keys.roles().keys()))
        # set a dummy key value
        keys.root = DUMMY_SSL_KEY
        # test
        self.assertIn('root', keys.roles().keys())

    def test_find_private_key(self):
        # create dummy private key files in separate folders
        key_names = [
            ('online', [Snapshot.type, Timestamp.type]),
            ('offline', [Root.type, Targets.type]),
        ]
        key_dirs = []
        for dir_name, role_names  in key_names:
            dir_path = self.temp_dir_path / dir_name
            dir_path.mkdir()
            key_dirs.append(dir_path)
            for role_name in role_names:
                filename = Keys.filename_pattern.format(key_name=role_name)
                (dir_path / filename).touch()
        # test
        for role_name in TOP_LEVEL_ROLE_NAMES:
            key_path = Keys.find_private_key(role_name=role_name, key_dirs=key_dirs)
            self.assertIn(role_name, str(key_path))
            self.assertTrue(key_path.exists())


class RolesTests(TempDirTestCase):
    def test_init(self):
        self.assertTrue(Roles(dir_path=self.temp_dir_path))

    def test_init_import_roles(self):
        def mock_from_file(filename, *args, **kwargs):
            return pathlib.Path(filename).exists()

        # create dummy metadata files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            (self.temp_dir_path / f'{role_name}.json').touch()
        # test
        with patch.object(notsotuf.repo.Metadata, 'from_file', mock_from_file):
            roles = Roles(dir_path=self.temp_dir_path)
            self.assertTrue(all(getattr(roles, n) for n in TOP_LEVEL_ROLE_NAMES))

    def test_initialize_empty(self):
        # prepare
        mock_keys = Mock()
        mock_keys.public = Mock()
        mock_keys.roles = Mock(return_value={n: None for n in TOP_LEVEL_ROLE_NAMES})
        roles = Roles(dir_path=self.temp_dir_path)
        # test
        roles.initialize(keys=mock_keys)
        self.assertTrue(
            all(isinstance(getattr(roles, n), Metadata) for n in TOP_LEVEL_ROLE_NAMES)
        )
        # files do not exist yet, because the roles still need to be populated
        self.assertFalse(any(roles.dir_path.iterdir()))

    def test_initialize_existing_root(self):
        # prepare
        mock_keys = Mock()
        mock_keys.public = Mock()
        mock_keys.roles = Mock(return_value={n: None for n in TOP_LEVEL_ROLE_NAMES})
        roles = Roles(dir_path=self.temp_dir_path)
        # set existing root role
        mock_root_role = Mock()
        roles.root = mock_root_role
        # test
        roles.initialize(keys=mock_keys)
        # ensure the existing role has not been replaced
        self.assertEqual(mock_root_role, roles.root)

    def test_add_or_update_target(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        roles.targets = Mock(signed=Mock(targets=dict()))
        # test
        filename = 'my_app.tar.gz'
        local_target_path = self.temp_dir_path / filename
        # path must exist
        with self.assertRaises(FileNotFoundError):
            roles.add_or_update_target(local_path=local_target_path)
        local_target_path.write_bytes(b'some bytes')
        # test
        for segments, expected_url_path in [
            (None, filename), ([], filename), (['a', 'b'], 'a/b/' + filename)
        ]:
            roles.add_or_update_target(
                local_path=local_target_path, url_path_segments=segments
            )
            with self.subTest(msg=segments):
                self.assertIsInstance(
                    roles.targets.signed.targets[expected_url_path], TargetFile
                )

    def test_add_public_key(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Mock(signed=Mock(roles=dict(), add_key=Mock()))
        public_key_path = self.temp_dir_path / 'targets_key.pub'
        public_key_path.write_text(json.dumps(DUMMY_SSL_KEY))
        # test
        role_name = 'targets'
        roles.add_public_key(role_name=role_name, public_key_path=public_key_path)
        self.assertTrue(roles.root.signed.add_key.called)

    def test_set_signature_threshold(self):
        # prepare
        role_name = 'targets'
        threshold = 2
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Mock(signed=Mock(roles={role_name: Mock(threshold=1)}))
        # test
        roles.set_signature_threshold(role_name=role_name, threshold=threshold)
        self.assertEqual(threshold, roles.root.signed.roles[role_name].threshold)

    def test_sign_role(self):
        # prepare
        role_name = 'root'
        private_key_path = self.temp_dir_path / 'root_key'
        generate_and_write_unencrypted_ed25519_keypair(
            filepath=str(private_key_path)
        )
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Metadata(signed=DUMMY_ROOT, signatures=dict())
        # test
        roles.sign_role(
            role_name=role_name,
            private_key_path=private_key_path,
            expires=in_(0),
            encrypted=False,
        )
        self.assertTrue(roles.root.signatures)

    def test_file_path(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        # test
        self.assertEqual(
            self.temp_dir_path / 'root.json',
            roles.file_path(role_name='root'),
        )

    def test_persist_role(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Metadata(signed=DUMMY_ROOT, signatures=dict())
        # test
        roles.persist_role(role_name='root')
        self.assertTrue((self.temp_dir_path / 'root.json').exists())

    def test_publish_root(self):
        with patch.object(Roles, '_publish_metadata', Mock()):
            # prepare
            roles = Roles(dir_path=self.temp_dir_path)
            roles.root = Mock(signed=Mock(version=1))
            roles.encrypted = []
            # test
            roles.publish_root(private_key_paths=[], expires=in_(0))
            self.assertEqual(2, roles.root.signed.version)
            self.assertTrue(Roles._publish_metadata.called)  # noqa

    def test_publish_targets(self):
        with patch.object(Roles, '_publish_metadata', Mock()):
            # prepare
            roles = Roles(dir_path=self.temp_dir_path)
            roles.targets = Mock(signed=Mock(version=1))
            roles.snapshot = Mock(
                signed=Mock(meta={'targets.json': Mock(version=1)}, version=1)
            )
            roles.timestamp = Mock(
                signed=Mock(snapshot_meta=Mock(version=1), version=1)
            )
            roles.encrypted = []
            # test
            expires = DUMMY_EXPIRES.copy()
            expires.pop('root')  # no need to sign root
            private_key_paths = DUMMY_PRIVATE_KEY_PATHS.copy()
            private_key_paths.pop('root')
            roles.publish_targets(
                private_key_paths=private_key_paths, expires=expires
            )
            role_names = [Targets.type, Snapshot.type, Timestamp.type]
            self.assertTrue(
                all(getattr(roles, n).signed.version == 2 for n in role_names)
            )
            self.assertTrue(Roles._publish_metadata.called)  # noqa

    def test__publish_metadata(self):
        with patch.multiple(Roles, sign_role=Mock(), persist_role=Mock()):
            # prepare
            roles = Roles(dir_path=self.temp_dir_path)
            roles.encrypted = []
            # test
            roles._publish_metadata(
                private_key_paths=DUMMY_PRIVATE_KEY_PATHS, expires=DUMMY_EXPIRES
            )
            self.assertTrue(Roles.sign_role.called)  # noqa
            self.assertTrue(Roles.persist_role.called)  # noqa

    def test_replace_key(self):
        # prepare
        keys_dir = self.temp_dir_path / 'keystore'
        keys_dir.mkdir()
        keys = Keys(dir_path=keys_dir, encrypted=[])
        keys.create()
        roles = Roles(dir_path=self.temp_dir_path, encrypted=[])
        roles.initialize(keys=keys)
        # create new key pair to replace old one
        new_private_key_path = keys_dir / 'new_key'
        new_public_key_path = Keys.create_key_pair(
            private_key_path=new_private_key_path, encrypted=False
        )
        # test
        role_name = 'targets'
        old_key_id = roles.root.signed.roles[role_name].keyids[0]
        roles.replace_key(
            old_key_id=old_key_id,
            old_private_key_path=keys.private_key_path(key_name=role_name),
            new_private_key_path=new_private_key_path,
            new_public_key_path=new_public_key_path,
            root_expires=in_(365),
        )
        self.assertNotIn(old_key_id, roles.root.signed.roles[role_name].keyids)
