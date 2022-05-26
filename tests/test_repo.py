from datetime import datetime, timedelta
import json
import pathlib
from unittest.mock import patch, Mock

from securesystemslib.interface import (
    generate_and_write_unencrypted_ed25519_keypair,
    generate_and_write_ed25519_keypair,
)
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

from notsotuf.common import TargetMeta
import notsotuf.repo  # for patching
from notsotuf.repo import Base, Keys, Roles, in_, SUFFIX_PUB, make_gztar_archive
from tests import TempDirTestCase, TEST_REPO_DIR


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
        # test
        mock_input_no = Mock(return_value='n')
        for exists in [False, True]:
            with patch('builtins.input', mock_input_no):
                archive = make_gztar_archive(
                    src_dir=self.temp_dir_path,
                    dst_dir=self.temp_dir_path,
                    app_name=app_name,
                    version=version,
                    base_dir='.',  # this kwarg is allowed
                    root_dir='some path',  # this kwarg is removed
                )
            self.assertIsInstance(archive, TargetMeta)
            self.assertEqual(exists, mock_input_no.called)
            self.assertTrue(archive.path.exists())
            self.assertTrue(app_name in str(archive.path))
            self.assertTrue(version in str(archive.path))


class BaseTests(TempDirTestCase):
    def test_init(self):
        with patch('builtins.input', mock_input):
            # dir exists
            base = Base(dir_path=self.temp_dir_path)
            self.assertTrue(base.dir_path.exists())
            # dir does not exist yet
            base = Base(dir_path=self.temp_dir_path / 'new')
            self.assertTrue(base.dir_path.exists())


class KeysTests(TempDirTestCase):
    def test_init_no_key_files(self):
        # no public key files exist yet
        keys = Keys(dir_path=self.temp_dir_path)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsNone(getattr(keys, role_name))

    def test_init_and_import_all_public_keys(self):
        # create some key files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            private_key_filename = Keys.filename_pattern.format(key_name=role_name)
            file_path = self.temp_dir_path / private_key_filename
            generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        # test
        keys = Keys(dir_path=self.temp_dir_path)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name), dict)

    def test_init_and_import_all_public_keys_with_key_map(self):
        # create a single key-pair
        key_name = 'single'
        private_key_filename = Keys.filename_pattern.format(key_name=key_name)
        file_path = self.temp_dir_path / private_key_filename
        generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        key_map = {role_name: key_name for role_name in TOP_LEVEL_ROLE_NAMES}
        # test
        keys = Keys(dir_path=self.temp_dir_path, key_map=key_map)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name), dict)
            # all keys should be equal
            self.assertEqual(keys.root, getattr(keys, role_name))

    def test_import_all_public_keys(self):
        # note: import_all_public_keys is also (implicitly) tested via __init__
        keys = Keys(dir_path=self.temp_dir_path)
        # create some key files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            private_key_filename = Keys.filename_pattern.format(
                key_name=role_name)
            file_path = self.temp_dir_path / private_key_filename
            generate_and_write_unencrypted_ed25519_keypair(
                filepath=str(file_path))
        # test
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsNone(getattr(keys, role_name))
        keys.import_all_public_keys()
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
            keys = Keys(dir_path=self.temp_dir_path, encrypted=['root'])
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

    def test_create_with_key_map(self):
        # prepare
        key_name = 'single'
        key_map = {role_name: key_name for role_name in TOP_LEVEL_ROLE_NAMES}
        keys = Keys(dir_path=self.temp_dir_path, key_map=key_map)
        private_key_filename = Keys.filename_pattern.format(key_name=key_name)
        public_key_filename = private_key_filename + SUFFIX_PUB
        # test
        keys.create()
        # a single key pair should now exist
        filenames = [item.name for item in keys.dir_path.iterdir()]
        self.assertEqual(2, len(filenames))
        self.assertIn(private_key_filename, filenames)
        self.assertIn(public_key_filename, filenames)
        # and the public keys should have been imported
        self.assertTrue(all(getattr(keys, n) for n in TOP_LEVEL_ROLE_NAMES))

    def test_create_key_pair(self):
        public_key_path = Keys.create_key_pair(
            private_key_path=self.temp_dir_path / 'key_name', encrypted=False
        )
        self.assertTrue(public_key_path.exists())

    def test_create_key_pair_do_not_overwrite(self):
        # create dummy key pair
        key_name = 'dummy'
        private_key_filename = Keys.filename_pattern.format(key_name=key_name)
        private_key_path = self.temp_dir_path / private_key_filename
        generate_and_write_unencrypted_ed25519_keypair(
            filepath=str(private_key_path)
        )
        original_private_key = private_key_path.read_bytes()
        with patch('builtins.input', Mock(return_value='n')):
            Keys.create_key_pair(
                private_key_path=private_key_path, encrypted=False
            )
        self.assertEqual(original_private_key, private_key_path.read_bytes())

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
            key_path = Keys.find_private_key(key_name=role_name, key_dirs=key_dirs)
            self.assertIn(role_name, str(key_path))
            self.assertTrue(key_path.exists())


class RolesTests(TempDirTestCase):
    def test_init(self):
        self.assertTrue(Roles(dir_path=self.temp_dir_path))

    def test_init_import_roles(self):
        def mock_from_file(filename, *args, **kwargs):
            file_path = pathlib.Path(filename)
            assert file_path.exists()
            return file_path.stem

        # create dummy metadata files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            filenames = [f'{role_name}.json']
            if role_name == 'root':
                filenames.extend(f'{v}.{role_name}.json' for v in [1, 2, 3])
            for filename in filenames:
                (self.temp_dir_path / filename).touch()
        # test
        with patch.object(notsotuf.repo.Metadata, 'from_file', mock_from_file):
            roles = Roles(dir_path=self.temp_dir_path)
            for role_name in TOP_LEVEL_ROLE_NAMES:
                self.assertEqual(role_name, getattr(roles, role_name))

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

    def test_remove_target(self):
        # prepare
        filename = 'my_app-1.0.tar.gz'
        dirname = 'subdir'
        url_path = f'{dirname}/{filename}'
        subdir = self.temp_dir_path / dirname
        subdir.mkdir()
        local_target_path = subdir / filename
        local_target_path.touch()
        roles = Roles(dir_path=self.temp_dir_path)
        roles.targets = Mock(signed=Mock(targets={url_path: Mock()}))
        # test
        self.assertTrue(local_target_path.exists())
        roles.remove_target(local_path=local_target_path)
        self.assertNotIn(filename, roles.targets.signed.targets)
        self.assertFalse(local_target_path.exists())
        self.assertTrue(roles.targets_modified)
        # cannot remove non-existent target
        self.assertFalse(roles.remove_target(local_path=local_target_path))

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
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Metadata(signed=DUMMY_ROOT, signatures=dict())
        role_name = 'root'
        signature_count = 2
        password = 'mock-password'
        with patch('getpass.getpass', Mock(return_value=password)):
            for index in range(signature_count):
                private_key_path = self.temp_dir_path / f'{index}.{role_name}'
                # create key pair
                if index == 0:
                    generate_and_write_unencrypted_ed25519_keypair(
                        filepath=str(private_key_path)
                    )
                else:
                    generate_and_write_ed25519_keypair(
                        password=password, filepath=str(private_key_path)
                    )
                # test
                roles.sign_role(
                    role_name=role_name,
                    private_key_path=private_key_path,
                    expires=in_(0),
                )
        self.assertEqual(signature_count, len(roles.root.signatures))

    def test_file_path(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        # test
        self.assertEqual(
            self.temp_dir_path / '1.root.json',
            roles.file_path(role_name='root', version=1),
        )
        self.assertEqual(
            self.temp_dir_path / 'root.json',
            roles.file_path(role_name='root'),
        )
        self.assertEqual(
            self.temp_dir_path / 'targets.json',
            roles.file_path(role_name='targets', version=1),
        )

    def test_file_exists(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        (self.temp_dir_path / '1.root.json').touch()
        # test
        self.assertTrue(roles.file_exists(role_name='root'))
        self.assertFalse(roles.file_exists(role_name='targets'))

    def test_persist_role(self):
        # prepare
        roles = Roles(dir_path=self.temp_dir_path)
        roles.root = Metadata(signed=DUMMY_ROOT, signatures=dict())
        expected_filename = f'{DUMMY_ROOT.version}.root.json'
        # test
        roles.persist_role(role_name='root')
        self.assertTrue((self.temp_dir_path / expected_filename).exists())

    def test_publish_root(self):
        def mock_publish_metadata(roles_, **kwargs):
            roles_.file_path(
                role_name='root', version=roles_.root.signed.version
            ).touch()

        with patch.object(Roles, '_publish_metadata', mock_publish_metadata):
            # prepare
            roles = Roles(dir_path=self.temp_dir_path)
            roles.root = Mock(signed=Mock(version=1))
            roles.encrypted = []
            roles.root_modified = True
            # test
            roles.publish_root(private_key_paths=[], expires=in_(0))
            self.assertEqual(1, roles.root.signed.version)
            self.assertFalse(roles.root_modified)
            self.assertTrue(roles.file_path(role_name='root', version=1).exists())
            # ensure version is incremented if file exists
            roles.root_modified = True
            roles.publish_root(private_key_paths=[], expires=in_(0))
            self.assertEqual(2, roles.root.signed.version)
            self.assertTrue(roles.file_path(role_name='root', version=2).exists())
            # ensure a copy of the latest version exists, without version in
            # the filename, to be used as trusted root metadata for the
            # client distribution
            self.assertTrue(roles.file_path(role_name='root').exists())

    def test_publish_targets(self):
        with patch.object(Roles, '_publish_metadata', Mock()):
            # prepare
            roles = Roles(dir_path=self.temp_dir_path)
            roles.targets = Mock(signed=Mock(version=1))
            roles.snapshot = Mock(
                # note no version in filename
                signed=Mock(meta={'targets.json': Mock(version=1)}, version=1)
            )
            roles.timestamp = Mock(
                signed=Mock(snapshot_meta=Mock(version=1), version=1)
            )
            roles.encrypted = []
            roles.targets_modified = True
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
                all(getattr(roles, n).signed.version == 1 for n in role_names)
            )
            self.assertTrue(Roles._publish_metadata.called)  # noqa
            self.assertFalse(roles.targets_modified)
            # test version increment
            roles.targets_modified = True
            for role_name in role_names:
                roles.file_path(role_name=role_name, version=1).touch()
            roles.publish_targets(
                private_key_paths=private_key_paths, expires=expires
            )
            self.assertTrue(
                all(getattr(roles, n).signed.version == 2 for n in role_names)
            )

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

    def test_replace_root_key(self):
        role_name = 'root'
        # prepare
        keys_dir = self.temp_dir_path / 'keystore'
        keys_dir.mkdir()
        keys = Keys(dir_path=keys_dir, encrypted=None)
        keys.create()
        old_private_key_path = keys.private_key_path(key_name=role_name)
        roles = Roles(dir_path=self.temp_dir_path)
        roles.initialize(keys=keys)
        old_root_version = roles.root.signed.version
        roles.file_path(role_name='root', version=old_root_version).touch()
        # create new key pair to replace old one
        new_private_key_path = keys_dir / 'new_key'
        new_public_key_path = Keys.create_key_pair(
            private_key_path=new_private_key_path, encrypted=False
        )
        # test
        old_key_id = roles.root.signed.roles[role_name].keyids[0]
        roles.replace_key(
            old_key_id=old_key_id,
            old_private_key_path=old_private_key_path,
            new_private_key_path=new_private_key_path,
            new_public_key_path=new_public_key_path,
            root_expires=in_(365),
        )
        self.assertNotIn(old_key_id, roles.root.signed.roles[role_name].keyids)
        # root version must be incremented
        self.assertEqual(old_root_version + 1, roles.root.signed.version)
        # root should be signed using both the old key and the new key
        self.assertEqual(2, len(roles.root.signatures))

    def test_get_latest_archive(self):
        roles = Roles(dir_path=TEST_REPO_DIR / 'metadata')
        expected_filename = 'example_app-4.0a0.tar.gz'
        latest_archive = roles.get_latest_archive()
        self.assertEqual(expected_filename, latest_archive.path.name)

    def test_get_latest_archive_empty(self):
        roles = Roles(dir_path=self.temp_dir_path)
        self.assertIsNone(roles.get_latest_archive())

