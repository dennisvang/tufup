import copy
from datetime import date, datetime, timedelta
import json
import logging
import pathlib
from tempfile import TemporaryDirectory
from time import sleep
from unittest.mock import Mock, patch

from securesystemslib.interface import (
    generate_and_write_unencrypted_ed25519_keypair,
    generate_and_write_ed25519_keypair,
    import_ed25519_publickey_from_file,
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

from tests import TempDirTestCase, TEST_REPO_DIR
from tufup.common import TargetMeta
import tufup.repo  # for patching
from tufup.repo import (
    Base, in_, Keys, make_gztar_archive, Repository, Roles, SUFFIX_PUB
)


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
DUMMY_EXPIRATION_DAYS = dict(root=1000, targets=100, snapshot=10, timestamp=1)
DUMMY_PRIVATE_KEY_PATHS = dict(
    (role_name, [pathlib.Path('dummy', role_name)])
    for role_name in TOP_LEVEL_ROLE_NAMES
)
DUMMY_KEY_MAP = dict(
    root=['root_one', 'root_two'],
    targets=['targets'],
    snapshot=['snapshot'],
    timestamp=['timestamp'],
)
DUMMY_THRESHOLDS = dict(root=4, targets=3, snapshot=2, timestamp=1)


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
            self.assertFalse(getattr(keys, role_name))

    def test_init_and_import_all_public_keys(self):
        # create some key files
        for role_name in TOP_LEVEL_ROLE_NAMES:
            private_key_filename = Keys.filename_pattern.format(key_name=role_name)
            file_path = self.temp_dir_path / private_key_filename
            generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        # test
        keys = Keys(dir_path=self.temp_dir_path)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name)[0], dict)

    def test_init_and_import_all_public_keys_with_key_map(self):
        # create a single key-pair
        key_name = 'single'
        private_key_filename = Keys.filename_pattern.format(key_name=key_name)
        file_path = self.temp_dir_path / private_key_filename
        generate_and_write_unencrypted_ed25519_keypair(filepath=str(file_path))
        key_map = {role_name: [key_name] for role_name in TOP_LEVEL_ROLE_NAMES}
        # test
        keys = Keys(dir_path=self.temp_dir_path, key_map=key_map)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name)[0], dict)
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
            self.assertFalse(getattr(keys, role_name))
        keys.import_all_public_keys()
        for role_name in TOP_LEVEL_ROLE_NAMES:
            self.assertIsInstance(getattr(keys, role_name)[0], dict)

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
        keys = Keys(dir_path=self.temp_dir_path, key_map=DUMMY_KEY_MAP)
        expected_key_names = [
            key_name
            for key_names in DUMMY_KEY_MAP.values()
            for key_name in key_names
        ]
        # test
        keys.create()
        # we should now have five key-pairs (one for each, but two for root)
        filenames = [item.name for item in keys.dir_path.iterdir()]
        self.assertEqual(2*len(expected_key_names), len(filenames))
        for key_name in expected_key_names:
            self.assertIn(key_name, filenames)
            self.assertIn(key_name + SUFFIX_PUB, filenames)
        # and the public keys should have been imported
        for role_name, key_names in DUMMY_KEY_MAP.items():
            self.assertEqual(len(key_names), len(getattr(keys, role_name)))

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
        keys.root = [DUMMY_SSL_KEY]
        # test
        self.assertIn(DUMMY_SSL_KEY['keyid'], keys.public().keys())

    def test_roles(self):
        keys = Keys(dir_path=self.temp_dir_path)
        # test empty
        self.assertSetEqual(set(TOP_LEVEL_ROLE_NAMES), set(keys.roles().keys()))
        # set a dummy key value
        keys.root = [DUMMY_SSL_KEY]
        # test
        self.assertIn('root', keys.roles().keys())

    def test_roles_thresholds(self):
        # prepare
        keys = Keys(dir_path=self.temp_dir_path, thresholds=DUMMY_THRESHOLDS)
        for role_name in TOP_LEVEL_ROLE_NAMES:
            setattr(keys, role_name, [DUMMY_SSL_KEY])
        # test
        roles = keys.roles()
        for key, value in roles.items():
            self.assertEqual(DUMMY_THRESHOLDS[key], value.threshold)

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
        with patch.object(tufup.repo.Metadata, 'from_file', mock_from_file):
            roles = Roles(dir_path=self.temp_dir_path)
            for role_name in TOP_LEVEL_ROLE_NAMES:
                self.assertEqual(role_name, getattr(roles, role_name))

    def test_initialize_empty(self):
        # prepare
        mock_keys = Mock()
        mock_keys.public = Mock()
        mock_keys.roles = Mock(
            return_value={name: None for name in TOP_LEVEL_ROLE_NAMES}
        )
        roles = Roles(dir_path=self.temp_dir_path)
        # test
        roles.initialize(keys=mock_keys)
        self.assertTrue(
            all(
                isinstance(getattr(roles, n), Metadata)
                for n in TOP_LEVEL_ROLE_NAMES
            )
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
        original_targets_signed = copy.deepcopy(roles.targets.signed)
        # test
        self.assertTrue(local_target_path.exists())
        roles.remove_target(local_path=local_target_path)
        self.assertNotIn(filename, roles.targets.signed.targets)
        self.assertFalse(local_target_path.exists())
        self.assertNotEqual(original_targets_signed, roles.targets.signed)
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
                    role_name=role_name, private_key_path=private_key_path
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
        expected_filenames = [f'{DUMMY_ROOT.version}.root.json', 'root.json']
        # test
        roles.persist_role(role_name='root')
        for filename in expected_filenames:
            with self.subTest(msg=filename):
                self.assertTrue((self.temp_dir_path / filename).exists())

    def test_get_latest_archive(self):
        roles = Roles(dir_path=TEST_REPO_DIR / 'metadata')
        expected_filename = 'example_app-4.0a0.tar.gz'
        latest_archive = roles.get_latest_archive()
        self.assertEqual(expected_filename, latest_archive.path.name)

    def test_get_latest_archive_empty(self):
        roles = Roles(dir_path=self.temp_dir_path)
        self.assertIsNone(roles.get_latest_archive())


class RepositoryTests(TempDirTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG)

    def test_defaults(self):
        self.assertTrue(Repository(app_name='test'))

    def test_config_dict(self):
        app_name = 'test'
        repo = Repository(app_name=app_name)
        expected_config_dict = {
            'app_name': app_name,
            'app_version_attr': None,
            'encrypted_keys': None,
            'expiration_days': None,
            'key_map': None,
            'keys_dir': None,
            'repo_dir': None,
            'thresholds': None,
        }
        self.assertEqual(set(expected_config_dict), set(repo.config_dict))

    def test_app_version(self):
        # for convenience we use the notosotuf version attribute here,
        # but normally this would point to an external app version e.g.
        # 'my_app.__version__'
        app_version_attr = 'tufup.__version__'
        repo = Repository(app_name='test', app_version_attr=app_version_attr)
        self.assertEqual(str(tufup.__version__), repo.app_version)

    def test_get_config_file_path(self):
        self.assertTrue(Repository.get_config_file_path())

    def test_save_config(self):
        # prepare
        repo = Repository(app_name='test')
        # test
        repo.save_config()
        self.assertTrue(repo.get_config_file_path().exists())
        print(repo.get_config_file_path().read_text())

    def test_load_config(self):
        # file does not exist
        self.assertEqual(dict(), Repository.load_config())
        # file exists but invalid
        Repository.get_config_file_path().touch()
        # test
        self.assertEqual(dict(), Repository.load_config())

    def test_from_config(self):
        temp_dir = self.temp_dir_path.resolve()
        # prepare
        config_data = dict(
            app_name='test',
            app_version_attr='my_app.__version__',
            repo_dir=temp_dir / 'repo',
            keys_dir=temp_dir / 'keystore',
            key_map=dict(),
            encrypted_keys=[],
            expiration_days=dict(),
            thresholds=dict(),
        )
        Repository.get_config_file_path().write_text(
            json.dumps(config_data, default=str)
        )
        mock_load_keys_and_roles = Mock()
        # test
        with patch.object(
                Repository, '_load_keys_and_roles', mock_load_keys_and_roles,
        ):
            repo = Repository.from_config()
        self.assertEqual(
            config_data,
            {item: getattr(repo, item) for item in config_data.keys()},
        )
        self.assertTrue(mock_load_keys_and_roles.called)

    def test_initialize(self):
        # prepare
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
            expiration_days=DUMMY_EXPIRATION_DAYS,
        )
        # test
        repo.initialize()
        self.assertTrue(any(repo.keys_dir.iterdir()))
        self.assertTrue(any(repo.metadata_dir.iterdir()))
        self.assertTrue(
            all(getattr(repo.roles, name) for name in TOP_LEVEL_ROLE_NAMES)
        )
        self.assertEqual(
            date.today() + timedelta(days=DUMMY_EXPIRATION_DAYS['root']),
            repo.roles.root.signed.expires.date(),
        )

    def test_refresh_expiration_date(self):
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        repo.initialize()  # todo: make test independent...
        days = 999
        repo.refresh_expiration_date(role_name='root', days=days)
        self.assertEqual(
            date.today() + timedelta(days=days),
            repo.roles.root.signed.expires.date(),
        )

    def test_replace_key(self):
        role_name = 'root'
        # prepare
        new_key_name = 'new_key'
        old_key_name = 'old-key'
        key_map = {name: [name] for name in TOP_LEVEL_ROLE_NAMES}
        key_map['root'].append(old_key_name)
        key_map['targets'] = [old_key_name]
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
            key_map=key_map,
        )
        repo.initialize()  # todo: make test independent...
        old_key_id = repo.roles.root.signed.roles['targets'].keyids[0]
        # create new key pair to replace old one
        new_private_key_path = repo.keys_dir / new_key_name
        new_public_key_path = Keys.create_key_pair(
            private_key_path=new_private_key_path, encrypted=False
        )
        new_key_id = import_ed25519_publickey_from_file(
            filepath=str(new_public_key_path)
        )['keyid']
        # test
        expected_key_count = len(key_map[role_name])
        repo.replace_key(
            old_key_name=old_key_name,
            new_public_key_path=new_public_key_path,
            new_private_key_encrypted=True,  # pretend the key is encrypted
        )
        self.assertEqual(
            expected_key_count,
            len(repo.roles.root.signed.roles[role_name].keyids),
        )
        # old key removed?
        self.assertNotIn(
            old_key_id, repo.roles.root.signed.roles[role_name].keyids
        )
        self.assertNotIn(old_key_name, repo.key_map[role_name])
        self.assertIn(old_key_name, repo.revoked_key_names)
        # new key added?
        self.assertIn(
            new_key_id, repo.roles.root.signed.roles[role_name].keyids
        )
        self.assertIn(new_key_name, repo.key_map[role_name])
        self.assertIn(new_key_name, repo.encrypted_keys)
        # no duplicates in encrypted_keys?
        self.assertEqual(1, len(repo.encrypted_keys))
        # other keys still in key map?
        self.assertEqual(expected_key_count, len(repo.key_map[role_name]))
        # keys replaced for all roles?
        self.assertIn(new_key_name, repo.key_map['targets'])

    def test_add_key(self):
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        repo.initialize()  # todo: make test independent...
        # create new key pair to add
        new_key_name = 'new-key'
        new_private_key_path = repo.keys_dir / new_key_name
        new_public_key_path = Keys.create_key_pair(
            private_key_path=new_private_key_path, encrypted=False
        )
        new_key_id = import_ed25519_publickey_from_file(
            filepath=str(new_public_key_path)
        )['keyid']
        # test
        role_name = 'root'
        repo.add_key(
            role_name=role_name,
            public_key_path=new_public_key_path,
            encrypted=True,  # pretend the key is encrypted
        )
        # new key added?
        self.assertEqual(2, len(repo.roles.root.signed.roles[role_name].keyids))
        self.assertIn(
            new_key_id, repo.roles.root.signed.roles[role_name].keyids
        )
        self.assertIn(new_key_name, repo.key_map[role_name])
        self.assertIn(new_key_name, repo.encrypted_keys)

    def test_add_bundle(self):
        # prepare
        bundle_dir = self.temp_dir_path / 'dist' / 'test_app'
        bundle_dir.mkdir(parents=True)
        bundle_file = bundle_dir / 'dummy.exe'
        bundle_file.touch()
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        repo.initialize()  # todo: make test independent...
        # test
        repo.add_bundle(new_version='1.0', new_bundle_dir=bundle_dir)
        self.assertTrue((repo.metadata_dir / 'targets.json').exists())

    def test_remove_latest_bundle(self):
        # prepare
        bundle_dir = self.temp_dir_path / 'dist' / 'test_app'
        bundle_dir.mkdir(parents=True)
        bundle_file = bundle_dir / 'dummy.exe'
        bundle_file.touch()
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        repo.initialize()  # todo: make test independent...
        v1 = '1.0'
        v2 = '2.0'
        repo.add_bundle(new_version=v1, new_bundle_dir=bundle_dir)
        repo.add_bundle(new_version=v2, new_bundle_dir=bundle_dir)
        # test
        repo.remove_latest_bundle()
        remaining_target_keys = list(repo.roles.targets.signed.targets.keys())
        self.assertEqual(1, len(remaining_target_keys))
        self.assertIn(v1, remaining_target_keys[0])
        remaining_target_filenames = [p.name for p in repo.targets_dir.iterdir()]
        self.assertEqual(1, len(remaining_target_filenames))
        self.assertIn(remaining_target_keys[0], remaining_target_filenames)

    def test_threshold_sign(self):
        # prepare
        role_name = 'root'
        keys_dir = self.temp_dir_path / 'keystore'
        repo = Repository(
            app_name='test',
            keys_dir=keys_dir,
            repo_dir=self.temp_dir_path / 'repo',
        )
        repo.initialize()  # todo: make test independent...
        # create dummy "revoked key" and pretend it is encrypted
        revoked_key_name = 'revoked'
        repo.keys.create_key_pair(
            private_key_path=keys_dir / revoked_key_name, encrypted=False
        )
        repo.revoked_key_names.append(revoked_key_name)
        repo.encrypted_keys.append(revoked_key_name)
        # dummy modification
        repo.roles.root.signed.spec_version = 'x'
        versioned_file_path = repo.metadata_dir / f'1.{role_name}.json'
        non_versioned_file_path = repo.metadata_dir / f'{role_name}.json'
        versioned_last_modified = versioned_file_path.stat().st_mtime_ns
        non_versioned_last_modified = non_versioned_file_path.stat().st_mtime_ns
        # test
        sleep(0.1)  # enforce different modification time
        count = repo.threshold_sign(
            role_name=role_name, private_key_dirs=[repo.keys_dir]
        )
        self.assertEqual(2, count)  # existing key and revoked key
        self.assertFalse(repo.revoked_key_names)
        self.assertFalse(repo.encrypted_keys)
        # files should have been modified
        self.assertGreater(
            versioned_file_path.stat().st_mtime_ns, versioned_last_modified
        )
        self.assertGreater(
            non_versioned_file_path.stat().st_mtime_ns, non_versioned_last_modified
        )
        # if no signatures found
        for path in repo.keys_dir.iterdir():
            path.unlink()
        with self.assertRaises(Exception):
            repo.threshold_sign(
                role_name=role_name, private_key_dirs=[repo.keys_dir]
            )

    def test__load_keys_and_roles(self):
        # prepare
        keys_dir = self.temp_dir_path / 'keystore'
        repo = Repository(
            app_name='test',
            keys_dir=keys_dir,
            repo_dir=self.temp_dir_path / 'repo',
        )
        # test
        with patch('builtins.input', Mock(return_value='y')):
            repo._load_keys_and_roles(create_keys=True)
        self.assertTrue(
            all(getattr(repo.roles, name) for name in TOP_LEVEL_ROLE_NAMES)
        )
        self.assertTrue(
            all((keys_dir / name).exists() for name in TOP_LEVEL_ROLE_NAMES)
        )

    def test_publish_changes_no_change(self):
        # prepare
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        # note that initialize() already calls publish_changes...
        repo.initialize()  # todo: make test independent...
        # test
        repo.publish_changes(private_key_dirs=[repo.keys_dir])
        for role_name in ['root', 'targets', 'snapshot', 'timestamp']:
            role = getattr(repo.roles, role_name)
            with self.subTest(msg=role_name):
                self.assertEqual(1, role.signed.version)
                self.assertTrue(role.signatures)

    def test_publish_changes_threshold(self):
        # prepare
        repo = Repository(
            app_name='test',
            keys_dir=self.temp_dir_path / 'keystore',
            repo_dir=self.temp_dir_path / 'repo',
        )
        # note that initialize() already calls publish_changes...
        repo.initialize()  # todo: make test independent...
        # remove the root signature
        repo.roles.root.signatures = {}
        # test
        repo.publish_changes(private_key_dirs=[repo.keys_dir])
        for role_name in ['root', 'targets', 'snapshot', 'timestamp']:
            with self.subTest(msg=role_name):
                role = getattr(repo.roles, role_name)
                self.assertEqual(
                    repo.thresholds[role_name], len(role.signatures)
                )

    def test_publish_changes(self):
        days = 999
        role_names = ['root', 'targets', 'snapshot', 'timestamp']
        for test_role_name in role_names.copy():
            # use a fresh temporary dir and repo
            with TemporaryDirectory() as temp_dir:
                temp_dir_path = pathlib.Path(temp_dir)
                repo = Repository(
                    app_name='test',
                    keys_dir=temp_dir_path / 'keystore',
                    repo_dir=temp_dir_path / 'repo',
                )
                # note that initialize() already calls publish_changes...
                repo.initialize()  # todo: make test independent...
                # make a change to metadata (in memory)
                repo.roles.set_expiration_date(
                    role_name=test_role_name, days=days
                )
                # make a change to config
                config_change = 'dummy'
                repo.encrypted_keys.append(config_change)
                # test
                repo.publish_changes(private_key_dirs=[repo.keys_dir])
                for role_name in role_names:
                    role = getattr(repo.roles, role_name)
                    with self.subTest(msg=f'{test_role_name}: {role_name}'):
                        self.assertEqual(2, role.signed.version)
                        self.assertTrue(role.signatures)
                role_names.remove(test_role_name)
                #  re-load from file to verify change
                root = Metadata.from_file(
                    repo.roles.file_path(role_name=test_role_name)
                )
                self.assertEqual(
                    date.today() + timedelta(days=days),
                    root.signed.expires.date(),
                )
                # verify change in config
                config_from_disk = repo.load_config()
                self.assertIn(
                    config_change, config_from_disk['encrypted_keys']
                )
