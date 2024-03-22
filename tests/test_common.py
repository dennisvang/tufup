import gzip
import hashlib
import logging
import pathlib
from typing import Hashable
from unittest import TestCase

import bsdiff4
from packaging.version import Version

from tests import TempDirTestCase
from tufup.common import _immutable, Patcher, TargetMeta  # noqa


class ImmutableTests(TestCase):
    def test_immutable(self):
        cases = [
            'a',
            b'b',
            1,
            ('a', 1),
            ['a', 1],
            {'a', 1},
            bytearray(b'b'),
            dict(a=1),
            [dict(a=[dict(c={1})], b=bytearray(b'd'))],
            dict(a=dict(b=dict(c=dict()))),
        ]
        for case in cases:
            with self.subTest(msg=case):
                self.assertIsInstance(_immutable(case), Hashable)


class TargetMetaTests(TempDirTestCase):
    def test_init_whitespace(self):
        for kwargs in [
            dict(target_path='w h i t e s p a c e-1.2.3.tar.gz'),
            dict(name='w h i t e s p a c e'),
        ]:
            with self.subTest(msg=kwargs):
                with self.assertLogs(level=logging.CRITICAL):
                    TargetMeta(**kwargs)

    def test_eq_ne(self):
        target_meta = TargetMeta()
        self.assertEqual(target_meta, TargetMeta())
        self.assertNotEqual(target_meta, TargetMeta(target_path='something'))
        # two ways to initialize a TargetMeta instance:
        self.assertEqual(
            TargetMeta(target_path='my-app-1.2.3a0.patch'),
            TargetMeta(name='my-app', version='1.2.3a0', is_archive=False),
        )

    def test_repr(self):
        # https://docs.python.org/3/reference/datamodel.html#object.__repr__
        target_meta = TargetMeta(target_path='some.file')
        # the input to eval is known and trusted, so that should be safe, right?
        self.assertEqual(eval(repr(target_meta)), target_meta)

    def test_str(self):
        # see issue #3
        for target_path in ['str_path', pathlib.Path('pathlib_path')]:
            with self.subTest(msg=target_path):
                self.assertIsInstance(
                    TargetMeta(target_path=target_path).__str__(), str
                )

    def test_hashable(self):
        obj = TargetMeta()
        try:
            obj.__hash__()
        except Exception as e:
            self.fail(f'__hash__ failed unexpectedly: {e}')
        expected_obj_hashable = (
            ('target_path_str', 'None-None.tar.gz'),
            ('path', pathlib.Path('None-None.tar.gz')),
            ('_custom', (('user', ()), ('tufup', ()))),
        )
        self.assertEqual(hash(expected_obj_hashable), obj.__hash__())
        # we can use the obj as a set member or as dict key
        self.assertEqual({obj, obj}, {obj})

    def test_sortable(self):
        version_1 = TargetMeta(target_path='my-app-win-1.0.tar.gz')
        version_2 = TargetMeta(target_path='my-app-win-2.0.tar.gz')
        info_list = [version_2, version_1]
        self.assertEqual([version_1, version_2], sorted(info_list))

    def test_filename(self):
        target_path = 'url/path/somefile'
        target_meta = TargetMeta(target_path=target_path)
        self.assertEqual('somefile', target_meta.filename)

    def test_name(self):
        target_meta = TargetMeta(target_path='url/path/my-app-1.0.tar.gz')
        self.assertEqual('my-app', target_meta.name)

    def test_version(self):
        for version_str in ['1.2.3a4', '']:
            expected = Version(version_str) if version_str else None
            with self.subTest(msg=version_str):
                target_meta = TargetMeta(target_path=f'x-{version_str}.tar.gz')
                self.assertEqual(expected, target_meta.version)

    def test_suffix(self):
        valid_suffixes = ['.tar.gz', '.patch']
        for suffix in ['', '.zip', '.tar.gz', '.patch']:
            with self.subTest(msg=suffix):
                target_meta = TargetMeta(target_path=f'my-app-1.2.3a4{suffix}')
                if suffix in valid_suffixes:
                    self.assertEqual(suffix, target_meta.suffix)
                else:
                    self.assertIsNone(target_meta.suffix)

    def test_is_archive(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.tar.gz').is_archive)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.patch').is_archive)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.zip').is_archive)

    def test_is_patch(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.patch').is_patch)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.tar.gz').is_patch)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.zip').is_patch)

    def test_is_other(self):
        self.assertTrue(TargetMeta(target_path='my-app-1.0.zip').is_other)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.patch').is_other)
        self.assertFalse(TargetMeta(target_path='my-app-1.0.tar.gz').is_other)

    def test_parse_filename(self):
        cases = [
            # PEP440 versions are allowed (we do not parse them here...)
            ('app-1.patch', ('app', '1', '.patch')),
            ('app-1.tar.gz', ('app', '1', '.tar.gz')),
            ('app-1.2.tar.gz', ('app', '1.2', '.tar.gz')),
            ('app-1.2.3.tar.gz', ('app', '1.2.3', '.tar.gz')),
            ('app-1a.tar.gz', ('app', '1a', '.tar.gz')),
            ('app-1b.tar.gz', ('app', '1b', '.tar.gz')),
            ('app-1rc.tar.gz', ('app', '1rc', '.tar.gz')),
            ('app-1rc0.tar.gz', ('app', '1rc0', '.tar.gz')),
            ('app-2022.0.tar.gz', ('app', '2022.0', '.tar.gz')),
            # we don't impose a specific version format at this point (that
            # is deferred to packaging.Version)
            ('app-invalidversion.tar.gz', ('app', 'invalidversion', '.tar.gz')),
            # underscores, dashes, capitals, etc.
            ('app-name---1.tar.gz', ('app-name--', '1', '.tar.gz')),
            ('CAPS-1.tar.gz', ('CAPS', '1', '.tar.gz')),
            ('un_der_scores-1.0.tar.gz', ('un_der_scores', '1.0', '.tar.gz')),
            # invalid filenames
            ('sp ac es-1.zip', ()),
            ('app-1.gz', ()),
            ('app-1.xz', ()),
            ('anything', ()),
        ]
        for filename, expected in cases:
            match_dict = TargetMeta.parse_filename(filename=filename)
            with self.subTest(msg=filename):
                self.assertEqual(expected, tuple(match_dict.values()))

    def test_compose_filename(self):
        filename = TargetMeta.compose_filename(
            name='app', version='1.0', is_archive=True
        )
        self.assertEqual('app-1.0.tar.gz', filename)

    def test_custom_metadata(self):
        user_metadata = dict(foo='bar')
        internal_metadata = dict(something=True)
        target_meta = TargetMeta(
            custom=dict(user=user_metadata, tufup=internal_metadata)
        )
        self.assertEqual(user_metadata, target_meta.custom)
        self.assertEqual(internal_metadata, target_meta.custom_internal)

    def test_custom_metadata_backward_compatibility(self):
        # older versions of tufup did not distinguish between user and internal metadata
        custom_metadata = dict(foo='bar')
        target_meta = TargetMeta(custom=custom_metadata)  # noqa
        self.assertEqual(custom_metadata, target_meta.custom)
        self.assertEqual(custom_metadata, target_meta.custom_internal)

    def test_custom_metadata_not_specified(self):
        target_meta = TargetMeta()
        self.assertIsInstance(target_meta.custom, dict)
        self.assertIsInstance(target_meta.custom_internal, dict)
        # user overrides _custom attr
        target_meta._custom = None
        self.assertIsInstance(target_meta.custom, dict)


class PatcherTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        # define dummy .tar content
        self.tar_content = {
            'v-1': b'this is the original content',
            'v-2': b'this content is somewhat different',
            'v-3': b'this content has changed again',
        }
        # create patch content
        self.patch_content = dict()
        for src, dst in [('v-1', 'v-2'), ('v-2', 'v-3')]:
            self.patch_content[dst] = bsdiff4.diff(
                src_bytes=self.tar_content[src],
                dst_bytes=self.tar_content[dst],
            )
        # create dummy files
        self.targz_paths = dict()
        for key, tar_content in self.tar_content.items():
            self.targz_paths[key] = self.temp_dir_path / f'{key}.tar.gz'
            with gzip.open(self.targz_paths[key], mode='wb') as gz_file:
                gz_file.write(tar_content)
        self.patch_paths = dict()
        for key, patch_content in self.patch_content.items():
            self.patch_paths[key] = self.temp_dir_path / f'{key}.patch'
            self.patch_paths[key].write_bytes(patch_content)
        # determine size and hash
        hash_algorithm = 'sha256'
        self.tar_fingerprints = dict()
        for key, tar_content in self.tar_content.items():
            if key == 'v-1':
                continue
            hash_obj = getattr(hashlib, hash_algorithm)()
            hash_obj.update(tar_content)
            self.tar_fingerprints[key] = dict(
                tar_size=len(tar_content),
                tar_hash=hash_obj.hexdigest(),
                tar_hash_algorithm=hash_algorithm,
            )

    def test_diff_and_hash(self):
        # prepare
        src = 'v-1'
        dst = 'v-2'
        patch_path = self.temp_dir_path / 'test.patch'
        # test
        dst_fingerprint = Patcher.diff_and_hash(
            src_path=self.targz_paths[src],
            dst_path=self.targz_paths[dst],
            patch_path=patch_path,
        )
        self.assertTrue(patch_path.exists())
        self.assertEqual(self.patch_content[dst], patch_path.read_bytes())
        self.assertEqual(self.tar_fingerprints[dst], dst_fingerprint)

    def test_patch_and_verify(self):
        # prepare
        src = 'v-1'
        dst = 'v-3'  # note we're skipping v-2
        patch_targets = dict()
        for key, patch_path in self.patch_paths.items():
            patch_meta = TargetMeta(
                target_path=patch_path, custom=self.tar_fingerprints[key]
            )
            self.assertTrue(patch_meta.is_patch)  # just to be sure
            patch_targets[patch_meta] = patch_path
        # verify that we're applying two patches cumulatively
        self.assertEqual(2, len(patch_targets))
        # test
        dst_path = self.temp_dir_path / 'reconstructed.tar.gz'
        Patcher.patch_and_verify(
            src_path=self.targz_paths[src],
            dst_path=dst_path,
            patch_targets=patch_targets,
        )
        self.assertTrue(dst_path.exists())
        # note that gzip compressed files are not reproducible by default (even when
        # using identical uncompressed data), so we must compare the uncompressed data
        with gzip.open(self.targz_paths[dst], mode='rb') as original_tar:
            with gzip.open(dst_path, mode='rb') as reconstructed_tar:
                self.assertEqual(original_tar.read(), reconstructed_tar.read())
