import gzip
import hashlib
import logging
import pathlib
import re
from typing import Dict, get_type_hints, Optional, TypedDict, Union

import bsdiff4
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

KEY_REQUIRED = 'required'  # unlikely to be identical to user-specified key
SUFFIX_ARCHIVE = '.tar.gz'
SUFFIX_PATCH = '.patch'


class CustomMetadataDict(TypedDict):
    """
    explicitly separate custom metadata into user-specified metadata and metadata
    used by tufup internally
    """

    user: dict
    tufup: dict


def _immutable(value):
    """
    Make value immutable, recursively, so the result is hashable.

    Applies to (nested) dict, list, set, and bytearray [1] mutable sequence types.
    Everything else is passed through unaltered, so the more exotic mutable types are
    not supported.

    [1]: https://peps.python.org/pep-3137/
    """
    # recursive cases
    if isinstance(value, dict):
        return tuple((k, _immutable(v)) for k, v in value.items())
    elif isinstance(value, list):
        return tuple(_immutable(v) for v in value)
    elif isinstance(value, set):
        return frozenset(_immutable(v) for v in value)
    elif isinstance(value, bytearray):
        return bytes(value)
    # base case
    return value


class TargetMeta(object):
    filename_pattern = '{name}-{version}{suffix}'
    filename_regex = re.compile(
        r'^(?P<name>[\w-]+)-(?P<version>.+)(?P<suffix>\.tar\.gz|\.patch)$'
    )

    def __init__(
        self,
        target_path: Union[None, str, pathlib.Path] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
        is_archive: Optional[bool] = True,
        custom: Optional[CustomMetadataDict] = None,
    ):
        """
        Initialize either with target_path, or with name, version, archive.

        BEWARE: whitespace is not allowed in the filename,
        nor in the `name` or `version` arguments
        """
        super().__init__()
        if target_path is None:
            target_path = TargetMeta.compose_filename(
                name=name, version=version, is_archive=is_archive
            )
        self.target_path_str = str(target_path)  # keep the original for reference
        self.path = pathlib.Path(target_path)
        if ' ' in self.filename:
            logger.critical(
                f'invalid filename "{self.filename}": whitespace not allowed'
            )
        self._custom = custom or dict(user=dict(), tufup=dict())

    @property
    def custom(self) -> dict:
        """returns user-specified custom metadata dict"""
        return self._get_custom_metadata('user')

    @property
    def custom_internal(self) -> dict:
        """returns tufup-internal custom metadata dict"""
        return self._get_custom_metadata('tufup')

    def _get_custom_metadata(self, _key: str) -> dict:
        """
        get custom metadata in a backward-compatible manner (older versions did not
        distinguish between user-specified and internal metadata)
        """
        if isinstance(self._custom, dict):
            # check dict keys for backward compatibility
            if get_type_hints(CustomMetadataDict).keys() != self._custom.keys():
                return self._custom
            return self._custom.get(_key)
        return dict()

    def __str__(self):
        return str(self.target_path_str)

    def __repr__(self):
        return f'{self.__class__.__name__}(target_path="{self.target_path_str}")'

    def __hash__(self):
        """
        This makes the object hashable, so it can be used as dict key or set
        member.

        https://docs.python.org/3/glossary.html#term-hashable

        """
        return hash(_immutable(self.__dict__))

    def __eq__(self, other):
        if type(other) is not type(self):
            return NotImplemented
        return vars(self) == vars(other)

    def __lt__(self, other):
        """
        This makes the object sortable, based on the *version* property,
        without having to specify an explicit sorting key. Note this
        disregards app name, platform, and suffixes.
        """
        if type(other) is not type(self):
            return NotImplemented
        return self.version < other.version

    @property
    def filename(self):
        return self.path.name

    @property
    def name(self) -> Optional[str]:
        """The app name."""
        match_dict = self.parse_filename(self.filename)
        return match_dict.get('name')

    @property
    def version(self) -> Optional[Version]:
        match_dict = self.parse_filename(self.filename)
        try:
            version = Version(match_dict.get('version', ''))
        except InvalidVersion:
            version = None
            logger.critical(f'No valid version in filename: {self.filename}')
        return version

    @property
    def suffix(self) -> Optional[str]:
        """Returns the filename suffix, either '.tar.gz', '.patch', or None."""
        match_dict = self.parse_filename(self.filename)
        return match_dict.get('suffix')

    @property
    def is_archive(self) -> bool:
        return self.suffix == SUFFIX_ARCHIVE

    @property
    def is_patch(self) -> bool:
        return self.suffix == SUFFIX_PATCH

    @property
    def is_other(self) -> bool:
        return self.suffix not in [SUFFIX_ARCHIVE, SUFFIX_PATCH]

    @classmethod
    def parse_filename(cls, filename: str) -> dict:
        """
        Parse a filename to extract app name, version, and suffix.

        We do not impose any versioning requirements yet, such as defined in
        packaging.version.VERSION_PATTERN.
        """
        match = cls.filename_regex.search(string=filename)
        return match.groupdict() if match else {}

    @classmethod
    def compose_filename(cls, name: str, version: str, is_archive: bool):
        suffix = SUFFIX_ARCHIVE if is_archive else SUFFIX_PATCH
        return cls.filename_pattern.format(name=name, version=version, suffix=suffix)


class Patcher(object):
    DEFAULT_HASH_ALGORITHM = 'sha256'

    @staticmethod
    def _get_tar_size_and_hash(
        tar_content: Optional[bytes] = None, algorithm: str = DEFAULT_HASH_ALGORITHM
    ) -> dict:
        """
        Determines the size and hash of the specified data.

        Note we could also use tuf.api.metadata.TargetFile for this, but that we'll
        keep this part independent from python-tuf, for clarity and flexibility.
        """
        hash_obj = getattr(hashlib, algorithm)()
        hash_obj.update(tar_content)
        # hexdigest returns digest as string
        return dict(
            tar_size=len(tar_content),
            tar_hash=hash_obj.hexdigest(),
            tar_hash_algorithm=algorithm,
        )

    @classmethod
    def _verify_tar_size_and_hash(cls, tar_content: bytes, expected: dict):
        """
        Verifies that size and hash of data match the expected values.

        Raises an exception if this is not the case.
        """
        result = cls._get_tar_size_and_hash(
            tar_content=tar_content, algorithm=expected['tar_hash_algorithm']
        )
        for key in ['tar_size', 'tar_hash']:
            if result[key] != expected[key]:
                raise Exception(f'verification failed: {key} mismatch')

    @classmethod
    def diff_and_hash(
        cls, src_path: pathlib.Path, dst_path: pathlib.Path, patch_path: pathlib.Path
    ) -> dict:
        """
        Creates a patch file from the binary difference between source and destination
        .tar archives. The source and destination files are expected to be
        gzip-compressed tar archives (.tar.gz).

        Returns a dict with size and hash of the *uncompressed* destination archive.
        """
        with gzip.open(src_path, mode='rb') as src_file:
            with gzip.open(dst_path, mode='rb') as dst_file:
                dst_tar_content = dst_file.read()
                patch_path.write_bytes(
                    bsdiff4.diff(src_bytes=src_file.read(), dst_bytes=dst_tar_content)
                )
        return cls._get_tar_size_and_hash(tar_content=dst_tar_content)

    @classmethod
    def patch_and_verify(
        cls,
        src_path: pathlib.Path,
        dst_path: pathlib.Path,
        patch_targets: Dict[TargetMeta, pathlib.Path],
    ) -> None:
        """
        Applies one or more binary patch files to a source file in order to
        reconstruct a destination file.

        Source file and destination file are gzip-compressed tar archives, but the
        patches are applied to the *uncompressed* tar archives. The reason is that
        small changes in uncompressed data can cause (very) large differences in
        gzip compressed data, leading to excessively large patch files (see #69).

        The integrity of the patched .tar archive is verified using expected length
        and hash (from custom tuf metadata), similar to python-tuf's download
        verification. If the patched archive fails this check, the destination file
        is not written.
        """
        if not patch_targets:
            raise ValueError('no patch targets')
        # decompress .tar data from source .tar.gz file
        with gzip.open(src_path, mode='rb') as src_file:
            tar_bytes = src_file.read()
        # apply cumulative patches (sorted by version, in ascending order)
        for patch_meta, patch_path in sorted(patch_targets.items()):
            logger.info(f'applying patch: {patch_meta.name}')
            tar_bytes = bsdiff4.patch(
                src_bytes=tar_bytes, patch_bytes=patch_path.read_bytes()
            )
        # verify integrity of the final result (raises exception on failure)
        cls._verify_tar_size_and_hash(
            tar_content=tar_bytes,
            expected=patch_meta.custom_internal,  # noqa
        )
        # compress .tar data into destination .tar.gz file
        with gzip.open(dst_path, mode='wb') as dst_file:
            dst_file.write(tar_bytes)
