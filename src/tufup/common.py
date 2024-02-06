import logging
import pathlib
import re
from typing import Optional, Union

import bsdiff4
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

SUFFIX_ARCHIVE = '.tar.gz'
SUFFIX_PATCH = '.patch'


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
        custom: Optional[dict] = None,
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
        self.custom = custom

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
    @classmethod
    def create_patch(
        cls, src_path: pathlib.Path, dst_path: pathlib.Path
    ) -> pathlib.Path:
        """
        Create a binary patch file based on source and destination files.

        Patch file path matches destination file path, except for suffix.
        """
        # replace suffix twice, in case we have a .tar.gz
        patch_path = dst_path.with_suffix('').with_suffix(SUFFIX_PATCH)
        bsdiff4.file_diff(src_path=src_path, dst_path=dst_path, patch_path=patch_path)
        return patch_path

    @classmethod
    def apply_patch(cls, src_path: pathlib.Path, patch_path: pathlib.Path):
        """
        Apply binary patch file to source file to create destination file.

        Destination file path matches patch file path, except for suffix.
        """
        dst_path = patch_path.with_suffix(SUFFIX_ARCHIVE)
        bsdiff4.file_patch(src_path=src_path, dst_path=dst_path, patch_path=patch_path)
        return dst_path
