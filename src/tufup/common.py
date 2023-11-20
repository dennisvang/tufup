import gzip
import logging
import pathlib
import re
import shutil
from tempfile import TemporaryDirectory
from typing import Optional, Union

import bsdiff4
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)

SUFFIX_TAR = '.tar'
SUFFIX_GZIP = '.gz'
SUFFIX_ARCHIVE = SUFFIX_TAR + SUFFIX_GZIP
SUFFIX_PATCH = '.patch'


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
        return hash(tuple(self.__dict__.items()))

    def __eq__(self, other):
        if type(other) != type(self):
            return NotImplemented
        return vars(self) == vars(other)

    def __lt__(self, other):
        """
        This makes the object sortable, based on the *version* property,
        without having to specify an explicit sorting key. Note this
        disregards app name, platform, and suffixes.
        """
        if type(other) != type(self):
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
    def gzip(
            cls, src_path: pathlib.Path, dst_path: Optional[pathlib.Path] = None
    ) -> pathlib.Path:
        """
        compress or decompress a file using gzip

        the direction, i.e. compress or decompress, depends on src_path.suffix

        https://docs.python.org/3/library/gzip.html#examples-of-usage
        """
        if src_path.suffix == SUFFIX_GZIP:
            direction = 'decompress'
            dst_suffix = ''
            src_open = gzip.open
            dst_open = open
        else:
            direction = 'compress'
            dst_suffix = src_path.suffix + SUFFIX_GZIP
            src_open = open
            dst_open = gzip.open
        if dst_path is None:
            dst_path = src_path.with_suffix(dst_suffix)
        logger.debug(f'gzip {direction} {src_path} into {dst_path}')
        with src_open(src_path, mode='rb') as src_file:
            with dst_open(dst_path, mode='wb') as dst_file:
                shutil.copyfileobj(src_file, dst_file)
        return dst_path

    @classmethod
    def create_patch(
        cls, src_path: pathlib.Path, dst_path: pathlib.Path
    ) -> pathlib.Path:
        """
        Create a binary patch file based on source and destination files.

        If the source and/or destination files are compressed (.gz), decompress first.

        Patch file path matches destination file path, except for suffix.
        """
        # replace suffix twice, in case we have a .tar.gz
        patch_path = dst_path.with_suffix('').with_suffix(SUFFIX_PATCH)
        with TemporaryDirectory() as tmp_dir:
            tmp_dir_path = pathlib.Path(tmp_dir)
            # decompress files, if necessary, otherwise diff can become very large
            decompressed_paths = dict(src_path=src_path, dst_path=dst_path)
            for key, path in decompressed_paths.items():
                if path.suffix == SUFFIX_GZIP:
                    decompressed_paths[key] = tmp_dir_path / path.with_suffix('').name
                    cls.gzip(src_path=path, dst_path=decompressed_paths[key])
            # create patch
            bsdiff4.file_diff(**decompressed_paths, patch_path=patch_path)
        return patch_path

    @classmethod
    def apply_patch(cls, src_path: pathlib.Path, patch_path: pathlib.Path):
        """
        Apply binary patch file to source file to create destination file.

        Destination file path matches patch file path, except for suffix.
        """
        dst_path = patch_path.with_suffix(SUFFIX_ARCHIVE)
        # decompress source if necessary
        with TemporaryDirectory() as tmp_dir:
            tmp_dir_path = pathlib.Path(tmp_dir)
            decompressed_src_path = src_path
            if src_path.suffix == SUFFIX_GZIP:
                decompressed_src_path = tmp_dir_path / src_path.with_suffix('').name
                cls.gzip(src_path=src_path, dst_path=decompressed_src_path)
            decompressed_dst_path = tmp_dir_path / dst_path.with_suffix('').name
            # apply patch to .tar archives
            bsdiff4.file_patch(
                src_path=decompressed_src_path,
                dst_path=decompressed_dst_path,
                patch_path=patch_path,
            )
            # compress result
            cls.gzip(src_path=decompressed_dst_path, dst_path=dst_path)
        return dst_path
