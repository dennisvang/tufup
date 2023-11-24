import gzip
import logging
import pathlib
import re
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


class GZipper(object):
    @staticmethod
    def _fix_gzip_header(file_path: pathlib.Path):
        """
        quick & dirty fix to ensure that the OS byte in the gzip header is 255 "unknown"
        """
        OS_FIELD = dict(offset=9, bytes=b'\xff')  # noqa
        file_path = pathlib.Path(file_path).resolve()
        with file_path.open(mode='r+b') as file_obj:
            file_obj.seek(OS_FIELD['offset'])
            file_obj.write(OS_FIELD['bytes'])
        logger.debug(f'gzip header fixed for {file_path}')

    @classmethod
    def gzip(
        cls, src_path: pathlib.Path, dst_path: Optional[pathlib.Path] = None, **kwargs
    ) -> pathlib.Path:
        """
        Compress or decompress a file using gzip.

        The direction, i.e. compress or decompress, depends on src_path.suffix.

        Supported kwargs, i.e. `compresslevel` and/or `mtime`, are passed on to
        `gzip.compress()` [5].

        # Notes

        - See GZIP header definition in rfc1952 spec [6], and python's implementation
        in the gzip module [7].

        - The gzip header [6] includes an MTIME (timestamp) field by default,
        as well as an OS field. In addition, the FNAME (filename) field may be
        specified. This makes the default gzip header unreproducible. To fix this we
        need to do the equivalent of `gzip --no-name` from GNU gzip [1].

        - Both `gzip.open()` and the `gzip.GzipFile` class set the FNAME field in the
        header. To prevent this, we use `gzip.compress()` instead, which also
        supports an `mtime` argument to set a fixed timestamp [2].

        - To ensure identical gzip output, we need to make sure the same algorithm is
        used, with the same compression setting.

        - BEWARE: The output of the gzip compression depends on the implementation,
        so there is no guarantee that different operating systems will yield
        identical compressed data, even if all settings and headers are equal.

        [1]: https://www.gnu.org/software/gzip/manual/gzip.html#Invoking-gzip
        [2]: https://docs.python.org/3/library/gzip.html#examples-of-usage
        [3]: https://reproducible-builds.org/docs/source-date-epoch/
        [4]: https://www.gnu.org/software/gzip/manual/gzip.html#Environment
        [5]: https://docs.python.org/3/library/gzip.html#gzip.compress
        [6]: https://datatracker.ietf.org/doc/html/rfc1952#page-5
        [7]: https://github.com/python/cpython/blob/d9fc15222e96942e30ea8b0561dec5c82ecb4663/Lib/gzip.py#L599
        """
        if src_path.suffix == SUFFIX_GZIP:
            gzip_function = gzip.decompress
            dst_suffix = ''
            if kwargs:
                logger.warning(f'gzip.decompress does not accept kwargs: {kwargs}')
                kwargs = dict()
        else:
            gzip_function = gzip.compress
            dst_suffix = src_path.suffix + SUFFIX_GZIP
        if dst_path is None:
            dst_path = src_path.with_suffix(dst_suffix)
        logger.debug(f'gzip {gzip_function.__name__} {src_path} into {dst_path}')
        dst_path.write_bytes(gzip_function(data=src_path.read_bytes(), **kwargs))
        if dst_suffix:
            # fix compressed file header
            cls._fix_gzip_header(dst_path)
        return dst_path


class Patcher(object):
    @classmethod
    def create_patch(
        cls, src_path: pathlib.Path, dst_path: pathlib.Path
    ) -> pathlib.Path:
        """
        Create a binary patch file based on source and destination files.

        The source and destination files are decompressed first, so the patch is
        created based on the .tar archives. A diff based on the .tar.gz files could
        become very large, making it practically useless.

        Patch file path matches destination file path, except for suffix.
        """
        # only accept .tar.gz files
        for path in [src_path, dst_path]:
            assert path.suffix == SUFFIX_GZIP, f'not a .gz file: {path}'
        # replace suffix (twice, for .tar.gz)
        patch_path = dst_path.with_suffix('').with_suffix(SUFFIX_PATCH)
        # decompress files to prevent large diff
        with TemporaryDirectory() as tmp_dir:
            tmp_dir_path = pathlib.Path(tmp_dir)
            decompressed_paths = dict(src_path=src_path, dst_path=dst_path)
            for key, path in decompressed_paths.items():
                decompressed_paths[key] = tmp_dir_path / path.with_suffix('').name
                GZipper.gzip(src_path=path, dst_path=decompressed_paths[key])
            # create patch
            bsdiff4.file_diff(**decompressed_paths, patch_path=patch_path)
        return patch_path

    @classmethod
    def apply_patch(cls, src_path: pathlib.Path, patch_path: pathlib.Path):
        """
        Apply binary patch file to source file to create destination file.

        Patches are based on the (uncompressed) .tar archives, so the source .tar.gz
        archive is decompressed, then the patch is applied, and the resulting .tar is
        compressed again, to save storage space.

        Destination file path matches patch file path, except for suffix.
        """
        # only accept .tar.gz files
        assert src_path.suffix == SUFFIX_GZIP, f'not a .gz file: {src_path}'
        dst_path = patch_path.with_suffix(SUFFIX_ARCHIVE)
        # decompress archive, apply patch, and compress again
        with TemporaryDirectory() as tmp_dir:
            tmp_dir_path = pathlib.Path(tmp_dir)
            # decompress
            decompressed_src_path = tmp_dir_path / src_path.with_suffix('').name
            GZipper.gzip(src_path=src_path, dst_path=decompressed_src_path)
            # apply patch to .tar archives
            decompressed_dst_path = tmp_dir_path / dst_path.with_suffix('').name
            bsdiff4.file_patch(
                src_path=decompressed_src_path,
                dst_path=decompressed_dst_path,
                patch_path=patch_path,
            )
            # compress result (mtime=0 for reproducibility)
            GZipper.gzip(src_path=decompressed_dst_path, dst_path=dst_path, mtime=0)
        return dst_path
