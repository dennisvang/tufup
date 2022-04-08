import bsdiff4
import logging
import pathlib
import shutil
import sys
from tempfile import TemporaryDirectory
from typing import Callable, Optional, Union

import tuf.api.exceptions
from tuf.api.metadata import TargetFile
import tuf.ngclient

from notsotuf.tools.common import TargetPath

logger = logging.getLogger(__name__)


class Client(tuf.ngclient.Updater):
    def __init__(
            self,
            app_name: str,
            current_version: str,
            metadata_dir: pathlib.Path,
            metadata_base_url: str,
            target_dir: pathlib.Path,
            target_base_url: str,
            refresh_required: bool = False,
            **kwargs,
    ):
        # tuf.ngclient.Updater.__init__ loads local root metadata automatically
        super().__init__(
            metadata_dir=str(metadata_dir),
            metadata_base_url=metadata_base_url,
            target_dir=str(target_dir),
            target_base_url=target_base_url,
            **kwargs,
        )
        self.refresh_required = refresh_required
        self.current_archive = TargetPath(name=app_name, version=current_version)
        self.new_archive_local_path: Optional[pathlib.Path] = None
        self.new_archive_info: Optional[TargetFile] = None
        self.new_targets = {}
        self.downloaded_target_files = {}

    @property
    def trusted_target_paths(self) -> list:
        """
        Return a list of available trusted targets, as TargetPath objects.

        This is convenient because TargetPath objects can be sorted by version.
        """
        # todo: _trusted_set is private, but ideally we would use a public
        #  interface (if only tuf.ngclient exposed one...)
        _trusted_target_paths = []
        if self._trusted_set.targets:
            _trusted_target_paths = [
                TargetPath(target_path=key)
                for key in self._trusted_set.targets.signed.targets.keys()
            ]
        else:
            logger.warning('targets metadata not found')
        return _trusted_target_paths

    def get_targetinfo(self, target_path: Union[str, TargetPath]) -> Optional[TargetFile]:
        """Extend Updater.get_targetinfo to handle TargetPath input args."""
        if isinstance(target_path, TargetPath):
            target_path = target_path.target_path_str
        return super().get_targetinfo(target_path=target_path)

    def update(self, pre: Optional[str] = None):
        """
        Check, download, and apply updates.

        Final releases are always included. Pre-releases are excluded by
        default. If `pre` is specified, pre-releases are included, down to
        the specified level. Pre-release identifiers follow the PEP440
        specification, i.e. 'a', 'b', or 'rc', for alpha, beta, and release
        candidate, respectively.
        """
        if self._check_updates(pre=pre) and self._download_updates():
            self._apply_updates()

    def _check_updates(self, pre: Optional[str]) -> bool:
        included = {None: '', '': '', 'a': 'abrc', 'b': 'brc', 'rc': 'rc'}
        # refresh top-level metadata (root -> timestamp -> snapshot -> targets)
        try:
            self.refresh()
        except tuf.api.exceptions.DownloadError as e:
            logger.warning(f'Cannot refresh metadata: {e}')
            if self.refresh_required:
                logger.warning('Exiting: refresh is required')
                sys.exit()
            return False
        # check for new target files (archives and patches)
        all_new_targets = dict(
            (target_path, self.get_targetinfo(target_path))
            for target_path in self.trusted_target_paths
            if target_path.name == self.current_archive.name
            and target_path.version > self.current_archive.version
        )
        # determine latest archive, filtered by the specified pre-release level
        new_archives = dict(
            item for item in all_new_targets.items()
            if item[0].is_archive
            and (not item[0].version.pre or item[0].version.pre[0] in included[pre])
        )
        new_archive, self.new_archive_info = sorted(new_archives.items())[-1]
        self.new_archive_local_path = pathlib.Path(self.target_dir, new_archive.path.name)
        # patches must include all pre-releases and final releases up to,
        # and including, the latest archive as determined above
        new_patches = dict(
            item for item in all_new_targets.items()
            if item[0].is_patch
            and item[0].version <= new_archive.version
        )
        # determine size of patch update and archive update
        total_patch_size = sum(
            target_file.length for target_file in new_patches.values()
        )
        # use size to decide if we want to do a patch update or full update (
        # if there are no patches, we must do a full update)
        self.new_targets = new_patches
        if total_patch_size > self.new_archive_info.length or total_patch_size == 0:
            self.new_targets = {new_archive: self.new_archive_info}
        return len(self.new_targets) > 0

    def _download_updates(self) -> bool:
        # download the new targets selected in _check_updates
        for target_path, target_file in self.new_targets.items():
            # check if the target file has already been downloaded
            local_path_str = self.find_cached_target(targetinfo=target_file)
            if not local_path_str:
                # download the target file
                local_path_str = self.download_target(targetinfo=target_file)
            self.downloaded_target_files[target_path] = pathlib.Path(local_path_str)
        return len(self.downloaded_target_files) == len(self.new_targets)

    def _apply_updates(self):
        # patch current archive (if we have patches) or use new full archive
        archive_bytes = None
        for target, file_path in sorted(self.downloaded_target_files.items()):
            if target.is_archive:
                # just ensure the full archive file is available
                assert len(self.downloaded_target_files) == 1
                assert self.new_archive_local_path.exists()
            elif target.is_patch:
                # create new archive by patching current archive (patches
                # must be sorted by increasing version)
                if archive_bytes is None:
                    archive_bytes = self.current_archive.path.read_bytes()
                archive_bytes = bsdiff4.patch(archive_bytes, file_path.read_bytes())
        if archive_bytes:
            # verify the patched archive length and hash
            self.new_archive_info.verify_length_and_hashes(data=archive_bytes)
            # write the patched new archive
            self.new_archive_local_path.write_bytes(archive_bytes)
        # extract archive to temporary location
        with TemporaryDirectory() as temp_dir:
            # extract
            temp_dir_path = pathlib.Path(temp_dir)
            shutil.unpack_archive(
                filename=self.new_archive_local_path, extract_dir=temp_dir_path
            )
            # replace files in install directory
            ...

