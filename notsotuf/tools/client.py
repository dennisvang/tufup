import bsdiff4
import logging
import pathlib
import shutil
from tempfile import TemporaryDirectory
from typing import Optional

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
        self.current_archive = TargetPath(name=app_name, version=current_version)
        self.new_archive_path: Optional[pathlib.Path] = None
        self.new_targets = {}
        self.downloaded_target_files = {}

    @property
    def trusted_targets(self) -> dict:
        # todo: _trusted_set is private, but ideally we would use a public
        #  interface (if only tuf.ngclient exposed one...)
        _trusted_targets = dict()
        if self._trusted_set.targets:
            _trusted_targets = dict(
                (TargetPath(target_path=key), value)
                for key, value in
                self._trusted_set.targets.signed.targets.items()
            )
        else:
            logger.warning('targets metadata not found')
        return _trusted_targets

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
        self.refresh()
        # check for new target files (archives and patches)
        all_new_targets = dict(
            item for item in self.trusted_targets.items()
            if item[0].name == self.current_archive.name
            and item[0].version > self.current_archive.version
        )
        # determine latest archive, filtered by the specified pre-release level
        new_archives = dict(
            item for item in all_new_targets.items()
            if item[0].is_archive
            and (not item[0].version.pre or item[0].version.pre[0] in included[pre])
        )
        latest_archive, latest_archive_file = sorted(new_archives.items())[-1]
        self.new_archive_path = pathlib.Path(self.target_dir, latest_archive.path.name)
        self.new_archive_verify = latest_archive_file.verify_length_and_hashes
        # patches must include all pre-releases and final releases up to,
        # and including, the latest archive as determined above
        new_patches = dict(
            item for item in all_new_targets.items()
            if item[0].is_patch
            and item[0].version <= latest_archive.version
        )
        # determine size of patch update and archive update
        latest_archive_size = latest_archive_file.get('length')
        total_patch_size = sum(
            target_file.get('length') for target_file in new_patches.values()
        )
        # use size to decide if we want to do a patch update or full update (
        # if there are no patches, we must do a full update)
        self.new_targets = new_patches
        if total_patch_size > latest_archive_size or total_patch_size == 0:
            self.new_targets = {latest_archive: latest_archive_file}
        return len(self.new_targets) > 0

    def _download_updates(self) -> bool:
        # download the new targets selected in _check_updates
        for target_path, target_file in self.new_targets.items():
            local_path_str = self.download_target(targetinfo=target_file)
            self.downloaded_target_files[target_path] = pathlib.Path(local_path_str)
        return len(self.downloaded_target_files) == len(self.new_targets)

    def _apply_updates(self):
        # patch current archive (if we have patches) or use new full archive
        archive_bytes = None
        for target, file_path in sorted(self.downloaded_target_files.items()):
            if target.is_archive:
                # new full archive available, just rename the file
                assert len(self.downloaded_target_files) == 1
                file_path.replace(self.new_archive_path)
            elif target.is_patch:
                # create new archive by patching current archive (patches
                # must be sorted by increasing version)
                if archive_bytes is None:
                    archive_bytes = self.current_archive.path.read_bytes()
                archive_bytes = bsdiff4.patch(archive_bytes, file_path.read_bytes())
        if archive_bytes:
            # verify the patched archive length and hash
            self.new_archive_verify(data=archive_bytes)
            # write the patched new archive
            self.new_archive_path.write_bytes(archive_bytes)
        # extract archive to temporary location
        with TemporaryDirectory() as temp_dir:
            # extract
            temp_dir_path = pathlib.Path(temp_dir)
            shutil.unpack_archive(filename=self.new_archive_path, extract_dir=temp_dir_path)
            # replace files in install directory
            ...

