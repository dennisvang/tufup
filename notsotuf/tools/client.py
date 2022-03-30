import pathlib

import tuf.ngclient

from notsotuf.tools.common import TargetPath


class Client(tuf.ngclient.Updater):
    def __init__(self, current_archive_path: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_archive = TargetPath(current_archive_path)
        self.new_targets = {}
        self.downloaded_target_files = {}

    def update(self, ):
        if self._check_updates() and self._download_updates():
            self._apply_updates()

    def _check_updates(self) -> bool:
        # refresh top-level metadata (root -> timestamp -> snapshot -> targets)
        self.refresh()
        # check for new target files
        trusted_targets = dict(  # replace str keys by TargetPath instances
            (TargetPath(target_path=key), value)
            for key, value in self._trusted_set.targets.signed.targets.items()
        )
        all_new_targets = dict(
            item for item in trusted_targets.items()
            if item[0].name == self.current_archive.name
            and item[0].version > self.current_archive.version
        )
        # split new targets into patches and archives
        new_archives = dict(item for item in all_new_targets.items() if item[0].is_archive)
        new_patches = dict(item for item in all_new_targets.items() if item[0].is_patch)
        # determine size of patch update and archive update
        latest_archive_path, latest_archive_file = sorted(new_archives.items())[-1]
        latest_archive_size = latest_archive_file.get('length')
        total_patch_size = sum(
            target_file.get('length') for target_file in new_patches.values()
        )
        # use size to decide if we want to do a patch update or full update (
        # if there are not patches, do a full update)
        self.new_targets = new_patches
        if total_patch_size > latest_archive_size or total_patch_size == 0:
            self.new_targets = {latest_archive_path: latest_archive_file}
        return len(self.new_targets) > 0

    def _download_updates(self) -> bool:
        for target_path, target_file in self.new_targets.items():
            local_path_str = self.download_target(targetinfo=target_file)
            self.downloaded_target_files[target_path] = pathlib.Path(local_path_str)
        return len(self.downloaded_target_files) == len(self.new_targets)

    def _apply_updates(self):
        ...

