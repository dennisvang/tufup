from packaging.version import Version

import tuf.ngclient

from notsotuf.tools.common import TargetPath


class Client(tuf.ngclient.Updater):
    def __init__(self, target_name: str, current_version: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_name = target_name
        self.current_version = Version(current_version)
        self.new_targets = {}
        self.downloaded_targets = {}

    @property
    def new_patches(self):
        return dict(
            item for item in self.new_targets.items()
            if TargetPath(item[0]).is_patch
        )

    @property
    def new_archives(self):
        return dict(
            item for item in self.new_targets.items()
            if TargetPath(item[0]).is_archive
        )

    @property
    def new_target_paths_sorted(self):
        """Returns target_path values sorted by filename version"""
        return sorted(self.new_targets.keys(), key=lambda k: TargetPath(k))

    def update(self, ):
        if self._check_updates() and self._download_updates():
            self._apply_updates()

    def _check_updates(self) -> bool:
        # refresh top-level metadata (root -> timestamp -> snapshot -> targets)
        self.refresh()
        # check for new updates
        trusted_targets = self._trusted_set.targets.signed.targets
        trusted_target_paths = [
            TargetPath(target_path=key) for key in trusted_targets.keys()
        ]
        new_target_paths = [
            target_path for target_path in trusted_target_paths
            if target_path.name == self.target_name
            and target_path.version > self.current_version
        ]
        # determine size of patch update and full update
        latest_archive_path = sorted(
            target_path for target_path in new_target_paths if target_path.is_archive
        )[-1]
        latest_archive_size = trusted_targets[str(latest_archive_path)].get('length')
        total_patch_size = sum(
            trusted_targets[str(target_path)].get('length')
            for target_path in new_target_paths
            if target_path.is_patch
        )
        # decide if we want to do a patch update or full update
        self.new_targets = [str(latest_archive_path)]
        if total_patch_size < latest_archive_size:
            self.new_targets = [
                str(target_path) for target_path in new_target_paths
                if target_path.is_patch
            ]
        return len(self.new_targets) > 0

    def _download_updates(self) -> bool:
        ...
        return len(self.downloaded_targets) > 0

    def _apply_updates(self):
        pass

