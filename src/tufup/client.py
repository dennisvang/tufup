import bsdiff4
import json
import logging
import pathlib
import shutil
import sys
import tarfile
import tempfile
from typing import Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib import parse

import requests
from requests.auth import AuthBase
from tuf.api.exceptions import DownloadError, UnsignedMetadataError
import tuf.ngclient

from tufup.common import TargetMeta
from tufup.utils import remove_path
from tufup.utils.platform_specific import install_update

logger = logging.getLogger(__name__)

# dir name must be unequivocally linked to tufup, as dir contents are removed
EXTRACT_DIR_NAME = 'tufup_extract_dir'
DEFAULT_EXTRACT_DIR = pathlib.Path(tempfile.gettempdir()) / EXTRACT_DIR_NAME


class Client(tuf.ngclient.Updater):
    def __init__(
        self,
        app_name: str,
        app_install_dir: pathlib.Path,
        current_version: str,
        metadata_dir: pathlib.Path,
        metadata_base_url: str,
        target_dir: pathlib.Path,
        target_base_url: str,
        extract_dir: Optional[pathlib.Path] = None,
        refresh_required: bool = False,
        session_auth: Optional[Dict[str, Union[Tuple[str, str], AuthBase]]] = None,
        purge_extract_dir: bool = False,
        **kwargs,
    ):
        # tuf.ngclient.Updater.__init__ loads local root metadata automatically
        super().__init__(
            metadata_dir=str(metadata_dir),
            metadata_base_url=metadata_base_url,
            target_dir=str(target_dir),
            target_base_url=target_base_url,
            fetcher=AuthRequestsFetcher(session_auth=session_auth),
            **kwargs,
        )
        self.app_install_dir = app_install_dir
        self.extract_dir = extract_dir
        self.purge_extract_dir = purge_extract_dir
        self.refresh_required = refresh_required
        self.current_archive = TargetMeta(name=app_name, version=current_version)
        self.current_archive_local_path = target_dir / self.current_archive.path
        self.new_archive_local_path: Optional[pathlib.Path] = None
        self.new_archive_info: Optional[tuf.ngclient.TargetFile] = None
        self.new_targets: Optional[dict] = None
        self.downloaded_target_files = {}

    @property
    def trusted_target_metas(self) -> list:
        """
        Return a list of available trusted targets, as TargetMeta objects.

        This is convenient because TargetMeta objects can be sorted by version.
        """
        # todo: _trusted_set is private, but ideally we would use a public
        #  interface (if only tuf.ngclient exposed one...)
        _trusted_target_metas = []
        if self._trusted_set.targets:
            _trusted_target_metas = [
                TargetMeta(target_path=key)
                for key in self._trusted_set.targets.signed.targets.keys()
            ]
            logger.debug(f'{len(_trusted_target_metas)} TargetMeta objects created')
        else:
            logger.warning('targets metadata not found')
        return _trusted_target_metas

    def get_targetinfo(
        self, target_path: Union[str, TargetMeta]
    ) -> Optional[tuf.ngclient.TargetFile]:
        """Extend Updater.get_targetinfo to handle TargetMeta input args."""
        if isinstance(target_path, TargetMeta):
            target_path = target_path.target_path_str
        return super().get_targetinfo(target_path=target_path)

    @property
    def updates_available(self):
        if self.new_targets is None:
            logger.warning('Please call check_for_updates first.')
            return False
        else:
            return len(self.new_targets) > 0

    def download_and_apply_update(
        self,
        skip_confirmation: bool = False,
        install: Optional[Callable] = None,
        progress_hook: Optional[Callable] = None,
        **kwargs,
    ):
        """
        Download and apply available updates.

        Note that `check_for_updates` must be called first.

        This downloads the files found by `check_for_updates`, applies any
        patches, and extracts the resulting archive to the `extract_dir`. At
        that point, the update is ready to be installed (i.e. moved into
        place). This is done by calling `install` with the specified `**kwargs`.

        The default `install` callable moves the content of `extract_dir` to
        `app_install_dir`, and exits the application (not necessarily in that
        order).

        The **kwargs are passed on to the 'install' callable

        The default `install` callable accepts two additional arguments:

            `purge_dst_dir` (default False): if True, *ALL* content will be
            deleted from the `app_install_dir`

            `exclude_from_purge` (default None): list of paths to exclude
            from purge

            **DANGER**: Only set `purge_dst_dir=True` if your app is
            installed in its own separate directory, otherwise this will
            cause unrelated files and folders to be deleted.
        """
        if install is None:
            install = install_update
        if self.updates_available and self._download_updates(
            progress_hook=progress_hook
        ):
            self._apply_updates(
                install=install, skip_confirmation=skip_confirmation, **kwargs
            )

    def check_for_updates(
        self, pre: Optional[str] = None, patch: bool = True
    ) -> Optional[TargetMeta]:
        """
        Check if any updates are available, based on current app version.

        Returns latest archive meta, if a new archive is found.

        Final releases are always included. Pre-releases are excluded by
        default. If `pre` is specified, pre-releases are included, down to
        the specified level. Pre-release identifiers follow the PEP440
        specification, i.e. 'a', 'b', or 'rc', for alpha, beta, and release
        candidate, respectively.

        If `patch` is `False`, a full update is enforced.
        """
        included = {None: '', '': '', 'a': 'abrc', 'b': 'brc', 'rc': 'rc'}
        # refresh top-level metadata (root -> timestamp -> snapshot -> targets)
        try:
            self.refresh()
        except (DownloadError, UnsignedMetadataError) as e:
            logger.warning(f'Cannot refresh metadata: {e}')
            if self.refresh_required:
                logger.warning('Exiting: refresh is required')
                sys.exit()
            return None
        # check for new target files (archives and patches)
        logger.debug(f'current archive: {self.current_archive.filename}')
        all_new_targets = dict(
            (target_meta, self.get_targetinfo(target_meta))
            for target_meta in self.trusted_target_metas
            if target_meta.name == self.current_archive.name
            and target_meta.version > self.current_archive.version
        )
        logger.debug(f'{len(all_new_targets)} new *targets* found')
        # determine latest archive, filtered by the specified pre-release level
        new_archives = dict(
            item
            for item in all_new_targets.items()
            if item[0].is_archive
            and (not item[0].version.pre or item[0].version.pre[0] in included[pre])
        )
        new_archive_meta = None
        if new_archives:
            logger.debug(f'{len(new_archives)} new *archives* found')
            new_archive_meta, self.new_archive_info = sorted(new_archives.items())[-1]
            self.new_archive_local_path = pathlib.Path(
                self.target_dir, new_archive_meta.path.name
            )
            # patches must include all pre-releases and final releases up to,
            # and including, the latest archive as determined above
            new_patches = dict(
                item
                for item in all_new_targets.items()
                if item[0].is_patch and item[0].version <= new_archive_meta.version
            )
            # determine size of patch update and archive update
            total_patch_size = sum(
                target_file.length for target_file in new_patches.values()
            )
            # use file size to decide if we want to do a patch update or a
            # full update (if there are no patches, or if the current archive
            # is not available, we must do a full update)
            self.new_targets = new_patches
            no_patches = total_patch_size == 0
            patches_too_big = total_patch_size > self.new_archive_info.length
            current_archive_not_found = not self.current_archive_local_path.exists()
            if not patch or no_patches or patches_too_big or current_archive_not_found:
                self.new_targets = {new_archive_meta: self.new_archive_info}
                logger.debug('full update available')
            else:
                logger.debug('patch update(s) available')
        else:
            self.new_targets = {}
            logger.debug('no new archives found')
        return new_archive_meta

    def _download_updates(self, progress_hook: Optional[Callable]) -> bool:
        # download the new targets selected in check_for_updates
        for target_meta, target_file in self.new_targets.items():
            # check if the target file has already been downloaded
            local_path_str = self.find_cached_target(targetinfo=target_file)
            if not local_path_str:
                # attach progress hook
                if progress_hook:
                    self._fetcher.attach_progress_hook(
                        hook=progress_hook, bytes_expected=target_file.length
                    )
                # download the target file
                local_path_str = self.download_target(targetinfo=target_file)
            self.downloaded_target_files[target_meta] = pathlib.Path(local_path_str)
        return len(self.downloaded_target_files) == len(self.new_targets)

    def _apply_updates(
        self,
        install: Callable,
        skip_confirmation: bool,
        **kwargs,
    ):
        """
        kwargs are passed on to the 'install' callable

        Note this has a side-effect: if self.extract_dir is not specified,
        an extract_dir is created in a platform-specific temporary location.
        """
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
                    archive_bytes = self.current_archive_local_path.read_bytes()
                archive_bytes = bsdiff4.patch(archive_bytes, file_path.read_bytes())
        if archive_bytes:
            # verify the patched archive length and hash
            self.new_archive_info.verify_length_and_hashes(data=archive_bytes)
            # write the patched new archive
            self.new_archive_local_path.write_bytes(archive_bytes)
        # extract archive to "temporary" directory
        self._extract_archive()
        # install, i.e. move extracted files from "temporary" dir to final "install" dir
        confirmation_message = f'Install update in {self.app_install_dir}? [y]/n'
        if skip_confirmation or input(confirmation_message) in ['y', '']:
            # start a script that moves the extracted files to the app install
            # directory (overwrites existing files), then exit current process
            install(
                src_dir=self.extract_dir,
                dst_dir=self.app_install_dir,
                **kwargs,
            )
        else:
            logger.warning('Installation aborted.')

    def _extract_archive(self):
        # ensure extract_dir exists
        if self.extract_dir is None:
            self.extract_dir = DEFAULT_EXTRACT_DIR
            logger.debug(f'using default extract_dir: {self.extract_dir}')
        self.extract_dir.mkdir(exist_ok=True)
        # purge extract_dir
        purge_manifest = PurgeManifest(dir_to_purge=self.extract_dir)
        purge_manifest.purge()
        # extract the new archive into the extract_dir
        shutil.unpack_archive(
            filename=self.new_archive_local_path, extract_dir=self.extract_dir
        )
        logger.debug(f'files extracted to {self.extract_dir}')
        # create new purge manifest in extract_dir
        purge_manifest.create_from_archive(archive=self.new_archive_local_path)


class AuthRequestsFetcher(tuf.ngclient.RequestsFetcher):
    # RequestsFetcher is public as of python-tuf v2.1.0 (see python-tuf #2277)
    def __init__(
        self,
        session_auth: Optional[Dict[str, Union[Tuple[str, str], AuthBase]]] = None,
    ) -> None:
        """
        This extends the default tuf RequestsFetcher, so we can specify
        authentication tuples (or custom authentication objects) for each
        session.

        session_auth (optional):

            dict of the form {<scheme and server>: (<username>, <password>), ...}
            or {<scheme and server>: <requests.auth.AuthBase>, ...}
            or some combination of those

        where <scheme and server> can be e.g. https://example.com
        or http://localhost:8000.

        Naming follows [RFC 2396][1], which defines a generic uri as:

            <scheme>://<authority><path>?<query>

        where <authority> can be <server>.

        Also see session authentication example in requests docs: [1][2][3]

        [1]: https://datatracker.ietf.org/doc/html/rfc2396#section-3
        [2]: https://docs.python-requests.org/en/master/user/advanced/#session-objects
        [3]: https://docs.python-requests.org/en/latest/user/advanced/#custom-authentication
        [4]: https://docs.python-requests.org/en/master/api/#sessionapi
        """
        super().__init__()
        self.session_auth = session_auth or {}
        # default progress hook does nothing
        self._progress = lambda bytes_new: None

    def attach_progress_hook(self, hook: Callable, bytes_expected: int):
        """
        Allow clients to attach a progress hook which gets called after every
        downloaded chunk.

        The hook must accept two kwargs: bytes_downloaded and bytes_expected
        """

        def progress(
            bytes_new: int,
            _cache: List[int] = [],  # noqa: mutable default intentional
        ):
            # mutable default is used to keep track of downloaded chunk sizes
            _cache.append(bytes_new)
            return hook(bytes_downloaded=sum(_cache), bytes_expected=bytes_expected)

        self._progress = progress

    def _get_session(self, url: str) -> requests.Session:
        # set the Session.auth attribute for the specified server, if available
        session = super()._get_session(url=url)
        # determine session_auth key
        parsed_url = parse.urlparse(url)
        key = parse.urlunparse(
            parse.ParseResult._make(
                [parsed_url.scheme, parsed_url.netloc, '', '', '', '']
            )
        )
        session.auth = self.session_auth.get(key)
        return session

    def _chunks(self, response: 'requests.Response') -> Iterator[bytes]:
        """Call progress hook for every chunk."""
        for data in super()._chunks(response=response):
            self._progress(bytes_new=len(data))
            yield data


class PurgeManifest(object):
    _filename = 'purge.manifest'

    def __init__(self, dir_to_purge: Union[pathlib.Path, str]):
        """
        a purge manifest is used to remove files and subdirectories from the
        specified directory (`dir_to_purge`) in a safe manner, i.e. minimizing the
        risk of accidental removal of pre-existing files/dirs that are unrelated to
        the present application

        this is achieved by removing only those items listed in a purge.manifest file
        in the specified directory

        if there is no purge.manifest file, nothing is removed

        the purge.manifest file should be created (or updated) whenever files are
        added to the `dir_to_purge`

        the purge manifest can be used to clear the extract_dir or the
        app_install_dir, for example
        """
        self.dir_to_purge = pathlib.Path(dir_to_purge)

    @property
    def file_path(self) -> pathlib.Path:
        return self.dir_to_purge / self._filename

    def read_from_file(self) -> Optional[List[str]]:
        if not self.file_path.exists():
            logger.warning(f'cannot read manifest: {self.file_path} not found')
            return
        return json.loads(self.file_path.read_text())

    def write_to_file(self, manifest: List[str]):
        self.file_path.write_text(json.dumps(manifest))
        logger.debug(f'purge manifest created: {self.file_path}')

    def purge(self) -> None:
        """
        remove all files/folders listed in the purge manifest from the specified
        directory (`dir_to_purge`)
        """
        manifest = self.read_from_file()
        if manifest:
            for path in self.dir_to_purge.iterdir():
                relative_path = path.relative_to(self.dir_to_purge)
                if str(relative_path) in manifest:
                    remove_path(path=path, remove_readonly=True)
                else:
                    logger.warning(f'{path} remains: not in {self._filename}')
            logger.info(f'directory purged: {self.dir_to_purge}')

    def create_from_archive(self, archive: Union[pathlib.Path, str]) -> None:
        """create/overwrite purge manifest in extract_dir"""
        # note that `shutil.make_archive` puts everything in a dir called "." (for
        # cwd) and prefixes items with "./" (if this ever poses a problem, we could
        # switch to using `tarfile.TarFile.add()` with the `arcname` argument) see
        # e.g https://stackoverflow.com/a/70081512
        with tarfile.open(archive) as tar:
            manifest = [self._filename] + [
                tarinfo.name[2:] if tarinfo.name.startswith('./') else tarinfo.name
                for tarinfo in tar
                if tarinfo.name != '.'
            ]
        self.write_to_file(manifest=manifest)
