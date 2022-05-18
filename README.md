# notsotuf

![Build](https://github.com/dennisvang/notsotuf/actions/workflows/python-package.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/notsotuf)

A simple software updater for stand-alone Python *applications*.

The `notsotuf` package is built on top of [python-tuf][1], which is the reference implementation for [TUF][2] (The Update Framework).

The initial implementation is focused on Windows and macOS.
The package can be used on other platforms, but these are not actively supported.

## About

The `notsotuf` package was inspired by [PyUpdater][3], and uses a general approach to updating that is directly based on PyUpdater's implementation.

However, whereas PyUpdater implements a *custom* security mechanism to ensure authenticity (and integrity) of downloaded update files, `notsotuf` is built on top of the security mechanisms implemented in the [python-tuf][1] package, a.k.a. `tuf`.
By entrusting the design of security measures to the security professionals, `notsotuf` can focus on high-level tools.

Although `tuf` supports highly complex security infrastructures, see e.g. [PEP458][5], it also offers sufficient flexibility to allow *application* developers to tailor the security level to their use case.
For details and best practices, refer to the [tuf docs][2].

Based on the intended use, the `notsotuf` package supports only the top-level roles offered by `tuf`. At this time we do not support delegations.
Hence the name *"notsotuf"*.

*Disclaimer: It turns out there was once another package called [No-So-TUF][9] created by the author of PyUpdater.
These packages are not related, and the matching name is a pure coincidence.
The name did not appear on PyPI at the time our repo was created, nor did it appear on GitHub, as far as I know.*

## Overview

Borrowing `tuf` terminology, we have tools for the repository (*repo*) side and tools for the *client* side.

The *repo* tools are used by the app developer to:

- create update files (e.g. using PyInstaller)
- sign the resulting files (cryptographically)
- deploy these files to a server

The *client* tools are used by the app itself to:

- check for updates
- download update files
- apply the update files

The `tuf` package is used under the hood to check for updates and download update files in a secure manner, so `notsotuf` can safely apply the update.
See the [tuf docs][4] for more information.

## Archives and patches

Notsotuf works with *archives* (e.g. gzipped PyInstaller bundles) and *patches* (binary differences between subsequent archives).
Each archive, except the first one, must have a corresponding patch file.

Archive filenames and patch filenames follow the pattern

`<name>-<version><suffix>` 

where `name` is a short string that may contain alphanumeric characters, underscores, and hyphens, `version` is a version string according to the [PEP440][6] specification, and `suffix` is either `'.tar.gz'` or `'.patch'`.

Patches are typically smaller than archives, so the notsotuf client will always attempt to update using one or more patches.
However, if the total amount of patch data is greater than the desired full archive file, a full update will be performed.

## How updates are created (repo-side)

When a new release of your application is ready, the following steps need to be taken to enable clients to update to that new release:

1. Create an application archive for the new release (e.g. a zipped PyInstaller bundle).
2. Create a patch from the current archive to the new archive.
3. Add hashes for the newly created archive file and patch file to the `tuf` metadata.
4. Sign the modified `tuf` metadata files.
5. Upload the new target files, i.e. archive and patch, and the updated metadata files, to the update server.

The signed metadata and hashes ensure both authenticity and integrity of the update files (see [tuf docs][2]).
In order to sign the metadata, we need access to the private key files for the applicable `tuf` roles.

The `notsotuf.tools.repo` module provides a convenient way to streamline the above procedure, based on the `tuf` [basic repo example][7].

## How updates are applied (client-side)

Updates are applied by replacing all files in the current app installation path with files from the latest archive.
The latest archive is either downloaded in full (as described above), or it is derived from the current archive by applying one or more downloaded patches.
Once the latest archive is available, it is decompressed to a temporary location.
From there, a script is started that clears the current app installation dir, and moves the new files into place.
After starting the script, the currently running process will exit.

## Migrating from other update frameworks

Here's one way to migrate from another update framework, such as `pyupdater`, to `notsotuf`:

1. Add `notsotuf` to your main application environment as a core dependency, and move `pyupdater` from core dependencies to development dependencies.
2. Replace all `pyupdater` client code (and configuration) in your application by the `notsotuf` client.
3. Build, package, and sign using `pyupdater`, and deploy to your server, as usual. 
This will ensure your `pyupdater` clients currently in the field will be able to update to the new `notsotuf` client.
From here on, new updates will be deployed using `notsotuf`.
4. Set up your `notsotuf` repository (on the same server or another server), but keep the `pyupdater` repository in place as long as necessary to allow all clients to update.
5. From now on, build, package, sign and deploy using `notsotuf`, as described elsewhere in this document.

## Platform support

The `notsotuf` package is aimed primarily at **Windows** and **macOS** applications.
Basic `notsotuf.client` functionality should also work on Mac or Linux, provided a custom `move_and_exit` hook is specified in `Client.update()`.
However, these platforms are not actively supported.
Moreover, Linux applications are probably better off using native packaging solutions, or solutions such as Flatpak or Snapcraft.

Read the [Python packaging overview][8] for more information.

[1]: https://github.com/theupdateframework/python-tuf
[2]: https://theupdateframework.io/
[3]: https://www.pyupdater.org/
[4]: https://theupdateframework.io/overview/#software-updates-101
[5]: https://peps.python.org/pep-0458/
[6]: https://peps.python.org/pep-0440/
[7]: https://github.com/theupdateframework/python-tuf/blob/develop/examples/repo_example/basic_repo.py
[8]: https://packaging.python.org/en/latest/overview/
[9]: https://pythonhosted.org/not-so-tuf/
