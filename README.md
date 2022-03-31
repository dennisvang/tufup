# notsotuf

A simple software updater, built on top of [python-tuf][1], the reference implementation for [TUF][2] (The Update Framework).

The `notsotuf` package was inspired by [PyUpdater][3].

A detailed discussion of the intricacies of TUF implementation can be found in [PEP458][5].

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

Notsotuf works with *archives* (gzipped PyInstaller bundles) and *patches* (binary differences between subsequent archives).
Each archive, except the first one, must have a corresponding patch file.

Archive filenames and patch filenames follow the pattern

`<name>-<version><suffix>` 

where `name` is a short string that may contain alphanumeric characters, underscores, and hyphens, `version` is a version string according to the [PEP440][6] specification, and `suffix` is either `'.gz'` or `'.patch'`.

Patches are typically smaller than archives, so the notsotuf client will always attempt to update using one or more patches.
However, if the total amount of patch data is greater than the desired full archive file, a full update will be performed.

## How updates are applied

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


[1]: https://github.com/theupdateframework/python-tuf
[2]: https://theupdateframework.io/
[3]: https://www.pyupdater.org/
[4]: https://theupdateframework.io/overview/#software-updates-101
[5]: https://peps.python.org/pep-0458/
[6]: https://peps.python.org/pep-0440/
