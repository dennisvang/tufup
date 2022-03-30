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

Archive files (and patch files) are named according to [PEP440][6] version specifications.
Each archive (except the first one) has a corresponding patch file, with the matching filename but different extension (`.patch` vs `.gz`).

Patches are typically smaller than archives, so the notsotuf client will always attempt to update using one or more patches.
However, if the total amount of patch data is greater than the desired full archive file, a full update will be performed.


## Migrating from PyUpdater

If you have a working update framework built around PyUpdater, here's how you could migrate to `notsotuf`:

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
