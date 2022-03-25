# notsotuf

A simple software updater, built on top of [python-tuf][1], the reference implementation for [TUF][2] (The Update Framework).

The `notsotuf` package was inspired by [PyUpdater][3].

## Overview

Borrowing `tuf` terminology, we have tools for the *repo* side and for the *client* side.

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


[1]: https://github.com/theupdateframework/python-tuf
[2]: https://theupdateframework.io/
[3]: https://www.pyupdater.org/
[4]: https://theupdateframework.io/overview/#software-updates-101
