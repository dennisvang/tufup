# tufup

![Build](https://github.com/dennisvang/tufup/actions/workflows/python-package.yml/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/tufup)](https://pypi.org/project/tufup/)
[![Documentation Status](https://readthedocs.org/projects/tufup/badge/?version=latest)](https://tufup.readthedocs.io/en/latest/?badge=latest)

A simple software updater for stand-alone Python *applications*.

## Application updates and TUF

Here's what a basic update-cycle for a [self-updating application][15] could look like: 

1. the app's development team create a new release, and make it available on a server
2. an older version of the app, out in the wild, contacts the server to check for updates
3. the old app finds the new release, downloads it, and installs it
4. goto 1.

The principle is relatively simple, as long as you don't consider the security risks involved.

Unfortunately, in the real world, [security cannot be neglected][16]: You don't want to install untrusted software on your system.

So, how can we make sure our update-cycle is secure? This is where things get quite complicated.

Luckily, [python-tuf][1], the reference implementation for [TUF][2] (The Update Framework) takes care of this complexity. If used properly, TUF ensures a high level of security for your update system.

That's why the `tufup` package is built on top of `python-tuf`.

It is highly advisable to read the [TUF documentation][11] before proceeding. 


## Quickstart

The easiest way to understand how `tufup` works is by example. A minimal example of an application that uses `tufup` can be found in the companion repository: 
**[tufup-example][10]**

The example repository shows how to integrate the `tufup` client into your app, and it shows you how to set up a `tufup` update-repository.

>NOTE: Although the tufup-example repository uses PyInstaller to bundle an application, `tufup` can be used with ***any*** type of application bundle, even plain python scripts.  

## Questions and Issues

If you have questions about `tufup`, or need help getting started, please start a [new Q&A discussion][22], or post a question on [Stack Overflow][13].

If you encounter bugs or other problems that are likely to affect other users, please create a [new issue][14] here.

## Some background

The `tufup` package was inspired by [PyUpdater][3], and uses a general approach to updating that is directly based on PyUpdater's implementation.

> NOTE: `tufup` is completely *independent* of PyUpdater. In fact, `tufup` was created as a replacement for PyUpdater, given the fact that [PyUpdater has been archived and is no longer maintained][17]. 

However, whereas PyUpdater implements a *custom* security mechanism to ensure authenticity (and integrity) of downloaded update files, `tufup` is built on top of the security mechanisms implemented in the [python-tuf][1] package, a.k.a. `tuf`.
By entrusting the design of security measures to the security professionals, `tufup` can focus on high-level tools.

Although `tuf` supports highly complex security infrastructures, see e.g. [PEP458][5], it also offers sufficient flexibility to allow *application* developers to tailor the security level to their use case.
For details and best practices, refer to the [tuf docs][2].

Based on the intended use, the `tufup` package supports only the top-level roles offered by `tuf`. At this time we do not support delegations.

>NOTE: Whereas PyUpdater is tightly integrated with PyInstaller, `tufup` is completely *independent* of the type of packaging solution.
> At its core, `tufup` simply moves bundles of files from A to B, securely, regardless of how these bundles were created. 
> A bundle may consist of a simple python script, a PyInstaller bundle, a PEX package, or any other collection of files and folders. 

## Overview

Borrowing TUF terminology, we distinguish between a *repo*-side (repository) and a *client*-side (application).

Below you'll find a list of the basic steps that occur in an application update cycle. 
Steps covered by `tufup` are **highlighted**.

On the *repo*-side, the app *developer*

- modifies the application code
- **creates a new application archive file and corresponding patch file**
- **signs the resulting files cryptographically**
- deploys these files to a server

On the *client*-side, the *application*

- **checks for updates**
- **downloads update files**
- **applies the update files (i.e. installation)**

The `tuf` package is used under the hood to check for updates and download update files in a secure manner, so `tufup` can safely apply the update.
See the [tuf docs][4] for more information.

## Archives and patches

*Internally*, `tufup` works with *archives* (gzipped bundles of files and folders) and *patches* (binary differences between subsequent archives).
Each archive, except the first one, has a corresponding patch file.

Archive filenames and patch filenames follow the pattern

`<name>-<version><suffix>` 

where `name` is a short string that may *only* contain *alphanumeric characters*, *underscores*, and *hyphens*, `version` is a version string according to the [PEP440][6] specification, and `suffix` is either `'.tar.gz'` or `'.patch'`.

***BEWARE***: *whitespace* is NOT allowed in the filename.

Patches are typically smaller than archives, so the tufup *client* will always attempt to update using one or more patches.
However, if the total amount of patch data is greater than the desired full archive file, a full update will be performed.

If this sounds confusing, don't worry: it is all handled internally.

## How updates are created (repo-side)

When a new release of your application is ready, the following steps need to be taken to enable clients to update to that new release:

1. Create an application archive for the new release.
2. Create a patch from the current archive to the new archive.
3. Add hashes for the newly created archive file and patch file to the `tuf` metadata.
4. Sign the modified `tuf` metadata files.
5. Upload the new target files, i.e. archive and patch, and the updated metadata files, to the update server.

The `tufup.repo` module and the `tufup` CLI provide convenient ways to streamline steps 1 to 4, based on the `tuf` [basic repo example][7].
Step 5 is not covered by `tufup`, as it depends on the implementation.

The signed metadata and hashes ensure both authenticity and integrity of the update files (see [tuf docs][2]).
In order to sign the metadata, we need access to the private key files for the applicable `tuf` roles.

## How updates are applied (client-side)

By default, updates are applied by copying all files and folders from the latest archive to the current app installation directory.

Here's what happens during the update process:

- The latest archive is either downloaded in full, as described above, or it is derived from the current archive by applying one or more downloaded patches.
- Once the latest archive is available on disk, it is decompressed to a temporary directory.
- A default install script is then started, which copies the new files and folders from the temporary directory to the current app installation directory. On Windows, this script is started in a new process, after which the currently running process will exit.
- Alternatively, you can specify a custom install script to do whatever you want with the new files.

The default install script accepts an optional `purge_dst_dir` argument, which will cause *ALL* files and folders to be deleted from the app installation directory, before moving the new files into place.
This is a convenient way to remove any stale files and folders from the app installation directory.

>**WARNING**: The `purge_dst_dir` option should *only* be used if the app is properly installed in its *own separate* directory.
If this is not the case, for example if the app is running from the Windows `Desktop` directory, any *unrelated* files or folders in this directory will also be deleted! 

## App versions and release channels

When adding an application bundle to your `tufup` repository, you need to specify an app version string.
This version string is used in the archive filename, and must be [PEP440][18] compliant (internally we use [`packaging.version.Version`][20]).

The `tufup` client inspects these version strings to determine if updates are available.

By default, when the `tufup` client looks for updates, it only includes final releases.
Pre-releases are filtered out, unless you explicitly specify a "pre-release" channel.
Refer to the [`Client.check_for_updates()`][21] method for details:

> If `pre` is specified, pre-releases are included, down to the specified level. 
> Pre-release identifiers follow the PEP440 specification, i.e. `'a'`, `'b'`, or `'rc'`, for alpha, beta, and release candidate, respectively.

For example, suppose your latest final-release is `1.3.0`, and your latest pre-release is `2.0.0a3`. 
An app in the field still has old version `1.0.0`. 
If this app checks either the default channel, the release-candidate (`'rc'`) channel, or the beta (`'b'`) channel, it finds version `1.3.0` available.
If the app checks the alpha channel (`'a'`), it finds `2.0.0a3`.

Just to be clear: `tufup` assumes a typical linear release history without branching, so

```none
0.0 < 0.1a < 0.1b < 0.1rc < 0.1rc1 < 0.1 < ...
```

## Migrating from other update frameworks

Here's one way to migrate from another update framework, such as `pyupdater`, to `tufup`:

1. Add `tufup` to your main application environment as a core dependency, and move `pyupdater` from core dependencies to development dependencies.
2. Replace all `pyupdater` client code (and configuration) in your application by the `tufup` client.
3. Initialize the `tufup` repository, so the root metadata file `root.json` exists.
4. Modify your PyInstaller `.spec` file (from PyUpdater) to ensure that the `root.json` file is included in your package.
5. Build, package, and sign using `pyupdater`, and deploy to your server, as usual. 
This ensures that your `pyupdater` clients currently in the field will be able to update to the new `tufup` client.
6. From here on, new updates will be deployed using `tufup`.
7. If you want to enable a patch update from the `pyupdater` version to the new `tufup` version, extract the latest PyUpdater archive and add the resulting bundle to the `tufup` repository. 
8. To skip patch creation, just create a new app bundle and add that to the `tufup` repository. 
9. BEWARE: Keep the `pyupdater` repository in place as long as necessary to allow all clients to update.
10. From now on, build, package, sign and deploy using `tufup`, as described elsewhere in this document.

## Platform support

The `tufup.client` tools are aimed primarily at **Windows** and **macOS** applications, whereas the `tufup.repo` tools are platform independent, as `tufup.repo` is just a thin layer on top of `python-tuf`. 

Although `tufup.client` could also be used for Linux applications, those are probably better off using native packaging solutions, or solutions such as Flatpak or Snapcraft. 
Read the [Python packaging overview][8] for more information.

Platform dependence for `tufup.client` is related to file handling and process handling during the installation procedure, as can be seen in [tufup.utils.platform_specific][12].
A custom, platform *de*pendent, installation procedure can be specified via the optional `install` argument for the `Client.update()` method.



[1]: https://github.com/theupdateframework/python-tuf
[2]: https://theupdateframework.io/
[3]: https://github.com/Digital-Sapphire/PyUpdater/
[4]: https://theupdateframework.io/overview/#software-updates-101
[5]: https://peps.python.org/pep-0458/
[6]: https://peps.python.org/pep-0440/
[7]: https://github.com/theupdateframework/python-tuf/blob/develop/examples/repo_example/basic_repo.py
[8]: https://packaging.python.org/en/latest/overview/
[9]: https://pythonhosted.org/not-so-tuf/
[10]: https://github.com/dennisvang/tufup-example
[11]: https://theupdateframework.io/metadata/
[12]: https://github.com/dennisvang/tufup/blob/master/src/tufup/utils/platform_specific.py
[13]: https://stackoverflow.com/questions/ask
[14]: https://github.com/dennisvang/tufup/issues
[15]: https://theupdateframework.io/overview/#software-updates-101
[16]: https://theupdateframework.io/security/
[17]: https://github.com/Digital-Sapphire/PyUpdater#this-is-the-end
[18]: https://peps.python.org/pep-0440/
[19]: https://peps.python.org/pep-0440/#public-version-identifiers
[20]: https://packaging.pypa.io/en/stable/version.html#packaging.version.Version
[21]: https://github.com/dennisvang/tufup/blob/master/src/tufup/client.py
[22]: https://github.com/dennisvang/tufup/discussions/new?category=q-a
