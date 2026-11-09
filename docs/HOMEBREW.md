# Aevan on Homebrew

Aevan is distributed as a **Homebrew cask**, not a formula. The macOS artifact
is a signed-format `.pkg` (built with `pkgbuild`/`productbuild`), which installs
`/Applications/Aevan.app`, `/usr/local/bin` and a LaunchDaemon plist. A cask
models that kind of prebuilt package; a formula would build from source and
would not reproduce the package layout.

The cask lives in this repository at [Casks/aevan.rb](../Casks/aevan.rb) and
installs the `.pkg` attached to the matching GitHub release, verifying its
SHA-256.

## Install without a tap

From the root of a checkout of this repository:

```sh
brew install --cask ./Casks/aevan.rb
```

The `./` is required: without it Homebrew treats the argument as a tap-qualified
cask name instead of a local file.

To reinstall or move to a newer cask file after editing it:

```sh
brew reinstall --cask ./Casks/aevan.rb
```

A tap-less install is not checked for updates by `brew upgrade --cask`; re-run
the `brew reinstall` command above with an updated `Casks/aevan.rb`.

## What the cask installs

The `.pkg` payload is the same one documented in
[INSTALL.md](INSTALL.md#macos-package):

| Path | Contents |
| --- | --- |
| `/Applications/Aevan.app` | GUI bundle |
| `/usr/local/bin/aevan` | CLI |
| `/usr/local/bin/aevand` | daemon |
| `/usr/local/bin/aevan-uninstall` | uninstaller |
| `/Library/LaunchDaemons/com.github.kilisk.aevand.plist` | opt-in boot daemon |
| `/usr/local/share/doc/aevan/` | README and licences |

The package is unsigned and not notarised, so Gatekeeper warns on first launch.
The LaunchDaemon is installed but **not** loaded; see
[INSTALL.md](INSTALL.md#macos-package) for the `launchctl` opt-in. The cask
uninstall removes the package files; it does not remove your profile store.

## Updating the cask for a release

The cask has two values that must match the release the maintainer is
publishing:

```ruby
version "0.2.2"
sha256 "b46f885e33efe0c93c436d92ff1344025667b5ffaa65732a4afcafb5df9054b3"
```

The asset name contains a literal `+` (`arm64+x86_64`); the cask URL encodes it
as `%2B`. Keep that encoding: a literal `+` in the download path is not
reliable and GitHub returned 504 when it was tested.

When publishing a new version:

1. Attach the new `aevan-<version>-arm64+x86_64.pkg` to the GitHub release.
2. Download that exact asset and compute its checksum:

   ```sh
   shasum -a 256 aevan-<version>-arm64+x86_64.pkg
   ```

   The GitHub release API also reports it as `digest` for the asset.
3. Replace `version` and `sha256` in `Casks/aevan.rb` and commit the change.

Do not use `sha256 :no_check` and do not point the cask at a moving "latest"
URL: the checksum must belong to the published release.

## Publishing a tap later

There is **no tap repository today**; the tap-less command above is the
supported install. If you later want `brew install --cask aevan` without a
local file:

1. Create a public GitHub repository whose name starts with `homebrew-`, for
   example `homebrew-aevan` under your own account. This repository does not
   create or name one for you.
2. Put `Casks/aevan.rb` in that repository at `Casks/aevan.rb`.
3. Users then run:

   ```sh
   brew tap <owner>/aevan
   brew install --cask aevan
   ```

`brew tap <owner>/aevan` expands to the repository `homebrew-aevan`. If you
choose a different repository name, users must pass the full tap name.

Keep the cask's `version` and `sha256` in sync with the GitHub release in both
places. A tap makes `brew upgrade --cask aevan` work; a tap-less install does
not.
