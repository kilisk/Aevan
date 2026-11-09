# Aevan on Homebrew

Aevan is distributed as a **Homebrew cask**, not a formula. The macOS artifact
is a drag-install `.dmg` containing `/Applications/Aevan.app` and an
`Applications` symlink. A cask models that kind of prebuilt app bundle; a
formula would build from source and would not reproduce the image layout.

The cask lives in this repository at [Casks/aevan.rb](../Casks/aevan.rb) and
installs the `.dmg` attached to the matching GitHub release, verifying its
SHA-256. The `.pkg` is still published for the CLI/system install.

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

The DMG is the same one documented in
[INSTALL.md](INSTALL.md#macos-dmg-recommended-open-drag-launch):

| Path | Contents |
| --- | --- |
| `/Applications/Aevan.app` | GUI bundle with the daemon embedded in `Contents/MacOS/` |

The DMG and app are unsigned and not notarised (the app is ad-hoc signed only),
so Gatekeeper warns on first launch. The cask uninstall quits the app, unloads
the daemon label if present, and removes the app plus the support files listed
in the cask, including `~/Library/Application Support/aevan`. If you want to
keep profiles, copy that directory before uninstalling. The cask does not
install `aevan`, `aevand` or `aevan-uninstall` on `PATH`; use the `.pkg` for
that.

## Updating the cask for a release

The cask has two values that must match the release the maintainer is
publishing:

```ruby
version "0.2.4"
sha256 "0000000000000000000000000000000000000000000000000000000000000000"
```

The checked-in checksum is a placeholder because the first real DMG is produced
by the macOS CI job. Replace it before publishing the cask; `brew` will refuse
to install until it matches the downloaded image.

The asset name contains a literal `+` (`arm64+x86_64`); the cask URL encodes it
as `%2B`. Keep that encoding: a literal `+` in the download path is not
reliable and GitHub returned 504 when it was tested.

When publishing a new version:

1. Attach the new `aevan-<version>-arm64+x86_64.dmg` (and the `.pkg`) to the
   GitHub release.
2. Download that exact DMG and compute its checksum:

   ```sh
   shasum -a 256 aevan-<version>-arm64+x86_64.dmg
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
