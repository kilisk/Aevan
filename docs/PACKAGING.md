# Packaging Aevan

**Aevan** is the product and project name; the binaries and commands are
`aevan`, `aevand` and `aevan-gui`, and the install directories use `aevan`
paths.

This document describes how the release artifacts are built, what they
contain, how the version is bumped, and which parts are **not** tested.

The release now has seven downloadable artifacts: the Windows MSI and portable
zip, the macOS universal `.pkg` and its Homebrew cask, and the Linux tarball,
`.deb` and `.rpm`. The Windows package is a WiX Toolset v7 MSI built with
`wix build` (the v4+ command-line syntax, not WiX v3 `candle`/`light`). There is
no `makensis`, Inno Setup or Chocolatey dependency.

## Prerequisites

- Rust stable with `cargo` and `rustfmt`/`clippy` for the preferred checks
- `just` (the recipes use bash on every platform; on Windows that is Git Bash).
  CI installs the pinned `just 1.59.0` with `cargo install --locked`.
- `dpkg-deb` (the `dpkg` package on Debian/Ubuntu) to build the `.deb`
- `rpmbuild` (the `rpm` package on Debian/Ubuntu) to build the `.rpm`
- WiX Toolset v7, for example:
  ```bat
  dotnet tool install --global wix --version 7.0.1
  ```
- The pinned Wintun 0.14.1 DLL in `target\release\wintun.dll`
- `pwsh` or Windows PowerShell 5.1 for the zip step

### WiX v7 OSMF EULA

WiX v7 refuses to build until you accept the Open Source Maintenance Fee
(OSMF) EULA. Without acceptance the build fails with:

```text
error WIX7015: You must accept the Open Source Maintenance Fee (OSMF) EULA to use WiX Toolset v7.
For instructions, see https://wixtoolset.org/osmf/
```

Read <https://wixtoolset.org/osmf/> and then accept it once for your user:

```bat
wix eula accept wix7
```

`just wix-eula` runs the same command. CI accepts it explicitly in the
packaging job.

### Wintun

The build must not produce an MSI that cannot work. `just dist-windows` checks
for `target\release\wintun.dll` and fails with instructions if it is missing.
Arrange the pinned release with:

```bat
just fetch-wintun
```

The script downloads `https://www.wintun.net/builds/wintun-0.14.1.zip`, takes
`wintun\bin\amd64\wintun.dll`, verifies SHA-256
`E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`, and writes
it to `target\release\wintun.dll`. The prebuilt-binary license is reproduced in
`packaging/legal/LICENSE-WINTUN.txt` and shipped in both artifacts. aevan uses
only the documented Wintun API.

## Version: one source of truth

The only version that is edited is `[workspace.package] version` in the root
`Cargo.toml`:

```toml
[workspace.package]
version = "0.2.0"
```

Every crate uses `version.workspace = true`, so `cargo build` propagates it to
`aevan --version`, `aevand --version`, `aevan-gui --version`, the GUI banner and
the `Cargo.lock` entries. The `justfile` parses the same line:

```make
version := trim(`sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1`)
```

and uses it for `aevan-<version>-x64.msi`, `aevan-<version>-x64.zip`,
`aevan-<version>-arm64+x86_64.pkg`, `aevan-<version>-x86_64-linux.tar.gz`,
`aevan_<version>_amd64.deb` and `aevan-<version>-1.x86_64.rpm`.

The MSI `ProductVersion` is that string. Windows Installer requires a numeric
`major.minor.patch`; `just dist-windows` refuses to build a version with a
pre-release suffix. To release `0.2.0`, change the one line, rebuild, and the
MSI, zip, tar, GUI version and CLI version all move together.

The MSI uses the fresh Aevan `UpgradeCode`
(`97E628B1-458E-43F7-9722-DD29F9C222FE`) and `ProductCode="*"`, so every link
produces a new ProductCode. `<MajorUpgrade>` detects older Aevan products under
the same UpgradeCode and blocks a downgrade, making a new build a major upgrade.
The new UpgradeCode deliberately means it never upgrades an older product
install in place: uninstall that product before installing Aevan.

## Build

From the workspace root on Windows x64:

```bat
just fmt
just clippy
just test
just build
just fetch-wintun
just dist-windows
```

On Linux, the same three binary artifacts plus the two distribution packages
are built with:

```sh
just dist-linux
just deb
just rpm
```

`just dist` dispatches to `dist-windows` on Windows, `dist-macos` on macOS and
`dist-linux` elsewhere. `dist-windows` runs `cargo build --release` and then the
equivalent of:

```text
wix build -arch x64 -d Version=0.2.0 -d BinDir=target/release ^
  -d IconPath=assets/branding/Aevan-1024.ico ^
  -d LicensePath=LICENSE ^
  -d MitLicensePath=LICENSE-MIT ^
  -d ApacheLicensePath=LICENSE-APACHE ^
  -d WintunLicensePath=packaging/legal/LICENSE-WINTUN.txt ^
  -o target/dist/aevan-0.2.0-x64.msi packaging/windows/aevan.wxs
```

The zip is written with PowerShell `Compress-Archive`. Both recipes print the
artifact paths and their SHA-256 sums.

To inspect the MSI without installing it, use WiX's MSI export and validation
commands (see `wix msi --help` for the table and source export subcommands):

```bat
wix msi validate target/dist/aevan-0.2.0-x64.msi
```

The table export writes a zip whose `wix-wid.xml` contains the File table. The
current build has these File rows:

| File | Component |
| --- | --- |
| `aevan.exe` | `AevanExe` |
| `aevand.exe` | `AevandExe` |
| `aevan-gui.exe` | `AevanGuiExe` |
| `aevan.ico` | `AevanIconComponent` |
| `wintun.dll` (0.14.1.0) | `WintunDll` |
| `LICENSE` | `LicenseFile` |
| `LICENSE-MIT` | `MitLicenseFile` |
| `LICENSE-APACHE` | `ApacheLicenseFile` |
| `LICENSE-WINTUN.txt` | `WintunLicenseFile` |

`wix msi validate` passes with no ICE errors on the current build.

## What each artifact contains

### `aevan-<version>-x64.msi`

Per-machine package (`Scope="perMachine"`), installed to
`C:\Program Files\aevan`:

- `aevan.exe`, `aevand.exe`, `aevan-gui.exe`, `wintun.dll`, `aevan.ico`
- `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE` and `LICENSE-WINTUN.txt`
- `aevan.ico` is also the `ARPPRODUCTICON` (Add/Remove Programs icon)
- a Start menu shortcut named **Aevan** in a folder named **Aevan**, using the
  icon (it runs the `aevan` launcher; per-user shortcut, tracked with an HKCU
  keypath and removed on uninstall)
- a component that appends the install directory to the **system** `PATH` and
  restores the previous value on uninstall
- no `ServiceInstall`: the daemon is not a LocalSystem service

Custom actions:

| When | Action | Context |
| --- | --- | --- |
| install with `INSTALL_AUTOSTART=1` (the default; pass `0` to opt out) | `aevand --install-autostart --user <sid/user>` | deferred, LocalSystem, with rollback |
| uninstall | `aevan shutdown --if-running` | deferred, impersonating the invoking user |
| uninstall | `aevand --recover` | deferred, impersonating the invoking user |
| uninstall | `aevand --remove-autostart` | deferred, LocalSystem |

Install actions are conditioned on `NOT Installed`; uninstall actions on
`REMOVE="ALL"`. A repair (`REINSTALL`) matches neither, so no custom action
runs on repair. A rollback action is scheduled before the install action and
removes the task if a later step fails. A failure in any action makes the
install or uninstall fail rather than leaving a half-configured machine.

The trust model is deliberate. Profiles and the crash journal live in
`%APPDATA%\aevan`. A LocalSystem service would read SYSTEM's profile store
instead of the user's and would own a tunnel that the user's CLI could not
reach. The per-user `HighestAvailable` logon task is the supported primitive;
the SYSTEM service is out of scope for M5. See `docs/INSTALL.md`.

### `aevan-<version>-x64.zip`

Portable extraction, no installer, no PATH or autostart changes:

```text
aevan.exe
aevand.exe
aevan-gui.exe
wintun.dll
LICENSE
LICENSE-APACHE
LICENSE-MIT
LICENSE-WINTUN.txt
README.md
```

### macOS

`just dist-macos` builds both `aarch64-apple-darwin` and
`x86_64-apple-darwin`, joins each binary with `lipo`, and calls
`packaging/macos/build-pkg.sh`. The script creates the GUI
`Aevan.app` bundle (`CFBundleName`/`CFBundleDisplayName` `Aevan`, identifier
still `com.github.kilisk.aevan`), a component root with
`/usr/local/bin/{aevan,aevand,aevan-uninstall}` and
`/Library/LaunchDaemons/com.github.kilisk.aevand.plist`, then produces
`aevan-<version>-arm64+x86_64.pkg` with `pkgbuild` + `productbuild`. It also
leaves `target/dist/Aevan.app` for upload.

`AppIcon.icns` is built best-effort from `assets/branding/Aevan Icon.icon` with
`actool` when available; otherwise the script renders an `.iconset` from the
supplied PNGs with `sips` and runs `iconutil`. The script prints which path
ran. A missing tool or a tool failure only warns: the package still builds
without an icon and never fails because of it.

The LaunchDaemon is shipped but **not loaded** by the package. Enabling it is
an explicit `launchctl` step documented in `docs/INSTALL.md`. The package is
unsigned and not notarised; Gatekeeper will warn.

### Linux

`just dist-linux` builds the three release binaries and writes
`aevan-<version>-x86_64-linux.tar.gz` containing the binaries, `aevand.service`,
`install.sh`, `uninstall.sh`, `copyright`, `share/applications/aevan.desktop`,
`share/icons/hicolor/{64x64,128x128,256x256,512x512}/apps/aevan.png`, license
files and README. It runs in the CI `package-linux` job. `install.sh` copies
the binaries to `/usr/local/bin`, installs the unit, the PNGs and the desktop
entry (and never runs `gtk-update-icon-cache`), but leaves the service disabled
unless `--enable` is passed. `uninstall.sh` reverses that and keeps
`~/.config/aevan` unless `--purge` is passed.

#### Debian package

`just deb` builds `aevan_<version>_amd64.deb` with `dpkg-deb` alone; there is no
debhelper, lintian or dh_* dependency. The data tree is:

```text
/usr/bin/aevan
/usr/bin/aevand
/usr/bin/aevan-gui
/lib/systemd/system/aevand.service
/usr/share/applications/aevan.desktop
/usr/share/icons/hicolor/64x64/apps/aevan.png
/usr/share/icons/hicolor/128x128/apps/aevan.png
/usr/share/icons/hicolor/256x256/apps/aevan.png
/usr/share/icons/hicolor/512x512/apps/aevan.png
/usr/share/doc/aevan/README
/usr/share/doc/aevan/copyright
/usr/share/doc/aevan/LICENSE
/usr/share/doc/aevan/LICENSE-APACHE
/usr/share/doc/aevan/LICENSE-MIT
```

The control file is generated from `packaging/linux/control.in`:
`Architecture: amd64`, `Section: net`, `Priority: optional`,
`Depends: libc6, hicolor-icon-theme, systemd`, and the project maintainer
address. There are no conffiles. `postinst` runs `systemctl daemon-reload` but
does **not** enable or start `aevand.service`. `prerm` stops the unit only if it
is already enabled.

#### RPM package

`just rpm` runs `rpmbuild` on the same release tarball and produces
`aevan-<version>-1.x86_64.rpm`. The spec is
`packaging/linux/aevan.spec`. It installs the same file set as the `.deb`
(binaries, unit, desktop entry, icons, README, copyright and licenses),
declares `License: MIT OR Apache-2.0`, and requires `glibc`,
`hicolor-icon-theme` and `systemd`. `%post` only runs `systemctl daemon-reload`;
`%preun` stops `aevand.service` only if it is enabled. Neither enables or starts
the unit.

### Homebrew cask

[Casks/aevan.rb](../Casks/aevan.rb) is a cask, not a formula. It installs the
published macOS `.pkg` by URL and verifies the release asset's SHA-256. See
[docs/HOMEBREW.md](HOMEBREW.md) for the tap-less install
(`brew install --cask ./Casks/aevan.rb`) and for how to publish a tap later.
There is no tap repository today.

## CI

`.github/workflows/ci.yml` keeps the existing `test` matrix (Ubuntu, Windows,
`macos-latest`) and adds:

- `package-windows`: `needs: test`, installs Rust, pinned `just` and WiX v7,
  accepts the OSMF EULA, fetches Wintun, runs `just dist-windows`, validates the
  MSI and uploads `target/dist/*.msi` and `*.zip` as `aevan-windows-x64`.
- `package-macos`: `needs: test`, runs `just dist-macos` on `macos-latest` and
  uploads `target/dist/*.pkg` plus `target/dist/Aevan.app` as
  `aevan-macos-universal`.
- `package-linux`: `needs: test`, installs the pinned `just` and the `rpm`
  package, runs `just dist-linux`, `just deb` and `just rpm`, inspects the
  `.deb` with `dpkg-deb --info/--contents` and the `.rpm` with
  `rpm -qip/-qlp` (including path assertions), and uploads the tar, `.deb` and
  `.rpm` as `aevan-linux-x64`.

The packaging jobs do not publish or sign anything; they upload workflow
artifacts. The pinned `just` is installed with
`cargo install just --version 1.59.0 --locked` in a retry loop; no job fetches
an unversioned "latest" tool.

## Artifact status

Every artifact below is built by CI. Only the MSI, `.deb` and `.rpm` are also
inspected there. **No artifact has been installed on a clean machine**, and no
installer has been installed, upgraded or uninstalled by a user. CI inspection
proves package structure, not installation or runtime behaviour.

| Artifact | CI build | CI inspection | Installed on a clean machine |
| --- | --- | --- | --- |
| `aevan-<version>-x64.msi` | yes | `wix msi validate` | no |
| `aevan-<version>-x64.zip` | yes | no (binary VERSIONINFO only) | no |
| `aevan-<version>-arm64+x86_64.pkg` | yes | not inspected | no |
| `aevan-<version>-x86_64-linux.tar.gz` | yes | not inspected | no |
| `aevan_<version>_amd64.deb` | yes | `dpkg-deb --info/--contents` and path assertions | no |
| `aevan-<version>-1.x86_64.rpm` | yes | `rpm -qip/-qlp` and path assertions | no |
| `Casks/aevan.rb` | not built | not inspected | no (`brew install` never run) |

## Release process

1. Bump `[workspace.package] version` in `Cargo.toml`, commit, and tag the
   release. The `.deb` and `.rpm` names follow that one version.
2. Run CI and download the `aevan-windows-x64`, `aevan-macos-universal` and
   `aevan-linux-x64` workflow artifacts.
3. Create the GitHub release and attach **all** of these files:
   `aevan-<version>-x64.msi`, `aevan-<version>-x64.zip`,
   `aevan-<version>-arm64+x86_64.pkg`, `aevan-<version>-x86_64-linux.tar.gz`,
   `aevan_<version>_amd64.deb` and `aevan-<version>-1.x86_64.rpm`.
4. Publish `SHA256SUMS.txt` alongside them. The just recipes print each
   Linux artifact's sum; use `sha256sum`/`shasum -a 256` for the rest.
5. Copy [docs/RELEASE-NOTES-TEMPLATE.md](RELEASE-NOTES-TEMPLATE.md) to
   `docs/RELEASE-NOTES-<version>.md` and fill in the changes, including the new
   `.deb`, `.rpm` and cask downloads.
6. Update `version` and `sha256` in `Casks/aevan.rb` from the published `.pkg`
   asset, as described in [docs/HOMEBREW.md](HOMEBREW.md).

## What is not tested

Be explicit about this when handing the build to someone:

- **The MSI was built and validated on this host, but not installed.** The
  build environment has no Administrator. Install, uninstall, upgrade,
  rollback, the scheduled-task custom actions, the `aevan shutdown` action and
  the uninstall recovery action were not exercised here. `wix msi validate`
  checks the database structure, not runtime behaviour.
- **The portable zip has not been extracted and run from the archive on a clean
  machine.**
- **The Linux tarball is built by CI, not by the Windows build host.** It has
  not been installed or run from the archive in this environment.
- **The macOS universal `.app`/`.pkg` is built only by CI.** It could not be
  cross-compiled on the Windows host (no Apple SDK); CI compiles and packages
  it with `macos-latest`. The `actool`/`iconutil` icon path can therefore only
  be proven in CI. The package has never been installed on a clean Mac.
- **The `.deb` and `.rpm` are now built in CI, but they have never been
  installed by anyone.** CI is their first real build and its `dpkg-deb` /
  `rpm -qip/-qlp` checks prove package structure only. The recipes cannot be
  built on the Windows development host (no `dpkg-deb` or `rpmbuild`), so local
  inspection is limited to the file tree and metadata templates. Their
  dependency lists are deliberately minimal: the packages declare `libc6`,
  `hicolor-icon-theme` and `systemd` (or the RPM equivalents) but not the
  wgpu/Wayland/X11 stack the GUI uses or the `/dev/net/tun` permission the
  daemon needs.
- **The Homebrew cask has never been installed.** It is a checked-in Ruby file
  pointing at the published `.pkg`; CI does not run `brew`.
- **Nothing is code-signed.** Windows SmartScreen and macOS Gatekeeper will
  warn; the MSI is not Authenticode-signed and there is no notarization.
- **The MSI does not install a Windows service.** That is intentional, not a
  missing piece; see the trust model above.
