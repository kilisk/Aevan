# Packaging Aevan

**Aevan** is the product and project name; the binaries and commands are
`aevan`, `aevand` and `aevan-gui`, and the install directories use `aevan`
paths.

This document describes how the release artifacts are built, what they
contain, how the version is bumped, and which parts are **not** tested.

The Windows package is a WiX Toolset v7 MSI built with `wix build` (the v4+
command-line syntax, not WiX v3 `candle`/`light`). There is no `makensis`, Inno
Setup or Chocolatey dependency.

## Prerequisites

- Rust stable with `cargo` and `rustfmt`/`clippy` for the preferred checks
- `just` (the recipes use bash on every platform; on Windows that is Git Bash)
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

and uses it for `aevan-<version>-x64.msi`, `aevan-<version>-x64.zip` and
`aevan-<version>-x86_64-linux.tar.gz`.

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

`just dist` dispatches to `dist-windows` on Windows and `dist-linux` elsewhere.
`dist-windows` runs `cargo build --release` and then the equivalent of:

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

To inspect the MSI without installing it:

```bat
wix msi decompile -o target/dist/aevan-decompiled.wxs target/dist/aevan-0.2.0-x64.msi
wix msi decompile -data -o target/dist/aevan-data.xml target/dist/aevan-0.2.0-x64.msi
wix msi validate target/dist/aevan-0.2.0-x64.msi
```

`-data` writes a zip whose `wix-wid.xml` contains the File table. The current
build has these File rows:

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
`install.sh`, `uninstall.sh`, `share/applications/aevan.desktop`,
`share/icons/hicolor/{64x64,128x128,256x256,512x512}/apps/aevan.png`, license
files and README. It runs in the CI `package-linux` job. `install.sh` copies
the binaries to `/usr/local/bin`, installs the unit, the PNGs and the desktop
entry (and never runs `gtk-update-icon-cache`), but leaves the service disabled
unless `--enable` is passed. `uninstall.sh` reverses that and keeps
`~/.config/aevan` unless `--purge` is passed.

`just deb` and `just rpm` are **skeletons** driven by the same version
substitution. Their templates are `packaging/linux/control.in` and
`packaging/linux/aevan.spec`. They require `dpkg-deb` / `rpmbuild`, refuse to
run without them, and have not been built or installed on this host.

## CI

`.github/workflows/ci.yml` keeps the existing `test` matrix (Ubuntu, Windows,
`macos-latest`) and adds:

- `package-windows`: `needs: test`, installs Rust, `just` and WiX v7, accepts
  the OSMF EULA, fetches Wintun, runs `just dist-windows`, validates the MSI
  and uploads `target/dist/*.msi` and `*.zip` as `aevan-windows-x64`.
- `package-macos`: `needs: test`, runs `just dist-macos` on `macos-latest` and
  uploads `target/dist/*.pkg` plus `target/dist/Aevan.app` as
  `aevan-macos-universal`.
- `package-linux`: `needs: test`, runs `just dist-linux` and uploads the tar as
  `aevan-linux-x64`.

The packaging jobs do not publish or sign anything; they upload workflow
artifacts.

## What is not tested

Be explicit about this when handing the build to someone:

- **The MSI was built and validated on this host, but not installed.** The
  build environment has no Administrator. Install, uninstall, upgrade,
  rollback, the scheduled-task custom actions, the `aevan shutdown` action and
  the uninstall recovery action were not exercised here. `wix msi validate`
  checks the database structure, not runtime behaviour.
- **The Linux tarball is built by CI, not by the Windows build host.** It has
  not been installed or run from the archive in this environment.
- **The macOS universal `.app`/`.pkg` is built only by CI.** It could not be
  cross-compiled on the Windows host (no Apple SDK); CI compiles and packages
  it with `macos-latest`. The `actool`/`iconutil` icon path can therefore only
  be proven in CI.
- **The `.deb` and `.rpm` recipes are untested skeletons.** They have not been
  built on this host and their dependency lists are incomplete (for example
  `aevan-gui` needs a working wgpu/Wayland or X11 stack, and the daemon needs
  permission to create `/dev/net/tun`).
- **Nothing is code-signed.** Windows SmartScreen and macOS Gatekeeper will
  warn; the MSI is not Authenticode-signed and there is no notarization.
- **The MSI does not install a Windows service.** That is intentional, not a
  missing piece; see the trust model above.
