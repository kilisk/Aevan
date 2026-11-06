# Installing Aevan

**Aevan** is the product and project name. The binaries and commands are
`aevan`, `aevand` and `aevan-gui`; the crates, control pipe, scheduled task and
systemd unit use the `aevan` names.

Aevan ships as one Windows MSI, one macOS universal package and one Linux
tarball. The CLI, daemon and GUI are the same three binaries in every package:

| Binary | Purpose |
| --- | --- |
| `aevan` (`aevan.exe`) | CLI; talks to the daemon over the local control endpoint |
| `aevand` (`aevand.exe`) | elevated daemon; owns the tunnel, routes, journal and adapter |
| `aevan-gui` (`aevan-gui.exe`) | native GUI; a daemon client, never authenticates itself |
| `wintun.dll` (Windows only) | signed WireGuard LLC L3 driver library used by `aevand` |

Version 0.2.0 is the current build.

## Package matrix

| OS | Artifact | Installer | Administrator / sudo? | Where files land |
| --- | --- | --- | --- | --- |
| Windows 10/11 x64 | `aevan-<version>-x64.msi` | `msiexec` | Yes, for the MSI | `C:\Program Files\aevan`, system `PATH`, Start menu shortcut |
| Windows 10/11 x64 | `aevan-<version>-x64.zip` | extract | No | the directory you extract |
| macOS 11+ (arm64 + x86_64) | `aevan-<version>-arm64+x86_64.pkg` | `installer` / double-click | Yes (`sudo`) | `/Applications/Aevan.app`, `/usr/local/bin`, `/Library/LaunchDaemons` |
| Linux x86_64 | `aevan-<version>-x86_64-linux.tar.gz` | `install.sh` | Yes (`sudo`) | `/usr/local/bin`, `/etc/systemd/system` |

The macOS package is **unsigned and not notarised**, and nothing in this
repository is code-signed. Gatekeeper and Windows SmartScreen will warn. The
macOS steps to open an unsigned package are in the macOS section below.

## Tray / menu-bar availability

| OS | Tray | Notes |
| --- | --- | --- |
| Windows | Yes | Dedicated `tao` event-loop thread; left-click shows the window, right-click opens the menu |
| macOS | Yes | `NSStatusItem` created on the main thread during iced setup; the menu is opened from the menu bar |
| Linux | No | Shipping a tray needs GTK/libappindicator or a StatusNotifier host; aevan deliberately has neither dependency. Linux runs window-only |

Tray creation is best-effort on macOS. If the session refuses the status item
(headless login, missing permission, API refusal), the GUI logs once at info
and runs window-only; startup never fails and the window stays fully usable.

---

## Windows MSI (recommended, per machine)

Requirements: Windows 10/11 x64 and Administrator. The MSI installs to
`C:\Program Files\aevan`, adds that directory to the **system** `PATH`, and
creates a Start menu shortcut named **Aevan** (it runs the `aevan` launcher).

Double-click the MSI, or run an elevated command prompt:

```bat
msiexec /i aevan-0.2.0-x64.msi
```

For a silent install:

```bat
msiexec /i aevan-0.2.0-x64.msi /qn
```

### First run

1. Install the MSI and leave **Start at login** enabled (the default).
2. Launch **Aevan** from the Start menu.
3. The launcher checks for the control pipe. If `aevand` is not running yet it
   starts `aevand.exe` beside it with one UAC prompt, waits up to 10 seconds for
   the pipe, then opens `aevan-gui` and returns immediately.
4. If you dismiss the UAC prompt, the daemon is not started. The GUI still opens
   and shows **Daemon unavailable** with a **Start daemon (Administrator)**
   button. It never loops the prompt.
5. Closing the window hides it; the tray icon remains, the daemon keeps running
   and the tunnel keeps working. Choose **Quit** from the tray to disconnect,
   stop a daemon the GUI started, and exit.

The binaries must stay together: `aevan.exe`, `aevand.exe`, `aevan-gui.exe` and
`wintun.dll` in one directory. If a sibling is missing, the launcher names the
exact file (`aevand.exe is missing beside aevan.exe`) instead of failing
obscurely.

### Start at login is on by default

The tunnel belongs to the user who owns the profile store at
`%APPDATA%\aevan`. A normal install registers a **per-user** scheduled task named
`Aevan`, so `aevand` is already running (elevated) at your logon. This is why a
fresh install does not ask you to start the daemon by hand.

To opt out at install time:

```bat
msiexec /i aevan-0.2.0-x64.msi INSTALL_AUTOSTART=0
```

To change it later, use **Settings → Start at login** in the GUI, or run one of
these from an elevated prompt:

```bat
aevand.exe --install-autostart
aevand.exe --remove-autostart
```

The task triggers only at the installing user's logon, runs that user's
`aevand.exe`, and uses Task Scheduler's `HighestAvailable` run level so creating
the Wintun adapter does not need a fresh UAC prompt for every connection.

The task is not a Windows service. A machine-wide LocalSystem service is
explicitly out of scope for this release: profiles and the crash journal are
per-user, so a SYSTEM service would read
`C:\Windows\System32\config\systemprofile\AppData\Roaming\aevan` instead of the
logged-in user's store, find no profiles, and any tunnel it established would
belong to SYSTEM rather than the user. A per-user elevated logon task keeps the
daemon in the same user context and profile as the CLI and GUI, while still
giving the daemon the elevation that WinTun needs.

The MSI creates the task for the user who runs the installer. Run the installer
as the user who will use the tunnel (the normal UAC elevation flow does this).
If you install with a management tool that runs as SYSTEM, pass
`INSTALL_AUTOSTART=0`; register the task later from the user's own elevated
prompt:

```bat
aevand.exe --install-autostart --user "%USERDOMAIN%\%USERNAME%"
```

`--install-autostart`, `--remove-autostart` and the MSI custom actions require
Administrator. They exit 6 when they do not have it. `aevand.exe
--autostart-status` reports `present` (exit 0), `absent` (exit 1) or an unknown
state (exit 2), and does not require elevation.

The task starts at the next logon. To start it immediately after installing,
log off and on, or run `schtasks /Run /TN aevan` from an elevated prompt.

### CLI on PATH

Yes, by choice. The MSI adds `C:\Program Files\aevan` to the system `PATH`
through a Windows Installer environment component, and removes the entry on
uninstall. A new shell is required before `aevan` resolves from `PATH`. The
Start menu shortcut runs `aevan` with no subcommand, which is the first-run
launcher. From a terminal, `aevan` still behaves as the CLI; with no subcommand
it starts the daemon if necessary and opens the GUI.

If you do not want a machine-wide `PATH` change, use the portable zip.

### Windows uninstall

Use Apps & Features, or an elevated command prompt:

```bat
msiexec /x aevan-0.2.0-x64.msi
```

The uninstall runs, in order, before removing files:

1. `aevan shutdown --if-running` as the invoking user, so the daemon disconnects
   and restores routes, DNS and the adapter (and clears its journal);
2. `aevand --recover` as the invoking user, to clear a stale crash journal if no
   daemon is running. If live state remains and recovery needs Administrator,
   the uninstall stops and reports a failure instead of silently leaving state;
3. `aevand --remove-autostart` as LocalSystem, deleting the `aevan` task.

It then removes the files, the Start menu shortcut and the system `PATH`
entry. A major upgrade keeps the task (so autostart is not lost) and stops the
old daemon before replacing the binaries.

Uninstall removes machine and per-user integration, but **it may leave
`%APPDATA%\aevan`**. That directory is your data: profiles and the crash journal.
Secrets live in Windows Credential Manager, not in that file. To remove the
user data as well:

```bat
rmdir /s /q "%APPDATA%\aevan"
```

If another user's daemon is running, uninstall stops only the invoking user's
daemon; run `aevan shutdown` as that other user first. The autostart task is for
the installing user only, so uninstall does not remove tasks that other users
created manually.

---

## Portable Windows zip (no installer, no Administrator)

The zip contains `aevan.exe`, `aevand.exe`, `aevan-gui.exe`, `wintun.dll`,
`LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT`, `LICENSE-WINTUN.txt` and
`README.md`. Extract **all** files to one directory; `wintun.dll` must be
beside `aevand.exe`. The zip does not modify `PATH`, the Start menu or autostart.

From that directory:

```bat
aevan.exe --version
aevan.exe doctor
```

To register autostart for a portable extraction, run an elevated prompt from
the extraction directory:

```bat
aevand.exe --install-autostart
```

The task records the current `aevand.exe` path. If you move or delete the
extraction directory, re-run the command from the new path (or
`aevand.exe --remove-autostart` first). Portable autostart is therefore best
used from a stable directory.

---

## macOS package

> This package is **unsigned and not notarised**. Gatekeeper will warn on first
> use. It is built and published as-is by CI; there is no Apple Developer ID.

Requirements: macOS 11 or later; the package is universal (Apple silicon and
Intel). Installing needs `sudo` because it writes `/Applications`,
`/usr/local` and `/Library`.

```sh
sudo installer -pkg aevan-0.2.0-arm64+x86_64.pkg -target /
```

or double-click the `.pkg` in Finder and authenticate.

### Opening an unsigned package anyway

macOS may say the package or app "cannot be opened because it is from an
unidentified developer". That is expected. To proceed:

1. In Finder, **Control-click** the `.pkg` and choose **Open**, then **Open**
   again in the dialog.
2. If macOS still blocks it, open **System Settings → Privacy & Security**,
   scroll to **Security**, click **Open Anyway**, authenticate, and try again.
3. For the GUI's first launch, do the same with `/Applications/Aevan.app`:
   Control-click it and choose **Open**, or use
   **System Settings → Privacy & Security → Open Anyway**.

Do not disable Gatekeeper globally. To verify the download independently:

```sh
shasum -a 256 aevan-0.2.0-arm64+x86_64.pkg
```

### What the package installs

| Path | Contents |
| --- | --- |
| `/Applications/Aevan.app` | GUI bundle (`CFBundleIdentifier` `com.github.kilisk.aevan`) |
| `/usr/local/bin/aevan` | CLI |
| `/usr/local/bin/aevand` | daemon |
| `/usr/local/bin/aevan-uninstall` | uninstaller |
| `/Library/LaunchDaemons/com.github.kilisk.aevand.plist` | opt-in boot daemon |
| `/usr/local/share/doc/aevan/` | README and licenses |

The package does **not** load or start the LaunchDaemon during install. It is
an explicit opt-in:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.github.kilisk.aevand.plist
sudo launchctl enable system/com.github.kilisk.aevand
```

The daemon then runs as `root` and reads the root profile store
(`/var/root/Library/Application Support/aevan`). If you want the GUI and CLI to
use those profiles, run them with `sudo` or set `AEVAN_CONFIG_DIR` to the same
directory. This mirrors the Windows trust model, where the daemon must own the
tunnel and the per-user store is a separate concern.

To opt out again:

```sh
sudo launchctl bootout system/com.github.kilisk.aevand
```

### macOS uninstall

Run the installed uninstaller. It stops the daemon first, so routes, DNS and
the adapter are released, then unloads the LaunchDaemon and removes files:

```sh
sudo /usr/local/bin/aevan-uninstall
```

To remove the profile store as well:

```sh
sudo /usr/local/bin/aevan-uninstall --purge
```

The uninstaller is idempotent and prints every path as `removed:` or `absent:`.
It removes:

* `/Applications/Aevan.app`
* `/usr/local/bin/aevan`, `/usr/local/bin/aevand`, `/usr/local/bin/aevan-uninstall`
* `/Library/LaunchDaemons/com.github.kilisk.aevand.plist` and its loaded state
* `/usr/local/share/doc/aevan`
* `/var/run/aevan.sock`, and the real control socket and journal under
  `~/Library/Application Support/aevan` (and `/var/root/...` when the
  LaunchDaemon ran)

Unless `--purge` is passed it deliberately keeps `~/Library/Application
Support/aevan` and `~/.config/aevan`, which contain your profiles. `--purge`
removes both for the invoking user and for root.

---

## Linux tarball

Requirements: Linux x86_64 and `sudo`. The tarball contains:

```text
aevan
aevand
aevan-gui
aevand.service
install.sh
uninstall.sh
share/applications/aevan.desktop
share/icons/hicolor/64x64/apps/aevan.png
share/icons/hicolor/128x128/apps/aevan.png
share/icons/hicolor/256x256/apps/aevan.png
share/icons/hicolor/512x512/apps/aevan.png
README.md
LICENSE
LICENSE-APACHE
LICENSE-MIT
LICENSE-WINTUN.txt
```

Extract and install:

```sh
mkdir -p aevan-0.2.0
tar -xzf aevan-0.2.0-x86_64-linux.tar.gz -C aevan-0.2.0
cd aevan-0.2.0
sudo ./install.sh            # install only; service stays disabled
sudo ./install.sh --enable   # install, enable and start aevand.service
```

`install.sh` copies the three binaries to `/usr/local/bin`, installs
`aevand.service` to `/etc/systemd/system`, copies docs to
`/usr/local/share/doc/aevan`, installs the Aevan PNGs to
`/usr/local/share/icons/hicolor/{64x64,128x128,256x256,512x512}/apps/aevan.png`
and `aevan.desktop` to `/usr/local/share/applications`, then runs
`systemctl daemon-reload`. It does **not** run `gtk-update-icon-cache` and does
**not** enable or start the service unless `--enable` is passed. The desktop
entry is `Name=Aevan`, `Exec=aevan-gui`, `Icon=aevan`.

The systemd unit runs `aevand` as `root` (it needs `/dev/net/tun`, route and DNS
changes) and uses `HOME=/root`, so the daemon's profile store is
`/root/.config/aevan`. Run the GUI/CLI as that user, or point both at one store
with `AEVAN_CONFIG_DIR`.

Linux has no tray: see the matrix above. The GUI runs window-only.

### Linux uninstall

Run the uninstaller from the extracted tarball directory:

```sh
sudo ./uninstall.sh
```

To remove the profile store as well:

```sh
sudo ./uninstall.sh --purge
```

It stops the daemon first (`aevan shutdown --if-running`), retries journal
recovery, disables and removes `aevand.service`, runs `systemctl daemon-reload`,
and removes `/usr/local/bin/{aevan,aevand,aevan-gui}`,
`/usr/local/share/doc/aevan`, the Aevan icons under
`/usr/local/share/icons/hicolor`, `aevan.desktop`, the unit,
`/var/run/aevan.sock`, `/run/aevan.sock`, and the real socket and journal under
`~/.config/aevan` (and
`/root/.config/aevan`). It is idempotent and prints `removed:` or `absent:` for
every path.

Unless `--purge` is passed it keeps `~/.config/aevan` (your profiles).
`--purge` removes both the invoking user's and root's config directories.

---

## What needs Administrator or sudo and why

| Action | Windows | macOS / Linux | Why |
| --- | --- | --- | --- |
| Install / uninstall a package | Administrator | `sudo` | writes `Program Files` / `PATH`, or `/Applications`, `/usr/local`, `/Library`, `/etc/systemd/system` |
| `aevand` creating the TUN adapter | Administrator | `sudo` / root (or `CAP_NET_ADMIN`) | `WintunCreateAdapter`, `/dev/net/tun` and route/DNS changes are machine state |
| Autostart | Administrator | `sudo` | scheduled task, LaunchDaemon or systemd unit |
| `aevan doctor` | No | No | read-only probes; sends no credentials |
| `aevan status`, `aevan disconnect`, `aevan logs` | No | No | local control endpoint only |
| Uninstall | Administrator | `sudo` | stops machine-level daemon and removes system files |

With start at login disabled, launch the GUI from the Start menu (or run `aevan`
with no subcommand): the launcher starts the daemon with one UAC prompt. You can
also start it once from an elevated prompt and leave it running (it runs in the
foreground by default):

```bat
aevand.exe
```

```sh
sudo aevand
```

Then use the CLI from your normal account. `aevan connect` does **not** start the
daemon implicitly: if the pipe is unavailable it reports the reach failure and
leaves the deliberate, visible start to you (or to the `aevan` launcher).

## Verify an install

`aevan doctor` is the safe first check. It inspects DNS/TCP, the TLS chain, the
HTTP response and the TUN layer; it never authenticates and never changes
routes:

```sh
aevan doctor
aevan --json doctor
```

A real connect needs a gateway, a profile and your credentials. Nothing in this
repository supplies those:

```sh
aevan profile add work --url https://your-gateway.example/ --realm your-realm --user your-name
aevan login work
aevan connect work
aevan status
aevan disconnect
```

`aevan login` prompts for the password and, when the gateway requires it, the
one-time token. Authentication is attempted once per invocation; the client
never retries automatically. `aevan status` and `aevan logs --follow` read the
daemon's control endpoint. `aevan disconnect` tears down routes, DNS and the
adapter and lets the daemon clear its journal.

If something is left behind after a crash, run `aevan reset`; it retries the
journal rollback and prints the rolled-back, skipped-absent and failed counts.
A live rollback needs Administrator / `sudo`.

## What uninstall deliberately leaves behind

On every OS the uninstaller removes routes, DNS, the adapter, the daemon, the
journal and the control socket. It keeps the profile store unless you ask it to
purge:

| OS | Kept by default | Purge command |
| --- | --- | --- |
| Windows | `%APPDATA%\aevan` | `rmdir /s /q "%APPDATA%\aevan"` |
| macOS | `~/Library/Application Support/aevan` (and `~/.config/aevan`) | `sudo /usr/local/bin/aevan-uninstall --purge` |
| Linux | `~/.config/aevan` (the root service store is `/root/.config/aevan`) | `sudo ./uninstall.sh --purge` |
