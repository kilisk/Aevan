# Aevan 0.2.0 — a clean-room Ivanti Secure Access client

> **Aevan is the product and project name.** The binaries and commands are
> `aevan`, `aevand` and `aevan-gui`; the crates, control pipe, scheduled task and
> systemd unit use the `aevan` names.

A from-scratch Rust client for Ivanti Secure Access Network Connect gateways: password + TOTP login,
the binary oNCP handshake, ESP over UDP 4500, split routes and DNS, server-driven rekey, and clean
teardown.

**This is a pre-release.** The packages are unsigned and not notarised, and the installers have not been
exercised on pristine machines.

## Rebrand and icons

- The project is now called **Aevan**; every binary and command uses the new
  name (`aevan`, `aevand`, `aevan-gui`).
- `Aevan-1024.ico` is embedded in the PE of `aevan.exe`, `aevand.exe` and
  `aevan-gui.exe`, and the MSI uses it for Add/Remove Programs and the Start
  menu shortcut.
- The tray/menu-bar uses the supplied `Aevan-64.png` (`aevan.png` in the crate).
- macOS ships `Aevan.app` with an `AppIcon.icns`; Linux installs hicolor PNGs
  and `aevan.desktop`.

## Downloads

| OS | file | notes |
|---|---|---|
| Windows 10/11 x64 | `aevan-0.2.0-x64.msi` | per-machine install to `Program Files\aevan`; UAC required |
| Windows (portable) | `aevan-0.2.0-x64.zip` | three exes + `wintun.dll`; nothing installed |
| macOS (Apple silicon + Intel) | `aevan-0.2.0-arm64+x86_64.pkg` | universal; `/Applications/Aevan.app` + `/usr/local/bin` |
| Linux x86_64 | `aevan-0.2.0-x86_64-linux.tar.gz` | tarball with `install.sh` / `uninstall.sh` and a systemd unit |

## Install

**Windows**

```powershell
msiexec /i aevan-0.2.0-x64.msi
```

Then launch aevan from the Start menu. It starts the elevated daemon (one UAC prompt), opens the window,
and stays in the notification area when you close it. *Quit* disconnects first.

**macOS**

```sh
sudo installer -pkg aevan-0.2.0-arm64+x86_64.pkg -target /
```

The package is unsigned, so Gatekeeper will refuse it on first open; right-click → Open, or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`. The daemon needs root for `utun` and is not
started automatically — see `docs/INSTALL.md` for the LaunchDaemon opt-in.

**Linux**

```sh
tar xzf aevan-0.2.0-x86_64-linux.tar.gz && cd aevan-0.2.0-x86_64-linux
sudo ./install.sh          # does not enable or start the service
sudo ./install.sh --enable # also enables aevand.service
```

No GTK or AppIndicator dependency: the Linux build has no tray icon by design.

## What is verified

- Login against the live gateway with password + TOTP, one attempt per invocation.
- Tunnel: `10.20.0.10/32`, MTU 1396, four split routes, two DNS servers; internal DNS resolves and
  TCP connects through the tunnel.
- Idle stability past ten minutes, and a **live ESP rekey at 960 s** (the gateway sends KMP 302 with
  new outbound keys; the tunnel survived past 26 minutes).
- Crash recovery: a hard kill leaves a journal that the next start rolls back idempotently.

## Known limitations

- Unsigned binaries: SmartScreen and Gatekeeper warnings are expected.
- Install/uninstall/upgrade paths are authored and validated as MSI/pkg but have not been run on a clean
  VM. The Linux `.deb`/`.rpm` recipes are templates and untested.
- The macOS menu-bar item compiles in CI but has not been run on Apple hardware.
- No IF-T/TLS (`M6`) transport: this is the Network Connect path only.
- Rekey behaviour is inferred from the reference implementation and one live observation.
