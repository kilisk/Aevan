# Aevan 0.2.1

Aevan is an independent, clean-room Rust client for Ivanti Secure Access gateways that speak the
**Network Connect (NC)** protocol. It contains no code, binaries, configuration or session data from
any vendor. The wire protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** The packages are unsigned and not notarised, and the installers have not been run on
pristine machines.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.1-x64.msi` (UAC required) |
| Windows (portable) | `aevan-0.2.1-x64.zip` |
| macOS (Apple silicon + Intel) | `aevan-0.2.1-arm64+x86_64.pkg` |
| Linux x86_64 | `aevan-0.2.1-x86_64-linux.tar.gz` |

Every release publishes `SHA256SUMS.txt`; verify a download before running it.

## Install

**Windows**

```powershell
msiexec /i aevan-0.2.1-x64.msi
```

Launch **Aevan** from the Start menu: it starts the elevated daemon (one UAC prompt), opens the
window, and keeps running in the notification area when you close it. *Quit* disconnects first.

**macOS**

```sh
sudo installer -pkg aevan-0.2.1-arm64+x86_64.pkg -target /
```

The package is unsigned, so Gatekeeper refuses it on first open: right-click → Open, or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`. The daemon needs root for `utun` and is not
started automatically; see `docs/INSTALL.md` for the LaunchDaemon opt-in.

**Linux**

```sh
tar xzf aevan-0.2.1-x86_64-linux.tar.gz && cd aevan-0.2.1-x86_64-linux
sudo ./install.sh          # does not enable or start the service
sudo ./install.sh --enable # also enables aevand.service
```

## What changed in 0.2.1

- **Single instance.** Opening Aevan while it is already running raises the existing window instead of
  starting a second app and a second tray icon. The `aevan` launcher uses the same rule and returns in
  tens of milliseconds when a GUI is already up.
- **Add a profile in the GUI.** The profiles screen has an *Add profile* sheet (name, gateway URL,
  realm, username) with per-field validation, duplicate-name rejection, and an explicit note that no
  password is stored. Profiles keep no secrets, as before.
- **Public documentation.** `docs/PROTOCOL.md` describes the wire protocol from public sources
  (published endpoints, RFC 4303, the open-source openconnect reference client). The internal
  engineering notes are no longer part of the repository.
- **Windows metadata.** All three binaries carry VERSIONINFO and an `asInvoker` manifest, so they
  identify themselves as Aevan in Explorer and do not request elevation implicitly.

## What works

- Password + TOTP sign-in with exactly one authentication attempt per invocation.
- The oNCP handshake and a decoded configuration: assigned address, MTU, split routes, DNS servers.
- ESP over UDP 4500 with AES-CBC + HMAC, replay protection, keepalives, and **server-driven rekey**
  (verified against a live gateway past the 1200 s lifetime).
- A privileged daemon with a control socket, a single-connection guard, and a crash-recovery journal
  that rolls back idempotently.
- Tray/window GUI, per-user start-at-login, per-platform installers and uninstallers.

## Known limitations

- **Split DNS is not applied on macOS or Linux.** Windows applies the pushed DNS servers; on macOS and
  Linux the tunnel carries routes and traffic, but internal hostnames are not resolved through it yet.
  Those backends (scutil resolver entries; systemd-resolved/resolvconf) are the next planned work.
- Unsigned binaries: SmartScreen and Gatekeeper warnings are expected. See `SECURITY.md` for the
  false-positive position and how to verify a download.
- No IF-T/TLS (Pulse) transport; NC only.
- Install/uninstall paths are built and validated as packages but have not been exercised on clean
  virtual machines, and the Linux `.deb`/`.rpm` recipes are templates.
- The macOS menu-bar item is compiled by Apple's toolchain but has not been run on Apple hardware by
  the maintainer.
