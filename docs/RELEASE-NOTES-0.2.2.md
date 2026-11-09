# Aevan 0.2.2

Aevan is an independent, clean-room Rust client for Ivanti Secure Access gateways that speak the
**Network Connect (NC)** protocol. It contains no code, binaries, configuration or session data from
any vendor. The wire protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** The packages are unsigned and not notarised, and the installers have not been run on
pristine machines.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.2-x64.msi` (UAC required) |
| Windows (portable) | `aevan-0.2.2-x64.zip` |
| macOS (Apple silicon + Intel) | `aevan-0.2.2-arm64+x86_64.pkg` |
| Linux x86_64 | `aevan-0.2.2-x86_64-linux.tar.gz` |

`SHA256SUMS.txt` is published with every release; verify a download before running it.

## What changed in 0.2.2

- **DNS is now applied on every platform.** Windows already used `netsh`; macOS now records and sets
  the primary service's servers with `networksetup` and flushes the resolver cache, and Linux detects
  systemd-resolved (`resolvectl`), then `resolvconf`, then falls back to `/etc/resolv.conf` with a
  byte-for-byte backup that is restored on teardown. The chosen mechanism is remembered so a revert
  uses the same path, and the change is journalled like every other so a hard kill still recovers.
  macOS sets interface-wide DNS, because the gateway pushes servers without search domains — there is
  no per-domain split to honour.
- **Milestone status is documented.** [STATUS.md](STATUS.md) records, per milestone, what was actually
  exercised against a live gateway and what was only built or unit-tested.
- **IF-T/TLS assessment.** [M6-IFT.md](M6-IFT.md) explains why the second transport is a documented
  dead end rather than a half-built one.

## Install

**Windows**

```powershell
msiexec /i aevan-0.2.2-x64.msi
```

Launch **Aevan** from the Start menu: one UAC prompt starts the daemon, the window opens, closing it
leaves the app in the notification area, and *Quit* disconnects first. Opening Aevan again raises the
running window instead of starting a second copy.

**macOS**

```sh
sudo installer -pkg aevan-0.2.2-arm64+x86_64.pkg -target /
```

Unsigned, so Gatekeeper refuses it on first open: right-click → Open, or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`. The daemon needs root for `utun`; see
`docs/INSTALL.md` for the LaunchDaemon opt-in.

**Linux**

```sh
tar xzf aevan-0.2.2-x86_64-linux.tar.gz && cd aevan-0.2.2-x86_64-linux
sudo ./install.sh          # does not enable or start the service
sudo ./install.sh --enable # also enables aevand.service
```

## Known limitations

- **macOS and Linux DNS paths are unit-tested and cross-compiled, not run in a live tunnel** — the
  maintainer develops on Windows. Treat them as unproven until someone reports a real session.
- Unsigned binaries: SmartScreen and Gatekeeper warnings are expected; see `SECURITY.md`.
- No IF-T/TLS transport.
- Installers have not been exercised on clean virtual machines; the `.deb`/`.rpm` recipes are
  templates.
- The macOS menu-bar item compiles but has not been run on Apple hardware.
