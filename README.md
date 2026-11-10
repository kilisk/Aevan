# Aevan

**Aevan** is an independent, clean-room Rust implementation of a client for
Ivanti Secure Access gateways that speak the **Network Connect (NC)** protocol.
It is not a wrapper around any proprietary client and contains no code,
binaries, configuration or session data from Ivanti or any other vendor.

The binaries are `aevan` (CLI), `aevand` (privileged tunnel daemon) and
`aevan-gui` (native tray GUI). The crates, control pipe, scheduled task,
systemd unit and state directories all use the `aevan`/`Aevan` names. The wire
protocol is described in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## What works

- Password + TOTP sign-in with exactly one authentication attempt per
  invocation.
- The binary oNCP handshake and NCP/KMP configuration decode.
- ESP over UDP 4500, including server-driven rekey, with split routes and DNS
  applied per OS.
- A privileged daemon (`aevand`) with a local control endpoint, crash-recovery
  journal and explicit elevation at launch.
- A native GUI with a tray/menu-bar item.
- Installers: a Windows MSI and portable zip, a macOS universal `.dmg` (drag to
  Applications; also installable with the included Homebrew cask) and a macOS
  `.pkg` for the CLI/system install, and a Linux tarball plus `.deb` and `.rpm`
  packages.

## What does not work

- **No IF-T/TLS (pulse) transport.** Only the Network Connect path is
  implemented; gateways that require the pulse path are out of scope.
- **No code signing.** Binaries and packages are unsigned (the macOS app is
  ad-hoc signed only and not notarised), so Windows SmartScreen and macOS
  Gatekeeper will warn. See [SECURITY.md](SECURITY.md).
- **No commercial support.** This is an independent project; do not ask Ivanti
  for help with it.

## Provenance and legal

- Aevan is an independent, clean-room Rust implementation. The repository
  contains no code, binaries, configuration or session data from Ivanti or any
  other vendor.
- The protocol was implemented from public documentation, the gateway's
  publicly visible HTTP endpoints and form fields, the relevant RFCs (RFC 4303
  for ESP, together with RFC 2403, RFC 2404, RFC 3602 and RFC 2202 for the
  transforms and test vectors) and the open-source openconnect project, which is
  the reference client for these gateways.
- "Ivanti", "Pulse Secure" and "Secure Access" are trademarks of their
  respective owners; this project is not affiliated with, endorsed by, or
  supported by them.
- Aevan is provided as-is under the dual MIT/Apache-2.0 licence, with no
  warranty. You are responsible for complying with your employer's or
  provider's acceptable-use policy. Using an unofficial client against a
  corporate gateway may be blocked or detected by the gateway's host-checking
  features; check with your administrator before using it.

## Platform support

| Platform | Install | Status |
|---|---|---|
| **Windows 10/11** | `aevan-<version>-x64.msi` (Administrator) or portable `.zip` | Complete and live-verified: login, oNCP handshake, ESP tunnel, daemon, tray GUI, installers |
| **macOS** | `aevan-<version>-arm64+x86_64.dmg` (drag to Applications), the `.pkg` for the CLI/system install, or the Homebrew cask | The `utun` device backend is implemented and requires root (`sudo`). It builds, installs, runs the CLI, daemon and GUI, and the full route/MTU/DNS appliers exist. CI opens a real `utun` device under `sudo` with `crates/aevan-tun/examples/tun_smoke.rs`; **a full live tunnel still needs a human on macOS hardware.** |
| **Linux** | tarball + `install.sh`, `.deb` or `.rpm` | The `/dev/net/tun` device backend is implemented and requires root or `CAP_NET_ADMIN`. Packaging (tarball, `.deb`, `.rpm`) exists, and CI opens a real TUN device under `sudo` with the same smoke example. **A full live tunnel still needs a human on Linux hardware.** |

The device layer is real on all three platforms. Only the Windows data plane has been exercised end to end; macOS and Linux device creation is live-verified in CI, but their full tunnel path (handshake, ESP traffic, apply, teardown) is still a human check.

The per-capability implementation and verification state is tracked in [docs/PLATFORM-MATRIX.md](docs/PLATFORM-MATRIX.md); a capability that is implemented on one OS and stubbed or absent on another must carry a gap entry in [docs/platform-gaps.toml](docs/platform-gaps.toml), and the CI `platform-matrix` job enforces it.

## Install

Windows: use `aevan-<version>-x64.msi` (per-machine, Administrator) or the
portable `aevan-<version>-x64.zip`. macOS: open
`aevan-<version>-arm64+x86_64.dmg`, drag **Aevan** to Applications, eject and
launch; the first daemon start asks for administrator approval once. The
`aevan-<version>-arm64+x86_64.pkg` remains for the CLI/system install, and
`brew install --cask ./Casks/aevan.rb` works from a checkout. Linux: use
`aevan-<version>-x86_64-linux.tar.gz` and its `install.sh`, or the
`aevan_<version>_amd64.deb` / `aevan-<version>-1.x86_64.rpm` package.

The packages and the DMG are unsigned and not notarised. The `.deb` and `.rpm`
are built and inspected in CI, but no installer has been installed on a clean
machine. See
[docs/INSTALL.md](docs/INSTALL.md) for privileges, install locations, tray
availability, uninstall commands and the macOS Gatekeeper workaround,
[docs/PACKAGING.md](docs/PACKAGING.md) to build the artifacts yourself, and
[docs/HOMEBREW.md](docs/HOMEBREW.md) for the cask.

## Add a profile

A profile stores only the gateway URL, optional realm and optional username.
Passwords and TOTP secrets never go in a profile; the password is read from the
terminal and the TOTP secret, when enrolled, lives in the OS keyring. The realm
is optional too: the gateway advertises it, so `aevan` detects and saves it on
the first connect or login. Pass `--realm <value>` only to override detection.

```sh
aevan profile add work \
  --url https://vpn.example.com/staff \
  --user alice
aevan profile list
aevan doctor --json
aevan connect work
```

`aevan doctor` inspects the sign-in page and TLS chain without sending
credentials. `aevan connect` performs one authentication attempt and prompts for
the password and token. See [docs/CONNECT.md](docs/CONNECT.md),
[docs/DAEMON.md](docs/DAEMON.md) and [docs/GUI.md](docs/GUI.md) for the full
command and control contracts, [docs/STATUS.md](docs/STATUS.md) for what is
verified against a live gateway and what is not, and
[docs/M6-IFT.md](docs/M6-IFT.md) for why the IF-T transport is not implemented.

## Architecture

| Crate | Responsibility |
| --- | --- |
| `aevan-core` | Shared types, error/exit-code taxonomy, profile store, paths, redaction, state, time zone |
| `aevan-secrets` | OS keyring access and TOTP |
| `aevan-proto` | URL, HTTP/1.1, TLS, cookie-jar and HTML-form primitives |
| `aevan-nc` | Network Connect login, oNCP/KMP handshake, NCP config decode and ESP |
| `aevan-ift` | Feature-gated IF-T/pulse scaffold (not implemented) |
| `aevan-tun` | TUN device, route, DNS and MTU abstraction with per-OS backends and rollback |
| `aevan-daemon` | Supervisor, local control endpoint, authentication, connector, journal and elevation |
| `aevan-cli` | The `aevan` command-line binary |
| `aevan-gui` | The `aevan-gui` native tray GUI |

`aevan` and `aevan-gui` talk to `aevand` over a local control endpoint; only the
daemon applies network state, and it elevates explicitly when it is launched.

## Licence

Aevan is dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option. See [LICENSE](LICENSE) for the summary. The Windows
distribution also ships the unmodified `wintun.dll` from WireGuard LLC under its
own licence ([packaging/legal/LICENSE-WINTUN.txt](packaging/legal/LICENSE-WINTUN.txt)).
