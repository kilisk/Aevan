# Milestone status

Acceptance criteria are the ones fixed at the start of the project. A milestone is only "met" when the
criterion was exercised, not when the code merely exists. Where something could not be exercised from
a Windows development host, it says so.

## v0.2.20 verification

[GitHub Actions run 44735038224](https://github.com/kilisk/Aevan/actions/runs/44735038224)
passed the Windows, macOS and Ubuntu test and packaging jobs. The CI smoke
tests below do not sign in to a real VPN gateway.

| Environment | Verified | Not verified or still open |
| --- | --- | --- |
| **Ubuntu 26.04 under WSL2** (live, November 20, 2026) | Tunnel MTU 1214 on a 1280-byte outer path, four split routes, ICMP, direct UDP DNS and an authenticated SSH session. With an explicit server address, curl reached TLS certificate validation. | Curl rejected the self-signed certificate and did not receive an HTTP response. Aevan applied systemd-resolved link settings, but ordinary name lookups still went to the WSL DNS proxy. A later session disconnected after the peer closed the control channel during rekey; uninterrupted traffic across rekey is not verified. |
| **Ubuntu CI** | Real TUN packet I/O and route setup/cleanup in isolation. Headless `.deb` install, explicit systemd start, status from a normal user and package removal. RPM metadata and contents inspected. | Live gateway traffic on non-WSL Linux, boot-time startup and RPM/tarball installation. |
| **macOS CI** | Native tests, universal packages, DMG validation, real `utun` open and nonblocking empty read, root daemon control socket reachable from a normal user. | Live gateway traffic, interactive privileged-helper approval and startup, Console.app logging, and launching the CLI from a clean installation. |
| **Windows CI and earlier live testing** | v0.2.20 tests and MSI validation. Earlier builds verified live login, tunnel traffic, system DNS and teardown. | No new live Windows gateway run for v0.2.20 or clean-machine installer lifecycle in this run. |

## Milestones

| M | Deliverable | Status | Evidence |
|---|---|---|---|
| **M0** | Workspace, CI matrix, `aevan doctor`, TUN smoke on three OSes | **met at the device layer** | CI tests all three platforms; Ubuntu and macOS CI exercise real tunnel devices under `sudo`. Wintun was exercised in earlier live Windows testing. |
| **M1** | `auth-probe`, `login`, `config` without a tunnel | **met** | A live sign-in was completed against a real gateway (password + TOTP, exactly one attempt) and `aevan config --live --json` reproduced the pushed configuration: assigned address, MTU 1396, four split routes, two DNS servers. Exit 2 when a token is required, exit 3 on rejection |
| **M2** | `aevan-tun` + ESP data plane + `aevan connect` | **Live transport verified on Windows and WSL2** | Earlier Windows runs verified system DNS and teardown. v0.2.20 WSL2 verified live IP traffic but not ordinary hostname resolution or sustained traffic through rekey. macOS has native CI smoke coverage only. |
| **M3** | Daemon, control socket, `status/disconnect/logs`, exit codes, single-attempt guard | **met** | `connect` through the daemon, then `status --json` from a second shell (address, MTU, routes, DNS, bytes both ways, uptime); a second `connect` exits 5 without touching the gateway; a hard kill leaves a journal that the next start rolls back idempotently (`skipped_absent`, journal removed) |
| **M4** | GUI, tray, notifications, TOTP enrolment; A3 footprint | **met on Windows, compiled on macOS** | Window client with tray menu, notifications, TOTP enrolment and now profile creation; closing hides to tray, Quit disconnects first; a second launch raises the existing window (97 ms, one process). Footprint: `aevan-gui` ≈ 12 MB, install ≈ 5.4 MB, inside the ≤ 15 MB GUI and ≤ 25 MB install targets. The macOS menu-bar item compiles and is clippy-clean for `aarch64-apple-darwin` but has not been run on Apple hardware |
| **M5** | Packaging for Windows, macOS, Linux + install docs | **built and published; Debian install smoke passed** | Ubuntu CI installed and removed the `.deb` and verified systemd startup. MSI, DMG and RPM checks are not clean-machine install tests. |
| **M6** | IF-T/TLS transport behind a feature flag | **documented dead end, not implemented** | See [M6-IFT.md](M6-IFT.md). The crate is a feature-gated stub. The NC transport is complete; IF-T/TLS has no public specification and its handshake is vendor-specific, so a cooperating gateway would be required to develop against it |

## Cross-cutting status

| Area | State |
|---|---|
| Authentication | One attempt per invocation, enforced in code; password read with echo off or from stdin, never argv/env/log; profiles store no secrets |
| ESP | AES-CBC + HMAC, replay window and keepalives. Earlier Windows testing verified live rekey; uninterrupted traffic across rekey on WSL2 is not verified. |
| Crash recovery | Journal written before the first change, replayed idempotently on start, `aevan reset` / `aevand --recover` for manual recovery |
| DNS | Live Windows system DNS verified earlier. WSL2 verified systemd-resolved link configuration and direct DNS, but not ordinary application DNS. macOS and the other Linux DNS backends still need live validation. |
| Security | No secrets in logs, dumps or `status`; credentials cross an owner-only control pipe; the GUI never opens a socket of its own |
| Signing | **Not done.** Binaries are unsigned; see `SECURITY.md` for the false-positive position |

## What is knowingly incomplete

1. **Live VPN coverage.** macOS and non-WSL Linux need live gateway runs. WSL2 still needs
   ordinary hostname resolution and sustained traffic across rekey validated.
2. **Installer lifecycle.** The headless `.deb` install/start/remove smoke is verified. Clean
   Windows and macOS installs, Linux RPM/tarball installs and upgrade coverage remain gaps.
3. **Code signing / notarisation.** The real fix for scanner false positives. Deferred by decision.
4. **IF-T/TLS.** Not implemented; see the assessment.
5. **Tray on Linux.** Deliberately absent to avoid a GTK dependency; the window still works.
