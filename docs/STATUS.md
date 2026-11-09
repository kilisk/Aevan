# Milestone status

Acceptance criteria are the ones fixed at the start of the project. A milestone is only "met" when the
criterion was exercised, not when the code merely exists. Where something could not be exercised from
a Windows development host, it says so.

| M | Deliverable | Status | Evidence |
|---|---|---|---|
| **M0** | Workspace, CI matrix, `aevan doctor`, TUN smoke on three OSes | **met at the device layer** | CI runs the full matrix (ubuntu, macOS, Windows) on every push and `aevan doctor --json` reports TLS, HTTP, device and privilege state. `platform::open` now creates a real device on all three platforms: Wintun, macOS `utun`, and Linux `/dev/net/tun`. `crates/aevan-tun/examples/tun_smoke.rs` is built and run under `sudo` on ubuntu-latest and macos-latest with the skip escape hatch removed. **That CI step is the first real device proof for macOS and Linux and has not been observed from the Windows development host used to write it.** |
| **M1** | `auth-probe`, `login`, `config` without a tunnel | **met** | A live sign-in was completed against a real gateway (password + TOTP, exactly one attempt) and `aevan config --live --json` reproduced the pushed configuration: assigned address, MTU 1396, four split routes, two DNS servers. Exit 2 when a token is required, exit 3 on rejection |
| **M2** | `aevan-tun` + ESP data plane + `aevan connect` | **met on Windows; device layer implemented on macOS/Linux** | On Windows a live tunnel carried traffic (assigned `/32` on the adapter, all four routes on-link, both DNS servers applied, internal name resolved and a TCP connection through the tunnel succeeded); teardown left no route, DNS or adapter residue. Keepalive and liveness fixes were proven by a ten-minute idle session, and the ESP data plane was later made non-blocking and batched after measured latency and packet loss. On macOS and Linux the `utun`/`tun` device now opens under root and the route/DNS/MTU appliers are unit-tested, but a full tunnel on those OSes still needs a human on real hardware (see below) |
| **M3** | Daemon, control socket, `status/disconnect/logs`, exit codes, single-attempt guard | **met** | `connect` through the daemon, then `status --json` from a second shell (address, MTU, routes, DNS, bytes both ways, uptime); a second `connect` exits 5 without touching the gateway; a hard kill leaves a journal that the next start rolls back idempotently (`skipped_absent`, journal removed) |
| **M4** | GUI, tray, notifications, TOTP enrolment; A3 footprint | **met on Windows, compiled on macOS** | Window client with tray menu, notifications, TOTP enrolment and now profile creation; closing hides to tray, Quit disconnects first; a second launch raises the existing window (97 ms, one process). Footprint: `aevan-gui` ≈ 12 MB, install ≈ 5.4 MB, inside the ≤ 15 MB GUI and ≤ 25 MB install targets. The macOS menu-bar item compiles and is clippy-clean for `aarch64-apple-darwin` but has not been run on Apple hardware |
| **M5** | Packaging for Windows, macOS, Linux + install docs | **built and published; install unverified on clean VMs** | CI produces MSI + portable zip, universal `.pkg` with `Aevan.app` and `AppIcon.icns`, and Linux tarball, `.deb` and `.rpm`; all are attached to releases with `SHA256SUMS.txt`. The MSI is ICE-validated, and the `.deb`/`.rpm` are inspected with `dpkg-deb` and `rpm -qip/-qlp` in CI. A tap-less Homebrew cask installs the `.pkg`. **No installer has been run on a pristine machine**: install, upgrade and uninstall are authored and reviewed, not executed. The `.deb`/`.rpm` have never been installed by anyone, and there is no Homebrew tap |
| **M6** | IF-T/TLS transport behind a feature flag | **documented dead end, not implemented** | See [M6-IFT.md](M6-IFT.md). The crate is a feature-gated stub. The NC transport is complete; IF-T/TLS has no public specification and its handshake is vendor-specific, so a cooperating gateway would be required to develop against it |

## Cross-cutting status

| Area | State |
|---|---|
| Authentication | One attempt per invocation, enforced in code; password read with echo off or from stdin, never argv/env/log; profiles store no secrets |
| ESP | AES-CBC + HMAC, replay window, keepalives, server-driven rekey verified live past the 1200 s lifetime |
| Crash recovery | Journal written before the first change, replayed idempotently on start, `aevan reset` / `aevand --recover` for manual recovery |
| DNS | Implemented for all three platforms (Windows netsh; macOS `networksetup`, interface-wide; Linux systemd-resolved → resolvconf → `resolv.conf` fallback with backup). The macOS and Linux TUN devices now exist, so their DNS paths are reachable when the process runs as root. **Only the Windows path has been exercised in a live tunnel**; the macOS/Linux DNS code is unit-tested and the device opens in CI, but the full apply/teardown cycle there still needs a human |
| Security | No secrets in logs, dumps or `status`; credentials cross an owner-only control pipe; the GUI never opens a socket of its own |
| Signing | **Not done.** Binaries are unsigned; see `SECURITY.md` for the false-positive position |

## What is knowingly incomplete

1. **A full tunnel on macOS and Linux has not been verified by a human.** The device backends are
   implemented and CI opens a real `utun` and `/dev/net/tun` device under `sudo` (the `tun_smoke`
   example). What is still unproven on those OSes is the complete cycle on real hardware: handshake,
   ESP traffic through the device, address/MTU/route/DNS application, and teardown restoring the
   machine. The appliers were already unit-tested and the device layer now exists, but no live
   end-to-end session has been run there.
2. **Installer execution.** MSI, `.pkg`, tarball, `.deb`, `.rpm` and the Homebrew cask: built,
   inspected (where noted) and published — never installed on a clean VM. The `.deb` and `.rpm`
   are new CI artifacts and have not been installed by anyone. Upgrade and uninstall behaviour is
   the least-tested part of the project.
3. **Code signing / notarisation.** The real fix for scanner false positives. Deferred by decision.
4. **IF-T/TLS.** Not implemented; see the assessment.
5. **Tray on Linux.** Deliberately absent to avoid a GTK dependency; the window still works.
