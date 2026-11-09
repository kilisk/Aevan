# Aevan 0.2.4

Aevan is an independent, clean-room Rust client for Ivanti Secure Access gateways that speak the
**Network Connect (NC)** protocol. It contains no code, binaries, configuration or session data from
any vendor. The wire protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** The packages are unsigned and not notarised.

## The headline

**macOS and Linux can now create a tunnel device.** Until this release only Windows had a TUN backend;
the other two platforms could sign in and complete the handshake but failed at device creation with a
typed "unsupported" error.

- **macOS**: a `utun` control socket (`PF_SYSTEM`/`SYSPROTO_CONTROL`, `CTLIOCGINFO`, `connect`),
  interface name from `UTUN_OPT_IFNAME`, and the 4-byte address-family header handled on every packet.
- **Linux**: `/dev/net/tun` with `TUNSETIFF` and `IFF_TUN|IFF_NO_PI`, kernel-assigned `aevan%d` name.
- Both are non-blocking, hand their file descriptor to the same event wait the ESP loop uses, and map
  missing privilege to a typed error naming root/`CAP_NET_ADMIN`.

Proven, not asserted:

- Linux, locally: `tun_smoke` opened `aevan0`, reported `wait_handle 3`, exited 0, and left no
  interface behind.
- CI, both platforms: the same example runs under `sudo` with the skip flag explicitly unset, so a
  green step means a device really opened — on an Apple runner and an Ubuntu runner.

**What is still unproven:** a complete tunnel on macOS or Linux — routes, DNS and ESP carrying traffic
end to end. The appliers exist and are unit-tested, and the device now opens, but nobody has run a full
session on either OS yet. Windows remains the only platform with a verified end-to-end tunnel.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.4-x64.msi`, portable `aevan-0.2.4-x64.zip` |
| macOS (universal) | `aevan-0.2.4-arm64+x86_64.pkg` (or the Homebrew cask) |
| Linux x86_64 | `aevan-0.2.4-x86_64-linux.tar.gz`, `aevan_0.2.4_amd64.deb`, `aevan-0.2.4-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Install

**Windows** — `msiexec /i aevan-0.2.4-x64.msi`, launch Aevan from the Start menu (one UAC prompt).

**macOS** — `sudo installer -pkg aevan-0.2.4-arm64+x86_64.pkg -target /`, or
`brew install --cask ./Casks/aevan.rb`. Unsigned: right-click → Open, or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`. Creating a tunnel needs root.

**Debian/Ubuntu** — `sudo apt install ./aevan_0.2.4_amd64.deb`.
**Fedora/RHEL** — `sudo dnf install ./aevan-0.2.4-1.x86_64.rpm`.
**Portable** — the tarball's `install.sh`.

On macOS and Linux the daemon must run as root to create the device: `sudo aevand`.

## Known limitations

- A full macOS/Linux tunnel is unverified (see above). Windows is the only end-to-end proven platform.
- No installer has been run on a clean machine, including the `.deb`/`.rpm`; install, upgrade and
  uninstall remain authored-and-inspected rather than executed.
- Unsigned binaries: SmartScreen and Gatekeeper warn. See `SECURITY.md`.
- No IF-T/TLS transport (`M6-IFT.md`); no tray on Linux; the macOS menu-bar item compiles but has not
  been exercised on Apple hardware.
