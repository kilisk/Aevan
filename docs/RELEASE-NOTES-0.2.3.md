# Aevan 0.2.3

Aevan is an independent, clean-room Rust client for Ivanti Secure Access gateways that speak the
**Network Connect (NC)** protocol. It contains no code, binaries, configuration or session data from
any vendor. The wire protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** The packages are unsigned and not notarised, and no installer has been run on a
pristine machine.

## Downloads

| OS | file | built in CI | installed by anyone |
|---|---|---|---|
| Windows 10/11 x64 | `aevan-0.2.3-x64.msi` | yes | no |
| Windows (portable) | `aevan-0.2.3-x64.zip` | yes | n/a |
| macOS (universal) | `aevan-0.2.3-arm64+x86_64.pkg` | yes | no |
| Linux x86_64 | `aevan-0.2.3-x86_64-linux.tar.gz` | yes | no |
| Debian / Ubuntu | `aevan_0.2.3_amd64.deb` | yes | no |
| Fedora / RHEL | `aevan-0.2.3-1.x86_64.rpm` | yes | no |

`SHA256SUMS.txt` covers every asset.

## What changed in 0.2.3

- **Real `.deb` and `.rpm`.** Both are now built in CI with `dpkg-deb` and `rpmbuild` from the same
  file set the tarball installs: binaries in `/usr/bin`, `aevand.service`, the desktop entry and the
  hicolor icons. `postinst` reloads systemd but does not enable or start the unit; `prerm` stops it if
  enabled. Previously these were untested templates.
- **Homebrew cask.** `Casks/aevan.rb` installs the published `.pkg` and uninstalls by `pkgutil` id.
  Install without a tap: `brew install --cask ./Casks/aevan.rb`.
- **CI no longer fetches `just` at "latest".** The installer is pinned, so a transient CDN error can
  no longer fail a packaging job.

## Install

**Windows** — `msiexec /i aevan-0.2.3-x64.msi`, then launch Aevan from the Start menu (one UAC prompt).

**macOS** — `sudo installer -pkg aevan-0.2.3-arm64+x86_64.pkg -target /`, or the cask above. Unsigned:
right-click → Open, or `xattr -dr com.apple.quarantine /Applications/Aevan.app`.

**Debian / Ubuntu** — `sudo apt install ./aevan_0.2.3_amd64.deb` (or `dpkg -i`), then
`sudo systemctl enable --now aevand` if you want the daemon at boot.

**Fedora / RHEL** — `sudo dnf install ./aevan-0.2.3-1.x86_64.rpm`, same service step.

**Portable** — the tarball's `install.sh` / `uninstall.sh` remain the no-packaging path.

## Known limitations

- **No installer has been installed on a clean machine**, including the new `.deb` and `.rpm`: they are
  built and inspected in CI, but install, upgrade and uninstall remain unexercised.
- macOS and Linux DNS paths are unit-tested and cross-compiled, never run in a live tunnel here.
- Unsigned binaries: SmartScreen and Gatekeeper warnings expected; see `SECURITY.md`.
- No IF-T/TLS transport (see `M6-IFT.md`); no tray icon on Linux; macOS menu-bar item compiled but not
  run on Apple hardware.
