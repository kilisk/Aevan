# Aevan <version>

Aevan is an independent, clean-room Rust client for Ivanti Secure Access gateways that speak the
**Network Connect (NC)** protocol. It contains no code, binaries, configuration or session data from
any vendor. The wire protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** The packages are unsigned and not notarised, and the installers have not been run on
pristine machines. The `.deb` and `.rpm` are built and inspected in CI, but they have never been
installed by anyone.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-<version>-x64.msi` (UAC required) |
| Windows (portable) | `aevan-<version>-x64.zip` |
| macOS (Apple silicon + Intel) | `aevan-<version>-arm64+x86_64.pkg` |
| macOS (Homebrew cask) | `Casks/aevan.rb` (installs the `.pkg` above) |
| Linux x86_64 (tarball) | `aevan-<version>-x86_64-linux.tar.gz` |
| Debian/Ubuntu amd64 | `aevan_<version>_amd64.deb` |
| Fedora/RHEL x86_64 | `aevan-<version>-1.x86_64.rpm` |

`SHA256SUMS.txt` is published with every release; verify a download before running it.

## What changed in <version>

- <!-- user-visible changes -->

## Install

**Windows**

```powershell
msiexec /i aevan-<version>-x64.msi
```

Launch **Aevan** from the Start menu: one UAC prompt starts the daemon, the window opens, closing it
leaves the app in the notification area, and *Quit* disconnects first.

**macOS**

```sh
sudo installer -pkg aevan-<version>-arm64+x86_64.pkg -target /
```

Or with the cask from a checkout:

```sh
brew install --cask ./Casks/aevan.rb
```

Unsigned, so Gatekeeper refuses it on first open: right-click → Open, or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`. The daemon needs root for `utun`; see
`docs/INSTALL.md` for the LaunchDaemon opt-in.

**Linux tarball**

```sh
tar xzf aevan-<version>-x86_64-linux.tar.gz && cd aevan-<version>-x86_64-linux
sudo ./install.sh          # does not enable or start the service
sudo ./install.sh --enable # also enables aevand.service
```

**Debian / Ubuntu**

```sh
sudo apt install ./aevan_<version>_amd64.deb
```

The package reloads systemd but does not enable or start `aevand.service`.

**Fedora / RHEL**

```sh
sudo dnf install ./aevan-<version>-1.x86_64.rpm
```

The package reloads systemd but does not enable or start `aevand.service`.

## Packaging status

| Artifact | Built in CI | Inspected in CI | Installed on a clean machine |
| --- | --- | --- | --- |
| MSI | yes | yes | no |
| portable zip | yes | version metadata only | no |
| `.pkg` | yes | no | no |
| Linux tarball | yes | no | no |
| `.deb` | yes | yes | no |
| `.rpm` | yes | yes | no |
| Homebrew cask | not built | no | no |

## Known limitations

- **macOS and Linux DNS paths are unit-tested and cross-compiled, not run in a live tunnel** — the
  maintainer develops on Windows. Treat them as unproven until someone reports a real session.
- Unsigned binaries: SmartScreen and Gatekeeper warnings are expected; see `SECURITY.md`.
- No IF-T/TLS transport.
- The `.deb` and `.rpm` are built in CI but not yet installed by anyone; their dependency lists are
  minimal. Installers have not been exercised on clean virtual machines.
- The macOS menu-bar item compiles but has not been run on Apple hardware.
