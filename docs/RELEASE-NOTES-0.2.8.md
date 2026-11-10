# Aevan 0.2.8

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. No vendor code, binaries, configuration or session data is included.

**Pre-release.** Packages are unsigned and not notarised.

## What 0.2.7 still got wrong

0.2.7 fixed the *endpoint* so a root daemon would not need `$HOME` — but the daemon still called
`config_dir()` at startup to create its state directory, and that call needs `HOME`. Under launchd,
which gives system daemons no `HOME`, the process exited 1 there, before the socket code ever ran.
`KeepAlive` then respawned it indefinitely: `runs = 327, last exit code = 1`, and no state directory on
disk.

Running the same binary by hand always worked, because a shell sets `HOME`. That is why every release
looked fine locally and in CI.

**Fix:** startup resolves the state directory with a root fallback — `/var/root/Library/Application
Support/aevan` on macOS, `/root/.config/aevan` on Linux — so `aevand` starts under launchd with a bare
plist, with or without `EnvironmentVariables`. The plist still sets `HOME=/var/root`, but correctness no
longer depends on it.

## Upgrading from 0.2.7

1. Replace `Aevan.app`.
2. Remove the old helper so the app installs the current one:

```bash
sudo launchctl bootout system/com.github.kilisk.aevand 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.github.kilisk.aevand.plist
```

3. Open Aevan once. It installs the helper behind a single admin prompt and bootstraps it.

Verify before using the GUI:

```bash
sudo launchctl print system/com.github.kilisk.aevand | grep -E "runs|last exit code"
ls -l "/Library/Application Support/Aevan/"
```

Expected: `last exit code = 0`, and `aevan.sock` owned by root with mode `srw-rw-rw-`.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.8-x64.msi`, portable `aevan-0.2.8-x64.zip` |
| macOS | `aevan-0.2.8-arm64+x86_64.dmg` (drag to Applications) or `.pkg` (CLI/system) |
| Linux x86_64 | `aevan-0.2.8-x86_64-linux.tar.gz`, `aevan_0.2.8_amd64.deb`, `aevan-0.2.8-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Known limitation

An app upgrade does **not** replace an already-installed LaunchDaemon: the helper lives in
`/Library/LaunchDaemons` and only the app installs it. Until the app gains a "repair helper" check that
compares the installed plist with the one it would write, upgrading requires the `bootout` + `rm` above
once. 0.2.8's tolerance of a bare plist means an old helper still starts the new daemon, so this is
untidy rather than blocking.

## Still unproven

- No end-to-end macOS connect by a human: the daemon now starts under launchd, but sign-in, tunnel and
  Quit have not been exercised there.
- A full tunnel on macOS/Linux generally: the TUN smoke step opens a real `utun`/`tun` under `sudo`;
  routes, DNS and ESP have not carried traffic on either OS.
- No Windows or Linux installer has been run on a clean machine. Unsigned binaries; see `SECURITY.md`.
