# Aevan 0.2.6

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. No vendor code, binaries, configuration or session data is included; the wire
protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** Packages are unsigned and not notarised.

## What 0.2.5 got wrong on the Mac, fixed

### The daemon was invisible to the GUI

`aevan.sock` lived in `config_dir()`, which follows `$HOME`. Started as root, `aevand` bound
`/var/root/…/aevan.sock`; the GUI looked in `/Users/<you>/…/aevan.sock`. The admin prompt could succeed
and the GUI would still say *"no daemon is listening"*.

A root daemon now binds a **system endpoint** — `/Library/Application Support/Aevan/aevan.sock`, directory
`0755 root:wheel`, socket `0666` — and clients try the system path first, then the per-user one.
`status` reports which path answered.

Proven on a real macOS runner, not asserted: the daemon runs under `sudo`, then the unprivileged user
runs `aevan status --json` and the job requires the socket at that path, mode exactly `srw-rw-rw-`,
directory `drwxr-xr-x`, and that path in the JSON.

### One admin prompt, once — not on every start

The macOS daemon is now a **LaunchDaemon** (`com.github.kilisk.aevand`, `RunAtLoad`, `KeepAlive`) that the
GUI installs behind a **single** prompt the first time, then bootstraps. After that:

- relaunch → the socket already answers, **no prompt**;
- job installed but stopped → `launchctl kickstart`, **no prompt**;
- reboot → `RunAtLoad` brings it up.

This is the model WireGuard and the vendor client use: elevation belongs to installing a privileged
helper, not to starting a client.

### Quit disconnects, then exits

| Action | Tunnel | Daemon | Icon |
|---|---|---|---|
| **Quit** (tray/menu bar, Cmd+Q) | disconnected first | installed, idle | gone |
| **Disconnect** | down | running | present |
| **Close window** | unaffected | unaffected | present |
| **Relaunch** | — | already up | present, no prompt |

If the Quit disconnect fails or times out, the GUI does **not** exit silently: it shows
*"Disconnect failed: <reason>"* with **Quit anyway** / **Cancel**. The contract is written down in
`docs/GUI.md` so it cannot drift.

### The menu-bar icon was a white block

A status item needs a **template image**. The colour artwork was being handed to AppKit, which drew an
opaque bitmap. Aevan now ships an alpha-only silhouette (`18×18 pt`, `36 px @2x`, `with_icon_templated`),
generated from the glyph at build time, with a non-template fallback instead of a white square.

### Smaller things

- A stale `aevan-gui.sock` from a crashed instance is removed at startup instead of blocking the app;
  a clean quit unlinks it.
- Elevated starts write `~/Library/Logs/Aevan/daemon-start.log` (dir `0700`, file `0600`) and the GUI
  shows the last lines when a start fails, so a failure names itself instead of failing silently.
- The empty profile list points at the **Add profile** button instead of telling you to run
  `aevan profile add`.
- Uninstall instructions for the drag-install, and a cask `zap` stanza, so removal leaves nothing behind.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.6-x64.msi`, portable `aevan-0.2.6-x64.zip` |
| macOS | `aevan-0.2.6-arm64+x86_64.dmg` (drag to Applications) or `.pkg` (CLI/system) |
| Linux x86_64 | `aevan-0.2.6-x86_64-linux.tar.gz`, `aevan_0.2.6_amd64.deb`, `aevan-0.2.6-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Still unproven

- No human has clicked the drag, the Gatekeeper prompt, the one-time admin prompt or the tray Quit.
  CI mounts the image and proves the socket across UIDs; it cannot click a menu.
- A full tunnel on macOS or Linux: device creation and route/DNS appliers exist and the TUN smoke step
  opens a real `utun`/`tun` under `sudo`, but no end-to-end session has carried traffic there.
- No Windows or Linux installer has been run on a clean machine. Unsigned binaries; see `SECURITY.md`.
