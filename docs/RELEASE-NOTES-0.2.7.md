# Aevan 0.2.7

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. No vendor code, binaries, configuration or session data is included; the wire
protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** Packages are unsigned and not notarised.

## 0.2.6 could not start its own daemon

If you installed 0.2.6 on a Mac, the GUI reported *"the daemon did not answer within 10 seconds"* while
`launchctl print` showed `runs = 39, last exit code = 1`. The daemon was starting and dying instantly, and
`KeepAlive` respawned it forever. Two independent causes:

### 1. `HOME` is not set for launchd daemons

```rust
endpoint_path_for_root(root) {
    select_binding_endpoint(root, system_endpoint_path(), per_user_endpoint_path()?)
}
```

The per-user path was resolved **even when running as root**, and `config_dir()` errors when `HOME` is
unset — so `aevand` failed before opening a socket. Running it by hand worked because a shell sets
`HOME`; CI missed it for exactly that reason.

Fixed: a root daemon binds the system endpoint without touching `$HOME`, candidate resolution tolerates
a missing per-user path, and the LaunchDaemon plist also sets `HOME=/var/root` for anything that still
reads it.

### 2. A root daemon cannot own the profile store

`connect` carried a profile **name**, and the daemon resolved it from its own store —
`/var/root/Library/Application Support/aevan` — which holds none of your profiles. Even with the daemon
running, every connect would have failed with `profile 'work' was not found`.

Fixed by inverting the responsibility: **the client resolves the profile and sends the connection
parameters** (`gateway_url`, `realm`) with the request. Protocol version 2; version-1 requests are still
accepted and fall back to the store lookup, so an old CLI keeps working. Secrets remain `SecretString`
and are never logged; the new fields are not logged at info either.

This is the same split WireGuard uses: the privileged helper is handed a complete configuration and
never reads a user's files.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.7-x64.msi`, portable `aevan-0.2.7-x64.zip` |
| macOS | `aevan-0.2.7-arm64+x86_64.dmg` (drag to Applications) or `.pkg` (CLI/system) |
| Linux x86_64 | `aevan-0.2.7-x86_64-linux.tar.gz`, `aevan_0.2.7_amd64.deb`, `aevan-0.2.7-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Upgrading from 0.2.6

Replace `Aevan.app`, then reload the helper so it picks up the new plist:

```bash
sudo launchctl bootout system/com.github.kilisk.aevand 2>/dev/null
sudo launchctl bootstrap system /Library/LaunchDaemons/com.github.kilisk.aevand.plist
```

If the old job lingers, `sudo rm /Library/LaunchDaemons/com.github.kilisk.aevand.plist` and let the GUI
install it again with one prompt.

## Still unproven

- No human has completed a macOS connect: the daemon now starts as a root service and receives its
  configuration over the socket, but the full path — prompt, connect, tunnel, Quit — has not been run on
  Apple hardware by anyone.
- A full tunnel on macOS or Linux generally: device creation and the route/DNS appliers exist and the TUN
  smoke step opens a real `utun`/`tun` under `sudo`, but no end-to-end session has carried traffic there.
- No Windows or Linux installer has been run on a clean machine. Unsigned binaries; see `SECURITY.md`.
