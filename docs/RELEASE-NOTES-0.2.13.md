# Aevan 0.2.13

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13+.** Pre-release: unsigned, not notarised.

## The macOS tunnel: what we know, and what this build does about it

Observed on a real Mac: the tunnel comes up (`utun0` = `10.251.99.97/32`, MTU 1396, all four pushed
routes on `utun0`, ESP socket held by `aevand` to `58.27.108.239:4500`), the KMP exchange completes
(`301` in, `302`/`303` out), and then **nothing**. Pinging `10.251.3.18` returns
`sendto: No buffer space available`, while `tcpdump -ni any` shows the echo requests leaving
`10.251.99.97` on `utun0`. The device queue is full because nothing is draining it.

This build does not claim to have fixed that yet. It makes the daemon answer the question:

- **Device drain runs first** every iteration, so a stalled or erroring UDP read can no longer starve
  the tunnel device.
- **One trace line per iteration**: UDP packets, device packets, poll readiness, both fds. Enabled with
  `RUST_LOG=trace`, silent otherwise.
- **Watchdog**: if the device is reported readable but drains nothing 100 times in a row, an error names
  the fd and polling of the device stops — which distinguishes "no packets" from "poll is lying".
- **Device read errors no longer end the session** unless the device is genuinely gone
  (`NotFound` / `NotConnected` / `BrokenPipe`).

To capture it:

```bash
sudo launchctl bootout system/com.github.kilisk.aevand 2>/dev/null
sudo RUST_LOG=trace /Applications/Aevan.app/Contents/MacOS/aevand 2>&1 | tee /tmp/aevand-trace.log
```

connect, ping, then `grep -iE "esp|device|poll" /tmp/aevand-trace.log | tail -40`.

## Route conflicts are replaced, not ignored

A pushed route that already exists on another interface is now read, journalled, deleted and replaced
with ours scoped to the tunnel (`-ifscope`); disconnect restores exactly what was there. A route that
already points at our own interface is left alone, a refused delete names the conflicting interface, and
`apply` verifies every pushed route is on the tunnel afterwards instead of reporting success blind.

## The DMG ships the CLI

`aevan` is now copied into `Aevan.app/Contents/MacOS` alongside `aevan-gui` and `aevand`, and
**Settings → Install command-line tools** symlinks `/usr/local/bin/{aevan,aevand}` to those copies behind
one administrator prompt — with *Remove*, stale-link detection when the bundle moves, and a refusal to
overwrite a real file that isn't ours. That is the Windows-MSI parity the drag install never had.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.13-x64.msi`, portable `aevan-0.2.13-x64.zip` |
| macOS 13+ | `aevan-0.2.13-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.13-x86_64-linux.tar.gz`, `aevan_0.2.13_amd64.deb`, `aevan-0.2.13-1.x86_64.rpm` |

## Unproven

- The data-plane stall is instrumented, **not fixed** — the trace output is what will identify it.
- The route takeover and the Settings actions are compile-checked only on macOS.
- A full macOS or Linux tunnel, installers on a clean machine. `docs/PLATFORM-MATRIX.md` says the same.
