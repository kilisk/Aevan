# Aevan 0.2.16

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13+.** Pre-release: unsigned, not notarised.

## Why the helper install kept saying the plist was missing

The plist was in the bundle; the bundle check passed. What failed was `SMAppService` itself, and its
`kSMErrorJobPlistNotFound` was being reported to you as *"the daemon plist is missing… reinstall"* — a
message about the wrong thing, from a registration path that can never succeed on this build.

`SMAppService` validates the **helper's code signature** before it looks at anything else. An ad-hoc
signed app — which is what Aevan is until it has a Developer ID — therefore fails regardless of the
bundle being correct.

Now:

- At registration time the app asks `codesign -dv` whether its own bundle is ad-hoc signed. If it is,
  `SMAppService` is **skipped entirely** and the helper is installed as a `LaunchDaemon` through one
  administrator prompt — the path that demonstrably works unsigned.
- If the bundle is properly signed, `SMAppService` runs as before, with approval in System Settings.
- `kSMErrorJobPlistNotFound` no longer masquerades as a bundle problem: the message names the code,
  the plist path and the bundle root.

## Reading the banner correctly

`~/Library/Logs/Aevan/daemon-start.log` is **appended**, and the banner shows its last three lines — so
after a failed attempt, a later screenshot can show a stale failure. Every entry now begins with a
timestamp:

```
2026-11-11T08:31:04Z aevan daemon start
command: legacy LaunchDaemon install (/Library/LaunchDaemons/com.github.kilisk.aevand.plist)
exit: 0
```

If the newest timestamp is older than the attempt you just made, the banner is stale, not the install.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.16-x64.msi`, portable `aevan-0.2.16-x64.zip` |
| macOS 13+ | `aevan-0.2.16-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.16-x86_64-linux.tar.gz`, `aevan_0.2.16_amd64.deb`, `aevan-0.2.16-1.x86_64.rpm` |

Artifacts carry their own `SHA256SUMS.txt`.

## Unproven

- The ad-hoc short-circuit is unit-tested; running it needs Apple hardware.
- The interface-naming fix (0.2.14) still awaits a working ping on macOS.
- Windows remains the only verified-live end-to-end tunnel; see `docs/PLATFORM-MATRIX.md`.
