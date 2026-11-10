# Aevan 0.2.9

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol.

**Pre-release.** Packages are unsigned and not notarised. **macOS 13 or newer is now required.**

## No AppleScript left in the app

0.2.8 stopped the crash by moving notification delivery into a child process. This release removes the
script entirely:

- **Notifications** use `UNUserNotificationCenter` (`objc2-user-notifications 0.3.2`): authorization is
  requested once, denial is reported in the UI instead of failing silently, and delivery goes through
  `UNNotificationRequest`.
- **Daemon registration** uses `SMAppService` (`objc2-service-management 0.3.2`). The LaunchDaemon plist
  ships inside the bundle at `Contents/Library/LaunchDaemons/com.github.kilisk.aevand.plist` and is
  registered with the system, so approval happens in **System Settings → Login Items & Extensions** —
  no password dialog, no `osascript`. `status()` distinguishes enabled / requires approval / not
  registered and the UI says which.
- A test fails the build if `osascript`, `AppleScript`, `NSUserNotification`, `SMJobBless` or
  `AuthorizationExecuteWithPrivileges` reappears anywhere in the tree. `grep -rni osascript crates/`
  returns zero hits.

## iced 0.14

The GUI moved from iced 0.13 to **0.14.0** (wgpu 27). Behaviour is unchanged; the binary grew from
13.6 MB to 14.3 MB (+5.7%).

Honest note on the `block v0.1.6` future-incompatibility warning: 0.14 removes it from Windows/Linux
builds, but **Apple targets still resolve it** (`iced_wgpu 0.14 → wgpu 27 → metal 0.32 → block 0.1.6`).
It is dropped in wgpu 29, which iced does not support yet. It's upstream; forking a graphics dependency
to silence a warning is not worth the risk.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.9-x64.msi`, portable `aevan-0.2.9-x64.zip` |
| macOS 13+ | `aevan-0.2.9-arm64+x86_64.dmg` (drag to Applications) or `.pkg` |
| Linux x86_64 | `aevan-0.2.9-x86_64-linux.tar.gz`, `aevan_0.2.9_amd64.deb`, `aevan-0.2.9-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Upgrading from 0.2.8

Replace `Aevan.app`, then remove the old helper so the new registration path is used:

```bash
sudo launchctl bootout system/com.github.kilisk.aevand 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.github.kilisk.aevand.plist
```

Open Aevan once; it registers through `SMAppService` and asks for approval in System Settings.

## Still unproven

- The `UserNotifications` and `SMAppService` paths are **compile-checked only** — they have not run on
  Apple hardware.
- No end-to-end macOS connect by a human; the daemon starts under launchd (verified by
  `launchctl print` showing `last exit code = 0` is what to look for).
- No Windows or Linux installer has been run on a clean machine.
