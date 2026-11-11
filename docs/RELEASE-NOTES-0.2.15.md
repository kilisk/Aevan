# Aevan 0.2.15

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13+.** Pre-release: unsigned, not notarised.

## The helper install could not find its own bundle

Reported from a real Mac: the app was `0.2.14`, the plist was demonstrably in place —

```
$ defaults read /Applications/Aevan.app/Contents/Info.plist CFBundleShortVersionString
0.2.14
$ ls -l /Applications/Aevan.app/Contents/Library/LaunchDaemons/
-rw-r--r--@ 1 kilisk admin 662 … com.github.kilisk.aevand.plist
```

— and the GUI still said *"The Aevan daemon plist is missing from the app bundle."* The plist was never
missing; the code computed the bundle root by string surgery and looked in the wrong place.

Now:

- The bundle root is asked from **`NSBundle.mainBundle.bundleURL`**, with a fallback that walks up from
  `current_exe()` to the nearest ancestor containing `Contents/Info.plist` (a pure, tested function).
- **App Translocation** is a separate, named outcome. A quarantined app launched from `~/Downloads` or
  the mounted DMG runs from `/private/var/folders/…/AppTranslocation/…`, where registering a daemon is
  not possible. Aevan says exactly that, tells you to move it to `/Applications`, and gives the
  `xattr -dr com.apple.quarantine` command — instead of blaming a missing plist.
- When something really is absent, the message names **the path checked and the bundle root**, and the
  same detail goes to `daemon-start.log`, so the Copy button is enough to diagnose it.
- Before registering, it verifies in order: bundle root, `Contents/Library/LaunchDaemons`, the plist's
  presence and readability, and its `Label`. Each failure has its own message.

Also in this release: an experimental blocking-reader change that had been committed by an interrupted
job was **reverted before shipping** — it was unverified, and the real defect it was meant to address
turned out to be the interface-naming bug fixed in 0.2.14.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.15-x64.msi`, portable `aevan-0.2.15-x64.zip` |
| macOS 13+ | `aevan-0.2.15-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.15-x86_64-linux.tar.gz`, `aevan_0.2.15_amd64.deb`, `aevan-0.2.15-1.x86_64.rpm` |

Every artifact carries its own `SHA256SUMS.txt`.

## Unproven

- The macOS bundle resolution and translocation handling are unit-tested but the Apple framework path
  only runs on Apple hardware.
- A complete macOS tunnel is still unconfirmed: the interface-naming fix (0.2.14) is in place and
  verified by unit test, not yet by a working ping.
- `docs/PLATFORM-MATRIX.md` remains the honest record; Windows is the only verified-live end-to-end path.
