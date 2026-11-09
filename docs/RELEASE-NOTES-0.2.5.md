# Aevan 0.2.5

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. No vendor code, binaries, configuration or session data is included; the wire
protocol is documented in [PROTOCOL.md](PROTOCOL.md).

**Pre-release.** Packages are unsigned and not notarised.

## macOS now installs by dragging

`aevan-0.2.5-arm64+x86_64.dmg` opens as a normal Mac disk image: `Aevan.app` sits beside an
`Applications` shortcut, and installing means dragging one onto the other. No installer, no package
receipt, no Terminal.

Two things had to change for a dragged app to actually work:

- **The daemon travels inside the bundle** (`Aevan.app/Contents/MacOS/aevand`), because a copy-install
  cannot write to `/usr/local/bin`.
- **The GUI starts it with one native admin prompt** (`osascript … with administrator privileges`) when
  no daemon answers — the same consent a normal Mac app asks for, without a console window. Dismissing
  the prompt leaves the window usable and says so; it never re-prompts in a loop.

CI mounts the finished image and asserts the bundle inside it: `CFBundleIdentifier`
`com.github.kilisk.aevan`, the icon, `aevan-gui --version`, the embedded `aevand --version`, and the
`Applications` symlink.

The `.pkg` is still published for anyone who wants the CLI on `PATH` and a LaunchDaemon.
Ad-hoc signed only, so the first launch needs right-click → Open (or
`xattr -dr com.apple.quarantine /Applications/Aevan.app`). Nothing is notarised.

## The Apple icon is actually compiled now

`actool` was being invoked with its output discarded, so a failure silently fell back to a flat icon.
It now:

- compiles the Icon Composer bundle (`assets/branding/Aevan Icon.icon`) into a layered **Assets.car**
  (2.3 MB in this build), which is what macOS 26 uses for appearances;
- still builds a complete flat `.icns` from the 1024 master for older systems;
- surfaces `actool`'s error in the build log instead of swallowing it;
- and CI converts the shipped `.icns` back into an iconset and **fails the job** unless all ten sizes
  are present.

From the 0.2.5 macOS job:

```
icon: actool compiled the layered icon from 'Aevan Icon.icon' (Assets.car)
icon: built AppIcon.icns with iconutil from the PNGs
icns sizes: 10
Assets.car: 2,388,360 bytes (layered icon)
```

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.5-x64.msi`, portable `aevan-0.2.5-x64.zip` |
| macOS | `aevan-0.2.5-arm64+x86_64.dmg` (drag to Applications) or `.pkg` (CLI/system) |
| Linux x86_64 | `aevan-0.2.5-x86_64-linux.tar.gz`, `aevan_0.2.5_amd64.deb`, `aevan-0.2.5-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Still unproven

- No macOS install has been performed by a human: CI mounts the image and inspects the bundle, but the
  drag, the Gatekeeper prompt and the admin prompt have never been clicked.
- A full tunnel on macOS or Linux — device creation is proven (the TUN smoke step opens a real `utun`
  and `tun` under `sudo`), but routes, DNS and ESP have not carried traffic end to end there.
- No Windows or Linux installer has been run on a clean machine.
- Unsigned binaries: SmartScreen and Gatekeeper warn. See `SECURITY.md`.
