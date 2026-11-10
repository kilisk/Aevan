# Aevan 0.2.10

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13 or newer.** Pre-release: unsigned and not notarised.

## Profiles can be edited and deleted

The GUI managed only *adding* a profile. Now:

- **Edit** reopens the same sheet, pre-filled with name, gateway URL, realm and username. Validation is
  the add validation plus rename rules: a name another profile already uses is rejected per-field, and
  saving under its own current name is fine. Editing the profile that is currently connected says
  plainly that the change applies to the next connection and the live tunnel is untouched.
- **Delete** asks for confirmation by name ("Delete “work”? This cannot be undone."), removes it, and
  clears the selection if it was selected. Deleting the connected profile is refused with a message to
  disconnect first — the tunnel is never torn down behind your back.
- No password, token or TOTP secret is involved in either path.

## A platform matrix that fails CI

The last weeks had a pattern: features landed Windows-first, CI compiled the other platforms, the docs
called them done, and the gaps surfaced only when someone used a Mac. That is now a build failure.

- `docs/PLATFORM-MATRIX.md` is **generated**: every capability × Windows/macOS/Linux, each cell
  implemented / stub / absent, with a **Verified** column populated *only* from
  `docs/platform-evidence.toml` — never inferred from code.
- `docs/platform-gaps.toml` must explain every implemented-on-one-OS / stub-or-absent-on-another
  difference, with a reason and an owner or tracking note.
- A new `platform-matrix` CI job runs `python scripts/platform-matrix.py --check` in under a minute and
  fails when the table is stale or a gap is undocumented. Removing one entry produces:

```
platform-matrix: capability 'tray-icon' is absent on linux while it is implemented on windows, macos;
add an entry to docs/platform-gaps.toml with capability = 'tray-icon', platform = 'linux', a reason,
and an owner_note or tracking_note
```

Current honest state: the Windows tunnel is the only **verified-live** end-to-end path. Device
creation is verified live on macOS and Linux by the CI smoke step; routes, DNS and ESP are
**compile-only** there. Tray is absent on Linux by decision.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.10-x64.msi`, portable `aevan-0.2.10-x64.zip` |
| macOS 13+ | `aevan-0.2.10-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.10-x86_64-linux.tar.gz`, `aevan_0.2.10_amd64.deb`, `aevan-0.2.10-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Still unproven

- A full macOS or Linux tunnel: device creation is proven, routes/DNS/ESP are not exercised.
- No installer has been installed on a clean machine.
- The macOS window has never been clicked by a human in a release build with these changes.
