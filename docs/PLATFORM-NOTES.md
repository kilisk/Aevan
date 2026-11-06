# Platform notes

The table is the design notes §5, with the M0 status and the constraints that make
each row non-trivial. Nothing below changes the contract; it records what the
implementer must know before M2.

| OS | device | privileges | DNS | routes | M0 status |
|---|---|---|---|---|---|
| Windows 10/11 | Wintun (`wintun.dll` shipped beside the exe, signed by WireGuard LLC, redistribution allowed) | adapter creation needs admin, so a small signed helper service runs as LocalSystem; the CLI/GUI talks to it over a named pipe | `SetInterfaceDnsSettings` / NRPT for split DNS | `CreateIpForwardEntry2`, route table v2 | `platform::probe` looks for `wintun.dll` beside the exe or in `System32`; `open` returns typed `Unsupported` |
| macOS 12+ | `utun` via `socket(PF_SYSTEM)` | needs root or a privileged launchd helper. NetworkExtension/App Store "VPN" integration is out of scope (needs an Apple entitlement) | `scutil --dns` resolver entries per domain, restored on exit | `route -n add` over the `utun` | `platform::probe` reports the M2 deferral; `open` returns typed `Unsupported` |
| Linux | `/dev/net/tun` | `CAP_NET_ADMIN` or a systemd service + polkit | `systemd-resolved` per-link split DNS, with `resolvconf` and NetworkManager fallback | netlink via the `rtnetlink` crate | `platform::probe` checks for `/dev/net/tun`; `open` returns typed `Unsupported` |

## Split tunnel

Only install the routes the gateway pushes (the observed gateway behaviour: `10/8` and the `172.30.x`
blocks). Never install a default route unless the gateway says so. Honour IPv6
only when the gateway assigns an IPv6 address.

## Teardown

Routes, DNS, MTU and the device must be restored in reverse order and on every
exit path. `aevan-tun::Session` implements the ordering and the `Drop` fallback;
the real backends must make each inverse idempotent.

## Privileges

`aevan doctor` reports elevation honestly as `elevated`, `not_elevated` or
`unknown`. On Windows it reads the mandatory-level SID from `whoami /groups`; on
Unix it reads `id -u`. The check never requests elevation.

## Profile-file permissions

the design notes §8 requires owner-only profiles. On Unix the store is written with
mode `0600` and a group/world-writable file is refused. On Windows the store
lives under `%APPDATA%\aevan`, whose per-user ACL is the operative control; a
portable ACL check would need another dependency and is deferred.
