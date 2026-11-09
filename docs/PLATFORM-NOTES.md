# Platform notes

The table is the design notes §5, with the M0 status and the constraints that make
each row non-trivial. Nothing below changes the contract; it records what the
implementer must know before M2.

| OS | device | privileges | DNS | routes | M0 status |
|---|---|---|---|---|---|
| Windows 10/11 | Wintun (`wintun.dll` shipped beside the exe, signed by WireGuard LLC, redistribution allowed) | adapter creation needs admin, so a small signed helper service runs as LocalSystem; the CLI/GUI talks to it over a named pipe | `SetInterfaceDnsSettings` / NRPT for split DNS | `CreateIpForwardEntry2`, route table v2 | `platform::probe` looks for `wintun.dll` beside the exe or in `System32`; `open` returns typed `Unsupported` |
| macOS 12+ | `utun` via `socket(PF_SYSTEM)` | needs root or a privileged launchd helper. NetworkExtension/App Store "VPN" integration is out of scope (needs an Apple entitlement) | `networksetup` on the primary network service (`route -n get default` → `networksetup -listnetworkserviceorder`, first enabled service as fallback); previous servers and service name recorded and restored. Interface-wide only: the gateway pushes servers without search domains, so per-domain split DNS is not available | `route -n add` over the `utun` | `platform::probe` reports the M2 deferral; `open` returns typed `Unsupported` |
| Linux | `/dev/net/tun` | `CAP_NET_ADMIN` or a systemd service + polkit | manager-dependent, selected at apply time: `resolvectl dns/domain` (systemd-resolved), then `resolvconf`, then an `/etc/resolv.conf` backup fallback; the choice is journaled so revert uses the same mechanism | netlink via the `rtnetlink` crate | `platform::probe` checks for `/dev/net/tun`; `open` returns typed `Unsupported` |

## DNS per platform

The apply layer makes the servers from KMP 301 group 2 attr 1 active and keeps
the previous state in the crash-recovery journal so teardown can restore it.

* **Windows** — `netsh interface ipv4 set/add dnsservers` on the tunnel alias;
  the inverse is `set dnsservers ... source=dhcp`.
* **macOS** — `networksetup -setdnsservers <service> <servers...>` on the primary
  network service. `route -n get default` supplies the interface, which is
  mapped to a service with `networksetup -listnetworkserviceorder`; an ambiguous
  or missing mapping falls back to the first enabled service. The old servers
  are read with `networksetup -getdnsservers` and the service name is journaled.
  Revert restores that list, or clears the service with `Empty` when it was
  empty. `dscacheutil -flushcache` and `killall -HUP mDNSResponder` run after
  apply and revert; a flush failure is a warning only. This sets **interface-wide
  DNS**, not per-domain split DNS: the gateway does not push search domains, so
  there is no domain to scope. That is the honest behaviour for a split-route
  tunnel.
* **Linux** — the manager is detected once at apply time and stored in the
  journal. Preferred order: `resolvectl dns <link> ...` then
  `resolvectl domain <link> ~.` when `resolvectl` resolves and
  `/run/systemd/resolve/io.systemd.Resolve` exists (revert:
  `resolvectl revert <link>`); otherwise `resolvconf -a <link>` with a
  `nameserver` block on stdin (revert: `resolvconf -d <link>`); otherwise back
  up `/etc/resolv.conf` to `/etc/resolv.conf.aevan.bak` once (mode `0644`) and
  write a managed file (revert: restore the backup byte-for-byte and delete it).
  An existing backup from a crashed run is never overwritten; it is reused as
  the restore source and logged. DNS behaviour is therefore **manager-dependent**:
  systemd-resolved is per-link, `resolvconf` is per-interface, and the file
  fallback is host-wide.

## Split tunnel

Only install the routes the gateway pushes (typical split-tunnel routes are `10/8` and the `172.30.x`
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
