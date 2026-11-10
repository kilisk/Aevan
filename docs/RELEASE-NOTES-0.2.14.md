# Aevan 0.2.14

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13+.** Pre-release: unsigned, not notarised.

## The tunnel was configuring the wrong interface

This is the bug behind everything since the first successful macOS connection: `ping` reporting
`sendto: No buffer space available`, `tcpdump` showing packets entering `utun0`, and the daemon's loop
insisting it had nothing to read.

The daemon opened a `utun` device, and macOS assigned the **next free unit** — unit 5, so `utun5`.
The applier was then handed the *configured* name (`utun0`) and dutifully applied the address, MTU, all
four routes and DNS **to that other interface**. Result: packets were routed into an interface nobody
read, its queue filled, and our reader sat on `utun5`, which had no routes.

Evidence, from `lsof` on the live daemon:

```
11u  systm  [ctl com.apple.net.utun_control id 5 unit 5]
```

against `ifconfig` showing `10.251.99.97` and MTU 1396 on **utun0**.

Fixed by inverting the source of truth: the device reports the name the OS assigned
(`UTUN_OPT_IFNAME` on macOS, `ifr_name` from `TUNSETIFF` on Linux), and everything that touches the
interface — address, MTU, routes, DNS *and the crash journal* — uses that name. A configured name is
only a fallback for backends that honour it. When the OS picks a different name than requested, the
daemon logs it once:

```
configured="utun0" assigned="utun5" the OS assigned a different tunnel interface name
```

A unit test pins it: `resolve_interface(Some("utun5"), "utun0") == "utun5"`.

This also makes crash recovery correct: the journal now records the interface that was really
configured, so a rollback after a hard kill targets the right one.

## Also in this release

- **Route takeover** (0.2.13): a pushed route that already exists on another interface is journalled and
  replaced with an `-ifscope` route on the tunnel, restored on disconnect.
- **CLI in the bundle** (0.2.13): `aevan` ships inside `Aevan.app/Contents/MacOS`, with Settings →
  *Install command-line tools*.
- **Artifact checksums** (CI): every packaged artifact now carries `SHA256SUMS.txt`, so a truncated
  download is detectable before anyone installs it.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.14-x64.msi`, portable `aevan-0.2.14-x64.zip` |
| macOS 13+ | `aevan-0.2.14-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.14-x86_64-linux.tar.gz`, `aevan_0.2.14_amd64.deb`, `aevan-0.2.14-1.x86_64.rpm` |

## Unproven

- The interface-name fix is verified by unit test and by matching `lsof` evidence, but the end-to-end
  result on macOS is yours to confirm: after connecting, `ifconfig` should show the address on the
  interface the daemon logs as `assigned`, and ping should work.
- Windows remains the only verified-live end-to-end tunnel. Linux/macOS routes, DNS and ESP are
  compile-only. `docs/PLATFORM-MATRIX.md` is generated and says the same.
