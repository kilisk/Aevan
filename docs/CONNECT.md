# `aevan connect` (foreground NC data plane)

This document describes the foreground `aevan connect` path in this tree. It is
deliberately explicit about what is implemented, what is exercised only by
offline tests, and what can still differ from the reference implementation.

## Sequence

1. Select the profile and run **exactly one** authentication attempt through the
   shared `aevan login` path (`crates/aevan-cli/src/login.rs`). There is no retry,
   no second profile and no fallback host.
2. Reuse the session cookies and run **exactly one** oNCP handshake attempt:
   `POST /dana/js?prot=1&svc=4` with the hostname packet. This path has no
   Content-Length fallback and no TCP/TLS connect retry.
3. If the handshake does not return a KMP 301 configuration, log the gateway
   status byte and exit with code **7** (`unsupported gateway or
   configuration`). No device is opened and no route, DNS server or MTU is
   touched.
4. If a KMP 301 is returned, decode it and answer on the **same still-open TLS
   stream**: KMP 302 (ESP negotiation) then KMP 303 (client MTU reply).
5. Open the platform device with that configuration.
6. Apply the configuration through `aevan-tun::apply`.
7. Run the ESP data plane over UDP until Ctrl+C, the peer goes silent, or an
   error occurs.
8. Tear everything down.

`--dry-run` stops after step 4 and **does not send KMP 302/303**. It performs
the login and handshake, prints the plan as JSON (always, with or without
`--json`) and changes nothing. A failed handshake still exits non-zero.

`aevan connect` is the daemon path by default (M3). `--foreground` or
`--no-daemon` keeps the connector in this process. Both paths use the shared
orchestration in `aevan-daemon`; the daemon adds the control socket, the status
state machine and the crash-recovery journal described in `docs/DAEMON.md`.

## Live ESP sequence (301 → 302 → 303 → ESP)

Verified against a live gateway and the reference layout in openconnect
`auth-juniper.c` / `oncp.c` (layout only; the code here is written
independently).

| direction | message | content |
|---|---|---|
| receive | KMP 301 | configuration: address, routes, DNS, MTU, ESP transforms, gateway SPI and key block |
| send | KMP 302 | group 7 attr 1 = our inbound SPI; group 7 attr 2 = the 0x40-byte client key block (payload length 86 on this gateway) |
| send | KMP 303 | group 6 attr 2 = the accepted MTU |
| both | ESP | AES-CBC with truncated HMAC over UDP, default port 4500 from group 8 attr 4 |

The 302 and 303 are framed exactly like the existing builders: little-endian
record length, 20-byte KMP header with a big-endian message number, the
outbound KMP tag, a big-endian payload length, then TLVs. They are separate
writes on the oNCP TLS connection. The connection is kept alive for the whole
ESP session; closing it would end the NC session.

### What the KMP 302 carries

* **Our inbound SPI** — a fresh 32-bit value. The gateway sends ESP packets
  with this SPI, and our receive SA rejects anything else.
* **Our inbound key block** — exactly `0x40` bytes:
  `encryption_key || hmac_key || zero padding`. With AES-128-CBC + HMAC-SHA1
  that is 16 bytes of encryption key, 20 bytes of HMAC key, then 28 zero bytes.
* The gateway's KMP 301 group 7 material is the opposite direction: its SPI
  and key block are what we use to encrypt packets **to** the gateway.

The ESP UDP endpoint is the TLS peer address (the public gateway), not the
internal `gateway` field in KMP 301. The socket binds the wildcard address and
lets the OS choose the local port.

### Key handling rules

* All ESP keys live in `SecretKey` (zeroized on drop) or in `EspKeys`, which
  wraps `SecretKey` values. `Debug` prints `redacted`, and none of these types
  implements `Serialize`.
* Keys, the KMP 302 payload and cookies never reach stdout, logs, the JSON
  summary, the dump or git. The connected summary carries only address, prefix,
  MTU, route count and DNS servers.
* Key and SPI generation uses the documented fallback in
  `aevan-nc::oncp::FallbackRng`: there is no random-number crate in the
  dependency set, so it seeds from `SystemTime`, the process id and OS-seeded
  `RandomState` values and expands with HMAC-SHA1. This is marked as a
  fallback, not an audited CSPRNG. Replace it with the OS random API when the
  dependency policy permits.
* The initial outbound CBC IV is generated the same way. The outbound IV chains
  to the last ciphertext block of the previous packet, as in the reference.

## What is applied, in order

The plan is built from the KMP 301 fields:

| step | source | notes |
|---|---|---|
| device | configuration/profile | `aevan` on Windows, `aevan0` on Linux, `utun0` on macOS |
| address + prefix | assigned IPv4 (or IPv6 if no IPv4) | prefix comes from the netmask when the gateway omits it |
| MTU | KMP 301 group 6 attr 2 | skipped when zero or absent |
| routes | split-include routes | installed on-link through the tunnel; exclude routes are not installed |
| DNS | KMP 301 group 2 attr 1 | IPv4 and IPv6 |

Order is address, MTU, routes, DNS. Every step is a `Change` with an inverse
(`aevan-tun::rollback::Change::inverse`), and `Session` records each successful
step. A failed step reports its name and rolls back the steps already applied.

Per-OS commands:

* **Windows** — `netsh interface ipv4 set address`, `set subinterface`,
  `set dnsservers`/`add dnsservers`, `add route`; the inverse of a route is
  `netsh interface ipv4 delete route`, and DNS is restored with
  `set dnsservers ... source=dhcp`.
* **Linux** — `ip addr add|del`, `ip link set dev ... mtu`, `ip route add|del`.
  DNS is manager-dependent and the manager is chosen once when the change is
  applied, then recorded in the journal so revert uses the same mechanism:
  `resolvectl dns <link> ...` + `resolvectl domain <link> ~.` with revert
  `resolvectl revert <link>` when systemd-resolved is live; otherwise
  `resolvconf -a <link>` fed a `nameserver` block on stdin with revert
  `resolvconf -d <link>`; otherwise a one-time
  `/etc/resolv.conf.aevan.bak` backup and a managed `/etc/resolv.conf`, with
  revert restoring the backup byte-for-byte. An existing backup from a crashed
  run is reused, not overwritten.
* **macOS** — `ifconfig utunN`, `route -n add|delete`. DNS uses
  `networksetup -setdnsservers <service> ...` on the primary service
  (`route -n get default` → `networksetup -listnetworkserviceorder`, first
  enabled service as fallback). The previous servers and service name are
  journaled; revert restores them or uses `Empty` when there were none.
  `dscacheutil -flushcache` and `killall -HUP mDNSResponder` follow both apply
  and revert, and a flush failure is only a warning. This is **interface-wide**
  DNS, not per-domain split DNS, because the gateway does not push search
  domains.

Argument vectors are passed to the program directly. No shell is involved and
no argument is concatenated into a command string.

## Rollback guarantees

`ConnectGuard` owns both the rollback `Session` and the device. Its `Drop` calls
teardown, so rollback runs on normal completion, on an early `?`, and while a
panic unwinds. Teardown:

1. applies every recorded inverse in reverse order (DNS, routes, MTU, address);
2. closes the device, which ends the Wintun session and closes the adapter.

Both are attempted even if the first fails; the first error is returned.
Rollback is idempotent: a second call sees an empty undo stack. A step that
failed is not recorded because it had no effect.

On Windows the ESP loop installs a console control handler, so Ctrl+C/Ctrl+Break
sets a stop flag and the loop returns normally: teardown then runs before the
process exits. The handler is specific to the `aevan-tun` Windows module, which
is also where the crate's `unsafe` is confined.

Teardown does not restore the previous MTU when no previous value was recorded. On all
three backends the interface itself is removed or reset, which restores the
platform default; the applier therefore does not guess a value.

## Wintun requirements (Windows)

* `wintun.dll` must be shipped unmodified by WireGuard LLC, beside `aevan.exe`
  first; `System32\wintun.dll` is accepted as a second location. A missing DLL
  is a typed `Unsupported` error that names `wintun.dll`, not a panic and not a
  silent no-op.
* Creating the adapter needs **Administrator**. `aevan` checks elevation and
  returns exit code 6 (`insufficient privilege`) when it is not elevated. It
  never attempts to elevate itself.
* The DLL exports are loaded at runtime with `LoadLibraryW`/`GetProcAddress`
  (`WintunCreateAdapter`, `WintunOpenAdapter`, `WintunCloseAdapter`,
  `WintunStartSession`, `WintunEndSession`, `WintunGetReadWaitEvent`,
  `WintunReceivePacket`, `WintunReleaseReceivePacket`,
  `WintunAllocateSendPacket`, `WintunSendPacket`). No import library or link
  dependency is used.
* `recv` is non-blocking: a single `WintunReceivePacket` call returns
  `WouldBlock` when the queue is empty, and the data-plane loop waits on the
  read-wait event together with the UDP socket. The caller's receive buffer is
  sized from the negotiated MTU. `send` allocates, copies and sends. `close`
  ends the session, closes the adapter and frees the DLL; it is idempotent.

This path **cannot be covered by unit tests**: it needs the signed DLL, an
elevated process and a real Windows network stack. The offline tests cover the
missing-DLL decision and the closed-device behaviour only. A full run is an
elevated manual check.

The complete live data plane therefore needs:

* an elevated (`Administrator`) process;
* `wintun.dll` beside `aevan.exe` (or in `System32`);
* route to the TLS peer on UDP 4500 from the local network;
* a valid account/session. Tests never open an adapter, change a route, send
  credentials or contact the gateway.

## Connected output

Once the plan is applied, `aevan connect` prints a short summary before entering
the ESP loop:

* human output: assigned address/prefix, device, MTU, route count and DNS;
* `--json`: `schema_version`, `connected: true`, profile, device, address,
  prefix length, MTU, `route_count` and `dns` (same `schema_version` as the
  dry-run report).

No key material, SPI, cookie or password is printed in either mode.

## Data plane

The ESP loop is built for throughput and low latency rather than one packet per
tick:

* **Non-blocking.** The UDP socket is set non-blocking at connect and the
  Wintun receive path makes one `WintunReceivePacket` call per packet. An empty
  socket returns `WouldBlock` immediately instead of waiting for a read
  timeout.
* **Unix blocking reader.** On macOS and Linux the `utun`/`tun` descriptor is
  opened blocking and one dedicated reader thread owns the read side, the same
  pattern WireGuard uses. It loops on a blocking `read(2)`, strips and validates
  the macOS 4-byte address-family header, and pushes packets into a bounded
  channel of 256 packets. A full channel drops the packet and logs a warning;
  `EINTR` retries, and EOF/`EBADF`/`EIO` mark the reader dead so the loop can
  end the tunnel. The ESP loop never polls or reads that descriptor. This
  replaces the readable-but-empty `poll(2)` design that left the interface
  queue full on a real Mac.
* **Batched.** Each poll drains every datagram already queued, then every
  device packet, capped at `ESP_BATCH_MAX` (64) per direction. Under load the
  loop does not block or sleep; a remainder stays queued for the next poll.
* **Event-driven when idle.** When both directions are empty the loop waits on
  the operating system primitive: `WaitForMultipleObjects` over the Winsock UDP
  event and the Wintun read event on Windows, and `poll(2)` over the UDP
  socket on Unix. The Windows wait is bounded at 50 ms; the Unix channel path
  uses 10 ms so a packet queued by the reader is consumed promptly without a
  busy spin. Keepalives, rekey deadlines and the stop flag run within that
  bound; shutdown never waits longer than one interval.
* **Unix writes stay on the loop.** Decrypted packets are written by the ESP
  loop, which prepends the macOS address-family header. A write that would
  block is retried once after a short sleep and then dropped with a warning
  instead of stalling the loop.
* **Buffer reuse.** `EspSession` allocates its UDP, device, plaintext and
  encrypt buffers once at construction. `encrypt_into`/`decrypt_into` write into
  caller-owned buffers, so steady-state packets do not allocate a `Vec` in
  either direction.
* **Socket and device sizing.** The connector requests 4 MiB `SO_SNDBUF` and
  `SO_RCVBUF` (failure is ignored), and the device receive buffer is sized from
  the negotiated MTU instead of a fixed guess.
* **Same protocol.** SA selection, the replay window, keepalives, liveness,
  confirm-before-switch rekey, byte counters and error mapping are unchanged. A
  non-blocking send that reports `WouldBlock` drops that datagram, as UDP
  permits, instead of failing the tunnel.
* **Diagnostics.** Opening a device logs the interface name read back from the
  OS and the descriptor number at info. A watchdog warns when the Unix reader
  channel has been empty for 5 seconds, naming the interface and descriptor.
  The reader is woken through a self-pipe and joined with a 2-second bound
  during teardown, so a wedged reader cannot delay route or DNS rollback.

Measure the offline packet path (encrypt + decrypt, with the old per-packet
`Vec` path and the buffer-reuse path measured in the same run):

```sh
cargo test -p aevan-nc --release esp_encrypt_decrypt_throughput_benchmark -- --ignored --nocapture
```

Measure the live tunnel from the account holder's machine (these are the
commands to run; the `iperf3` server endpoint depends on the account):

```sh
# latency and loss through the tunnel, 100 pings
ping -n 100 <inside-host>            # Windows
ping -c 100 <inside-host>            # Linux/macOS

# throughput through the tunnel, four parallel streams for 30 s
iperf3 -c <iperf3-server> -t 30 -P 4

# raw-link baseline: stop the tunnel first, then run the same command again
iperf3 -c <iperf3-server> -t 30 -P 4
```

Compare `sender`/`receiver` bitrates and the `ping` loss/time lines before and
after, not just the peak instant rate.

## ESP loop behaviour

* Outbound: every queued inner IPv4/IPv6 packet from the Wintun device (up to
  the batch cap) is encrypted with the KMP 301 outbound SA and sent to the TLS
  peer's address on the configured UDP port.
* Inbound: every queued datagram (up to the batch cap) is processed; packets
  with a different SPI, a bad ICV, a replay, a malformed frame or an
  unsupported next header are logged at debug and dropped. Nothing in this path
  panics on malformed input.
* Keepalives use the outbound SA on the configured interval (the KMP 301
  ESP-to-SSL fallback value, default 15 seconds), with a peer timeout of three
  intervals. If nothing authenticated arrives for that long, the command returns
  a network error and teardown runs.
* Rekey is driven by the gateway's own KMP 302 (see below). `EspSession` also
  keeps the client-initiated fallback from the KMP 301 lifetimes and
  `RekeyPolicy`; `AEVAN_DISABLE_REKEY=1` turns both off entirely.

## Rekey is server-driven

The rekey behaviour is definitive. At timestamps `1793838330`-`1793838331`,
exactly 960 s after connect, the daemon log shows:

```text
302 direction=inbound  bytes=208     <- the peer sends us a KMP 302 at rekey time
302 direction=outbound bytes=108     <- we then started our own rekey
303 direction=outbound bytes=38
inbound packet on the new SPI direction=inbound spi=0x2b4cf4b3 bytes=148
... 45 s of silence, then 'the ESP peer stopped responding'
```

A gateway KMP 302 is an **instruction**: group 7/attr 1 is the client's new
outbound SPI, and group 7/attr 2 is the client's new `0x40`-byte outbound key
block. Group 8 carries the transforms and lifetimes. The reference is
openconnect's `oncp.c`, whose `parse_conf_pkt` accepts only groups 7 and 8 in a
302 and splits the key block into encryption and HMAC keys only after reading
the encryption length from 8/1:

| group/attr | length | meaning |
|---|---|---|
| 7/1 | 4 | the recipient's outbound SPI (`vpninfo->esp_out.spi`) |
| 7/2 | `0x40` | outbound encryption + HMAC key block |
| 8/1 | 1 | encryption type (`0x02` AES-128, `0x05` AES-256) |
| 8/2 | 1 | HMAC type (`0x01` MD5, `0x02` SHA1) |
| 8/4 | 2 | ESP UDP port |
| 8/5 | 4 | lifetime in bytes |
| 8/6 | 4 | lifetime in seconds |
| 8/10 | 4 | replay protection |

The recorded 208-byte message is a 302 with groups 7 and 8. The initial
exchange remains **client-initiated**: after KMP 301 we send 302 then 303.
Only the rekey is server-driven.

### What the client does on an inbound 302

1. Parse groups 7 and 8 strictly. Unknown attributes inside those groups are
   ignored and logged by group/attr/length only. Any other group, a wrong
   attribute length or a truncated attribute is rejected; key bytes are never
   logged.
2. Build the new **outbound** SA from 7/1 and 7/2. Use group 8/1 and 8/2 when
   present (otherwise the current transforms) to split the `0x40` bytes into
   `encryption_key` and `hmac_key`.
3. Install it immediately as the active outbound SA, reset the sequence number
   and IV, update the lifetime from 8/5 and 8/6 when present, and restart the
   local rekey timer from now. The previous outbound SA is **simply replaced**:
   packet processing is synchronous and keeps no packet buffered across a poll,
   so no packet can still need the old keys.
4. Unless an exchange is already in flight, answer with our own KMP 302
   proposing fresh **inbound** keys, then KMP 303, in that order on the retained
   oNCP stream. Install the proposed inbound SA as current immediately and keep
   the previous inbound SA accepting packets for `rekey_grace` (about 30 s),
   then retire it.
5. An inbound 302 that arrives while an exchange is in flight still has its
   outbound keys applied, but does not start a second proposal. At most one
   exchange is in flight.

All of this is logged at info level with the outbound SPI, transforms, key
block length, lifetimes, what was sent back and which SA became active. SPIs are
logged; key bytes never are.

### Client-initiated fallback: confirm before switching

The KMP 301 soft time lifetime is 1200 s on this gateway. If the gateway does
not send its own 302, the client falls back to starting a rekey at **80 percent**
of that lifetime (960 s) via `RekeyPolicy::due` (20 percent time margin; the
byte lifetime has no margin). If a gateway 302 is processed first, the local
timer is reset and no client-initiated 302 is sent.

The oNCP TLS session is **retained** for the lifetime of the tunnel instead of
reconnecting with the saved cookies. A rekey sends a new KMP 302 on the same
authenticated stream that carried the initial handshake, through a `KmpChannel`
handle that can write framed KMP messages and poll for replies.

The fallback keeps the earlier **confirm-before-switch** rule so an unconfirmed
proposal cannot destroy a working SA:

1. Generate a fresh inbound SPI and `0x40`-byte key block.
2. Send KMP 302, then KMP 303.
3. Install the new **inbound** SA as *pending* and keep sending on the old
   outbound SA.
4. Wait up to `rekey_grace` for either a **KMP 303 reply** or an **inbound ESP
   packet that authenticates with the new inbound SPI**.
5. On confirmation, make the pending inbound SA current, retire the old inbound
   SA after the grace window, and switch the outbound SA only if a
   gateway-driven 302 has not already supplied it. Sequence numbers restart at
   zero.
6. If no confirmation arrives, abandon the pending inbound SA, keep the old SAs
   and retry after **60 s**, then **300 s**.

A failed KMP write is not a tunnel failure. Keys stay in `SecretKey`/`EspKeys`
and are never logged, serialised or placed in status. Logs carry only message
numbers, byte lengths, directions and SPIs.

### Turning rekey off

Set `AEVAN_DISABLE_REKEY=1` in the environment before `aevan connect` (or before
starting the daemon) to disable automatic rekey entirely. The tunnel keeps using
the initial SA until it is torn down. The connector logs a loud warning at
startup when the switch is active.

This is the fallback if the gateway never accepts our KMP 302: a tunnel that
does not rekey is better than one that dies at 16 minutes. Use it for a
multi-hour session to learn whether the gateway actually enforces the 1200 s
lifetime. Only the literal `1` (surrounding whitespace is ignored) enables the
switch; every other value leaves rekey enabled.

A gateway-initiated 302 was verified against a live gateway at the 960 s lifetime, so the
server-driven path above is the primary one. Its attribute layout is the
reference's `oncp.c` map. The client-initiated fallback and its confirmation
signals are still verified offline only; the live rekey was answered by the
server-driven path.

## Known differences from the reference

* The reference sends the 303 and 302 in one TLS record (303 first) in
  `oncp_connect`; a live gateway records 302 then 303. This client sends them as
  two records, 302 then 303, matching the recorded wire order.
* The recorded "302 size 86" is the KMP payload length; the full record is 108
  bytes including the two-byte length prefix and 20-byte KMP header. The 303
  builder is the existing 38-byte message (16-byte payload).
* ESP encryption/authentication cover the transforms this gateway offered
  (AES-128-CBC + HMAC-SHA1, 96-bit ICV). AES-256 and MD5 are implemented and
  tested offline but are not required by this gateway.
* LZO compression is not implemented; a packet with next header 5 is logged and
  dropped rather than decompressed.
* Rekey is server-driven and was verified against a live gateway at 960 s. The client-initiated
  fallback still uses confirm-before-switch and is covered by offline tests.
  `AEVAN_DISABLE_REKEY=1` disables both. The ESP-to-SSL fallback is not
  implemented: a dead peer is a clean error, not a fallback to the oNCP TLS data
  path.
* Key generation uses the documented fallback RNG described above because the
  dependency set has no OS random API. That is the main security difference
  from a production client.

## Exit codes on this path

| code | meaning |
|---|---|
| 0 | dry run printed the plan, or Ctrl+C shut down cleanly |
| 4 | TLS/network failure, ESP socket failure, or unresponsive ESP peer |
| 6 | privilege check refused the applier or adapter |
| 7 | handshake status byte, undecodable KMP 301, missing ESP material, or ESP packet-layer rejection |

## Verified against the live gateway (2026-11-04)

First working tunnel from the clean-room client, measured, not asserted:

| check | result |
|---|---|
| A1 tunnel is real | adapter `aevan` carries `10.20.0.10/32`; `10.0.0.0/8`, `172.30.0.0/21`, `172.30.6.0/24`, `172.30.8.0/24` on-link via the adapter |
| A1 DNS | interface has static DNS `10.20.0.53`, `10.20.0.54` |
| A2 internal reachability | `nslookup cm.dnsv.example.com 10.20.0.53` → `10.20.0.20`; TCP 443 to `10.20.0.20` succeeded |
| idle stability | up and idle for 10+ minutes with no drop, after the keepalive and liveness fixes |
| teardown | Ctrl+C: adapter gone, no route via `10.20.0.10`, no `10/8`, interface DNS settings gone — no residue |

Outstanding for a long session: rekey is implemented and tested offline (the
server-driven path was verified against a live gateway; the client-initiated
fallback was not), the ESP→SSL fallback path, and a keepalive shape that is an
interoperability assumption rather than a recorded gateway value. The
tunnel is stable while idle, but a multi-hour session has not been tested. For
that test, `AEVAN_DISABLE_REKEY=1` removes rekey as a variable and answers whether
the gateway enforces the 1200 s lifetime at all.
