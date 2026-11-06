# Protocol notes — Network Connect transport

This document records the implementation stages and the observed wire layout. It
is **not** a wire specification; the wire layout is read from openconnect
(`nc.c`, `esp.c`, `oncp.c`, LGPL-2.1 — read for layout, write our own code) and
from observed gateway behaviour.

Why NC first: some gateways reject the IFT/pulse handshake from a non-vendor
client at the EAP identity step before any credential is sent, while the NC path
authenticates end-to-end and returns an NCP configuration. IFT/TLS is the
optional M6 track and is feature-gated (`aevan-ift`, non-default `ift` feature).

## Stage checklist

- [x] **1. `aevan auth-probe`** — TLS connect, redirect-following `GET`, detect
      the form shape (`realm` hidden field, `frmLogin`, token page), then stop.
      No credentials, no TUN, no routes. Safe to run repeatedly because a
      pre-auth failure costs no login attempt. When no form is present it
      reports the redirect chain and `form_shape: "none"` rather than inventing
      a login page.
      Observations: a non-vendor IFT/pulse handshake is rejected at the EAP
      identity step before credentials, while the NC login page is reachable
      and the gateway certificate is publicly trusted for its realm
      (`example_realm`). Implemented in `aevan-nc::auth` with offline fixtures
      (see "Live observations" below); checked against a gateway at the portal
      path `/staff`.
- [x] **2. `aevan login`** — one credential POST to the detected `login.cgi`
      form (user/password/realm `example_realm`), then classify the response as
      success, token required, rejected or unexpected from status, headers and
      body. A recognised token page (`frmTotpToken` / `password#2`) yields one
      continuation POST; there is no loop, retry or fallback host. One
      authentication attempt per invocation remains the caller's rule.
      Observations: the vendor CLI cannot perform secondary auth; a token page
      is accepted and an NCP configuration is returned on success. Implemented
      in `aevan-nc::login` with offline fixtures. One live run authenticated and
      then treated a `302` to `welcome.cgi` as success. That was a **false
      success**: the redirect pointed back at the sign-in page and carried no
      `Set-Cookie`, and every post-login endpoint bounced to the auth page. The
      corrected rule below now rejects that response with exit 3.
- [x] **3. `aevan config`** — decode the **binary oNCP KMP/TLV** configuration
      into a typed struct and print JSON: assigned IPv4/IPv6, split routes
      (include and exclude), DNS servers, WINS, search domain, MTU, ESP
      encryption/authentication/compression, ESP UDP port, ESP key lifetimes,
      ESP-to-SSL fallback, replay protection and outbound SPI. The ESP key
      block is accepted but never serialised or rendered.
      Acceptance: field-for-field match with an observed gateway configuration
      (internal IP `10.20.0.10`, /32 netmask `255.255.255.255`, routes `10/8`,
      `172.30.0.0/21`, `172.30.8.0/24`, `172.30.6.0/24`, DNS `10.20.0.53` and
      `10.20.0.54`, gateway `10.20.0.1`, MTU 1396, AES-128/SHA1 on UDP
      4500, ESP→SSL fallback 15 s). Implemented in `aevan-nc::ncp`; the
      acceptance fixture is a synthetic binary blob (see below). `aevan config
      --live` now runs the post-login oNCP handshake and decodes a real KMP 301
      (see "Live handshake (M2)"); the live command has not been run in this
      build.
- [ ] **4. `aevan connect`** — create the device, apply routes/DNS/MTU, run ESP:
      AES-128/256-CBC with HMAC MD5-96/SHA1/SHA256, replay window, keepalive,
      rekey, and the 15 s ESP→SSL fallback path (unknown #2; implement only if
      ESP proves unstable, otherwise fail loudly and log the reason).
      Reference: the reference implementation and observed gateway behaviour
      (gateway offered AES-128/SHA1 over UDP 4500, ESP→SSL fallback 15 s).
- [ ] **5. Teardown** — always restore routes, DNS, MTU and the device;
      idempotent and run on panic/SIGINT.
      Reference: the reference implementation and host-checker analysis (driver/adapter/split-DNS filter are what must be
      restored).

## Stage 3 wire format (corrected)

The M1 stage 3 assumption of a line-oriented `KEY=value` body was wrong. An NC
configuration is a **binary oNCP** message carried inside the TLS stream. The
TLS record and KMP framing is:

| offset | field | status |
|---|---|---|
| record `0..2` | record length, little-endian, excluding the prefix | confirmed |
| KMP `+0..+6` | six bytes the reference treats as a constant header | inferred constant |
| KMP `+6..+8` | message number, big-endian: 301 config, 302 ESP, 303 reply | confirmed |
| KMP `+8..+18` | ten bytes the reference checks as `01 00 00 00 00 00 00 00 00 00` | inferred constant |
| KMP `+18..+20` | KMP payload length, big-endian | confirmed |
| KMP `+20` | first group block | confirmed |

The payload is a sequence of group blocks, `u16 group | u32 group_length |
attributes`, and each attribute is `u16 attr | u32 attribute_length | value`.
The confirmed attribute numbers are the ones in the table in
`crates/aevan-nc/src/ncp.rs`: group 1 address/netmask/gateway, group 2 DNS and
search domain, group 3 include/exclude routes, group 4 WINS, group 6 MTU,
group 7 outbound SPI and ESP keys, group 8 ESP transforms, UDP port, lifetimes,
fallback and replay protection. Group 7/attr 2 is live key material; the parser
keeps it out of JSON and `Debug` and zeroizes it on drop.

The M1 task also describes a flat attribute record form (`u16 group, u16 attr,
u32 length, value`). `aevan-nc::ncp::decode_flat_attributes` accepts that form,
but real oNCP messages use the nested group blocks above.

**Live acquisition belongs to M2.** The configuration is not in the HTTP login
response body: it is exchanged in the oNCP handshake after the HTTP login, on
the same TLS connection. M1 therefore validates the decoder only against the
synthetic blob below. The blob is **SYNTHETIC**, built from observed values plus
a synthetic ESP key/SPI, not a capture.

## oNCP handshake framing (M2, offline slice)

`crates/aevan-nc/src/oncp.rs` implements the post-login switch to oNCP as pure
byte builders and parsers; no socket or TLS handle is involved.

- The request is `POST /dana/js?prot=1&svc=4` with `Connection: close`,
  `Host`, `User-Agent`, optional `Cookie` and `Content-Length: 256`. The fixed
  length is what the reference sends; it is not the length of the following
  packet.
- The hostname packet is a little-endian length prefix, the fixed five-byte
  head, a little-endian hostname length, the hostname, and the fixed six-byte
  tail. It is a pure function of the hostname.
- KMP frames are parsed as a two-byte little-endian record length, the 20-byte
  KMP header, the big-endian message number (301 config, 302 ESP negotiation,
  303 reply) and the big-endian payload length. Truncated frames, inconsistent
  lengths, unknown header tags and unexpected message numbers are rejected.
- KMP 302 parses group 7/attr 1 (outbound SPI) and group 7/attr 2 (the 0x40-byte
  key block), then splits the block as `encryption_key || hmac_key` using the
  key lengths of the configured transforms. Group 8 attrs 1/2 carry the
  encryption and HMAC types, and 5/6 carry the byte and second lifetimes.
  Unknown attributes inside groups 7/8 are ignored and logged by
  group/attr/length only; any other group is refused, as in openconnect's
  `parse_conf_pkt`. Truncated attributes are refused.
- KMP 303 is built as group 6/attr 2 carrying the accepted MTU.

### Live rekey evidence: the gateway drives the exchange

The daemon log from the 960 s rekey is decisive. At timestamps
`1793838330`-`1793838331`, exactly 960 s after connect, the gateway sent an
inbound 208-byte KMP 302, then the client sent its own 302 (108 bytes) and 303
(38 bytes). The peer answered once on the SPI the client proposed, and then
stopped: the client had ignored the peer's outbound keys and kept encrypting
with the old SA.

The reference implementation is openconnect's `oncp.c`. Its attribute map for
a KMP 302 is:

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

`parse_conf_pkt` accepts only groups 7 and 8 in a 302, and splits the `0x40`
byte block into the encryption key (first `enc_key_len` bytes) and HMAC key
(remainder) only after the encryption length from 8/1 is known. A gateway 302
is therefore an **instruction**: "here is your new outbound SPI and key block".
The initial exchange remains **client-initiated** (we send 302 then 303 after
KMP 301); the live rekey is **server-driven**. See `docs/CONNECT.md` for the
implemented behaviour.

The byte layout is read from openconnect's `oncp.c` (LGPL-2.1, layout only,
written independently). The offline builders are verified against hand-built
arrays and the existing synthetic KMP 301 fixture; the live handshake path is
described below.

## Live handshake (M2)

`aevan config --live [profile] [--dump-dir PATH] [--keep-session] [--json]`
performs one authentication attempt through the same credential path as
`aevan login`, then runs the post-login oNCP handshake. The login session's
cookies are reused, but the handshake opens a fresh TLS connection: the oNCP
request and the binary switch happen on that one connection.

### Credential POST body and success rule

The credential POST is built from the vendor's field set, not only the three
credential fields. Provenance:

* Installed 22.8.3 client, `TNC Client Plugin/dsWinClient.dll` (strings read
  for wire layout only; no code copied):
  `username=%s&password=%s&realm=%s`,
  `xsauth=%s&tz_offset=%d&clienttime=%d&url=&activex_enabled=%d&java_enabled=%d`,
  `starter0.cgi has asked for tz_offset parameter`, and
  `DSIDConfirmForm` / `btnContinue` / `FormDataStr` for the confirmation page.
* Ivanti's documentation of the same flow: `GET` the sign-in page (which sets
  `DSSIGNIN`), then `POST` to `/dana-na/auth/<DSSIGNIN-value>/login.cgi` with
  `username`, `password`, `realm` and `btnContinue='Continue the session'`.

The body is written in this order:

| field | source |
|---|---|
| `username`, `password`, `realm` | profile and the discovered form's field names |
| `xsauth` | fresh 16-character lowercase-hex nonce per attempt |
| `tz_offset` | local UTC offset in minutes, for example `480` for UTC+8 |
| `clienttime` | current Unix time in seconds |
| `url` | empty |
| `activex_enabled`, `java_enabled` | `0` |
| `btnContinue` | `Continue the session` only for a confirmation page or a resumed session |
| carried hidden fields | every hidden input from the discovered form, such as `clientMAC` and CSRF state |

Explicitly built fields win over a duplicate hidden field. Values are never
logged or placed in the dump; the dump records field **names** only, so the
`xsauth` value never appears. The body remains zeroized.

`xsauth` has no direct RNG dependency in this workspace. It is derived from the
nanosecond clock, the process id and a per-process counter; the comment in
`aevan-nc::login` states that this is not a cryptographic RNG. `tz_offset` is
read from the OS once in `aevan-core::timezone` (PowerShell on Windows, `date
+%z` on Unix). That query is best-effort, is cached for the process, and falls
back to UTC if it fails; it cannot follow a DST transition during a long run.

#### Success classification

A redirect status is **not** success by itself. A login is successful only when
one of these holds:

1. the redirect target is not an auth/welcome/login URL (for example
   `/dana-na/`);
2. the login response itself carries `Set-Cookie` for `DSID` or `DSSIGNIN`;
3. a `200` body is a dashboard (or an explicit success page) rather than a
   sign-in form.

A `302` to `welcome.cgi`, `login.cgi`, `/dana-na/auth/...`, or a URL containing
`p=user-confirm` is therefore not success. Without a session cookie it is
`Rejected` (exit 3) with the reason `bounced back to the sign-in page`. A `200`
sign-in form is rejected the same way; any other response without a session
cookie is `Rejected` with `no session cookie issued`. The user-confirm
continuation is still answered once (below), but its result must independently
pass this rule before the command reports success.

### User-confirm continuation

A credential or token POST can answer with a redirect whose `Location` contains
`p=user-confirm`; a 200 page that carries a continuation form and no dashboard
is treated the same way. This is the gateway's "you already have a session,
confirm to continue" step, not a rejected login and not a retry.

The client handles it as part of the same authentication exchange:

1. `GET` the redirect target (or the POST target for a 200 page) with the
   session cookies.
2. Scrape the forms and select a continuation form. A page with exactly one form
   uses it; otherwise a form on the same host that carries a submit/button or a
   continue/confirm-style hidden field wins. Credential and token forms are
   never selected.
3. `POST` that form exactly once with its hidden fields plus
   `btnContinue`, then classify the response exactly like the credential POST.
   A real confirmation form (`DSIDConfirmForm` / `frmConfirmation`) contributes
   its hidden `FormDataStr` and `btnContinue='Continue the session'`;
   `btnCancel` is not submitted. If the credential POST itself served the
   confirmation page, that page is answered directly without an extra GET.

At most one continuation POST is sent. A result that redirects to another
`p=user-confirm` page stops the command with exit 7 and an explicit message; it
never loops. A continuation that bounces to `welcome.cgi`/`login.cgi` without a
session cookie is rejected with exit 3, not success. The continuation is not an
authentication attempt: the credential POST is still exactly one per
invocation.

The live sequence is:

1. `POST /dana/js?prot=1&svc=4 HTTP/1.1` with `Connection: close`, `Host`, a
   `User-Agent`, the session `Cookie` header from the login, and a
   `Content-Length`.
2. Read and discard the HTTP response (normally `200`) and any declared body.
3. Write the hostname packet built by `aevan-nc::oncp::hostname_packet`.
4. Read the gateway's three bytes: a little-endian record length and the
   status byte. A non-zero status is a gateway failure, not an auth retry.
5. Read the KMP 301 configuration. The status can arrive as its own one-byte
   record followed by a separate KMP record, or the KMP bytes can be
   concatenated after the status in the same record. The reader handles both,
   follows continuation records, ignores an interleaved legacy KMP 300 IP
   frame, and decodes the first KMP 301 with the existing `NcpConfig` decoder.
6. Print the same JSON shape as `config --from-file`, with
   `schema_version` and `source: "live"`.

### Single-session endpoint probe

`/dana/js?prot=1&svc=4` is the legacy oNCP entry, not this gateway's Network
Connect launch point. Live evidence (2026-11-04) shows that a POST to it with a
valid session is answered `302` to `/dana-na/auth/welcome.cgi` with
`Content-Length: 0`; the TLS stream never switches to binary KMP. The vendor
client (`JamUI/Pulse.exe`, `JamUI/DialogManager64.dll`) contains exactly one NC
launch path, `%ls/dana/nc/ncrun.cgi?launch_nc=1`, plus the string
`SAMLLoginBrowserWorker - Found ncrun.cgi` and the form content type
`application/x-www-form-urlencoded`. That is the path the real client is handed
after web login; `/dana/js` remains the legacy entry.

`aevan config --live` therefore runs one ordered probe list in the same login
session (one credential POST, no retries):

| probe | request | purpose |
|---|---|---|
| a | `GET /dana/nc/ncrun.cgi?launch_nc=1` | vendor NC launch path |
| b | `GET /dana/nc/nc_gina_ver.txt` | NC version/config hint |
| c | `GET /dana/home/am_params.cgi?am=0` | legacy access-method parameters |
| d | `POST /dana/js?prot=1&svc=4` | legacy oNCP, with the existing hostname packet and single `Content-Length: 256` fallback |

Every probe sends the session cookies using the host-matching rule, so a cookie
scoped to the login directory is still sent, and uses a short timeout. It records
status, reason, `Content-Type`, `Content-Length`, a redacted `Location`, and the
first 256 body bytes as hex plus lossy text when printable. A GET probe follows
at most one redirect; the legacy oNCP probe records its redirect without
following it. A probe failure is recorded and the list continues. The list stops
early only when a response parses as a KMP 301 or carries NC configuration keys.

If any probe yields a KMP 301, it is decoded exactly like `config --from-file`
and printed. Otherwise the command exits 7 with an error naming every probe that
ran and what it returned, and still writes the dump. The probe exists to
identify the real configuration source in a single session instead of guessing
the oNCP entry again.

### Content-Length ambiguity and the single fallback

The reference sends a fixed `Content-Length: 256` while the hostname packet is
shorter; the exact convention is not confirmed on this gateway. The first
attempt therefore writes the real packet length. If that does not yield an
HTTP 200 plus a KMP 301, the driver makes exactly one more request in the same
session with `Content-Length: 256` and the hostname packet zero-padded to 256
bytes. There is no loop. The fallback is not an authentication attempt: the
session already exists, and the login rule of one authentication attempt per
invocation is unchanged. The returned `HandshakeOutcome` records which variant
worked.

### Session cleanup

After `config --live` finishes, success or failure, it sends one best-effort
`GET /dana-na/auth/logout.cgi` with the session cookies so repeated runs do not
accumulate gateway sessions. A logout failure is logged at debug level,
recorded in the dump, and never changes the command's exit status.
`--keep-session` skips this request when the caller wants to retain the session.

### The dump, and what it deliberately omits

`--dump-dir PATH` writes `handshake.json` (owner-only, mode 0600 on Unix) with:

- the credential-free probe's redirect chain;
- the final login response status, reason and headers;
- the credential POST body field **names** in wire order, never values (so
  `xsauth` appears as a name but its value is absent);
- the user-confirm exchange: whether it was needed, every hop's URL, status and
  redacted headers, and the served HTML marked `captured`, redacted and capped
  at 8192 bytes;
- the ordered endpoint probe list, with cookie metadata for every request
  (name, domain, path, secure flag and whether it applied; never a value),
  status, reason, content type, content length, redacted `Location`, and the
  bounded body prefix;
- the handshake HTTP status and headers;
- the handshake status byte and every KMP frame's message number and lengths;
- the hex of the request and the binary response bytes, including the bytes
  received before a transport failure and that read offset in hex;
- the best-effort logout outcome;
- the decoded configuration, when one was obtained.

Every `Set-Cookie` value, the `Cookie` request header, every URL query value,
and the ESP key block are redacted. The key block is replaced by
`[redacted N bytes]`; its bytes never reach the dump, stdout or a log. The
decoded configuration also omits the ESP key block by construction. The dump is
`schema_version: 2`; the earlier fields keep their names and meaning.

The live path still has to be run by the account holder. Offline tests cover the
framing, the fallback, the decoder and the dump redaction with a scripted
transport; no test opens a socket or sends credentials, and the implementation
was not run against the live gateway while building this slice.

## ESP data plane (M2, offline slice)

`crates/aevan-nc/src/esp.rs` implements the ESP frame with the transforms this
gateway offered. Nothing here opens a UDP socket or creates a TUN device.

| offset | field | status |
|---|---|---|
| `0..4` | SPI, 32-bit network byte order | reference layout |
| `4..8` | sequence number, 32-bit network byte order | reference layout |
| `8..24` | CBC IV, 16 bytes | RFC 3602 |
| `24..N` | AES-CBC ciphertext | confirmed AES-CBC transform |
| `N-2` | pad length | RFC 4303 |
| `N-1` | next header (`4` IPv4, `41` IPv6, `5` LZO IPv4) | reference layout |
| `N..N+12` | truncated ICV | reference layout for MD5-96, inferred for SHA1 |

Parameters taken from evidence or standards:

- **Observed gateway:** AES-128-CBC, HMAC-SHA1, UDP 4500, MTU 1396, ESP-to-SSL fallback 15 s.
- **Reference implementation:** AES-128/256, `MD5-96`, `SHA1`, ESP keepalives and `rekey_count`.
- **RFC 3602:** AES-CBC block and IV sizes.
- **RFC 2403 / RFC 2404:** HMAC-MD5-96 and HMAC-SHA-1-96. The reference implementation records MD5-96
  explicitly; the 12-byte SHA1 ICV follows RFC 2404 and the reference, not a
  capture. The ICV covers the ESP header and ciphertext.
- **RFC 4303:** padding length byte, next-header byte and the anti-replay
  check. Padding contents are ignored on receive.
- **RFC 2202:** HMAC-MD5 and HMAC-SHA1 test vectors used by the unit tests.

Inferred, not observed on this gateway:

- The next CBC IV is the last ciphertext block of the previous packet. This is
  openconnect's `esp.c` behaviour; the vendor client's IV choice was not
  captured.
- Keepalive packet contents (a single zero byte with next header 4) are a typed
  helper driven by the session loop, but the gateway has not been observed
  sending or accepting a keepalive.
- Rekey is **server-driven** and was observed live at the 960 s lifetime. An
  inbound KMP 302 supplies the client's new outbound SPI and key block; the
  client installs that SA immediately (no confirmation for keys the peer
  supplied), resets the outbound sequence and IV, updates the lifetime from
  group 8 attrs 5/6 and restarts its local timer. It then answers with its own
  KMP 302 proposing fresh inbound keys plus KMP 303, keeps the previous inbound
  SA for a 2x-keepalive grace window, then retires it. The client-initiated
  path remains as a fallback with **confirm-before-switch**: a KMP 303 reply or
  an inbound packet on the newly proposed SPI must arrive before the outbound
  SA switches. If a gateway 302 is processed first, the local timer is reset and
  no client-initiated 302 is sent. Offline tests cover the 208-byte fixture, the
  `0x40` split for AES-256/SHA1, rejection of other groups and truncation, the
  timer reset, a 302 arriving mid-exchange, and the inbound grace window.
- A zero KMP lifetime is treated by `RekeyPolicy::from_esp_proposal` as "no
  limit". Unknown #6 (rekey transform negotiation) is now closed by the live
  server-driven evidence above.

No ESP packet has been captured from this gateway. The frame, the key split and
the replay window are therefore proven only against standards vectors and
offline round trips, not against live ESP traffic.

Receive-side state is a 64-packet sliding window: duplicates and packets older
than the window are rejected, in-window reordering is accepted once, and the
window advances only after the ICV verifies. Send-side sequence numbers start at
zero, increment per packet and refuse to wrap after `u32::MAX`. Key material is
held in a zeroizing type with a redacted `Debug` and no serialiser.

Still left for the live half of M2: the UDP socket, the Wintun/utun/tun
backends, route/DNS/MTU application, `aevan connect`, and the ESP-to-SSL fallback
path.

## Live observations

**The portal path is server-specific.** On the gateway this client was first
tested against, the portal path was `/staff`, not `/`; a credential-free probe of
the site root landed on the vendor's 404 shell. Treat the paths below as an
example, not a contract:

- `/` → `404` directly;
- `/example_realm/` → `302` to `/dana-na/auth/welcome.cgi` → `302` to `/` → `404`;
- `/dana-na/auth/url_default/welcome.cgi` → `302` to `/dana-na/auth/welcome.cgi`
  → `302` to `/` → `404`.

The portal path `/staff` reached the sign-in page:

- `/staff` → `302` `Location: /dana-na/auth/url_ExampleRealm01/welcome.cgi` → `200`;
- the final page carries `<form name="frmLogin" action="login.cgi" method="POST">`
  with hidden `realm` = `example_realm`, `tz_offset`, `clientMAC`, plus `username`
  and `password` inputs. No `frmTotpToken` / `password#2` field is present on the
  first page — the token page is served only after a credential POST;
- the `url_…` path segment is generated per realm, so the relative action has to be
  resolved against the **final** welcome URL. `aevan-nc::auth` does that, and
  `example_staff_page_resolves_the_relative_login_action` pins it.

Every fixture under `crates/aevan-nc/tests/fixtures/` is **SYNTHETIC**,
constructed for the offline tests; none is a captured page. `welcome-example.html`
models a welcome form with a relative action. `ncp-config-kmp.bin` is a synthetic
binary oNCP message; its note is in the adjacent `.README` and inside the blob as
an unknown `0xFFFF/1` attribute. The tests never perform a live login, because
that needs a real account and one failed attempt costs an authentication attempt.

## Open questions carried from the findings

1. Exact IFT (pulse) AVP/TLV wire encoding is not recoverable from strings
   an open analysis gap. It blocks a native pulse transport, not NC.
2. The on-wire SSL-fallback envelope for NC was not captured; `Switching to NCP
   mode` is the client-side label (reference implementation, unknown #2).
3. Whether the gateway enforces a minimum client build on the NC path is
   unknown. NC has been observed to work; this is a live server.
4. Host-checker/ZTA enforcement for the Example Corp realm is unknown (the host-checker analysis, unknown #5).
5. Rekey transform negotiation and whether this realm pushes session scripts
   were not observed (unknown #6).

## Rules that are not negotiable

- One authentication attempt per invocation. The Example Corp account locks after
  repeated failures.
- No credentials in argv, environment variables or logs; redact `password`,
  `token`, `cookie`, `authorization` (`aevan-core::redact`).
- No retry loop and no silent gateway fallback.

### Live probe results, oNCP handshake (2026-11-04, after a working login)

Recorded from `aevan config --live`, one session, cookies confirmed present (11 in the jar, `Cookie`
header non-empty, `DSSIGNIN` scoped to `/dana-na/`):

| probe | result |
|---|---|
| `GET /dana/nc/ncrun.cgi?launch_nc=1` | 200 `text/html` — the vendor's NC launch page (setup parameters, not the tunnel config) |
| `GET /dana/nc/nc_gina_ver.txt` | 404 |
| `GET /dana/home/am_params.cgi?am=0` | 200 `text/html` — `<OBJECT><param …>` setup parameters |
| `POST /dana/js?prot=1&svc=4` | 200 `application/octet-stream`, `NCP-Version: 3`, body `00 00 01` — status byte `0x01` |

So `/dana/js` is the right endpoint and the session is authenticated; the gateway accepts the request
and then rejects the handshake payload with status `1`. The real-length and fixed-256
`Content-Length` variants both fail the same way (fixed 256 is now tried first, see `aevan-nc::oncp`).

What the reference client does on this same gateway, from its own log
(`C:\ProgramData\Pulse Secure\Logging\PulseClient.log`): `received kmp message 301 size 361`,
`send kmp message 302 size 86`, `send kmp message 303 size 13`. Our 303 builder is 13 bytes, so the
KMP framing is right; the rejected step is the HTTP-level handshake that precedes it.

Static analysis: no `/dana/js`, `/dana/nc` or `prot=` strings exist anywhere in the installed
binaries — the path is assembled at runtime. `ncAccessMethod.dll` carries the RTTI names
`KmpIpcConnection` and `KmpIpcExchange` and its KMP receiver (`FUN_10058e30`, which logs
`received kmp message`) takes already-framed KMP, so **another component owns the HTTPS handshake and
hands the stream over IPC**. That component is not `ncAccessMethod.dll` and not `iveConnMethod.dll`.

Next dig target: the service-side binaries under `JUNS/` and `Common/`. Do not guess further on the
live gateway; each attempt costs an authentication.

### Why the handshake failed, and what fixed it (2026-11-04)

Every attempt got HTTP 200, `Content-Type: application/octet-stream`, a response header `NCP-Version: 3`
and the three-byte body `00 00 01` — a status byte of `1` with an empty payload. The cause was a **missing
request header**: the reference's `oncp_common_headers()` (`auth-juniper.c`) appends
`NCP-Version: 3` after `Host`, `User-Agent` and `Cookie`. Without it the gateway rejects the oNCP
request with status 1. With it, `POST /dana/js?prot=1&svc=4` returns KMP 301 and the configuration
decodes.

Two dead ends worth recording so nobody repeats them: the vendor client **never requests `/dana/js`**
(its log shows only `ncrun.cgi`, `psalparams.cgi` and jam endpoints, and its KMP 301 arrives over the
IF-T/TLS path), and no `/dana/js`, `prot=` or `svc=` literal exists anywhere in the installed binaries,
so static string hunting cannot find this path.

### Live configuration decoded from the gateway (first successful handshake)

`10.20.0.10/32`, split routes `10.0.0.0/8`, `172.30.0.0/21`, `172.30.8.0/24`, `172.30.6.0/24`,
DNS `10.20.0.53` and `10.20.0.54`, gateway `10.20.0.1`, MTU **1396**, ESP
AES-128-CBC + HMAC-SHA1 on UDP 4500, lifetime 1200 s, replay protection on, ESP→SSL fallback 15 s.
Unrecognised attributes recorded rather than dropped: `3/1`, `3/2`, `2/3`, `8/8`, `8/11`, `8/12`.

Note: a vendor-client session on the same day logged MTU 1496 for its tunnel, while the oNCP config
hands us 1396. The difference is the access method, not a decode error — our MTU comes straight from
TLV group 6 attr 2.
