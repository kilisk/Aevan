# Network Connect protocol

This document describes the wire protocol that Aevan implements. It is a
specification of observable protocol behaviour, not an implementation guide.
The description is derived from public sources: the gateway's publicly visible
HTTP endpoints and sign-in form fields, the relevant IETF RFCs, and the
open-source openconnect project, which is the reference implementation for
these gateways (`oncp.c` and `esp.c`, LGPL-2.1).

Where a value is not fixed by a public standard or by the published endpoint
behaviour, it is called an **interoperability assumption, verified against a
live gateway**. No fact below depends on the proprietary client.

Most examples use documentation placeholders: gateway `vpn.example.com`, portal
path `/staff`, realm `example_realm`, and the internal range `10.20.0.0/24`.
Nothing here is specific to one organisation.

## 1. Transport and sign-in

The client speaks HTTPS (TLS 1.2 or later) to the gateway portal. A
credential-free `GET` follows ordinary HTTP redirects and lands on a sign-in
page. The portal path is server-specific (for example `/staff`); the redirect
target looks like `/dana-na/auth/url_<realm>/welcome.cgi`. Relative form
actions must be resolved against the final welcome URL because the
`url_<realm>` segment is generated per realm.

### Sign-in form

The sign-in page carries an HTML form, conventionally named `frmLogin`, whose
action is relative (`login.cgi`) and whose method is `POST`. Publicly visible
fields are:

| field | kind | meaning |
|---|---|---|
| `realm` | hidden | realm selector, for example `example_realm` |
| `username` | text | account name |
| `password` | password | account password |
| `tz_offset` | hidden | client UTC offset in minutes |
| `clientMAC` | hidden | client identifier field carried through unchanged |

A secondary token page, served only after a credential `POST`, uses the form
name `frmTotpToken` or the input name `password#2`.

### Credential POST

The credential submission is
`application/x-www-form-urlencoded` to the resolved `login.cgi` URL. The body
fields, in wire order, are:

| field | value |
|---|---|
| `username` | profile username |
| `password` | entered password |
| `realm` | realm from the form |
| `xsauth` | fresh 16-character lowercase-hex nonce per attempt |
| `tz_offset` | local UTC offset in minutes, for example `480` for UTC+8 |
| `clienttime` | current Unix time in seconds |
| `url` | empty |
| `activex_enabled` | `0` |
| `java_enabled` | `0` |
| `btnContinue` | `Continue the session`, only for a confirmation page or a resumed session |
| carried hidden fields | every hidden input from the discovered form, such as `clientMAC` and CSRF state |

Explicitly built fields take precedence over a duplicate hidden field.
`xsauth` is a request/anti-cache nonce; it is not the session credential. The
gateway issues the actual session cookie.

### Success classification

A redirect status alone is not success. A login succeeds only when one of the
following holds:

1. the redirect target is not an authentication, welcome or login URL (for
   example `/dana-na/`);
2. the login response itself sets `DSID` or `DSSIGNIN` via `Set-Cookie`;
3. a `200` body is a dashboard or an explicit success page rather than a
   sign-in form.

A `302` to `welcome.cgi`, `login.cgi`, `/dana-na/auth/...`, or any URL carrying
`p=user-confirm` is not success. Without a session cookie it is a rejection. A
`200` sign-in form is rejected the same way.

### User-confirm continuation

A credential or token `POST` can answer with a redirect whose `Location`
contains `p=user-confirm`, or with a `200` continuation form and no dashboard.
This is the gateway's "you already have a session, confirm to continue" step.
The client:

1. `GET`s the redirect target (or the `POST` target for a `200` page) with the
   session cookies;
2. selects a continuation form (a single form on the page, otherwise a form on
   the same host that carries a submit control or a continue/confirm-style
   hidden field; credential and token forms are never selected);
3. `POST`s that form exactly once with its hidden fields plus `btnContinue`,
   then classifies the response exactly like the credential `POST`.

A confirmation form (`DSIDConfirmForm` or `frmConfirmation`) contributes its
hidden `FormDataStr` and `btnContinue=Continue the session`. `btnCancel` is
never submitted. At most one continuation `POST` is sent; a further
`p=user-confirm` response is an error, never a loop.

### Other public endpoints

These endpoints are part of the gateway's publicly visible HTTP surface:

| method | path | purpose |
|---|---|---|
| `GET` | `/dana/nc/ncrun.cgi?launch_nc=1` | Network Connect launch page |
| `GET` | `/dana/nc/nc_gina_ver.txt` | Network Connect version/config hint |
| `GET` | `/dana/home/am_params.cgi?am=0` | legacy access-method parameters |
| `POST` | `/dana/js?prot=1&svc=4` | legacy oNCP entry (binary switch) |
| `GET` | `/dana-na/auth/logout.cgi` | session logout |

A credential-free probe may use these read-only endpoints, but each login
attempt is a single credential `POST`.

## 2. oNCP entry point

After the HTTP login, the client sends one oNCP request on the authenticated
TLS connection:

```http
POST /dana/js?prot=1&svc=4 HTTP/1.1
Host: vpn.example.com
User-Agent: <client>
Cookie: <session cookies>
NCP-Version: 3
Connection: close
Content-Length: 256
```

`NCP-Version: 3` is required; without it the gateway answers with status byte
`1` and no payload. `Connection: close` tells the gateway to stop speaking HTTP
even though the TLS stream stays open.

`Content-Length` is a fixed `256` while the hostname packet that follows is
usually shorter. This is the reference convention; the gateway then reads the
binary payload, not the declared HTTP length. An **interoperability
assumption, verified against a live gateway** is that some gateways also accept
the actual packet length. The client sends the fixed-`256` form first, then at
most one fallback with the actual length, never a loop.

After the HTTP response, the client writes the hostname packet:

```text
u16le  length prefix
[5]    fixed head
u16le  hostname length
[..]   hostname bytes
[6]    fixed tail
```

The packet is a pure function of the hostname. The gateway answers with three
bytes — a little-endian record length and a status byte — followed by the KMP
301 configuration. A non-zero status byte is a gateway failure, not an
authentication retry.

## 3. KMP framing

KMP messages are carried in TLS records. The framing is:

```text
TLS record:
  0..2    record length, little-endian, excluding these two bytes
  2..22   KMP header, 20 bytes
    +6    message number, big-endian u16
          301 = configuration
          302 = ESP negotiation
          303 = client reply
    +8    ten-byte constant tag (01 00 00 00 00 00 00 00 00 00)
    +18   KMP payload length, big-endian u16
  22..    payload: one or more group blocks
```

Group blocks and attributes are big-endian:

```text
group     : u16 group | u32 group_length | group_length bytes of attributes
attribute : u16 attr  | u32 attribute_length | value
```

Truncated frames, inconsistent lengths, unknown header tags and unexpected
message numbers are rejected. The ten-byte tag at `+8` and the fixed five-byte
hostname head and six-byte tail are **interoperability assumptions, verified
against a live gateway**.

### KMP 301 — configuration

The payload is a sequence of group blocks. The attribute groups this client
decodes are:

| group | attributes |
|---|---|
| 1 | assigned address, netmask, gateway |
| 2 | DNS servers, search domain |
| 3 | split-tunnel include and exclude routes |
| 4 | WINS servers |
| 6 | MTU |
| 7 | outbound SPI and ESP key material |
| 8 | ESP transforms, UDP port, key lifetimes, ESP-to-SSL fallback, replay protection |

Group 7/attr 2 is live key material. It is kept out of JSON and `Debug` output
and zeroized on drop.

### KMP 302 — ESP negotiation

A 302 carries the recipient's ESP parameters. The attribute map is:

| group/attr | length | meaning |
|---|---|---|
| 7/1 | 4 | recipient outbound SPI |
| 7/2 | `0x40` | outbound encryption + HMAC key block |
| 8/1 | 1 | encryption type: `0x02` AES-128-CBC, `0x05` AES-256-CBC |
| 8/2 | 1 | HMAC type: `0x01` HMAC-MD5, `0x02` HMAC-SHA1 |
| 8/4 | 2 | ESP UDP port |
| 8/5 | 4 | key lifetime in bytes |
| 8/6 | 4 | key lifetime in seconds |
| 8/10 | 4 | replay protection |

Only groups 7 and 8 are accepted in a 302. The `0x40`-byte block is split as
`encryption_key || hmac_key` after the encryption length from 8/1 is known.
Unknown attributes inside groups 7 and 8 are ignored; any other group is
refused.

The initial exchange is client-initiated: after KMP 301 the client sends its
own 302 (fresh inbound SPI and key block) and then 303 on the same stream. A
gateway 302 at rekey time is an instruction (see §5).

### KMP 303 — client reply

A 303 carries the MTU the client accepted, as group 6/attr 2.

## 4. ESP data plane (RFC 4303)

ESP runs over UDP to the TLS peer address on the port from group 8/attr 4
(typically 4500). The frame is:

| offset | field |
|---|---|
| `0..4` | SPI, 32-bit network byte order |
| `4..8` | sequence number, 32-bit network byte order |
| `8..24` | CBC IV, 16 bytes |
| `24..N` | ciphertext: payload, padding, pad length, next header |
| `N..N+12` | truncated ICV, 12 bytes |

Cipher and authentication follow these standards:

* AES-CBC block and IV sizes: RFC 3602.
* HMAC-MD5-96: RFC 2403. HMAC-SHA1-96: RFC 2404.
* ESP padding, pad-length byte, next-header byte and anti-replay: RFC 4303.
* HMAC-MD5 and HMAC-SHA1 test vectors: RFC 2202.

Transforms this build supports are AES-128-CBC and AES-256-CBC with
HMAC-MD5-96 or HMAC-SHA1-96. The ICV covers the ESP header (SPI, sequence, IV)
and the ciphertext. Next-header values are `4` (IPv4), `41` (IPv6) and `5` (LZO
IPv4); LZO compression is not implemented, so a packet with next header `5` is
dropped.

The next CBC IV is the last ciphertext block of the previous packet. This is an
**interoperability assumption, verified against a live gateway**. Padding
contents are ignored on receive.

Receive-side state is a 64-packet sliding window: duplicates and packets older
than the window are rejected, in-window reordering is accepted once, and the
window advances only after the ICV verifies. Send-side sequence numbers start
at zero, increment per packet, and refuse to wrap after `u32::MAX`.

The transforms, MTU and UDP port are taken from the KMP 301 configuration. On a
live gateway the values are commonly AES-128-CBC + HMAC-SHA1 over UDP 4500, MTU
1396, and a 1200-second soft lifetime; AES-256 and HMAC-MD5 are supported by the
same code path and are exercised offline.

## 5. Keepalives and server-driven rekey

Keepalives use the outbound SA on the interval derived from the KMP 301
ESP-to-SSL fallback value (typically 15 seconds), with a peer timeout of three
intervals. The keepalive payload is a single zero byte with next header `4`.
That payload shape is an **interoperability assumption, verified against a live
gateway**.

ESP rekey is server-driven. At the soft lifetime the gateway sends an inbound
KMP 302 carrying the client's new **outbound** SPI (7/1) and `0x40`-byte key
block (7/2), plus group 8 transforms and lifetimes. The client:

1. installs the supplied outbound SA immediately, resets the outbound sequence
   number and IV, updates the lifetime from 8/5 and 8/6 when present, and
   restarts its timer;
2. answers with its own KMP 302 proposing fresh **inbound** keys, then KMP 303,
   unless an exchange is already in flight;
3. installs the proposed inbound SA as current and keeps the previous inbound
   SA accepting packets for a grace window of about two keepalive intervals.

The initial exchange remains client-initiated. A client-initiated fallback
starts at 80 percent of the soft lifetime if the gateway sends no 302. It uses
**confirm-before-switch**: after sending 302 and 303 it keeps the old outbound
SA until a KMP 303 reply or an authenticated inbound packet on the new SPI
arrives. If confirmation does not arrive, the pending SA is abandoned and the
attempt is retried after 60 seconds, then 300 seconds.

## 6. Secret handling

ESP keys, the KMP 302 payload, credentials and cookies are never written to
stdout, logs, JSON output or dumps. Key types zeroize on drop and redact their
`Debug` output. The decoded configuration omits the key block by construction.
