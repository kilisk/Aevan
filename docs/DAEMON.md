# `aevand` daemon and control protocol (M3)

`aevand` owns the tunnel: it authenticates, performs the oNCP handshake, applies
the NCP configuration, runs ESP and tears down. `aevan connect/status/disconnect/logs`
talk to it over a local control endpoint. The foreground path
(`aevan connect --foreground` or `--no-daemon`) still runs the same shared
orchestration in the CLI process.

This document is the M3 contract. It covers the protocol, the state machine, the
single-attempt guard, the crash-recovery journal and how to run the daemon.

## Endpoints

| platform | endpoint |
|---|---|
| Windows | named pipe `\\.\pipe\aevan` |
| Unix | `<aevan config dir>/aevan.sock` |

The config directory comes from `aevan-core` (`AEVAN_CONFIG_DIR`, `%APPDATA%\aevan`,
`~/Library/Application Support/aevan`, or `$XDG_CONFIG_HOME/aevan`). On Unix the
directory is set to mode `0700` and the socket to `0600`. On Windows the
per-user directory ACL is the operative control.

A second daemon refuses to start: the Unix listener probes the socket and the
Windows pipe uses `first_pipe_instance`. A stale Unix socket left by a killed
process is removed after a failed probe.

## Elevation and the pipe

`aevand` must run elevated because creating the WinTun adapter needs
Administrator. The CLI, however, is normally started from an ordinary
medium-integrity shell. A Windows named pipe created with the default security
descriptor by an elevated process can only be opened by elevated clients, which
appears as `Access is denied. (os error 5)`.

The daemon therefore creates every pipe instance with an explicit security
descriptor built from the current user's SID:

```text
D:(A;;GA;;;<current user SID>)S:(ML;;NW;;;ME)
```

The DACL grants only that user generic-all access (not the Administrators group
as a group), and the Medium mandatory label lets a medium-integrity process of
the same user connect. No other user may connect. If the descriptor cannot be
applied, `aevand` logs the reason and refuses to start; it never falls back to
the default descriptor.

A Windows service is not used. The profile store and crash journal are
per-user under `%APPDATA%\aevan`, so a LocalSystem service would read SYSTEM's
store and own a tunnel that the user's CLI cannot reach. M5 packaging installs
a per-user logon task by default (`aevand --install-autostart`, with
`HighestAvailable`), which keeps the daemon in the user's profile while still
giving it the elevation that WinTun requires. `INSTALL_AUTOSTART=0` opts out and
the GUI Settings switch can toggle it later. See `docs/INSTALL.md`.

The CLI names the daemon and the remedy for each reachability failure:

| condition | exit code | message |
|---|---|---|
| no daemon listening | 4 | `cannot reach the aevan daemon on <pipe>: no daemon is listening — start aevand first` |
| access denied (error 5) | 6 | `cannot reach the aevan daemon on <pipe>: access denied — run aevand and aevan at the same elevation, or start aevand first` |
| protocol mismatch | 7 | `cannot reach the aevan daemon on <pipe>: protocol mismatch — stop aevand and restart it with the same version as aevan` |

`status`, `disconnect`, `logs` and `connect` all use these messages. If the pipe
is already owned, `aevand` logs at error level and prints
`another aevand is already listening on <pipe>; stop it first`, then exits with
code 5.

## Protocol

* Version 2, JSON, one request per line and one response per line.
* Every response carries `schema_version` (currently `2`). A daemon accepts
  both version 1 and version 2 requests and answers in the request's version, so
  an older client still understands the response.
* A daemon that receives any other version answers with exit code `7`
  (unsupported) and does not execute the request.
* The request line limit is 64 KiB.
* `logs` is the only command that returns more than one response line: one line
  per record, then `{"done":true}` when `--follow` is absent. A following stream
  stays open until the client disconnects or the daemon shuts down.

### Requests

Common fields:

| field | type | meaning |
|---|---|---|
| `schema_version` | number | `1` or `2` (version 2 is current) |
| `command` | string | `status`, `connect`, `disconnect`, `recover`, `logs`, `shutdown` |

`connect` (version 2):

```json
{"schema_version":2,"command":"connect","profile":"example","gateway_url":"https://vpn.example.net/example_realm","realm":"example_realm","username":"example_user","password":"...","token":"..."}
```

`gateway_url` and `realm` are optional. When both are present the daemon builds
the connection from the request; `profile` is then only a display name for
status and logs. When both are absent the daemon uses the legacy version-1
lookup in its own profile store (and `profile` selects the entry, defaulting to
the store default). Supplying only one of the two is a typed configuration
error. The new fields are not secret, but are not logged at info level.

`password` is required. `token` is optional; when the gateway asks for a token
and none was supplied, the daemon returns exit code 2 rather than retrying or
prompting.

The CLI and GUI resolve the profile from the user's own store and send the
version-2 fields, so a root LaunchDaemon never needs a per-user profile file.

`disconnect`:

```json
{"schema_version":2,"command":"disconnect","profile":"example","all":false}
```

`all` is accepted for the CLI contract; M3 has one tunnel.

`recover`:

```json
{"schema_version":2,"command":"recover"}
```

This re-runs crash recovery (the same operation as `aevan reset`) and answers
with the three counts. The journal is deleted only when no genuine step
failed. Rejected with exit code 5 while a tunnel is live, because the journal
then describes that live connection.

`logs`:

```json
{"schema_version":2,"command":"logs","follow":false,"level":"info"}
```

`level` is `error`, `warn`, `info`, `debug` or `trace` and defaults to `info`.

`status`:

```json
{"schema_version":2,"command":"status"}
```

`shutdown`:

```json
{"schema_version":2,"command":"shutdown"}
```

The daemon answers, then stops accepting connections, signals a live tunnel and
waits for teardown.

### Responses

Success:

```json
{"schema_version":2,"ok":true,"command":"status","status":{"state":"connected","profile":"example","device":"aevan","address":"10.20.0.10","prefix_len":32,"mtu":1396,"route_count":4,"dns":["10.20.0.53","10.20.0.54"],"bytes_in":0,"bytes_out":0,"uptime_secs":12}}
```

Failure:

```json
{"schema_version":2,"ok":false,"command":"connect","error":"authentication rejected: ...","exit_code":3}
```

Log record:

```json
{"schema_version":2,"ok":true,"command":"logs","record":{"seq":7,"timestamp_unix":1762300000,"level":"info","target":"aevan_daemon::runtime","message":"..."}}
```

`status` reports the state, profile, device, assigned address/prefix, MTU, route
count, DNS servers, bytes in/out and uptime. It contains no key material, SPI,
cookie or credential.

## State machine

```text
Disconnected ──connect──> Authenticating ──auth ok──> Connecting ──applied──> Connected
     ^                          │                         │                       │
     │                          │ failure                 │ failure               │ disconnect
     │                          v                         v                       v
     └──────────────────── Failed{reason} <───────────────┘                 Disconnecting
                                                                                   │
                                                                                   v
                                                                              Disconnected
```

* `Authenticating` is entered before any credential leaves the daemon.
* `Connecting` covers the oNCP handshake, journal, device open and apply.
* `Connected` is entered only after every change is applied and the ESP loop is
  about to start.
* A disconnect request sets `Disconnecting`, signals the ESP loop, then waits
  for rollback and device close before reporting `Disconnected`.
* A failed authentication, handshake, apply or ESP session ends in
  `Failed{reason}`. The reason never contains a credential.
* `RecoveryIncomplete` is separate from `Failed`. It means an interrupted
  journal still has steps that could not be undone, so connecting is refused
  until `aevan reset` succeeds. The status report carries the recovery counts
  and failures; this is not a failed connect attempt.

## Data plane

The blocking connector worker runs the ESP loop described in
[`docs/CONNECT.md`](CONNECT.md#data-plane): a non-blocking UDP socket,
batched drains in both directions, reusable packet buffers, and a bounded event
wait when the tunnel is idle. On Windows that wait covers the socket and the
Wintun read event with a 50 ms bound. On macOS and Linux a dedicated reader
thread owns the blocking `utun`/`tun` descriptor, feeds a bounded 256-packet
channel, and the loop polls only the UDP socket with a 10 ms bound; shutdown
wakes and joins the reader with a 2-second bound before rolling back routes and
DNS. A disconnect sets the stop flag and is noticed within the bounded wait.

## Single-attempt guard

The daemon enforces the guard itself, not the CLI:

1. `connect` checks the state and refuses with exit code 5 (`already
   connected`) unless the state is `Disconnected` or `Failed`.
2. It then calls `reserve_connect`, which re-checks and moves to
   `Authenticating` under one mutex. Two concurrent requests cannot both pass.
3. Only after the slot is claimed does the blocking connector start the single
   authentication attempt.

A rejected request never opens a socket to the gateway. A failed authentication
is not retried by any path: the connector performs one credential POST, a token
challenge may add its single continuation POST, and the thread then stops.
`disconnect` while `Disconnected` or `Failed` returns exit code 5.

## Journal and crash recovery

Path: `<config directory>/aevand.journal` (owner-only where the platform
supports Unix modes).

Format (JSON, rewritten as changes are applied):

```json
{
  "schema_version": 1,
  "device": "aevan",
  "pid": 12345,
  "created_unix": 1762300000,
  "changes": [
    {"kind":"set_addr","old":null,"new":["10.20.0.10",32]},
    {"kind":"set_mtu","old":null,"new":1396},
    {"kind":"add_route","route":{"destination":"10.0.0.0","prefix_len":8,"metric":0}},
    {"kind":"set_dns","old":[],"new":["10.20.0.53"]}
  ]
}
```

Write order:

1. The journal is created (empty) before the first change.
2. Before each address/MTU/route/DNS change is applied, it is appended and the
   file is rewritten. A change that fails is removed again because it had no
   effect.
3. A clean teardown applies the inverses in reverse order, closes the device,
   then deletes the journal.
4. If rollback fails, the journal is kept for the next start.

Recovery runs before the daemon binds its control endpoint, and again whenever
`aevan reset` asks for it. Every pass reports three separate counts:

| count | meaning |
|---|---|
| `rolled_back` | an inverse ran and changed something |
| `skipped_absent` | the state the inverse would remove was already absent |
| `failed` | a genuine failure; the journal is retained |

A hard kill on Windows (`taskkill /F`, Stop-Process, or `kill -9` on Unix) also
removes the WinTun adapter. On the next start every journal entry is therefore
device-scoped state that is already gone: the address, MTU, routes bound to the
alias and interface DNS.

Recovery orders its work as **presence, privilege, then `netsh`**:

1. Probe whether the interface alias still exists. Enumerating it needs no
   Administrator.
2. If the alias is absent, every entry is counted under `skipped_absent`, no
   `netsh` delete runs, and the journal is deleted. This clears without
   elevation, even from a non-elevated shell.
3. If the alias exists, the journal describes live state. Recovery checks
   elevation before running any inverse. Without Administrator it touches
   nothing, keeps the journal, and reports
   `insufficient privilege: Administrator elevation is required ...`.
4. Only an elevated process runs the `netsh` inverses.

This is why the expected outcome after a hard kill is "already absent", not a
failure, and why a stale journal whose adapter is gone no longer blocks a
non-elevated start.

When elevation is available and the device exists, each inverse checks the
current state where that is cheap and otherwise classifies the platform error.
`netsh` messages such as "The system cannot find the file specified",
"Element not found" or "no such" mean the element is already absent and count
as `skipped_absent`. Any other error is a real `failed` step.

The pass then behaves as follows:

* No journal: nothing to do.
* Every entry is absent or rolled back (`failed == 0`): delete the journal and
  log at info level (`journal recovery complete; nothing left to undo`).
* At least one genuine failure (`failed > 0`): keep the journal, log every
  failed step with its reason, and set `RecoveryIncomplete` in `status` along
  with the three counts. New connects are refused. A malformed journal is a
  typed error, and a live journal without elevation is a privilege error; the
  file is retained in both cases.

`aevan reset` is the operator remedy. It re-runs recovery through the running
daemon, prints `rolled back`, `skipped (already absent)` and `failed`, and lists
every remaining failed step plus the journal path. It deletes the journal only
when `failed` is zero. If a genuine failure remains it says exactly which step
still needs attention and to run `aevan reset` again after fixing the platform
state. `aevan reset` refuses while a tunnel is live, so a journal that describes
live state is never deleted.

`aevand --recover` performs the same one-shot recovery without a running daemon
or control endpoint. It uses the same presence, privilege, `netsh` ordering,
prints `rolled_back`, `skipped_absent` and `failed` plus any remaining failures,
and deletes the journal only when `failed` is zero. Its exit codes are `0`
(clean), `6` (live state but no elevation) and `1` (genuine failure).

The acceptance path is: connect, kill the daemon process (`kill -9`,
`taskkill /F`, or Stop-Process), start `aevand` again. The new process logs the
journal recovery; because the adapter is gone it reports the entries as already
absent and deletes the journal. The GUI shows a `Journal recovery incomplete`
banner with the same three counts and a `Retry recovery` button (which sends the
`recover` command) only when `failed > 0`; it clears automatically when recovery
succeeds or the journal disappears.

## Credentials and logs

* The password and token are read at the terminal (echo off) or from stdin when
  redirected, and are sent only inside a `connect` request on the local control
  endpoint. They are never in argv, never in the environment and never logged.
* The control endpoint is owner-only. This is the same trust boundary as the
  user's terminal; the alternatives (argv or environment) are strictly worse.
  A local process running as the same user could read the socket, so the daemon
  does not claim protection from a same-user attacker.
* Credential fields use a zeroizing string with redacted `Debug`.
* The log subscriber redacts fields whose names look sensitive. The daemon
  never logs request bodies, cookies or key material.
* `status` deliberately has no key, SPI or cookie field.

## Running it

Build:

```sh
cargo build --release
```

Run the daemon in the foreground (Ctrl+C stops it):

```sh
aevand
```

With no arguments `aevand` runs the daemon exactly as above. The other arguments
are:

| flag | behaviour |
|---|---|
| `--help`, `-h` | print usage and exit 0 without touching the journal, the control pipe or the adapter |
| `--version`, `-V` | print `aevand <version>` and exit 0, with the same no-touch guarantee |
| `--recover` | run one-shot recovery (identical presence, privilege, `netsh` ordering), print the three counts and remaining failures, delete the journal only when nothing remains, and exit 0 (clean), 6 (needs elevation) or 1 (genuine failure) |
| anything else | print usage on stderr and exit 2 |

`aevand --recover` works offline and without the daemon. An absent adapter is
cleared without elevation; live state still requires Administrator.

Then from another shell:

```sh
aevan connect example
aevan status --json
aevan logs --level info
aevan disconnect
```

If a previous hard kill left a journal, check and retry recovery explicitly
through the daemon or directly:

```sh
aevan reset
aevand --recover
```

`aevan connect` starts `aevand` automatically when the binary is beside `aevan`.
If it is not, the command fails with exit code 4 and a message naming the
missing binary.

Offline checks (no gateway, no credentials, no elevation):

```sh
cargo test --workspace
```

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 2 | interaction required (for example a token challenge) |
| 3 | authentication rejected |
| 4 | network/TLS, ESP failure, or control endpoint unavailable |
| 5 | already connected / already disconnected |
| 6 | insufficient privilege |
| 7 | unsupported gateway or configuration |
| 1 | genuinely internal failure (malformed daemon response, corrupted state) |

The daemon sends the code in the response; the CLI reconstructs the typed error
so a daemon-level failure keeps the documented code.

## M3 scope notes

* No reconnect policy, heartbeat watch or automatic retry. A failed session is
  `Failed` and waits for a new user-initiated connect.
* One tunnel and one profile at a time. `disconnect --all` is equivalent to
  `disconnect`.
* The daemon runs in the foreground; M3 does not install a service or detach it.
* `logs` mirrors the tracing records the daemon captured in this process. The
  daemon starts with an `info` stderr display but captures all levels for the
  control stream.
