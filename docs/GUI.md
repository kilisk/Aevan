# Aevan GUI (`aevan-gui`, M4)

**Aevan** is the product and project name. The binary and command are
`aevan-gui`, the daemon `aevand`, and the CLI `aevan`; the crates and control
endpoint use the `aevan` names.

`aevan-gui` is the native desktop client. It is a **client of `aevand` and
nothing more**: the daemon owns the tunnel, and the GUI only sends the same
versioned JSON requests the CLI sends over the local control endpoint.

```text
aevan-gui ──control socket──> aevand ──TLS/oNCP/ESP──> gateway
   │                            │
   └── displays status only     └── owns routes, DNS, MTU, adapter
```

The GUI never opens a TLS connection, never sends a credential to a gateway,
never reads a credential from argv or the environment, and never changes a
route, DNS server, MTU or adapter. Those operations exist only in
`aevan-daemon`/`aevan-tun`.

## Running it

The installed first-run path is **`aevan` with no subcommand** (the Start menu
shortcut does this). It ensures `aevand` is running — starting it with one UAC
prompt if the control pipe is unavailable — then launches `aevan-gui` detached
and returns. `aevan-gui` itself never starts the daemon silently.

On macOS the `.pkg` installs the LaunchDaemon once and bootstraps it; a
drag-installed app installs and bootstraps it from the **Start daemon
(Administrator)** action. After that a reboot starts the root daemon with no
prompt, and the GUI only prompts once in the app's lifetime. On relaunch the
GUI first uses the answering system socket, then tries an unelevated
`launchctl kickstart` of the installed job; only a missing job or a refused
kickstart asks for administrator approval. `aevand` binds the system endpoint
when it runs as root (`/Library/Application Support/Aevan/aevan.sock`, mode
0666 in a 0755 root:wheel directory); clients try that path first and then the
per-user `~/Library/Application Support/aevan/aevan.sock`. `aevan status`
prints the endpoint that answered.

```sh
cargo run -p aevan-gui
cargo run -p aevan-gui -- --headless
cargo run -p aevan-gui -- --headless --json
cargo run -p aevan-gui -- --version
cargo run -p aevan-gui -- --help
```

On Windows `aevan-gui` is a GUI-subsystem binary, so double-clicking it never
flashes a console window. `--version` and `--headless` still print when the
process is started from an existing terminal: the GUI attaches to that parent
console before the first write, and leaves an inherited pipe or file untouched.
`--version` and `--help` exit 0 without initialising a window. `--headless`
loads the profile store, performs one read-only `status` probe and prints the
resolved view-model state; it exits 0 even when no daemon is listening, so CI
can use it without elevation, a display or a gateway. `--json` selects the
machine-readable document for `--headless`.

The binary name stays `aevan-gui`.

## Single instance

There is one GUI per user. The first process binds a per-user endpoint — the
named pipe `\\.\pipe\aevan-gui` on Windows (created with the same explicit
user-SID + Medium-integrity DACL as the daemon) or
`<config dir>/aevan-gui.sock` on Unix. Later starts connect, send one line
`show`, and exit 0 without creating a window or tray icon; the primary raises
and focuses its window. `aevan` with no subcommand follows the same rule: if
the GUI endpoint answers it asks the running GUI to show, and only then does
the normal daemon/GUI launch path run.

A stale Unix socket (or a pipe name that no longer accepts connections) is
probed with a short connect timeout. A dead owner fails with
`ECONNREFUSED`/`ENOENT`; the file is removed, the bind is retried once, and
that process becomes the primary. It never falls through to a second window or
tray icon. A clean quit also unlinks the socket (the listener's `Drop` plus the
quit cleanup), so the next launch starts from nothing.

## Quit, disconnect, close and relaunch

| Action | Contract |
| --- | --- |
| **Quit** (tray/menu bar, or **Cmd+Q** on macOS) | If a tunnel is connected, send one `disconnect`, wait for the response (bounded by the control client's timeout), then exit. If no tunnel is connected, exit immediately with no dialog. On Windows, also stop a daemon this GUI started. On macOS the keepalive system LaunchDaemon is never killed; it is left idle (no tunnel, no keepalives), which is what makes the next launch prompt-free. |
| **Disconnect** | Send one `disconnect` and show `disconnecting` until the daemon reports `disconnected`. This is the explicit teardown action at any time. |
| **Close window** | Hide the window only. The tray/menu-bar item, the daemon and any tunnel keep running, and the process stays alive. |
| **Relaunch** (start the app while it is already running) | The new process connects to the primary instance, sends `show`, and exits. No second window and no second tray icon. |

If the Quit disconnect fails or times out, the GUI does **not** exit silently.
The window stays open with `Disconnect failed: <reason>` and two buttons:

* **Quit anyway** — exits and logs that the tunnel may still be up.
* **Cancel** — dismisses the dialog and returns to the connected view; the GUI
  keeps running.

On macOS, the only password prompt is the one-time daemon helper install (and
the single administrator fallback for that same helper when macOS refuses the
unelevated kickstart). Ordinary relaunches after the helper is installed never
ask: they use the answering system socket or the unelevated `launchctl
kickstart`. No tunnel action, Quit, or ordinary relaunch ever asks for a
password. A failed start names itself in the banner from the daemon-start log
(see below).

## System tray / menu-bar item (Windows and macOS)

The same menu exists on both platforms:

* **Status** — read-only; shows the state and, when connected, the address
  (`Connected · 10.20.0.10/32`).
* **Connect** — disabled while connecting/connected; opens the connect sheet
  for the selected profile and focuses the window.
* **Disconnect** — disabled while disconnected; sends one `disconnect`.
* **Show window** — focuses the existing window.
* **Quit** — disconnects a live tunnel first and then exits, as in the contract
  table above. On Windows it also stops a daemon this GUI started; on macOS the
  keepalive system LaunchDaemon is left running and idle. If the disconnect
  fails, the window stays open and offers **Quit anyway** or **Cancel**; a
  half-torn-down tunnel is never abandoned silently.

Closing the window with its close button only hides it. The tray icon (or the
macOS menu-bar item) remains, the daemon keeps running and the tunnel keeps
working. Only **Quit** (or **Cmd+Q** on macOS) ends the application. Linux has
no tray, so a hidden window cannot be restored there; use the launcher again or
stop the process.

Menu enablement is derived from the same view-model rules the window uses, so
the tray cannot offer an action the state machine would refuse. Events cross
into `iced` through one bounded channel exposed as an `iced` `Subscription`.

On **Windows** the tray runs on its own `tao` event-loop thread, so tray
messages never enter or block the `iced` event loop. Left-clicking the icon
opens/focuses the window; right-click opens the menu.

On **macOS** the equivalent control is an `NSStatusItem` in the menu bar.
AppKit requires it to be created on the main thread, and iced owns the only
event loop, so `tray::start()` builds the item during iced application setup
(on the main thread, before the event loop runs) and returns a handle the app
stores for its lifetime. Clicking the item opens the same native menu; menu
clicks arrive through the existing channel and subscription. Creation is
best-effort: if AppKit refuses the item (headless session, missing permission,
API refusal) the GUI logs once at info and continues window-only. It never
panics, never aborts startup and never requires the tray.

**Linux has no tray.** A tray on Linux would require GTK/libappindicator or a
StatusNotifier host, and aevan deliberately adds neither system dependency.
Linux runs window-only.

### Icon

`crates/aevan-gui/assets/aevan.png` is the supplied Aevan artwork
(`assets/branding/Aevan-64.png`) embedded with `include_bytes!`; there is no
build step or runtime asset path. Decoding and tray creation stay best-effort:
if the PNG cannot be decoded or the platform refuses the tray, the GUI logs once
at info and continues window-only.

## Notifications

Desktop notifications are shown for three transitions only:

* connected — includes the assigned address;
* failed — includes the daemon's already-redacted failure reason;
* recovery incomplete — includes the number of failed teardown steps.

Notifications are emitted through a small `Notifier` trait; the production
implementation uses `notify-rust` (Windows toast backend) and tests use a
recording implementation. Notification text is built only from the state name,
the tunnel address and the redacted reason, so it can never contain a password,
one-time token or TOTP secret. A missing notification service is not fatal: the
tray tooltip always carries the current state.

On an unpackaged Windows build the toast is shown through the built-in
PowerShell app identity; a dedicated app identity is part of M5 packaging. No
notification is shown for a plain `disconnected` transition or for repeated
`status` polls.

## Screens

### Profiles

* One row per profile, sorted by name, with a status dot:
  green connected, amber busy, red failed/unavailable, grey disconnected.
* The daemon's own state and failure message are shown above the list.
* `Add profile` opens a sheet for the name, gateway URL, realm and username.
  Each field is validated in the view model (required name, unique name, an
  http(s) URL with a host, realm and username), Save stays disabled until the
  draft is valid, and saving writes through `ProfileStore`, refreshes the list,
  selects the new profile and returns to it. No password or token field exists:
  profiles store no secrets. Editing an existing profile and deleting from the
  GUI are not included in this pass (use `aevan profile rm`).
* `Connect` opens the connect sheet for that profile; `Settings` opens that
  profile's settings.
* `Retry` performs one `status` probe. `Refresh` reloads `profiles.toml`.
* When the daemon cannot be reached, the screen shows the control client's
  exact reach-failure message (not-listening, access-denied or
  protocol-mismatch) and a **Start daemon (Administrator)** action. On Windows
  it performs the same one-UAC-prompt start as the `aevan` launcher. On macOS
  it checks, in order: (a) does the system socket answer — use it and do
  nothing; (b) is the LaunchDaemon installed but idle — run
  `launchctl kickstart -k system/com.github.kilisk.aevand` as the logged-in
  user, without elevation; (c) is it not installed — install
  `/Library/LaunchDaemons/com.github.kilisk.aevand.plist` once behind a single
  administrator prompt. A normal user's kickstart of an already-bootstrapped
  system job may be refused; only then does the GUI fall back to the single
  admin prompt. It then retries `status` and clears the banner on success.
* Every elevated or prompted daemon start appends to
  `$HOME/Library/Logs/Aevan/daemon-start.log` (directory 0700, file 0600):
  timestamp, the exact command, exit status and stderr. The log never contains
  credentials or the tunnel key block. If a start fails, the banner quotes the
  last three lines so the failure names itself. If the prompt is cancelled the
  message stays and the button can be pressed again; it is never looped
  automatically.

### Connect sheet

* Username (pre-filled from the profile when present), password and one-time
  token fields.
* When the selected profile has a decoded TOTP secret in the keyring, a live
  `code expires in Ns` countdown is shown. A code is generated fresh for the
  attempt when the token field is left empty; a typed token wins.
* `Connect` sends one `connect` request. The button is disabled while a session
  is already authenticating, connecting, connected or disconnecting.
* The sheet never retries. The daemon keeps its one-attempt rule.

### Connected view

Shows the daemon's `status` snapshot:

* profile and state;
* assigned address and prefix (`10.20.0.10/32`);
* device name;
* MTU (`1396`, or `default` when the gateway omitted it);
* route count (`4 applied`, `none` when zero);
* DNS servers (comma-separated, or `none`);
* bytes in and out, formatted with binary units;
* session uptime (`12s`, `1m 02s`, `1h 01m 01s`).

`Disconnect` sends one `disconnect` request and shows `disconnecting` until the
daemon reports `disconnected`.

The daemon's status document contains a route **count**, not the route list, so
the connected view reports the count. The settings screen previews the routing
the selected profile asks for.

### Settings

* Profile, realm, gateway URL.
* Split-tunnel preview from the profile: gateway routes only, all traffic, or
  the custom route list.
* TOTP enrollment state (keyring present or absent).
* TOTP enrolment: paste a base32 secret, validate it locally, compare the
  current code and countdown with the authenticator app, then save it to the
  OS keyring or cancel. An enrolled profile has a Remove action.
* Start at login: reads the same per-user `aevan` task the MSI creates and
  offers Enable/Disable. The write goes through `aevand --install-autostart` /
  `--remove-autostart` with one UAC prompt. If the task state cannot be read,
  the screen says so instead of showing a guessed value.
* Log level (displayed and cycled in memory; the GUI does not stream logs yet).
* Daemon endpoint (named pipe on Windows, Unix socket elsewhere).

## State machine

The view model mirrors the daemon, plus one local state for an unreachable
control endpoint:

```text
Disconnected / Failed / DaemonUnavailable
        │ connect
        v
Authenticating ──> Connecting ──> Connected
                                     │
                                     v
                                Disconnecting ──> Disconnected
```

Any failure moves to `Failed{reason}` (a daemon-reported failure) or
`DaemonUnavailable{message}` (the control endpoint could not be reached or spoke
a different protocol). A reach failure uses the CLI's own messages, including
the hint to start `aevand`.

## Polling

`status` is polled about once per second while the state is `Authenticating`,
`Connecting`, `Connected` or `Disconnecting`, so bytes and uptime stay live.
Polling stops in `Disconnected`, `Failed` and `DaemonUnavailable`; `Retry`
performs a single probe. Only one poll is in flight at a time, and the tick is
also used for the TOTP countdown while the connect sheet is open, so the
application never busy-loops.

## Credential handling

* The password and token are held in `zeroize::Zeroizing<String>` buffers.
* On submit they are moved into the request's `SecretString` (also zeroizing and
  redacted in `Debug`). The sheet fields are empty immediately afterwards, so
  the values are never displayed after submission.
* Any failure, disconnect, daemon-unavailable transition, profile switch or
  connect-sheet reopen clears the username, password and token fields.
* Credentials are never written to disk, never logged, and never placed in argv
  or the environment.
* The only place a credential exists outside the GUI is the one `connect`
  request line on the owner-only local control endpoint. The same-user threat
  model and the daemon's redaction rules are documented in `docs/DAEMON.md`.
* The GUI never reads secrets from a profile file. Profiles remain non-secret
  TOML.

## TOTP

The GUI reads a TOTP secret from the OS keyring under service `aevan` and account
`<profile>/totp`, decodes it as RFC 4648 base32, and uses the existing
`aevan-secrets` RFC 6238 implementation (SHA-1, six digits, 30 seconds).

* On Windows the real Credential Manager backend is enabled for `aevan-secrets`.
* On macOS and Linux the keyring backend is not enabled in this build, so the
  probe reports "not enrolled" instead of pretending a secret exists.
* Codes are generated per attempt and never cached. A missing or malformed
  secret is treated as "no TOTP"; it is never logged.

### Enrolment

Settings is the **only** place the GUI writes a secret. The flow is:

1. Paste or type the base32 secret (spaces, dashes and lower case are
   accepted; anything outside the base32 alphabet is rejected).
2. **Validate** decodes it locally and shows the current six-digit code and the
   `code expires in Ns` countdown so it can be compared with the phone. Nothing
   is stored yet.
3. **Save to keyring** writes the normalized base32 text through the existing
   `aevan-secrets` keyring interface (service `aevan`, account
   `<profile>/totp`). The input field and preview secret are cleared
   immediately; the secret is never displayed again.
4. **Remove from keyring** deletes the entry and immediately clears the
   connect-sheet countdown source for that profile.

The secret is never logged, never placed in argv or the environment, and never
written to disk outside the keyring. Invalid input produces a generic error
that does not echo the input. The connect sheet then uses the enrolled secret
exactly as before.

## What the GUI explicitly does not do

* No TLS, oNCP, ESP or any other gateway traffic.
* No credentials in argv or the environment.
* No routes, DNS, MTU, adapter or driver access.
* No silent daemon auto-start. `aevan` with no subcommand may start the daemon,
  and the explicit **Start daemon (Administrator)** action may start it, but
  opening `aevan-gui` never does.
* No profile creation/editing/removal; use `aevan profile add`.
* No log streaming. The GUI only reads the tail of its own owner-only
  `daemon-start.log` to name a failed daemon start.
* No tray on Linux (see above). macOS has a menu-bar item; notifications still
  use the cross-platform `notify-rust` path.
* No password persistence; a TOTP secret is stored only in the OS keyring.
* No service installation. The Settings switch does not install a service; it
  only creates or removes the same per-user logon task the MSI uses, through
  `aevand --install-autostart` / `--remove-autostart` and one UAC prompt.

## Current limitations

* **Tray platform:** Windows uses a dedicated `tao` thread; macOS uses an
  `NSStatusItem` created on the main thread and stored by the app; Linux is
  window-only because no GTK/libappindicator dependency is shipped. The icon is
  a placeholder glyph, not final art.
* **Notification identity:** unpackaged Windows builds show toasts under the
  built-in PowerShell app identity; a packaged app identity is future work.
* **macOS/Linux keyring:** the packages (`.pkg` and `.tar.gz`) exist, but the
  macOS/Linux keyring backends are still not enabled in this build, so TOTP
  enrolment reports "not enrolled" there.
* **TOTP secret formats:** RFC 6238 SHA-1 / six digits / 30 seconds only, which
  matches the gateway realm; other digits or periods are not configurable.
* **One tunnel:** like the daemon, the GUI shows one profile/tunnel at a time.
* **Route detail:** the connected view shows the applied route count because the
  control `status` document exposes a count, not the route list.
* **Log level:** shown and cycled in memory, but not yet sent anywhere; there is
  no log viewer in M4.
* **Rendering:** `iced` 0.13 with the `wgpu` renderer. A machine without a
  working GPU/software adapter is out of scope for this milestone.

## Offline tests

`cargo test -p aevan-gui` runs the view-model suite with no daemon, display,
network or elevation:

* a status poll updates bytes and uptime;
* a daemon failure moves to `Failed` with the message;
* a reach failure moves to `DaemonUnavailable` with the message;
* a connect submission clears the secret buffers and redacts `Debug`;
* a typed token wins over a generated TOTP code, and a generated code matches
  the RFC 6238 vector;
* the TOTP countdown formats correctly at 0, 1, 29 and 30 seconds;
* address, MTU, routes and DNS render as specified;
* poll scheduling is active only while live/changing or while a countdown is
  visible;
* the split-tunnel preview follows the profile;
* Quit disconnects first when connected, exits at once when not connected,
  shows `Disconnect failed` without exiting, and Cancel restores the connected
  view; the Windows shutdown decision stops only a daemon this GUI started,
  while the macOS keepalive daemon is never stopped;
* the relaunch decision uses an answering socket with no action, kickstarts an
  installed job without elevation, and only uses the one admin prompt for a
  refused kickstart or a missing job;
* the daemon-start log records timestamp, command, exit status and stderr,
  tails correctly, and stays owner-only on Unix;
* a stale Unix socket is removed so the next process becomes primary, a live
  socket makes the second process send `show`, and dropping the listener
  unlinks the socket;
* tray menu enablement matches the state machine (Connect disabled while
  connected, Disconnect disabled while disconnected, both disabled during
  recovery or while the daemon is unreachable) and the status line includes the
  address when connected;
* the connected, failed and recovery-incomplete notifications carry the right
  text, fire once per transition, and never contain password, token or TOTP
  material;
* TOTP validation accepts valid base32 with spaces/dashes/lower case, rejects
  invalid or empty input without echoing it, clears the input after save, and
  removal clears the countdown source.

The full workspace suite (`cargo test --workspace`) still runs offline.
