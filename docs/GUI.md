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

On macOS the app bundle ships its LaunchDaemon plist at
`Contents/Library/LaunchDaemons/com.github.kilisk.aevand.plist`. The explicit
**Start daemon** action in Settings first tries ServiceManagement
(`SMAppService`); a Developer ID signed build then asks the user to approve
Aevan in System Settings > Login Items & Extensions. The published build is
ad-hoc signed, so macOS refuses that registration before the approval UI
appears. In that case the same button falls back once to the legacy
LaunchDaemon install: it writes
`/Library/LaunchDaemons/com.github.kilisk.aevand.plist` and runs
`launchctl bootstrap` through one native administrator prompt. The helper has
`RunAtLoad`, so later launches never prompt again. Cancelling that prompt says
`The helper was not installed. Aevan needs administrator approval once.` and
leaves the window usable; the GUI never loops the prompt. Once the daemon is
registered or installed, a reboot starts the root daemon and later starts reuse
the answering system socket. If approval is still outstanding, the GUI says so
and waits; it does not retry silently. `aevand` binds the system endpoint
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

On macOS a Developer ID signed build has no password prompt for the helper:
the first **Start daemon** registers the bundled LaunchDaemon with
ServiceManagement and macOS may ask for approval in System Settings > Login
Items & Extensions. The published build is ad-hoc signed, so that registration
is refused and the same action asks for administrator approval once to install
the legacy LaunchDaemon; later relaunches never prompt again. Ordinary
relaunches reuse the answering system socket or an unelevated `launchctl
kickstart`. No tunnel action, Quit, or ordinary relaunch ever asks for a
password after that one install. A failed start names itself in the banner from
the daemon-start log (see below).

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

Notifications are emitted through a small `Notifier` trait; tests use a
recording implementation. Windows and Linux use `notify-rust`. macOS uses the
UserNotifications framework directly (`objc2-user-notifications`): at startup it
requests authorization for alert and sound, records granted or denied, and
delivers each transition as a `UNNotificationRequest` with a nil trigger. There
is no scripting bridge and no shell quoting anywhere.

When authorization is denied, the GUI says once that notifications are disabled
in System Settings instead of failing silently; the tray tooltip still carries
the current state. Notification text is built only from the state name, the
tunnel address and the redacted reason, so it can never contain a password,
one-time token or TOTP secret. A missing notification service is logged and
ignored. Message handlers, notification delivery and tray callbacks run under
`std::panic::catch_unwind`; a caught panic becomes a banner instead of aborting
the UI (the workspace keeps `panic = "unwind"`).

On an unpackaged Windows build the toast is shown through the built-in
PowerShell app identity; a dedicated app identity is part of M5 packaging. No
notification is shown for a plain `disconnected` transition or for repeated
`status` polls.

## Screens

### Profiles

* One row per profile, sorted by name, with a status dot:
  green connected, amber busy, red failed/unavailable, grey disconnected.
* The daemon's own state and failure message are shown above the list.
* **Add profile** opens a sheet for the name, gateway URL, realm and username.
  Each field is validated in the view model (non-empty unique name, an http(s)
  URL with a host and non-empty username for non-interactive login; the realm
  is optional), Save stays disabled until the draft is valid, and saving writes
  through `ProfileStore`, refreshes the list, selects the new profile and
  returns to it. The realm field's placeholder is “detect automatically”: leave
  it empty and the gateway's advertised realm is detected and saved on the first
  connect. No password or token field exists: profiles store no secrets.
* **Edit** opens the same sheet pre-filled with the stored name, gateway URL,
  realm and username. Saving writes through the same `ProfileStore` path,
  refreshes the list in place and keeps the edited profile selected. A name
  already used by a different profile is rejected on the name field; saving
  under its own current name is allowed. If the edited profile is the connected
  one, the sheet says changes apply to the next connection and the live tunnel
  is not touched. After a successful detection the sheet shows the detected
  realm. No password, token or TOTP secret is shown or stored here.
* **Delete** asks `Delete “<name>”? This cannot be undone.` with Delete and
  Cancel. Confirming removes the profile from the store, refreshes the list,
  and clears the selection and shows the empty state when the deleted profile
  was the selected one. Deleting the profile whose tunnel is connected is
  refused with a message to disconnect first; nothing is removed. Cancel leaves
  the store untouched.
* `Connect` opens the connect sheet for that profile; `Settings` opens that
  profile's settings.
* `Retry` performs one `status` probe. `Refresh` reloads `profiles.toml`.
* When the daemon cannot be reached, the screen names the endpoint in GUI
  wording (not-listening, access-denied or protocol-mismatch) alongside the
  **Start daemon** action in Settings; it never tells the reader to run a CLI
  command. Starting the daemon is the explicit **Start daemon** action, never
  part of Connect. On Windows it performs the same one-UAC-prompt start as the
  `aevan` launcher. On macOS it checks the socket, then reads
  `SMAppService.status()`: enabled services may be started again and
  unregistered services are registered. If ServiceManagement refuses because
  the build is ad-hoc signed, the GUI falls back once to the legacy
  LaunchDaemon install described under **Running it**. A service that still
  requires approval tells the user to approve Aevan in System Settings > Login
  Items & Extensions. The Settings sheet also offers **Open Login Items &
  Extensions** and **Unregister daemon**. It then retries `status` and clears
  the banner on success.
* Every elevated or prompted daemon start appends to
  `$HOME/Library/Logs/Aevan/daemon-start.log` (directory 0700, file 0600):
  timestamp, the exact command, exit status and stderr. The log never contains
  credentials or the tunnel key block. If a start fails, the banner quotes the
  last three lines so the failure names itself. Every banner and error block
  has a **Copy** button that puts the displayed text, including that log tail,
  on the clipboard through the toolkit API and briefly shows **Copied**. If the
  prompt is cancelled the message stays and the button can be pressed again; it
  is never looped automatically.

### Connect sheet

* Username (pre-filled from the profile when present), password and one-time
  token fields.
* When the selected profile has a decoded TOTP secret in the secret store, a live
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
* TOTP enrollment state (present or absent).
* TOTP enrolment: paste a base32 secret, validate it locally, compare the
  current code and countdown with the authenticator app, then save it to the
  owner-only secret store or cancel. An enrolled profile has a Remove action.
* Start at login: reads the real per-user login item and offers Enable/Disable.
  On Windows the write goes through `aevand --install-autostart` /
  `--remove-autostart` with one UAC prompt. On macOS and Linux it writes the
  per-user GUI login item described below with no elevation. If the state
  cannot be read, the screen says so instead of showing a guessed value.
* Command-line tools (macOS DMG build): shows `not installed`, `installed at
  <path>`, or `installed but pointing elsewhere`. **Install command-line
  tools** creates `/usr/local/bin/aevan` and `/usr/local/bin/aevand` as
  symlinks to the copies inside `Aevan.app/Contents/MacOS` behind one
  administrator prompt; **Remove command-line tools** deletes them. Both actions
  are idempotent. A real file or a symlink that is not one of Aevan's own links
  is refused with the path named; the existing file is left untouched. If the
  app bundle is moved, the next launch reports that the links are stale and the
  same Install action repairs them.
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

The GUI reads a TOTP secret under service `aevan` and account `<profile>/totp`,
decodes it as RFC 4648 base32, and uses the existing `aevan-secrets` RFC 6238
implementation (SHA-1, six digits, 30 seconds).

The backend is chosen per platform:

| Platform | Backend | Location |
| --- | --- | --- |
| Windows | Credential Manager (`windows-native`) | per-user Windows credential store |
| macOS | owner-only file | `~/Library/Application Support/aevan/secrets.json` |
| Linux | owner-only file | `$XDG_CONFIG_HOME/aevan/secrets.json`, or `~/.config/aevan/secrets.json` |

The Unix file backend creates its directory with mode 0700 and writes the file
with mode 0600. The document is a JSON object keyed by service and account; it
never contains a profile password. Codes are generated per attempt and never
cached. A missing or malformed secret is treated as "no TOTP"; it is never
logged.

### Enrolment

Settings is the **only** place the GUI writes a secret. The flow is:

1. Paste or type the base32 secret (spaces, dashes and lower case are
   accepted; anything outside the base32 alphabet is rejected).
2. **Validate** decodes it locally and shows the current six-digit code and the
   `code expires in Ns` countdown so it can be compared with the phone. Nothing
   is stored yet.
3. **Save secret** writes the normalized base32 text through the
   `aevan-secrets` backend above. The write is read back immediately: the GUI
   decodes the stored value and generates a code at the same timestamp, and the
   save is accepted only when that code equals the code from the enrolled
   value. The input field and preview secret are cleared immediately; the
   secret is never displayed again.
4. **Remove secret** deletes the entry and immediately clears the connect-sheet
   countdown source for that profile.

Every backend failure (permission denied, read-only directory, corrupt
document, a missing entry after a write, or a failed round-trip) is returned to
the view model and shown in the Settings banner. The secret is never logged,
never placed in argv or the environment, and never echoed in an error. Invalid
input produces a generic error that does not echo the input. The connect sheet
then uses the enrolled secret exactly as before.

## Keyboard navigation

Tab moves focus forward through the current form and wraps at the end; Shift+Tab
moves backward and wraps at the start. Enter submits that screen's primary
action (`Connect`, `Save profile`, `Validate secret` / `Save secret`, or
`Disconnect`). Escape closes the open sheet (connect, add profile, settings) and
cancels the quit confirmation.

The order is a plain list of field ids in `view_model` (`FocusField`), not a
property of the widget tree, so it is tested without a display. The shell applies
it with iced's focusable operation and gives each `text_input` the matching id.

## Start at login

The Settings toggle reports the real per-user login item and changes it without
guessing.

| Platform | Mechanism | Path | Contract |
| --- | --- | --- | --- |
| Windows | per-user Task Scheduler task | task name `Aevan` | `HighestAvailable`, one UAC prompt; the MSI creates it by default |
| macOS | per-user LaunchAgent | `~/Library/LaunchAgents/com.github.kilisk.aevan.plist` | `ProgramArguments` runs `aevan-gui`; `RunAtLoad` true; `KeepAlive` false; no elevation |
| Linux | XDG autostart entry | `~/.config/autostart/aevan.desktop` | `Exec=aevan-gui`; ordinary user permissions; no elevation |

On macOS the agent is also loaded with a best-effort `launchctl load -w`; the
file alone is the source of truth for the reported state, so a refused load does
not make a successful install look disabled. Removing the file (and best-effort
unload) disables it. The Linux entry is a standard desktop autostart file with
`X-GNOME-Autostart-enabled=true`; a systemd user unit is not used because the
XDG entry is the simpler equivalent and needs no service manager. Enable and
disable are idempotent, and a missing file reports `Absent`.

The macOS and Linux paths are tested with an injected command runner and
temporary home directories, so the enable/disable/state cycle runs offline on
every build host; the Windows task path keeps its existing `schtasks` tests.

## What the GUI explicitly does not do

* No TLS, oNCP, ESP or any other gateway traffic.
* No credentials in argv or the environment.
* No routes, DNS, MTU, adapter or driver access.
* No silent daemon auto-start. `aevan` with no subcommand may start the daemon,
  and the explicit **Start daemon** action may start it, but opening
  `aevan-gui` never does.
* No profile secrets: adding, editing and deleting touch only the non-secret
  profile store (`profiles.toml`), never a password, token or TOTP secret.
* No log streaming. The GUI only reads the tail of its own owner-only
  `daemon-start.log` to name a failed daemon start.
* No tray on Linux (see above). macOS has a menu-bar item and delivers
  notifications through UserNotifications.
* No password persistence; a TOTP secret is stored only in the owner-only
  secret store (Credential Manager on Windows, a 0600 file on macOS/Linux).
* No service installation. The Settings switch does not install a service; it
  creates or removes the per-user login item described below.

## Current limitations

* **Tray platform:** Windows uses a dedicated `tao` thread; macOS uses an
  `NSStatusItem` created on the main thread and stored by the app; Linux is
  window-only because no GTK/libappindicator dependency is shipped. The icon is
  a placeholder glyph, not final art.
* **Notification identity:** unpackaged Windows builds show toasts under the
  built-in PowerShell app identity; a packaged app identity is future work.
* **macOS/Linux secret backend:** TOTP uses an owner-only JSON file rather than
  a keychain or Secret Service entry, because this build does not compile those
  native backends. The file is 0600 in a 0700 directory.
* **TOTP secret formats:** RFC 6238 SHA-1 / six digits / 30 seconds only, which
  matches the gateway realm; other digits or periods are not configurable.
* **One tunnel:** like the daemon, the GUI shows one profile/tunnel at a time.
* **Route detail:** the connected view shows the applied route count because the
  control `status` document exposes a count, not the route list.
* **Log level:** shown and cycled in memory, but not yet sent anywhere; there is
  no log viewer in M4.
* **Rendering:** `iced` 0.14 with the `wgpu` 27 renderer. A machine without a
  working GPU/software adapter is out of scope for this milestone.

## Offline tests

`cargo test -p aevan-gui` runs the view-model suite with no daemon, display,
network or elevation:

* a status poll updates bytes and uptime;
* profile editing pre-fills exactly the stored values, rejects a rename onto
  another profile's name, and accepts saving under its own current name;
* profile deletion requires confirmation, cancel leaves the store untouched,
  confirming removes the profile and clears a deleted selection, and deleting
  the connected profile is refused with the disconnect-first message;
* a failed profile-store write becomes an error banner rather than a panic;
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
* the start decision uses an answering socket with no action, registers an
  unregistered service once, reports approval without retrying, never registers
  or kickstarts while approval is outstanding, and installs the legacy
  LaunchDaemon exactly once when ServiceManagement refuses an unsigned build;
* clipboard text equals the displayed banner, including the daemon-start log
  tail, and the brief Copied confirmation is generation-safe;
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
  removal clears the countdown source;
* Tab cycles each form in declaration order and wraps, Shift+Tab reverses and
  wraps, and Enter maps to the right primary action per screen;
* the GUI source guard proves that Connect and its daemon-bridge call contain no
  process spawn, URL opener, elevation or helper-install path, and that
  production GUI code contains no `unwrap`, `expect` or panic;
* a TOTP save round-trips through the file backend, the stored secret generates
  the same code, a second save replaces cleanly, a read-only directory gives a
  typed error, and the Unix directory/file modes are 0700/0600;
* macOS LaunchAgent and Linux XDG login items enable, disable and report their
  state through an injected runner and temporary home directories.

The full workspace suite (`cargo test --workspace`) still runs offline.
