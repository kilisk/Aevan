# Protocol notes

## Why a root daemon cannot own the profile store

A macOS system LaunchDaemon runs as root with `HOME=/var/root`. Its profile
store is therefore `/var/root/Library/Application Support/aevan`, which is not
the store of the logged-in user who started the GUI or CLI. Resolving a
`connect` request by profile name inside the daemon makes the GUI fail with
`profile not found` even when the user's own store is valid.

Reading another user's home directory instead is not acceptable: it crosses an
ownership boundary, needs privileges the daemon should not rely on, and breaks
under SIP-protected or network home directories.

Version 2 of the control protocol fixes this by moving profile resolution to
the client:

* The CLI and GUI load the profile from *their* store.
* The `connect` request carries `gateway_url`, `realm`, `username`, the
  password and the optional token, plus `profile` as a display name.
* The daemon builds the connection from those fields and never reads a profile
  file for that request. An empty, absent or unreadable root store is harmless.

## Version-1 compatibility

A version-1 request has no `gateway_url` or `realm`. The daemon keeps the old
behavior for that case only: it looks the named profile up in the store resolved
at startup (the default profile when no name is given). This keeps an older CLI
working against a new daemon, including the response version (the daemon echoes
the request's `schema_version`).

Supplying only one of `gateway_url` and `realm` is rejected as a configuration
error rather than silently falling back.

## Secrets

Passwords and tokens remain `SecretString` values: they zeroize on drop and
redact in `Debug`. `gateway_url` and `realm` are not secret, but they are not
logged at info level either.
