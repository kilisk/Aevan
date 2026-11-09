# Security policy

Aevan is an unofficial client. Please report problems privately; do not open a
public issue for a vulnerability.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. Open the **Security** tab.
2. Choose **Report a vulnerability** (GitHub Security Advisories).
3. Include the version, operating system, a description, and a minimal
   reproduction. Never include a real password, TOTP secret, session cookie or
   private key.

If private reporting is unavailable, open a public issue that says only that
you have a security report and ask for a private channel; do not put the details
in the issue.

## What is in scope

- The Rust crates in this repository (`crates/`).
- The CLI, daemon and GUI binaries built from them.
- The packaging and install scripts in `packaging/` and `scripts/`.
- Handling of credentials, cookies, key material and profile data.

Out of scope: the official client, the gateway itself, and problems that require
an already-compromised machine or physical access.

## Credentials and profile data

Credentials never leave the machine. The client talks only to the gateway you
configure, and authentication is one attempt per invocation.

Profiles store no secrets. A profile contains the gateway URL, realm, optional
username and split-tunnel intent. Passwords are read from the terminal and are
not written to disk, argv, environment variables or logs. A TOTP secret, when
you enrol one, is stored in the OS keyring, not in the profile file. Request
bodies, cookies, authorization headers and key material are redacted from logs
and diagnostics.

## False positives

**The binaries are unsigned.** There is no code-signing certificate for this
project, so Windows SmartScreen and some antivirus engines treat the downloads
as untrusted. Windows Defender has flagged `aevand.exe` and `aevan.exe` as
severe threats on some machines.

This is a known consequence of what the software is: an unsigned network
daemon that self-elevates, creates a virtual adapter and runs system network
commands. Those behaviours overlap with what malware does, so heuristic and
reputation-based scanners can flag it without analysing the code. It is also
why the project does not try to hide those behaviours: there is no packing, no
obfuscation, no runtime decryption and no hidden child process.

You should still verify what you downloaded rather than trusting a claim:

- Every release publishes a **SHA-256** for each artifact. Compare it with the
  file you downloaded (`sha256sum`, `shasum -a 256`, or
  `Get-FileHash -Algorithm SHA256`).
- The full source is public and can be built from the tagged commit. The release
  notes name the commit that produced the artifacts, so you can reproduce the
  build and confirm the binary matches the source.

If you see a detection, first confirm the hash matches the published one, then
report the false positive to Microsoft:

<https://www.microsoft.com/en-us/wdsi/filesubmission>

Choose **Software developer** and submit the flagged file with a short
explanation that it is an open-source unsigned VPN client whose source is
public. Do not disable your antivirus and do not run an unverified copy.

**Code signing is the real fix.** It is not currently done because the project
has no certificate; until then, reputation-based detections can recur after
each release.
