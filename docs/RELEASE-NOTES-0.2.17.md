# Aevan 0.2.17

## Logging and diagnostics

- CLI, GUI and daemon write separate rotating logs. Settings can change the app log level and open the log folder; the privileged daemon has a separate administrator-controlled level.
- **Settings → About → Copy diagnostics** includes build and daemon versions, paths, and the last 50 GUI log lines.
- Daemon startup errors show only the current attempt. On macOS, the verified bundle is checked before deciding between ServiceManagement and the ad-hoc fallback; an initial `NotFound` no longer bypasses the fallback.
- The CLI resolves symlinks before looking for its companion GUI, including when invoked through the command-line tools symlink on macOS.

## Headless Ubuntu

Ubuntu Server 24.04 or newer on amd64 can install the checksum-verified `.deb` with the one-line installer in the README. The Debian and RPM services now point to `/usr/bin/aevand`, where the packages actually install the daemon. The Debian package does not start or enable the service; use `sudo systemctl start aevand.service` and check it with `aevan status`.

## Verification limits

The macOS universal DMG and PKG are built in Actions. The app is ad-hoc signed and not notarised. CI does not verify the interactive helper approval, Console.app display, or live tunnel traffic on Selene. Live VPN traffic on a headless Ubuntu server also remains unverified.
