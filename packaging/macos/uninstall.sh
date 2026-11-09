#!/bin/bash
# Remove aevan on macOS. Installed as /usr/local/bin/aevan-uninstall.
#
# Stops the daemon first (so routes, DNS, the adapter and the journal are
# released), then unloads the opt-in LaunchDaemon and removes the files.
# Idempotent: absent paths are reported, not treated as errors.
set -u

PURGE=0
for argument in "$@"; do
    case "$argument" in
        --purge) PURGE=1 ;;
        -h | --help)
            cat <<'EOF'
Usage: sudo aevan-uninstall [--purge]

Removes /Applications/Aevan.app, /usr/local/bin/{aevan,aevand,aevan-uninstall},
the LaunchDaemon plist and its loaded state, the control socket and the
daemon journal. The profile store is kept unless --purge is passed:

  ~/Library/Application Support/aevan
  ~/.config/aevan
EOF
            exit 0
            ;;
        *)
            echo "aevan-uninstall: unknown argument '$argument'" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "aevan-uninstall: run with sudo (it removes /Applications, /usr/local, /Library and /var/run entries)" >&2
    exit 1
fi

FAIL=0
TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$TARGET_USER" = "root" ]; then
    TARGET_HOME="/var/root"
elif command -v dscl >/dev/null 2>&1; then
    TARGET_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
else
    TARGET_HOME="$HOME"
fi
[ -n "${TARGET_HOME:-}" ] || TARGET_HOME="$HOME"

remove_path() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        if rm -rf "$1"; then
            echo "removed: $1"
        else
            echo "error: could not remove $1" >&2
            FAIL=1
        fi
    else
        echo "absent: $1"
    fi
}

# Stop the daemon and release routes/DNS/adapter/journal before deleting files.
stop_for_home() {
    local home="$1"
    if [ -x /usr/local/bin/aevan ]; then
        if ! HOME="$home" /usr/local/bin/aevan shutdown --if-running; then
            echo "error: cannot stop the daemon for $home; no files were removed" >&2
            return 1
        fi
    fi
    if [ -x /usr/local/bin/aevand ]; then
        if ! HOME="$home" /usr/local/bin/aevand --recover >/dev/null; then
            echo "error: journal recovery failed for $home; no files were removed" >&2
            return 1
        fi
    fi
    return 0
}

if ! stop_for_home "$TARGET_HOME"; then
    exit 1
fi
if [ "$TARGET_HOME" != "/var/root" ]; then
    if ! stop_for_home "/var/root"; then
        exit 1
    fi
fi

# The LaunchDaemon is opt-in; unload it if it was ever loaded.
launchctl bootout system/com.github.kilisk.aevand 2>/dev/null || true
launchctl unload -w /Library/LaunchDaemons/com.github.kilisk.aevand.plist 2>/dev/null || true

remove_path /Library/LaunchDaemons/com.github.kilisk.aevand.plist
remove_path /Applications/Aevan.app
remove_path /usr/local/bin/aevan
remove_path /usr/local/bin/aevand
remove_path /usr/local/bin/aevan-uninstall
remove_path "/Library/Application Support/Aevan/aevan.sock"
remove_path "/Library/Application Support/Aevan"
remove_path /run/aevan/aevan.sock
remove_path /run/aevan
remove_path /var/run/aevan.sock

for base in "$TARGET_HOME" /var/root; do
    [ -n "$base" ] || continue
    remove_path "$base/Library/Application Support/aevan/aevan.sock"
    remove_path "$base/Library/Application Support/aevan/aevand.journal"
    remove_path "$base/.config/aevan/aevan.sock"
    remove_path "$base/.config/aevan/aevand.journal"
done

if [ "$PURGE" -eq 1 ]; then
    for base in "$TARGET_HOME" /var/root; do
        [ -n "$base" ] || continue
        remove_path "$base/Library/Application Support/aevan"
        remove_path "$base/.config/aevan"
    done
else
    echo "kept: $TARGET_HOME/Library/Application Support/aevan (profiles)"
    echo "kept: $TARGET_HOME/.config/aevan (if present)"
    echo "run with --purge to remove the profile store too"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "aevan-uninstall: some removals failed" >&2
    exit 1
fi
echo "aevan is uninstalled"
