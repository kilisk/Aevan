#!/bin/bash
# Remove aevan installed by install.sh. Run as root/sudo.
#
# Stops the daemon first so routes, DNS, the adapter and the journal are
# released, then removes the unit, binaries, socket and journal. The profile
# store (~/.config/aevan) is kept unless --purge is passed.
set -u

PURGE=0
for argument in "$@"; do
    case "$argument" in
        --purge) PURGE=1 ;;
        -h | --help)
            cat <<'EOF'
Usage: sudo ./uninstall.sh [--purge]

Stops aevand, disables and removes aevand.service, removes /usr/local/bin/{aevan,
aevand,aevan-gui}, the unit, /usr/local/share/doc/aevan, the Aevan icons under
/usr/local/share/icons/hicolor, aevan.desktop, the control socket and the
journal. ~/.config/aevan is kept unless --purge is passed.
EOF
            exit 0
            ;;
        *)
            echo "uninstall.sh: unknown argument '$argument'" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh: run as root or with sudo" >&2
    exit 1
fi

FAIL=0
TARGET_USER="${SUDO_USER:-$(id -un)}"
if command -v getent >/dev/null 2>&1; then
    TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
else
    TARGET_HOME="$(eval echo "~$TARGET_USER" 2>/dev/null || echo "$HOME")"
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

stop_for_home() {
    local home="$1"
    local -a env_args=(HOME="$home")
    if [ "$home" = "/root" ]; then
        env_args=(-u XDG_CONFIG_HOME HOME=/root)
    fi
    if [ -x /usr/local/bin/aevan ]; then
        if ! env "${env_args[@]}" /usr/local/bin/aevan shutdown --if-running; then
            echo "error: cannot stop the daemon for $home; no files were removed" >&2
            return 1
        fi
    fi
    if [ -x /usr/local/bin/aevand ]; then
        if ! env "${env_args[@]}" /usr/local/bin/aevand --recover >/dev/null; then
            echo "error: journal recovery failed for $home; no files were removed" >&2
            return 1
        fi
    fi
    return 0
}

if ! stop_for_home "$TARGET_HOME"; then
    exit 1
fi
if [ "$TARGET_HOME" != "/root" ]; then
    if ! stop_for_home "/root"; then
        exit 1
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now aevand.service 2>/dev/null || true
    systemctl stop aevand.service 2>/dev/null || true
fi

remove_path /etc/systemd/system/aevand.service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

remove_path /usr/local/bin/aevan
remove_path /usr/local/bin/aevand
remove_path /usr/local/bin/aevan-gui
remove_path /usr/local/share/doc/aevan
remove_path /usr/local/share/icons/hicolor/64x64/apps/aevan.png
remove_path /usr/local/share/icons/hicolor/128x128/apps/aevan.png
remove_path /usr/local/share/icons/hicolor/256x256/apps/aevan.png
remove_path /usr/local/share/icons/hicolor/512x512/apps/aevan.png
remove_path /usr/local/share/applications/aevan.desktop

for base in "$TARGET_HOME" /root; do
    [ -n "$base" ] || continue
    remove_path "$base/.config/aevan/aevan.sock"
    remove_path "$base/.config/aevan/aevand.journal"
done
remove_path /var/run/aevan.sock
remove_path /run/aevan.sock

if [ "$PURGE" -eq 1 ]; then
    for base in "$TARGET_HOME" /root; do
        [ -n "$base" ] || continue
        remove_path "$base/.config/aevan"
    done
else
    echo "kept: $TARGET_HOME/.config/aevan (profiles)"
    echo "run with --purge to remove the profile store too"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "uninstall.sh: some removals failed" >&2
    exit 1
fi
echo "aevan is uninstalled"
