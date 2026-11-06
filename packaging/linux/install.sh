#!/bin/bash
# Install aevan from this tarball. Run as root/sudo.
#
#   sudo ./install.sh            # install, leave the service disabled
#   sudo ./install.sh --enable   # install, enable and start aevand.service
set -eu

ENABLE=0
for argument in "$@"; do
    case "$argument" in
        --enable) ENABLE=1 ;;
        -h | --help)
            cat <<'EOF'
Usage: sudo ./install.sh [--enable]

Copies aevan, aevand and aevan-gui to /usr/local/bin, installs the systemd unit
to /etc/systemd/system/aevand.service, installs the Aevan icons under
/usr/local/share/icons/hicolor and aevan.desktop under
/usr/local/share/applications, then runs systemctl daemon-reload.

The service is NOT enabled or started unless --enable is passed.
EOF
            exit 0
            ;;
        *)
            echo "install.sh: unknown argument '$argument'" >&2
            exit 2
            ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root or with sudo" >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
DOC_DIR="$PREFIX/share/doc/aevan"

install -d "$PREFIX/bin" "$DOC_DIR" /etc/systemd/system
install -m 0755 "$HERE/aevan" "$HERE/aevand" "$HERE/aevan-gui" "$PREFIX/bin/"
install -m 0644 "$HERE/aevand.service" /etc/systemd/system/aevand.service

for size in 64x64 128x128 256x256 512x512; do
    install -d "$PREFIX/share/icons/hicolor/$size/apps"
    install -m 0644 "$HERE/share/icons/hicolor/$size/apps/aevan.png" \
        "$PREFIX/share/icons/hicolor/$size/apps/aevan.png"
done
install -d "$PREFIX/share/applications"
install -m 0644 "$HERE/share/applications/aevan.desktop" \
    "$PREFIX/share/applications/aevan.desktop"

for file in README.md LICENSE LICENSE-APACHE LICENSE-MIT LICENSE-WINTUN.txt; do
    if [ -f "$HERE/$file" ]; then
        install -m 0644 "$HERE/$file" "$DOC_DIR/$file"
    fi
done

if ! command -v systemctl >/dev/null 2>&1; then
    echo "install.sh: systemctl was not found; files are installed but the unit was not reloaded" >&2
    exit 1
fi
systemctl daemon-reload

if [ "$ENABLE" -eq 1 ]; then
    systemctl enable --now aevand.service
    echo "installed and started aevand.service"
else
    echo "installed; aevand.service is not enabled or started"
    echo "enable it with: sudo systemctl enable --now aevand.service"
fi
