#!/bin/bash
# Build the universal Aevan.app and .pkg. Runs on macOS only.
#
# Usage: build-pkg.sh <version> <universal-bin-dir> <dist-dir>
set -eu

VERSION="${1:?usage: build-pkg.sh <version> <universal-bin-dir> <dist-dir>}"
BIN="${2:?usage: build-pkg.sh <version> <universal-bin-dir> <dist-dir>}"
DIST="${3:?usage: build-pkg.sh <version> <universal-bin-dir> <dist-dir>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="$DIST/macos-staging"
APP="$STAGE/Applications/Aevan.app"
DMG_STAGE="$DIST/macos-dmg-staging"
DMG="$DIST/aevan-$VERSION-arm64+x86_64.dmg"

# Build AppIcon.icns best-effort. Prefer actool over the Icon Composer bundle
# ("Aevan Icon.icon"); otherwise render an .iconset from the supplied PNGs and
# let iconutil consume it. A missing tool or a tool failure only warns: the
# package must still build without an icon.
build_icon() {
    local resources="$1"
    local icon_dir="$ROOT/assets/branding/Aevan Icon.icon"
    local png="$ROOT/assets/branding/Aevan-1024.png"
    local icns="$resources/AppIcon.icns"
    local tmp iconset actool_out size name spec

    if command -v actool >/dev/null 2>&1 && [ -d "$icon_dir" ]; then
        tmp="$(mktemp -d)"
        if actool --compile "$tmp" \
                --platform macosx \
                --minimum-deployment-target 11.0 \
                --output-partial-info-plist "$tmp/asset-info.plist" \
                --app-icon "Aevan Icon" \
                "$icon_dir" >/dev/null 2>&1; then
            actool_out="$(find "$tmp" -name '*.icns' -print -quit)"
            if [ -n "$actool_out" ] && cp "$actool_out" "$icns"; then
                rm -rf "$tmp"
                echo "icon: built AppIcon.icns with actool from 'Aevan Icon.icon'"
                return 0
            fi
        fi
        rm -rf "$tmp"
        echo "icon: actool could not produce AppIcon.icns; falling back to iconutil" >&2
    fi

    if ! command -v iconutil >/dev/null 2>&1; then
        echo "icon: iconutil is unavailable; building without an app icon" >&2
        return 1
    fi

    tmp="$(mktemp -d)"
    iconset="$tmp/AppIcon.iconset"
    mkdir -p "$iconset"
    for spec in \
        16:icon_16x16.png 32:icon_16x16@2x.png \
        32:icon_32x32.png 64:icon_32x32@2x.png \
        128:icon_128x128.png 256:icon_128x128@2x.png \
        256:icon_256x256.png 512:icon_256x256@2x.png \
        512:icon_512x512.png 1024:icon_512x512@2x.png; do
        size="${spec%%:*}"
        name="${spec#*:}"
        if ! sips -z "$size" "$size" "$png" --out "$iconset/$name" >/dev/null 2>&1; then
            rm -rf "$tmp"
            echo "icon: sips could not render the iconset; building without an app icon" >&2
            return 1
        fi
    done
    if iconutil -c icns "$iconset" -o "$icns"; then
        rm -rf "$tmp"
        echo "icon: built AppIcon.icns with iconutil from the PNGs"
        return 0
    fi
    rm -rf "$tmp"
    echo "icon: iconutil failed; building without an app icon" >&2
    return 1
}

rm -rf "$STAGE" "$DIST/Aevan.app" "$DMG_STAGE" "$DMG"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m 0755 "$BIN/aevan-gui" "$APP/Contents/MacOS/aevan-gui"
sed "s/@VERSION@/$VERSION/g" \
    "$ROOT/packaging/macos/Info.plist.in" > "$APP/Contents/Info.plist"
if ! build_icon "$APP/Contents/Resources"; then
    echo "icon: continuing without AppIcon.icns" >&2
fi

# Ad-hoc sign the finished bundle. There is no Developer ID and nothing is
# notarised; a "-" identity only makes the bundle internally consistent so the
# embedded executable and resources validate after the drag install.
if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - --timestamp=none "$APP"
    codesign --verify --deep --strict "$APP"
    echo "sign: ad-hoc signed Aevan.app"
else
    echo "sign: codesign is unavailable; building an unsigned Aevan.app" >&2
fi
cp -R "$APP" "$DIST/Aevan.app"

mkdir -p "$STAGE/usr/local/bin" \
         "$STAGE/usr/local/share/doc/aevan" \
         "$STAGE/Library/LaunchDaemons"
install -m 0755 "$BIN/aevan" "$STAGE/usr/local/bin/aevan"
install -m 0755 "$BIN/aevand" "$STAGE/usr/local/bin/aevand"
install -m 0755 "$ROOT/packaging/macos/uninstall.sh" \
    "$STAGE/usr/local/bin/aevan-uninstall"
install -m 0644 "$ROOT/packaging/macos/com.github.kilisk.aevand.plist" \
    "$STAGE/Library/LaunchDaemons/com.github.kilisk.aevand.plist"
for file in README.md LICENSE LICENSE-APACHE LICENSE-MIT; do
    install -m 0644 "$ROOT/$file" "$STAGE/usr/local/share/doc/aevan/$file"
done

pkgbuild --root "$STAGE" \
    --identifier com.github.kilisk.aevan \
    --version "$VERSION" \
    --install-location "/" \
    "$DIST/aevan-component.pkg"

productbuild --package "$DIST/aevan-component.pkg" \
    --identifier com.github.kilisk.aevan \
    --version "$VERSION" \
    "$DIST/aevan-$VERSION-arm64+x86_64.pkg"

rm -f "$DIST/aevan-component.pkg"

# Drag-install disk image: Aevan.app plus an Applications symlink pointing at
# the real /Applications. The user opens the image and drags the app across.
mkdir -p "$DMG_STAGE"
cp -R "$DIST/Aevan.app" "$DMG_STAGE/Aevan.app"
ln -s /Applications "$DMG_STAGE/Applications"
hdiutil create \
    -volname "Aevan" \
    -srcfolder "$DMG_STAGE" \
    -ov \
    -format UDZO \
    "$DMG"
rm -rf "$DMG_STAGE"

# Signing the image is best-effort: some hdiutil versions and signing setups do
# not mix, so a failure only warns and never discards a good DMG.
if command -v codesign >/dev/null 2>&1; then
    if codesign --force --sign - --timestamp=none "$DMG"; then
        echo "sign: ad-hoc signed the DMG"
    else
        echo "sign: could not ad-hoc sign the DMG; the image itself is unchanged" >&2
    fi
fi

echo "dmg: $DMG"
