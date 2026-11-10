# aevan workspace tasks. Run `just --list` for the short list.
#
# Packaging uses bash on every platform (Git Bash on Windows) so the version
# parser, tar and sha256sum are identical in a developer shell and CI.

set shell := ["bash", "-uc"]

version := trim(`sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1`)
bin_dir := "target/release"
dist_dir := "target/dist"
msi := dist_dir + "/aevan-" + version + "-x64.msi"
portable_zip := dist_dir + "/aevan-" + version + "-x64.zip"
linux_tar := dist_dir + "/aevan-" + version + "-x86_64-linux.tar.gz"
deb_pkg := dist_dir + "/aevan_" + version + "_amd64.deb"
rpm_pkg := dist_dir + "/aevan-" + version + "-1.x86_64.rpm"
macos_pkg := dist_dir + "/aevan-" + version + "-arm64+x86_64.pkg"
macos_dmg := dist_dir + "/aevan-" + version + "-arm64+x86_64.dmg"
universal_dir := "target/universal/release"

build:
    cargo build --release

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Cross-compilation. These commands run on a host that has the matching
# toolchain; they are not used by CI.
cross:
    @echo "cargo zigbuild --target x86_64-unknown-linux-musl"
    @echo "cargo xwin build --target x86_64-pc-windows-msvc"
    @echo "macOS: build on a macOS host and lipo the two architectures"

# Optional live smoke checks. With no arguments it prints the checks and exits
# without touching the network; pass a host and profile to run the
# credential-free probe. A live gateway and account are required for the rest.
e2e-example host="" profile="":
    bash scripts/e2e-example.sh "{{host}}" "{{profile}}"

# Print the single source-of-truth version parsed from Cargo.toml.
version:
    @echo {{version}}

# Accept the WiX v7 OSMF EULA once for this user. WiX v7 refuses to build
# until this is done (WIX7015). Read https://wixtoolset.org/osmf/ first.
wix-eula:
    wix eula accept wix7

# Download the pinned Wintun release into target/release/wintun.dll.
fetch-wintun:
    @if command -v pwsh >/dev/null 2>&1; then \
        pwsh -NoProfile -File scripts/fetch-wintun.ps1; \
    else \
        powershell -NoProfile -ExecutionPolicy Bypass -File scripts/fetch-wintun.ps1; \
    fi

# Build the native artifacts for this host.
dist:
    @if [ "{{os()}}" = "windows" ]; then \
        just dist-windows; \
    elif [ "{{os()}}" = "macos" ]; then \
        just dist-macos; \
    else \
        just dist-linux; \
    fi

# Windows: MSI + portable zip in target/dist.
dist-windows: build
    @echo "{{version}}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { \
        echo "error: workspace version '{{version}}' is not numeric major.minor.patch; MSI ProductVersion requires a numeric version" >&2; \
        exit 1; \
    }
    @test -f "{{bin_dir}}/wintun.dll" || { \
        echo "error: {{bin_dir}}/wintun.dll is missing." >&2; \
        echo "       The MSI cannot work without the signed Wintun DLL beside aevand.exe." >&2; \
        echo "       Run 'just fetch-wintun' (pinned Wintun 0.14.1), or copy" >&2; \
        echo "       wintun\\bin\\amd64\\wintun.dll from https://www.wintun.net/builds/wintun-0.14.1.zip" >&2; \
        echo "       to {{bin_dir}}/wintun.dll, then retry." >&2; \
        exit 1; \
    }
    @command -v wix >/dev/null 2>&1 || { \
        echo "error: wix was not found on PATH. Install WiX Toolset v7 (dotnet tool install --global wix --version 7.0.1) and run 'just wix-eula'." >&2; \
        exit 1; \
    }
    @mkdir -p {{dist_dir}}
    wix build -arch x64 -d Version={{version}} -d BinDir={{bin_dir}} \
        -d IconPath=assets/branding/Aevan-1024.ico \
        -d LicensePath=LICENSE \
        -d MitLicensePath=LICENSE-MIT \
        -d ApacheLicensePath=LICENSE-APACHE \
        -d WintunLicensePath=packaging/legal/LICENSE-WINTUN.txt \
        -o {{msi}} packaging/windows/aevan.wxs
    @if command -v pwsh >/dev/null 2>&1; then \
        pwsh -NoProfile -Command "Compress-Archive -Force -Path 'target/release/aevan.exe','target/release/aevand.exe','target/release/aevan-gui.exe','target/release/wintun.dll','LICENSE','LICENSE-APACHE','LICENSE-MIT','packaging/legal/LICENSE-WINTUN.txt','README.md' -DestinationPath '{{portable_zip}}'"; \
    else \
        powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Force -Path 'target/release/aevan.exe','target/release/aevand.exe','target/release/aevan-gui.exe','target/release/wintun.dll','LICENSE','LICENSE-APACHE','LICENSE-MIT','packaging/legal/LICENSE-WINTUN.txt','README.md' -DestinationPath '{{portable_zip}}'"; \
    fi
    @echo ""
    @echo "artifacts:"
    @ls -lh {{msi}} {{portable_zip}}
    @echo ""
    sha256sum {{msi}} {{portable_zip}}

# Linux: release binaries, systemd unit, install/uninstall scripts and
# licenses/docs as a .tar.gz in target/dist.
dist-linux: build
    @if [ "{{os()}}" != "linux" ]; then \
        echo "error: dist-linux must run on Linux (it packages ELF binaries)" >&2; \
        exit 1; \
    fi
    @mkdir -p {{dist_dir}}
    @stage="{{dist_dir}}/linux-staging"; \
    rm -rf "$stage"; \
    mkdir -p "$stage"; \
    cp {{bin_dir}}/aevan {{bin_dir}}/aevand {{bin_dir}}/aevan-gui "$stage/"; \
    cp README.md LICENSE LICENSE-APACHE LICENSE-MIT "$stage/"; \
    cp packaging/legal/LICENSE-WINTUN.txt "$stage/"; \
    cp packaging/linux/aevand.service packaging/linux/install.sh packaging/linux/uninstall.sh "$stage/"; \
    cp packaging/linux/copyright "$stage/"; \
    mkdir -p "$stage/share/icons/hicolor/64x64/apps" \
             "$stage/share/icons/hicolor/128x128/apps" \
             "$stage/share/icons/hicolor/256x256/apps" \
             "$stage/share/icons/hicolor/512x512/apps" \
             "$stage/share/applications"; \
    cp assets/branding/Aevan-64.png "$stage/share/icons/hicolor/64x64/apps/aevan.png"; \
    cp assets/branding/Aevan-128.png "$stage/share/icons/hicolor/128x128/apps/aevan.png"; \
    cp assets/branding/Aevan-256.png "$stage/share/icons/hicolor/256x256/apps/aevan.png"; \
    cp assets/branding/Aevan-512.png "$stage/share/icons/hicolor/512x512/apps/aevan.png"; \
    cp packaging/linux/aevan.desktop "$stage/share/applications/aevan.desktop"; \
    chmod 0755 "$stage/install.sh" "$stage/uninstall.sh"; \
    tar -C "$stage" -czf {{linux_tar}} .
    @echo ""
    @echo "artifact:"
    @ls -lh {{linux_tar}}
    @echo ""
    sha256sum {{linux_tar}}

# macOS: universal (arm64 + x86_64) .app, .pkg and drag-install .dmg in
# target/dist.
dist-macos:
    @if [ "{{os()}}" != "macos" ]; then \
        echo "error: dist-macos must run on macOS (it uses lipo, pkgbuild and productbuild)" >&2; \
        exit 1; \
    fi
    @if command -v rustup >/dev/null 2>&1; then \
        rustup target add aarch64-apple-darwin x86_64-apple-darwin; \
    fi
    MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release --target aarch64-apple-darwin
    MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release --target x86_64-apple-darwin
    @mkdir -p {{universal_dir}} {{dist_dir}}
    lipo -create -output {{universal_dir}}/aevan target/aarch64-apple-darwin/release/aevan target/x86_64-apple-darwin/release/aevan
    lipo -create -output {{universal_dir}}/aevand target/aarch64-apple-darwin/release/aevand target/x86_64-apple-darwin/release/aevand
    lipo -create -output {{universal_dir}}/aevan-gui target/aarch64-apple-darwin/release/aevan-gui target/x86_64-apple-darwin/release/aevan-gui
    chmod 0755 {{universal_dir}}/aevan {{universal_dir}}/aevand {{universal_dir}}/aevan-gui
    bash packaging/macos/build-pkg.sh "{{version}}" "{{universal_dir}}" "{{dist_dir}}"
    @echo ""
    @echo "artifacts:"
    @ls -lh {{macos_pkg}} {{macos_dmg}} {{dist_dir}}/Aevan.app
    @echo ""
    @if command -v sha256sum >/dev/null 2>&1; then \
        sha256sum {{macos_pkg}} {{macos_dmg}}; \
    else \
        shasum -a 256 {{macos_pkg}} {{macos_dmg}}; \
    fi

# Debian package built with dpkg-deb alone (no debhelper). The unit is
# installed but never enabled or started by the package; postinst only runs
# daemon-reload and prerm stops an already-enabled unit.
deb: build
    @if [ "{{os()}}" != "linux" ]; then \
        echo "error: deb must run on Linux (it packages ELF binaries)" >&2; \
        exit 1; \
    fi
    @command -v dpkg-deb >/dev/null 2>&1 || { \
        echo "error: dpkg-deb is not installed; install the dpkg package" >&2; \
        exit 1; \
    }
    @stage="{{dist_dir}}/deb/aevan_{{version}}_amd64"; \
    rm -rf "$stage"; \
    mkdir -p "$stage/DEBIAN" \
             "$stage/usr/bin" \
             "$stage/lib/systemd/system" \
             "$stage/usr/share/applications" \
             "$stage/usr/share/doc/aevan" \
             "$stage/usr/share/icons/hicolor/64x64/apps" \
             "$stage/usr/share/icons/hicolor/128x128/apps" \
             "$stage/usr/share/icons/hicolor/256x256/apps" \
             "$stage/usr/share/icons/hicolor/512x512/apps"; \
    sed 's/@VERSION@/{{version}}/g' packaging/linux/control.in > "$stage/DEBIAN/control"; \
    cp packaging/linux/postinst packaging/linux/prerm "$stage/DEBIAN/"; \
    chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm"; \
    install -m 0755 {{bin_dir}}/aevan {{bin_dir}}/aevand {{bin_dir}}/aevan-gui "$stage/usr/bin/"; \
    install -m 0644 packaging/linux/aevand.service "$stage/lib/systemd/system/aevand.service"; \
    install -m 0644 packaging/linux/aevan.desktop "$stage/usr/share/applications/aevan.desktop"; \
    install -m 0644 assets/branding/Aevan-64.png "$stage/usr/share/icons/hicolor/64x64/apps/aevan.png"; \
    install -m 0644 assets/branding/Aevan-128.png "$stage/usr/share/icons/hicolor/128x128/apps/aevan.png"; \
    install -m 0644 assets/branding/Aevan-256.png "$stage/usr/share/icons/hicolor/256x256/apps/aevan.png"; \
    install -m 0644 assets/branding/Aevan-512.png "$stage/usr/share/icons/hicolor/512x512/apps/aevan.png"; \
    install -m 0644 README.md "$stage/usr/share/doc/aevan/README"; \
    install -m 0644 packaging/linux/copyright "$stage/usr/share/doc/aevan/copyright"; \
    install -m 0644 LICENSE LICENSE-APACHE LICENSE-MIT "$stage/usr/share/doc/aevan/"; \
    dpkg-deb -Zgzip --build --root-owner-group "$stage" {{deb_pkg}}
    @echo ""
    @echo "artifact:"
    @ls -lh {{deb_pkg}}
    @echo ""
    sha256sum {{deb_pkg}}

# The .deb is built with gzip, not the default zstd: `dpkg-deb --info` shells out to
# `tar`, and some CI images ship a tar without zstd support, which fails with
# "tar subprocess failed with exit status 2" on a package that installs fine.
# gzip is readable by every dpkg and tar in use, at a small size cost.
# RPM built with rpmbuild from the release tarball. It installs the same file
# set as the .deb: binaries, unit, desktop entry, icons and docs. The unit is
# installed but not enabled or started; %post only reloads systemd and %preun
# stops an already-enabled unit.
rpm: dist-linux
    @if [ "{{os()}}" != "linux" ]; then \
        echo "error: rpm must run on Linux (it packages ELF binaries)" >&2; \
        exit 1; \
    fi
    @command -v rpmbuild >/dev/null 2>&1 || { \
        echo "error: rpmbuild is not installed; install the rpm package" >&2; \
        exit 1; \
    }
    @top="$(pwd)/{{dist_dir}}/rpmbuild"; \
    rm -rf "$top"; \
    mkdir -p "$top/SOURCES" "$top/SPECS" "$top/BUILD" "$top/RPMS" "$top/SRPMS"; \
    cp {{linux_tar}} "$top/SOURCES/"; \
    sed 's/@VERSION@/{{version}}/g' packaging/linux/aevan.spec > "$top/SPECS/aevan.spec"; \
    rpmbuild --define "_topdir $top" --define "dist %{nil}" -bb "$top/SPECS/aevan.spec"; \
    cp "$top/RPMS/x86_64/aevan-{{version}}-1"*.rpm {{rpm_pkg}}
    @echo ""
    @echo "artifact:"
    @ls -lh {{rpm_pkg}}
    @echo ""
    sha256sum {{rpm_pkg}}
