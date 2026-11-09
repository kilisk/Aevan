# RPM spec for aevan. The version is substituted from Cargo.toml by the
# justfile; do not edit @VERSION@ here.
#
# Build from the release tarball produced by `just dist-linux`. The tarball
# supplies the prebuilt binaries plus the unit, desktop entry, icons and docs.
# The unit is installed but never enabled or started by the package.

%global debug_package %{nil}

Name:           aevan
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Independent Ivanti Secure Access (Network Connect) client
License:        MIT OR Apache-2.0
URL:            https://github.com/kilisk/aevan
Source0:        aevan-@VERSION@-x86_64-linux.tar.gz
BuildArch:      x86_64
Requires:       glibc
Requires:       hicolor-icon-theme
Requires:       systemd
Requires(post): systemd
Requires(preun): systemd

%description
aevan is a clean-room command-line client, privileged daemon and GUI for
Ivanti Secure Access gateways that speak the Network Connect protocol.

The package installs aevan, aevand, aevan-gui, a systemd unit, a desktop entry
and hicolor icons. The aevand.service unit is installed but deliberately not
enabled or started; see /usr/share/doc/aevan/README.

%prep
%setup -q -c

%build
# Prebuilt release binaries are supplied in Source0.

%install
mkdir -p %{buildroot}/usr/bin \
         %{buildroot}/lib/systemd/system \
         %{buildroot}/usr/share/applications \
         %{buildroot}/usr/share/doc/aevan \
         %{buildroot}/usr/share/icons/hicolor/64x64/apps \
         %{buildroot}/usr/share/icons/hicolor/128x128/apps \
         %{buildroot}/usr/share/icons/hicolor/256x256/apps \
         %{buildroot}/usr/share/icons/hicolor/512x512/apps
install -m 0755 aevan aevand aevan-gui %{buildroot}/usr/bin/
install -m 0644 aevand.service %{buildroot}/lib/systemd/system/aevand.service
install -m 0644 share/applications/aevan.desktop %{buildroot}/usr/share/applications/aevan.desktop
for size in 64x64 128x128 256x256 512x512; do
    install -m 0644 "share/icons/hicolor/$size/apps/aevan.png" \
        "%{buildroot}/usr/share/icons/hicolor/$size/apps/aevan.png"
done
install -m 0644 README.md %{buildroot}/usr/share/doc/aevan/README
install -m 0644 copyright %{buildroot}/usr/share/doc/aevan/copyright
install -m 0644 LICENSE LICENSE-APACHE LICENSE-MIT %{buildroot}/usr/share/doc/aevan/

%post
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

%preun
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled --quiet aevand.service 2>/dev/null; then
        systemctl stop aevand.service || true
    fi
fi

%files
/usr/bin/aevan
/usr/bin/aevand
/usr/bin/aevan-gui
/lib/systemd/system/aevand.service
/usr/share/applications/aevan.desktop
/usr/share/icons/hicolor/64x64/apps/aevan.png
/usr/share/icons/hicolor/128x128/apps/aevan.png
/usr/share/icons/hicolor/256x256/apps/aevan.png
/usr/share/icons/hicolor/512x512/apps/aevan.png
%dir /usr/share/icons/hicolor/64x64/apps
%dir /usr/share/icons/hicolor/128x128/apps
%dir /usr/share/icons/hicolor/256x256/apps
%dir /usr/share/icons/hicolor/512x512/apps
%dir /usr/share/doc/aevan
/usr/share/doc/aevan/README
/usr/share/doc/aevan/copyright
/usr/share/doc/aevan/LICENSE
/usr/share/doc/aevan/LICENSE-APACHE
/usr/share/doc/aevan/LICENSE-MIT

%changelog
* Sun Nov 09 2026 aevan contributors <kilisk@users.noreply.github.com> - @VERSION@-1
- Build the package in CI from the release tarball.
