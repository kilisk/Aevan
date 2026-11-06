# RPM skeleton for aevan. UNTESTED.
#
# Build with `just rpm` on a host that has rpmbuild. The version is substituted
# from Cargo.toml by the justfile; do not edit @VERSION@ here.
#
# The runtime dependency list is deliberately minimal and incomplete: aevan-gui
# needs a working wgpu/wayland or X11 stack, and the daemon needs whatever
# capabilities the distribution grants for creating a TUN device. Review before
# distributing.

Name:           aevan
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Ivanti Secure Access client replacement
License:        MIT OR Apache-2.0
Source0:        aevan-@VERSION@-x86_64-linux.tar.gz
BuildArch:      x86_64
Requires:       ca-certificates

%description
aevan is a small CLI, daemon and GUI for Ivanti Secure Access gateways.
This package is a skeleton and has not been install-tested. It installs the
three binaries plus license and README files; it does not install a system
service because the tunnel belongs to the per-user profile store.

%prep
%setup -q -c

%build
# Prebuilt release binaries are supplied in Source0.

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 aevan aevand aevan-gui %{buildroot}/usr/bin/
mkdir -p %{buildroot}/usr/share/doc/aevan
install -m 0644 README.md LICENSE LICENSE-APACHE LICENSE-MIT LICENSE-WINTUN.txt %{buildroot}/usr/share/doc/aevan/

%files
/usr/bin/aevan
/usr/bin/aevand
/usr/bin/aevan-gui
/usr/share/doc/aevan/README.md
/usr/share/doc/aevan/LICENSE
/usr/share/doc/aevan/LICENSE-APACHE
/usr/share/doc/aevan/LICENSE-MIT
/usr/share/doc/aevan/LICENSE-WINTUN.txt

%changelog
* Thu Nov 05 2026 aevan contributors - @VERSION@-1
- Skeleton package; not install-tested.
