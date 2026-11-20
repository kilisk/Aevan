#!/usr/bin/env bash
# Keep the call within this block so Bash parses the whole download first.
{
install_aevan() (
  set -euo pipefail

  local version=0.2.19
  local deb="aevan_${version}_amd64.deb"
  local base="https://github.com/kilisk/Aevan/releases/download/v${version}"
  local deb_sha256
  local -a elevate=()

  if ! command -v dpkg >/dev/null || ! command -v apt-get >/dev/null; then
    printf '%s\n' 'This installer requires Ubuntu or another Debian-based distribution.' >&2
    exit 1
  fi
  if [[ $(dpkg --print-architecture) != amd64 ]]; then
    printf '%s\n' 'This installer supports amd64 (x86-64) only.' >&2
    exit 1
  fi
  if (( EUID != 0 )); then
    if ! command -v sudo >/dev/null; then
      printf '%s\n' 'Run this installer as root or install sudo first.' >&2
      exit 1
    fi
    elevate=(sudo)
  fi

  tmp=$(mktemp -d /tmp/aevan-install.XXXXXXXX)
  trap 'rm -f -- "$tmp/$deb" "$tmp/SHA256SUMS.txt"; rmdir -- "$tmp"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/SHA256SUMS.txt" \
    "$base/SHA256SUMS.txt"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/$deb" \
    "$base/$deb"
  deb_sha256=$(awk -v name="$deb" '$2 == name || $2 == "*" name { print $1 }' "$tmp/SHA256SUMS.txt")
  if [[ ! $deb_sha256 =~ ^[a-f0-9]{64}$ ]] ||
     ! printf '%s  %s\n' "$deb_sha256" "$tmp/$deb" | sha256sum --check --status; then
    printf '%s\n' 'Aevan package checksum did not match. Nothing was installed.' >&2
    exit 1
  fi

  # Let APT's unprivileged download user read the verified local package.
  chmod 0644 "$tmp/$deb"
  chmod 0755 "$tmp"
  "${elevate[@]}" apt-get update
  "${elevate[@]}" apt-get install -y --no-install-recommends "$tmp/$deb"
  printf '\nAevan %s installed. To start the daemon on a systemd host:\n' "$version"
  printf '  %s\n' "${elevate[*]:+${elevate[*]} }systemctl start aevand.service" 'aevan status'
)
install_aevan
}
