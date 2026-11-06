#!/usr/bin/env sh
# e2e-example — generic live smoke checks for a Network Connect gateway.
#
# Usage:
#   scripts/e2e-example.sh <host> <profile>
#
#   host     gateway portal URL, for example https://vpn.example.com/staff
#   profile  aevan profile name to use for connect/status/disconnect
#
# With either argument missing the script prints what it would check and exits
# 0 without touching the network. When both are set it runs the credential-free
# `aevan doctor` probe against <host> and then prints the remaining manual
# steps. It never accepts, prints or stores a password or token; run the
# connect step yourself so the CLI can prompt on the terminal.
set -eu

host=${1:-}
profile=${2:-}

if [ -z "$host" ] || [ -z "$profile" ]; then
    cat <<'EOF'
e2e-example — live acceptance checks (skipped)

No host/profile supplied, so nothing was run. To execute:

    scripts/e2e-example.sh https://vpn.example.com/staff <profile>

Checks:
    1. aevan doctor --url <host> --json   (no credentials)
    2. aevan connect <profile>            (one authentication attempt)
    3. aevan status --json                (adapter, routes, DNS, MTU)
    4. aevan disconnect <profile>
EOF
    exit 0
fi

echo "host:    $host"
echo "profile: $profile"
echo
echo "== credential-free probe =="
aevan doctor --url "$host" --json
echo
cat <<EOF
== remaining manual checks ==
Run these in order; connect prompts for the password and one-time token:

    aevan connect $profile
    aevan status --json
    aevan disconnect $profile

Nothing above is executed automatically. One authentication attempt per
connect/login invocation is the rule; do not retry a failed login.
EOF
