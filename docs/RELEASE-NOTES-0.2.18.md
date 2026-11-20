# Aevan 0.2.18

Fixes a Linux VPN connection failure after successful authentication and negotiation: Aevan now brings the kernel-assigned TUN interface up before installing routes. Previously Linux could reject the first route with `Device for nexthop is not up`.

The Linux smoke test now installs a route in an isolated network namespace and checks that it disappears when the TUN device closes. This verifies local route setup and teardown without requiring a VPN login. It does not verify live tunnel traffic.

On Ubuntu, upgrade with the one-line installer in the README, then run `sudo systemctl start aevand.service` and reconnect as your normal user. macOS builds are ad-hoc signed and not notarised.
