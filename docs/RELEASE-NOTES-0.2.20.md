# Aevan 0.2.20

Fixes an MTU mismatch on Linux paths such as WSL where small tunneled packets work but larger TCP segments stall. Aevan now checks the connected ESP UDP socket’s known path MTU and accounts for the outer IP, UDP and ESP headers, authentication tag and CBC padding. If the resulting MTU is lower than the gateway’s offer, the client uses it consistently for the tunnel interface, the initial configuration reply and rekey replies. On the tested WSL2 setup, a 1280-byte outer IPv4 path capped an advertised MTU of 1396 at 1214 bytes.

Other platforms keep using the gateway’s MTU. The change does not alter WSL’s DNS configuration or trust self-signed certificates.

## Verified

- **Ubuntu 26.04 under WSL2:** A live VPN session used MTU 1214 and four split routes. ICMP, direct UDP DNS and an authenticated SSH session worked. HTTPS with an explicit address reached TLS certificate verification; curl rejected the endpoint’s self-signed certificate, so no HTTP response was verified.
- **GitHub Actions:** Windows, macOS and Ubuntu tests and packaging passed in [run 44735038224](https://github.com/kilisk/Aevan/actions/runs/44735038224). Ubuntu exercised the real TUN route lifecycle and Debian package install, service startup and removal. macOS exercised `utun`, root-daemon socket access and DMG validation. Windows validated the MSI.

## Not verified or still open

- WSL’s default application resolver still used its host DNS proxy even though Aevan installed VPN DNS in systemd-resolved. Direct DNS worked; ordinary application hostname resolution did not.
- During a later WSL observation, the peer closed the control channel around rekey and the session disconnected. Sustained traffic across rekey is not verified; the cause of the disconnect is not established.
- No live non-WSL Linux or v0.2.20 Windows gateway run is recorded. No successful live macOS tunnel, interactive helper startup, Console.app logging or clean macOS installation was verified for this release.
