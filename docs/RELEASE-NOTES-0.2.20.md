# Aevan 0.2.20

Fixes an MTU mismatch on Linux paths such as WSL where small tunneled packets work but larger TCP segments stall. Aevan now checks the connected ESP UDP socket’s known path MTU and accounts for the outer IP, UDP and ESP headers, authentication tag and CBC padding. If the resulting MTU is lower than the gateway’s offer, the client uses it consistently for the tunnel interface, the initial configuration reply and rekey replies. On Aster’s 1280-byte outer IPv4 path, an advertised MTU of 1396 is capped at 1214 bytes.

Other platforms keep using the gateway’s MTU. The change does not alter WSL’s DNS configuration or trust self-signed certificates.
