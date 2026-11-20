# Aevan 0.2.19

Fixes a tunnel that could report connected on Linux or macOS but stall after the transmit queue drained. The ESP loop reads directly from the TUN device, so an empty queue now returns immediately on Linux and macOS instead of blocking UDP receive, timers and shutdown. Temporary TUN write backpressure no longer tears down the tunnel.

The Linux smoke test sends a local datagram through a real TUN in a disposable network namespace and verifies that the empty read returns immediately and the test route disappears at teardown. Native macOS CI checks that an empty `utun` read returns immediately. Neither test uses gateway credentials or verifies live VPN traffic.
