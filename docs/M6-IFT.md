# M6 — IF-T/TLS transport: assessment

**Outcome: not implemented. Documented as a dead end for this project's current position.**

## What IF-T/TLS is

IF-T is the second transport these gateways offer, alongside Network Connect. It runs inside a TLS
tunnel (typically on TCP 443) rather than over ESP/UDP, and it is the transport the vendor's own client
pads by default on current gateway releases. Supporting it would remove the dependency on UDP 4500
being reachable, which is the most common reason NC fails on restrictive networks.

## Why it is not implemented

1. **No public specification.** The NC path is documented well enough by the open-source
   reference client to implement independently. IF-T has no equivalent public description: its
   message framing, session establishment and framing layer are not published.
2. **Vendor-specific handshake.** The transport carries its own authentication and framing that a
   third-party client cannot derive from observable HTTP behaviour, because the exchange happens
   inside the encrypted tunnel.
3. **No cooperating gateway.** Developing it blind would mean guessing a proprietary wire format
   against a production gateway — the exact failure mode this project avoided elsewhere by anchoring
   every protocol decision to documentation or a reference implementation.
4. **NC is sufficient where it works.** The current client completes the full lifecycle over NC:
   sign-in, configuration, tunnel, rekey, teardown.

## What is in the tree

`aevan-ift` is a feature-gated stub: it reports the milestone, whether the `ift` feature is enabled,
and returns a typed "unimplemented" error otherwise. Nothing in the CLI, daemon or GUI depends on it,
so it cannot be reached accidentally.

## What would change the decision

- A published specification of the transport, or a vendor-sanctioned implementation to reference.
- A cooperating test gateway where an unsuccessful handshake is expected and allowed.
- A report from a network where NC is blocked and IF-T is the only working transport, which would
  justify the reverse-engineering effort and its legal risk.

Until one of those exists, the honest status is a documented dead end rather than a half-built
transport that could send credentials into a protocol it does not understand.
