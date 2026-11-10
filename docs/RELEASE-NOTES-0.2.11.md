# Aevan 0.2.11

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13 or newer.** Pre-release: unsigned and not notarised.

## You no longer type a realm

The vendor client never asks for one, and now neither does Aevan. On the first connect with an empty
realm, Aevan performs **one unauthenticated GET** of the portal, follows the redirect to
`/dana-na/auth/url_<id>/welcome.cgi`, and reads the realm from the sign-in form's hidden `realm` input
— falling back to the `url_<realm>` path segment if the form is absent.

- It sends no credentials and posts nothing: it is not a login attempt and cannot consume one.
- The detected value is stored in the profile, so later connections are instant, and the banner says
  `realm: mygovnet_staff (detected)` once.
- An explicit `--realm <value>` is honoured and never overwritten.
- If the page advertises nothing, the error is explicit — *"the sign-in page did not advertise a
  realm; pass --realm <value>"* — instead of a silent failed login.
- `aevan doctor` now reports whether the realm was configured or detected; the GUI's realm field is
  optional with the placeholder *detect automatically*.

## Also in this release

- Profile editing and deletion in the GUI (0.2.10).
- The generated platform matrix and its CI gate (0.2.10).

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.11-x64.msi`, portable `aevan-0.2.11-x64.zip` |
| macOS 13+ | `aevan-0.2.11-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.11-x86_64-linux.tar.gz`, `aevan_0.2.11_amd64.deb`, `aevan-0.2.11-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Still unproven

- Realm detection is tested against fixtures, not against the live portal in this build.
- A full macOS or Linux tunnel; installers on a clean machine; the macOS window clicked by a human.
  See `docs/PLATFORM-MATRIX.md`, which is generated and cannot drift from the code.
