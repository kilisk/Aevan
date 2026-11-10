# Aevan 0.2.12

An independent, clean-room Rust client for Ivanti Secure Access gateways speaking the **Network
Connect (NC)** protocol. **macOS 13 or newer.** Pre-release: unsigned and not notarised.

## The daemon now starts from the GUI, even unsigned

Reported from a real Mac: *"ServiceManagement error 1: The operation couldn't be completed. Operation
not permitted."* `SMAppService` validates the **code signature** of the helper before it will register
it; an ad-hoc signed app is refused before the approval sheet is ever shown. Nothing was wrong with the
daemon or its plist.

The install sequence is now a chain:

1. **`SMAppService`** is tried first — the modern path, approval in System Settings → Login Items. This
   is what runs once the app has a Developer ID signature.
2. If the system refuses it, Aevan installs the LaunchDaemon through **one** native administrator
   prompt and bootstraps it. `RunAtLoad` means every later launch, and every reboot, needs no prompt.
3. Cancelling is reported plainly (*"The helper was not installed. Aevan needs administrator approval
   once."*) and never loops.

`osascript` exists in exactly one module (`macos_elevate.rs`), is spawned as a child process so it can
never abort the UI, and the source guard fails the build if it appears anywhere else. It disappears
entirely once the app is Developer ID signed.

## Errors are copyable, and the GUI stops telling you to use the terminal

- Every banner and error block has a **Copy** button that puts the message *and* the daemon-start log
  tail on the clipboard, with a brief **Copied** confirmation.
- No GUI string suggests an `aevan`/`aevand` command any more. Where the GUI can do the thing, it does
  it; where it cannot, it says why.

## You no longer type a realm

On first connect with an empty realm, Aevan does one unauthenticated GET of the portal, reads the realm
from the sign-in form's hidden `realm` input (falling back to the `url_<realm>` path segment), stores
it, and reports `realm: … (detected)` once. No credentials are sent and no login attempt is spent. An
explicit `--realm` is never overwritten; failure names the fix instead of failing a login.

## Downloads

| OS | file |
|---|---|
| Windows 10/11 x64 | `aevan-0.2.12-x64.msi`, portable `aevan-0.2.12-x64.zip` |
| macOS 13+ | `aevan-0.2.12-arm64+x86_64.dmg` or `.pkg` |
| Linux x86_64 | `aevan-0.2.12-x86_64-linux.tar.gz`, `aevan_0.2.12_amd64.deb`, `aevan-0.2.12-1.x86_64.rpm` |

`SHA256SUMS.txt` covers every asset.

## Still unproven, stated plainly

- The macOS elevation fallback is **compile-checked only** — it has not been executed on Apple hardware
  by anyone in this build. That is the single most important thing to test on the next install.
- A full macOS or Linux tunnel; installers on a clean machine; the macOS window clicked by a human.
  `docs/PLATFORM-MATRIX.md` is generated from the code and evidence, and cannot drift from it.
