# CI

The workflow is [.github/workflows/ci.yml](../.github/workflows/ci.yml). It
runs on every push and pull request.

## Jobs

| Job | Runner | What it proves |
| --- | --- | --- |
| `platform-matrix` | `ubuntu-latest` | The committed capability matrix is current and every platform difference has a gap entry. It does not build Rust. |
| `test (ubuntu-latest)` | `ubuntu-latest` | Formatting, clippy, the workspace tests, a release build, a real `/dev/net/tun` smoke run, and the Linux packages. |
| `test (windows-latest)` | `windows-latest` | Formatting, clippy, the workspace tests, a release build, and the Windows packages. |
| `test (macos-latest)` | `macos-latest` | Formatting, clippy, the workspace tests, the cross-UID control-socket check, and the `utun` smoke run. |

## Platform invariant

A new capability must land on all three platforms or carry a gap entry. In
practice, add the capability to `crates/aevan-core/src/capabilities.rs`, land its
modules for Windows, macOS and Linux, and run
`python scripts/platform-matrix.py`. If one platform is a stub or is
deliberately absent while another platform is implemented, add a matching
`[[gap]]` entry to `docs/platform-gaps.toml` with a reason and either an
`owner_note` or a `tracking_note`. `platform-matrix` fails with the capability
and platform named when that entry is missing.

The matrix's `Verified` column is not a code claim. It is read only from
`docs/platform-evidence.toml`; `compile-only` means the capability compiles for
that OS but nobody has run it there.

## Required checks

Configure branch protection for `main` in **Settings > Branches > Branch
protection rules** and require these status checks:

- `platform-matrix`
- `test (ubuntu-latest)`
- `test (windows-latest)`
- `test (macos-latest)`
- `package (windows-x64)`
- `package (macos-universal)`
- `package (linux-x64)`

`platform-matrix` is deliberately first and fast so an OS drift fails before the
longer build matrix starts.
