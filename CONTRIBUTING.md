# Contributing to Aevan

Thanks for helping. Aevan is a clean-room client, so correctness and provenance
matter more than speed.

## Build prerequisites

- A stable Rust toolchain (rustup). The workspace declares its minimum Rust
  version in `Cargo.toml`.
- A C toolchain and linker for your platform:
  - Windows: Visual Studio Build Tools with **Desktop development with C++**
    (MSVC).
  - macOS: Xcode Command Line Tools.
  - Linux: `build-essential` and `pkg-config`.
- [`just`](https://github.com/casey/just) for the workspace recipes (optional but
  used by CI).
- Packaging only: WiX Toolset v7 and the .NET SDK on Windows, `pkgbuild` /
  `productbuild` on macOS, and `cargo` targets for the architectures you build.

```sh
cargo build
cargo test --workspace
```

## The four gates

Every change must pass all four before review:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

The suite currently reports **352 passing tests and 1 ignored test**. Do not
weaken or delete a test to get green; explain a platform skip in the PR.

## Authentication rule

Exactly **one authentication attempt per `connect` or `login` invocation**.
Never add a retry loop, an automatic fallback account, or a second password
prompt. Repeated failures can lock a corporate account. Tests must not perform a
live login; stand up offline fixtures or a local scripted transport instead.

## No secrets in tests

Never commit real credentials, TOTP secrets, session cookies, private keys or
captured traffic. Use placeholders such as `example_user`, `example_realm` and
`hunter2`, and prefer synthetic fixtures over captured pages. Say clearly in a
fixture header whether it is synthetic.

## Protocol work

Anchor every protocol change to documentation or the openly available reference
implementation (for example openconnect, read for wire layout, with our own
code). Do not guess field meanings, magic numbers or fallback behaviour. If
something is unknown, encode the uncertainty explicitly and add a test for the
unknown case rather than inventing a value. Record the source you relied on in
the commit message.

## Commits

Keep commits focused: one concern per commit. Run the four gates locally before
pushing. Do not commit build output under `target/`.
