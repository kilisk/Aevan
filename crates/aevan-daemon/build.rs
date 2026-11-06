//! Embed the Aevan icon, VERSIONINFO block and application manifest into the
//! Windows executable.
//!
//! `winresource` is a build-dependency only: it runs at build time for Windows
//! targets and is never linked into the binary. Every other target, including
//! the macOS and Linux release builds, skips this entirely.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let icon = absolute(&root.join("assets/branding/Aevan-1024.ico"));
    let manifest = absolute(&root.join("packaging/windows/aevand.manifest"));
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", manifest.display());

    let version = env!("CARGO_PKG_VERSION");
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(&icon.display().to_string());
    resource.set_manifest_file(&manifest.display().to_string());
    resource
        .set("CompanyName", "Aevan contributors")
        .set("ProductName", "Aevan")
        .set("FileDescription", "Aevan daemon")
        .set("FileVersion", version)
        .set("ProductVersion", version)
        .set("LegalCopyright", "Copyright (c) Aevan contributors")
        .set("OriginalFilename", "aevand.exe");
    resource
        .compile()
        .expect("failed to embed resources into the Windows executable");
}

fn absolute(path: &std::path::Path) -> std::path::PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}
