//! Embed the Aevan icon, VERSIONINFO block and application manifest into the
//! Windows executable.
//!
//! `winresource` is a build-dependency only: it runs at build time for Windows
//! targets and is never linked into the binary. Every other target, including
//! the macOS and Linux release builds, skips this entirely.

fn main() {
    emit_build_metadata();
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

fn emit_build_metadata() {
    let seconds = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=AEVAN_BUILD_DATE={}", utc_date(seconds));
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=AEVAN_BUILD_COMMIT={commit}");
}

fn utc_date(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
