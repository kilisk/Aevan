//! Embed the Aevan icon, VERSIONINFO block and application manifest into the
//! Windows executable.
//!
//! `winresource` is a build-dependency only: it runs at build time for Windows
//! targets and is never linked into the binary. The GUI manifest adds DPI
//! awareness for high-density displays. Every other target, including the macOS
//! and Linux release builds, skips this entirely.

fn main() {
    generate_template_icon();

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let icon = absolute(&root.join("assets/branding/Aevan-1024.ico"));
    let manifest = absolute(&root.join("packaging/windows/aevan-gui.manifest"));
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", manifest.display());

    let version = env!("CARGO_PKG_VERSION");
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(&icon.display().to_string());
    resource.set_manifest_file(&manifest.display().to_string());
    resource
        .set("CompanyName", "Aevan contributors")
        .set("ProductName", "Aevan")
        .set("FileDescription", "Aevan GUI")
        .set("FileVersion", version)
        .set("ProductVersion", version)
        .set("LegalCopyright", "Copyright (c) Aevan contributors")
        .set("OriginalFilename", "aevan-gui.exe");
    resource
        .compile()
        .expect("failed to embed resources into the Windows executable");
}

/// Render the menu-bar template from the colour artwork.
///
/// macOS renders a template image from its alpha channel only. The asset is a
/// 36x36 RGBA PNG (18x18 points at 2x) with black pixels whose alpha is the
/// thresholded source alpha, so the status item shows the Aevan glyph instead
/// of an opaque white square. The existing `png` crate is used; no image tool
/// is required at build time.
fn generate_template_icon() {
    const TEMPLATE: usize = 36;

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("assets/aevan.png");
    let destination = manifest.join("assets/aevan-template.png");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", destination.display());

    let Ok(bytes) = std::fs::read(&source) else {
        return;
    };
    let Ok(template) = render_template(&bytes, TEMPLATE) else {
        return;
    };
    if std::fs::read(&destination).ok().as_deref() == Some(template.as_slice()) {
        return;
    }
    let _ = std::fs::write(&destination, template);
}

fn render_template(bytes: &[u8], size: usize) -> Result<Vec<u8>, ()> {
    use std::io::Cursor;

    let mut reader = png::Decoder::new(Cursor::new(bytes))
        .read_info()
        .map_err(|_| ())?;
    let mut buffer = vec![0; reader.output_buffer_size().ok_or(())?];
    let info = reader.next_frame(&mut buffer).map_err(|_| ())?;
    let width = info.width as usize;
    let height = info.height as usize;
    let channels = match info.color_type {
        png::ColorType::Rgba => 4,
        png::ColorType::Rgb => 3,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Grayscale => 1,
        png::ColorType::Indexed => return Err(()),
    };
    let alpha_at = |x: usize, y: usize| -> u8 {
        let pixel = (y * width + x) * channels;
        match info.color_type {
            png::ColorType::Rgba => buffer[pixel + 3],
            png::ColorType::GrayscaleAlpha => buffer[pixel + 1],
            png::ColorType::Rgb | png::ColorType::Grayscale => 255,
            png::ColorType::Indexed => 0,
        }
    };

    let mut pixels = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let x0 = x * width / size;
            let x1 = ((x + 1) * width / size).max(x0 + 1).min(width);
            let y0 = y * height / size;
            let y1 = ((y + 1) * height / size).max(y0 + 1).min(height);
            let mut total = 0u32;
            let mut count = 0u32;
            for sy in y0..y1 {
                for sx in x0..x1 {
                    total += u32::from(alpha_at(sx, sy));
                    count += 1;
                }
            }
            let alpha = total.checked_div(count).unwrap_or(0);
            let index = (y * size + x) * 4;
            pixels[index] = 0;
            pixels[index + 1] = 0;
            pixels[index + 2] = 0;
            pixels[index + 3] = if alpha >= 128 { 255 } else { 0 };
        }
    }

    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut output, size as u32, size as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| ())?;
        writer.write_image_data(&pixels).map_err(|_| ())?;
    }
    Ok(output)
}

fn absolute(path: &std::path::Path) -> std::path::PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}
