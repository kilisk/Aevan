//! One application log per process, with a single persisted verbosity.
//!
//! Every binary writes to the platform log directory (macOS
//! `~/Library/Logs/Aevan`, Linux `$XDG_STATE_HOME/aevan/log`, Windows
//! `%LOCALAPPDATA%\Aevan\logs`). Files rotate at 5 MiB and three generations are
//! kept. The directory is owner-only (0700) and each file is owner-only (0600)
//! on Unix.
//!
//! The verbosity is one setting shared by `aevan`, `aevand` and `aevan-gui`.
//! `RUST_LOG` overrides it for one run, and the GUI can change it at runtime.
//! The same records are mirrored to the platform's developer log: the macOS
//! unified log through `os_log`, Linux stderr when it is a terminal, and
//! Windows `OutputDebugString` when a debugger is attached.
//!
//! No credential is ever passed to this module: sensitive field names are
//! redacted before a record is formatted, matching the daemon's control-log
//! redaction.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::{Context, Identity};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, Layer, Registry};

use crate::paths;

/// Maximum size of one log file before it rotates.
pub const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Number of files kept for one process, including the current one.
pub const KEPT_LOG_FILES: usize = 3;

/// Number of trailing lines copied by the About block's diagnostics action.
pub const DIAGNOSTIC_LINES: usize = 50;

/// Subsystem shown by Console.app on macOS.
pub const OSLOG_SUBSYSTEM: &str = "com.github.kilisk.aevan";

/// The verbosity setting shared by every binary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and above.
    Warn,
    /// Informational and above.
    #[default]
    Info,
    /// Debug and above.
    Debug,
    /// Everything, including trace.
    Trace,
}

impl LogLevel {
    /// Every level in display order, for the Settings dropdown.
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// The spelling used by `RUST_LOG`, the settings file and the protocol.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parse a level, accepting `warning` and falling back to `info`.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => Self::Info,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SettingsDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    log_level: Option<LogLevel>,
}

/// The persisted verbosity, or `info` when no settings file exists.
pub fn configured_level() -> LogLevel {
    settings_path()
        .as_deref()
        .and_then(settings_level)
        .unwrap_or_default()
}

fn settings_level(path: &Path) -> Option<LogLevel> {
    if is_root() && !trusted_file(path).ok()? {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    toml::from_str::<SettingsDocument>(&text)
        .ok()
        .and_then(|document| document.log_level)
}

/// Persist the verbosity for every binary.
fn save_level_at(path: &Path, level: LogLevel) -> crate::AevanResult<()> {
    if let Some(parent) = path.parent() {
        if is_root() {
            trusted_directory(parent)?;
        } else {
            fs::create_dir_all(parent)?;
        }
    }
    let document = SettingsDocument {
        log_level: Some(level),
    };
    let text = toml::to_string(&document).map_err(|error| {
        crate::AevanError::Config(format!("cannot serialise settings: {error}"))
    })?;
    let temporary = path.with_extension(format!("{}-{}.tmp", std::process::id(), now_millis()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    private_options(&mut options);
    let mut file = options.open(&temporary)?;
    let result = file.write_all(text.as_bytes());
    drop(file);
    if let Err(error) = result.and_then(|()| fs::rename(&temporary, path)) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

/// Platform log directory, or `None` when the home directory is unavailable.
pub fn log_dir() -> Option<PathBuf> {
    if is_root() {
        return system_log_dir();
    }
    platform_log_dir()
}

#[cfg(target_os = "macos")]
fn platform_log_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Logs/Aevan"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_log_dir() -> Option<PathBuf> {
    if let Some(state) = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Some(state.join("aevan/log"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/state/aevan/log"))
}

#[cfg(target_os = "windows")]
fn platform_log_dir() -> Option<PathBuf> {
    Some(windows::known_folder(&windows::FOLDERID_LocalAppData)?.join("Aevan/logs"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn platform_log_dir() -> Option<PathBuf> {
    None
}

/// Full path of one binary's log file (`<log_dir>/<binary>.log`).
pub fn log_path(binary: &str) -> Option<PathBuf> {
    log_dir().map(|dir| dir.join(format!("{binary}.log")))
}

/// Trusted, system-owned log directory for a privileged daemon.
///
/// This never consults `HOME` or
/// `XDG_STATE_HOME`: a root process must not follow a path an unprivileged
/// caller can choose.
pub fn system_log_dir() -> Option<PathBuf> {
    platform_system_log_dir()
}

#[cfg(target_os = "macos")]
fn platform_system_log_dir() -> Option<PathBuf> {
    Some(PathBuf::from("/Library/Logs/Aevan"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_system_log_dir() -> Option<PathBuf> {
    Some(PathBuf::from("/var/log/aevan"))
}

#[cfg(not(unix))]
fn platform_system_log_dir() -> Option<PathBuf> {
    None
}

/// Trusted settings path for a privileged daemon.
///
/// The GUI still writes the per-user setting; a root daemon reads a
/// system-owned file and defaults to `info` when that file is absent.
#[cfg(target_os = "macos")]
pub fn system_settings_path() -> Option<PathBuf> {
    Some(PathBuf::from(
        "/Library/Application Support/Aevan/settings.toml",
    ))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn system_settings_path() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/aevan/settings.toml"))
}

#[cfg(not(unix))]
pub fn system_settings_path() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn settings_path() -> Option<PathBuf> {
    Some(
        windows::known_folder(&windows::FOLDERID_RoamingAppData)?
            .join("aevan")
            .join(paths::SETTINGS_FILE),
    )
}

#[cfg(not(windows))]
fn settings_path() -> Option<PathBuf> {
    if is_root() {
        system_settings_path()
    } else {
        paths::default_settings_path().ok()
    }
}

/// Configure application tracing. `RUST_LOG` overrides the saved level;
/// the CLI's `--verbose` raises the saved level to at least debug for one run.
pub fn init(binary: &'static str, verbose: bool) {
    init_with(binary, verbose, Identity::new());
}

type ReloadLevel = Box<dyn Fn(LogLevel) + Send + Sync>;
static RELOAD_LEVEL: OnceLock<ReloadLevel> = OnceLock::new();
static ENV_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// Whether a valid `RUST_LOG` filter takes precedence for this process.
pub fn has_env_override() -> bool {
    ENV_OVERRIDE.load(Ordering::Relaxed)
}

/// Install the application log and an additional consumer (e.g. daemon history).
pub fn init_with<L>(binary: &'static str, verbose: bool, extra: L)
where
    L: Layer<Registry> + Send + Sync + 'static,
{
    let override_filter = EnvFilter::try_from_default_env().ok();
    let overridden = override_filter.is_some();
    ENV_OVERRIDE.store(overridden, Ordering::Relaxed);
    let level = configured_level();
    let filter = override_filter.unwrap_or_else(|| {
        EnvFilter::new(if verbose && level != LogLevel::Trace {
            "debug"
        } else {
            level.as_str()
        })
    });
    let (filter, handle) = reload::Layer::new(filter);
    let path = log_path(binary);
    let layer = AppLogLayer {
        path,
        binary,
        reported_io_error: Default::default(),
    };
    if tracing_subscriber::registry()
        .with(extra)
        .with(layer)
        .with(filter)
        .try_init()
        .is_ok()
        && !overridden
    {
        let _ = RELOAD_LEVEL.set(Box::new(move |level| {
            let _ = handle.reload(EnvFilter::new(level.as_str()));
        }));
    }
}

/// Change the level of the running process and persist it for every binary.
pub fn set_runtime_level(level: LogLevel) -> crate::AevanResult<()> {
    let path = settings_path()
        .ok_or_else(|| crate::AevanError::Config("log settings path unavailable".into()))?;
    save_level_at(&path, level)?;
    if let Some(reload) = RELOAD_LEVEL.get() {
        reload(level);
    }
    Ok(())
}

/// Log the startup facts that make a bug report actionable.
pub fn log_startup(binary: &str, version: &str, build_date: &str, build_commit: &str) {
    let path = log_path(binary);
    let executable = std::env::current_exe().ok().map(|path| canonicalize(&path));
    let bundle = executable.as_deref().and_then(bundle_root_from);
    tracing::info!(
        binary,
        version,
        build_date,
        build_commit,
        bundle = %display_path(bundle.as_deref()),
        executable = %display_path(executable.as_deref()),
        log_path = %display_path(path.as_deref()),
        pid = std::process::id(),
        "startup"
    );
}

/// Last `count` lines of one binary's log, oldest first, across rotations.
pub fn tail(binary: &str, count: usize) -> Vec<String> {
    log_path(binary)
        .map(|path| tail_path(&path, count))
        .unwrap_or_default()
}

/// The tracing layer installed by [`init`].
struct AppLogLayer {
    path: Option<PathBuf>,
    binary: &'static str,
    reported_io_error: std::sync::atomic::AtomicBool,
}

impl<S: Subscriber> Layer<S> for AppLogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let Some(body) = diagnostic_event(event) else {
            return;
        };
        let line = format_record(event.metadata(), &body).replace(['\r', '\n', '\0'], " ");
        if let Some(path) = &self.path {
            if let Err(error) = append_line(path, &line) {
                if !self
                    .reported_io_error
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    let message = format!(
                        "{}: cannot write log {}: {error}",
                        self.binary,
                        path.display()
                    );
                    mirror(self.binary, &tracing::Level::WARN, &message);
                }
            }
        }
        mirror(self.binary, event.metadata().level(), &line);
    }
}

/// Render only application-owned events. Dependency debug output is not a
/// diagnostic surface, even when RUST_LOG enables it.
pub fn diagnostic_event(event: &Event<'_>) -> Option<String> {
    if !event.metadata().target().starts_with("aevan") {
        return None;
    }
    let mut visitor = Visitor::default();
    event.record(&mut visitor);
    Some(visitor.render())
}

fn format_record(metadata: &Metadata<'_>, body: &str) -> String {
    format!(
        "{} {} {} {}",
        utc_timestamp_millis(now_millis()),
        metadata.level(),
        metadata.target(),
        body
    )
}

fn display_path(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn canonicalize(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn bundle_root_from(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|ancestor| ancestor.join("Contents/Info.plist").is_file())
        .map(Path::to_path_buf)
}

fn append_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        prepare_directory(parent)?;
    }
    // Keep even a malformed/overlong event within the rotation budget.
    let end = line.floor_char_boundary(line.len().min(16 * 1024));
    let mut bytes = line.as_bytes()[..end].to_vec();
    bytes.push(b'\n');
    // Separate inode: the lock stays put while the log is renamed. This also
    // serializes concurrent CLI invocations that share a binary log.
    let lock = open_private(&path.with_extension("log.lock"))?;
    lock.lock()?;
    if is_root() {
        for candidate in [path.to_path_buf(), rotated(path, 1), rotated(path, 2)] {
            trusted_file(&candidate)?;
        }
    }
    rotate_if_needed(path, bytes.len() as u64)?;
    open_private(path)?.write_all(&bytes)
}

fn open_private(path: &Path) -> io::Result<fs::File> {
    if is_root() {
        trusted_file(path)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true).read(true);
    private_options(&mut options);
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    let _ = options;
}

/// Create the application's log directory, using owner-only Unix modes.
pub fn prepare_directory(path: &Path) -> io::Result<()> {
    if is_root() {
        trusted_directory(path)?;
    } else {
        private_directory(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(unix)]
fn check_ancestors(path: &Path, create: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "system path must be absolute",
        ));
    }
    let ancestors: Vec<_> = path.ancestors().collect();
    for ancestor in ancestors.into_iter().rev() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                private_directory(ancestor)?;
                fs::symlink_metadata(ancestor)?
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("untrusted system directory {}", ancestor.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_directory(path: &Path) -> io::Result<()> {
    check_ancestors(path, true)
}

#[cfg(unix)]
fn trusted_file(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "system path has no parent"))?;
    check_ancestors(parent, false)?;
    match fs::symlink_metadata(path) {
        Ok(meta)
            if meta.is_file()
                && meta.uid() == 0
                && meta.mode() & 0o022 == 0
                && meta.nlink() == 1 =>
        {
            Ok(true)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted system file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn trusted_directory(path: &Path) -> io::Result<()> {
    private_directory(path)
}

#[cfg(not(unix))]
fn trusted_file(path: &Path) -> io::Result<bool> {
    path.try_exists()
}

fn rotate_if_needed(path: &Path, incoming: u64) -> io::Result<()> {
    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    if size == 0 || size.saturating_add(incoming) <= MAX_LOG_BYTES {
        return Ok(());
    }
    let last = KEPT_LOG_FILES.saturating_sub(1);
    remove_if_present(&rotated(path, last))?;
    for index in (1..last).rev() {
        let from = rotated(path, index);
        if from.exists() {
            fs::rename(&from, rotated(path, index + 1))?;
        }
    }
    fs::rename(path, rotated(path, 1))
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn rotated(path: &Path, index: usize) -> PathBuf {
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(format!(".{index}"));
    path.with_file_name(name)
}

fn tail_path(path: &Path, count: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for path in
        std::iter::once(path.to_path_buf()).chain((1..KEPT_LOG_FILES).map(|i| rotated(path, i)))
    {
        if lines.len() == count {
            break;
        }
        if is_root() && !trusted_file(&path).unwrap_or(false) {
            continue;
        }
        let Ok(file) = fs::File::open(path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file.take(MAX_LOG_BYTES).read_to_end(&mut bytes).is_ok() {
            lines.extend(
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .rev()
                    .take(count - lines.len())
                    .map(str::to_owned),
            );
        }
    }
    lines.reverse();
    lines
}

#[derive(Default)]
struct Visitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visitor {
    fn push(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = value;
        } else if crate::redact::is_sensitive_key(name) {
            self.fields
                .push((name.to_owned(), crate::redact::REDACTED.to_owned()));
        } else {
            self.fields.push((name.to_owned(), value));
        }
    }

    fn render(&self) -> String {
        if self.fields.is_empty() {
            return self.message.clone();
        }
        let fields = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        if self.message.is_empty() {
            fields
        } else {
            format!("{} {fields}", self.message)
        }
    }
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), value.to_string());
    }
}

fn mirror(binary: &str, level: &tracing::Level, line: &str) {
    let _ = (binary, level, line);
    #[cfg(target_os = "macos")]
    {
        static LOG: OnceLock<oslog::OsLog> = OnceLock::new();
        let level = match *level {
            tracing::Level::ERROR => oslog::Level::Fault,
            tracing::Level::WARN => oslog::Level::Error,
            tracing::Level::INFO => oslog::Level::Default,
            tracing::Level::DEBUG => oslog::Level::Info,
            tracing::Level::TRACE => oslog::Level::Debug,
        };
        LOG.get_or_init(|| oslog::OsLog::new(OSLOG_SUBSYSTEM, binary))
            .with_level(level, line);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::io::IsTerminal;
        if std::io::stderr().is_terminal() {
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
    }

    #[cfg(windows)]
    windows::debug_output(line);
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, ptr};
    use windows_sys::core::GUID;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Diagnostics::Debug::{IsDebuggerPresent, OutputDebugStringW};
    pub(super) use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_RoamingAppData,
    };
    use windows_sys::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_DEFAULT_PATH};

    pub(super) fn known_folder(id: &GUID) -> Option<PathBuf> {
        let mut path = ptr::null_mut();
        // SAFETY: out pointer is writable; the null token selects the current account.
        let result = unsafe {
            SHGetKnownFolderPath(id, KF_FLAG_DEFAULT_PATH as u32, ptr::null_mut(), &mut path)
        };
        if path.is_null() {
            return None;
        }
        // SAFETY: Windows returns a NUL-terminated UTF-16 allocation on success.
        let value = (result >= 0).then(|| unsafe {
            let len = (0..).take_while(|i| *path.add(*i) != 0).count();
            PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, len)))
        });
        // SAFETY: the output must be freed with CoTaskMemFree.
        unsafe { CoTaskMemFree(path.cast()) };
        value
    }

    pub(super) fn debug_output(line: &str) {
        // SAFETY: IsDebuggerPresent has no preconditions.
        if unsafe { IsDebuggerPresent() } == 0 {
            return;
        }
        let text: Vec<_> = line.encode_utf16().chain([b'\n' as u16, 0]).collect();
        // SAFETY: `text` is NUL-terminated and held for the duration of the
        // call; OutputDebugString only reads it.
        unsafe { OutputDebugStringW(text.as_ptr()) };
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for Unix milliseconds, without a date crate.
fn utc_timestamp_millis(millis: u64) -> String {
    let seconds = millis / 1_000;
    let days = (seconds / 86_400) as i64;
    let remainder = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = remainder / 3_600;
    let minute = (remainder % 3_600) / 60;
    let second = remainder % 60;
    let millis = millis % 1_000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
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
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn temp_path() -> PathBuf {
        let unique = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "aevan-logging-test-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join("aevan.log")
    }

    #[test]
    fn levels_parse_display_and_default() {
        assert_eq!(LogLevel::parse("WARNING"), LogLevel::Warn);
        assert_eq!(LogLevel::parse("debug"), LogLevel::Debug);
        assert_eq!(LogLevel::parse("nonsense"), LogLevel::Info);
        assert_eq!(LogLevel::default(), LogLevel::Info);
        assert_eq!(LogLevel::ALL[4].as_str(), "trace");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn a_line_is_appended_and_tail_returns_the_last_lines() {
        let path = temp_path();
        for index in 0..5 {
            append_line(&path, &format!("line {index}")).expect("write");
        }
        let lines = tail_path(&path, 3);
        assert_eq!(lines, vec!["line 2", "line 3", "line 4"]);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn missing_files_tail_to_an_empty_list() {
        let path = temp_path();
        assert!(tail_path(&path, 10).is_empty());
    }

    #[test]
    fn rotation_keeps_three_files_and_moves_the_current_one() {
        let path = temp_path();
        let dir = path.parent().expect("parent").to_path_buf();
        fs::create_dir_all(&dir).expect("dir");
        for n in 0..3 {
            fs::write(&path, format!("generation {n}\n")).expect("seed file");
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open")
                .set_len(MAX_LOG_BYTES)
                .expect("full file");
            append_line(&path, "new line").expect("rotate");
        }
        assert_eq!(fs::read_to_string(&path).expect("current"), "new line\n");
        assert!(fs::read(rotated(&path, 1))
            .expect("newest archive")
            .starts_with(b"generation 2\n"));
        assert!(fs::read(rotated(&path, 2))
            .expect("oldest archive")
            .starts_with(b"generation 1\n"));
        assert!(!rotated(&path, 3).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path();
        append_line(&path, "private").expect("write");
        let dir_mode = fs::metadata(path.parent().expect("parent"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn a_sensitive_field_is_redacted_before_formatting() {
        let mut visitor = Visitor::default();
        visitor.push("message", "connect".to_owned());
        visitor.push("password", "hunter2".to_owned());
        visitor.push("profile", "example".to_owned());
        let rendered = visitor.render();
        assert!(rendered.contains("password=[REDACTED]"), "{rendered}");
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("profile=example"));
    }

    #[test]
    fn settings_round_trip_and_reload_changes_existing_callsites() {
        let path = temp_path();
        let settings = path.with_file_name("settings.toml");
        assert_eq!(settings_level(&settings), None);
        save_level_at(&settings, LogLevel::Warn).expect("save warn");
        assert_eq!(settings_level(&settings), Some(LogLevel::Warn));
        let (filter, handle) = reload::Layer::new(EnvFilter::new("warn"));
        let subscriber = tracing_subscriber::registry()
            .with(AppLogLayer {
                path: Some(path.clone()),
                binary: "aevan-test",
                reported_io_error: Default::default(),
            })
            .with(filter);
        let emit = || {
            tracing::debug!(
                password = "marker-password",
                request_body = "marker-body",
                "test event"
            )
        };
        tracing::subscriber::with_default(subscriber, || {
            emit();
            assert!(!path.exists());
            save_level_at(&settings, LogLevel::Debug).expect("save debug");
            let level = settings_level(&settings).expect("read debug");
            handle
                .reload(EnvFilter::new(level.as_str()))
                .expect("reload");
            tracing::warn!(target: "dependency", "marker-raw-request");
            emit();
        });
        let lines = tail_path(&path, 50);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("password=[REDACTED] request_body=[REDACTED]"));
        assert!(!lines[0].contains("marker-"));
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[cfg(unix)]
    #[test]
    fn privileged_paths_reject_untrusted_locations() {
        let path = temp_path();
        assert_eq!(
            trusted_directory(&path)
                .expect_err("refuse temp directory")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn timestamps_are_utc_with_milliseconds() {
        assert_eq!(utc_timestamp_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            utc_timestamp_millis(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z"
        );
    }
}
