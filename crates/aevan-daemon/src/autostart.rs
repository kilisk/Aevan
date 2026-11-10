//! Per-user logon autostart.
//!
//! * **Windows:** the daemon is registered as a `HighestAvailable` Task
//!   Scheduler task, so the tunnel belongs to the logged-in user. Registering
//!   that task requires Administrator.
//! * **macOS:** a per-user LaunchAgent at
//!   `~/Library/LaunchAgents/com.github.kilisk.aevan.plist` starts `aevan-gui`
//!   at login with `RunAtLoad` and no `KeepAlive`.
//! * **Linux:** an XDG autostart entry at
//!   `~/.config/autostart/aevan.desktop` with `Exec=aevan-gui`.
//!
//! The macOS and Linux paths need no elevation. Their layout, payload and
//! state functions take an explicit home directory and executable so the whole
//! enable/disable/state cycle can be tested with a temporary directory and an
//! injected command runner on every build host.

use std::path::{Path, PathBuf};

use aevan_core::{AevanError, AevanResult};

/// Name of the scheduled task.
pub const TASK_NAME: &str = "Aevan";

/// Observed state of the autostart task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// `schtasks` reports the task.
    Present,
    /// `schtasks` reports that the task does not exist.
    Absent,
    /// `schtasks` ran but returned an unexpected result.
    Unknown,
}

/// The GUI login item used on the two Unix platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItem {
    /// `~/Library/LaunchAgents/com.github.kilisk.aevan.plist`
    MacOs,
    /// `~/.config/autostart/aevan.desktop`
    Linux,
}

/// Label and file stem of the macOS LaunchAgent.
pub const GUI_LABEL: &str = "com.github.kilisk.aevan";

/// A command runner used by the macOS login item.
///
/// Tests inject a recorder; production uses the real `launchctl`. The login
/// item is considered installed from its file, so a refused `launchctl` call
/// never turns a successful write into an error.
pub trait Runner {
    /// Run one command.
    fn run(&self, program: &Path, arguments: &[&str]) -> Result<(), String>;
}

/// The real process runner.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &Path, arguments: &[&str]) -> Result<(), String> {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .map_err(|error| format!("cannot run {}: {error}", program.display()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{} failed with {}: {}",
                program.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

/// Path of the GUI login item document.
pub fn login_item_path(item: LoginItem, home: &Path) -> PathBuf {
    match item {
        LoginItem::MacOs => home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{GUI_LABEL}.plist")),
        LoginItem::Linux => home.join(".config").join("autostart").join("aevan.desktop"),
    }
}

/// The exact document written for a GUI login item.
pub fn login_item_payload(item: LoginItem, executable: &Path) -> String {
    match item {
        LoginItem::MacOs => {
            let executable = xml_escape(&executable.to_string_lossy());
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{GUI_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
            )
        }
        LoginItem::Linux => {
            // The packaged GUI lives on PATH as `aevan-gui`, so use that
            // spelling; a renamed or portable binary keeps its full path.
            let executable =
                if executable.file_name().and_then(|name| name.to_str()) == Some("aevan-gui") {
                    "aevan-gui".to_owned()
                } else {
                    desktop_quote(executable)
                };
            format!(
                "[Desktop Entry]
Type=Application
Name=Aevan
Comment=Aevan VPN client
Exec={executable}
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
"
            )
        }
    }
}

/// Write the GUI login item and best-effort load it.
pub fn install_login_item(
    item: LoginItem,
    home: &Path,
    executable: &Path,
    runner: &dyn Runner,
) -> AevanResult<()> {
    let path = login_item_path(item, home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            AevanError::Config(format!(
                "cannot create the autostart directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&path, login_item_payload(item, executable)).map_err(|error| {
        AevanError::Config(format!(
            "cannot write the autostart entry {}: {error}",
            path.display()
        ))
    })?;
    if item == LoginItem::MacOs {
        let path_text = path.to_string_lossy();
        let _ = runner.run(Path::new("/bin/launchctl"), &["load", "-w", &path_text]);
    }
    Ok(())
}

/// Remove the GUI login item. A missing entry is already disabled.
pub fn remove_login_item(item: LoginItem, home: &Path, runner: &dyn Runner) -> AevanResult<()> {
    let path = login_item_path(item, home);
    if item == LoginItem::MacOs {
        let path_text = path.to_string_lossy();
        let _ = runner.run(Path::new("/bin/launchctl"), &["unload", "-w", &path_text]);
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AevanError::Config(format!(
            "cannot remove the autostart entry {}: {error}",
            path.display()
        ))),
    }
}

/// Report whether the GUI login item exists.
pub fn login_item_state(item: LoginItem, home: &Path) -> AevanResult<TaskState> {
    let path = login_item_path(item, home);
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(TaskState::Present),
        Ok(_) => Ok(TaskState::Unknown),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(TaskState::Absent),
        Err(error) => Err(AevanError::Config(format!(
            "cannot read the autostart entry {}: {error}",
            path.display()
        ))),
    }
}

fn desktop_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text
        .chars()
        .any(|character| character.is_whitespace() || "\"'\\`$".contains(character))
    {
        let escaped = text
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$");
        format!("\"{escaped}\"")
    } else {
        text.into_owned()
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn home_directory() -> AevanResult<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        AevanError::Config("HOME is not set; cannot locate the autostart directory".into())
    })?;
    Ok(PathBuf::from(home))
}

#[cfg_attr(windows, allow(dead_code))]
fn gui_executable() -> AevanResult<PathBuf> {
    let current = std::env::current_exe().map_err(|error| {
        AevanError::Config(format!("cannot locate the aevan-gui executable: {error}"))
    })?;
    let name = if cfg!(windows) {
        "aevan-gui.exe"
    } else {
        "aevan-gui"
    };
    if current.file_name().and_then(|file| file.to_str()) == Some(name) {
        return Ok(current);
    }
    if let Some(parent) = current.parent() {
        let sibling = parent.join(name);
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    Ok(current)
}

/// Build the Task Scheduler XML for `exe` and the principal `user`.
///
/// `user` is either a SID (`S-1-5-...`) or `DOMAIN\User`. Kept free of Win32
/// calls so the literal document can be tested on every host.
pub fn task_xml(exe: &Path, user: &str) -> String {
    let exe = exe.to_string_lossy();
    let working = exe
        .rsplit_once(['\\', '/'])
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.is_empty())
        .unwrap_or(".");
    let exe = xml_escape(&exe);
    let working = xml_escape(working);
    let user = xml_escape(user);

    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Aevan per-user tunnel daemon</Description>
    <URI>\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{exe}"</Command>
      <WorkingDirectory>{working}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#
    )
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(windows)]
pub fn install(user: Option<&str>) -> AevanResult<String> {
    imp::install(user)
}

#[cfg(target_os = "macos")]
pub fn install(_user: Option<&str>) -> AevanResult<String> {
    install_gui(LoginItem::MacOs).map(|()| GUI_LABEL.to_owned())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn install(_user: Option<&str>) -> AevanResult<String> {
    install_gui(LoginItem::Linux).map(|()| GUI_LABEL.to_owned())
}

#[cfg(not(any(windows, unix)))]
pub fn install(_user: Option<&str>) -> AevanResult<String> {
    Err(unsupported("installing the autostart task"))
}

#[cfg(windows)]
pub fn remove() -> AevanResult<()> {
    imp::remove()
}

#[cfg(target_os = "macos")]
pub fn remove() -> AevanResult<()> {
    remove_login_item(LoginItem::MacOs, &home_directory()?, &SystemRunner)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn remove() -> AevanResult<()> {
    remove_login_item(LoginItem::Linux, &home_directory()?, &SystemRunner)
}

#[cfg(not(any(windows, unix)))]
pub fn remove() -> AevanResult<()> {
    Err(unsupported("removing the autostart task"))
}

#[cfg(windows)]
pub fn status() -> AevanResult<TaskState> {
    imp::status()
}

#[cfg(target_os = "macos")]
pub fn status() -> AevanResult<TaskState> {
    login_item_state(LoginItem::MacOs, &home_directory()?)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn status() -> AevanResult<TaskState> {
    login_item_state(LoginItem::Linux, &home_directory()?)
}

#[cfg(not(any(windows, unix)))]
pub fn status() -> AevanResult<TaskState> {
    Err(unsupported("reading the autostart task"))
}

#[cfg(target_os = "macos")]
fn install_gui(item: LoginItem) -> AevanResult<()> {
    install_login_item(item, &home_directory()?, &gui_executable()?, &SystemRunner)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn install_gui(item: LoginItem) -> AevanResult<()> {
    install_login_item(item, &home_directory()?, &gui_executable()?, &SystemRunner)
}

#[cfg(not(any(windows, unix)))]
fn unsupported(action: &str) -> AevanError {
    AevanError::Unsupported(format!(
        "{action} is not implemented on this platform; this build has no login-item mechanism"
    ))
}

#[cfg(windows)]
mod imp {
    use std::process::{Command, Output};

    use aevan_core::{AevanError, AevanResult};
    use aevan_tun::{elevation, Elevation};

    use super::{task_xml, TaskState, TASK_NAME};

    const EXIT_ABSENT: i32 = 1;

    pub fn install(user: Option<&str>) -> AevanResult<String> {
        require_elevation("installing the per-user 'Aevan' logon task")?;

        let principal = resolve_principal(user)?;
        let exe = std::env::current_exe().map_err(|error| {
            AevanError::Io(std::io::Error::new(
                error.kind(),
                format!("cannot locate aevand.exe: {error}"),
            ))
        })?;
        let xml = task_xml(&exe, &principal);
        let path = std::env::temp_dir().join(format!(
            "aevan-autostart-{}-{}.xml",
            std::process::id(),
            principal.replace(['\\', ':'], "_")
        ));

        write_utf16(&path, &xml)?;
        let result = Command::new("schtasks")
            .args(["/Create", "/TN", TASK_NAME, "/XML"])
            .arg(&path)
            .arg("/F")
            .output();
        let _ = std::fs::remove_file(&path);

        let output = result.map_err(|error| {
            AevanError::Config(format!(
                "cannot run schtasks.exe to create the '{TASK_NAME}' task: {error}"
            ))
        })?;
        ensure_success(output, "create", &principal)?;

        if status()? != TaskState::Present {
            return Err(AevanError::Config(format!(
                "schtasks reported success but the '{TASK_NAME}' task is not present"
            )));
        }
        Ok(principal)
    }

    pub fn remove() -> AevanResult<()> {
        require_elevation("removing the per-user 'Aevan' logon task")?;

        if status()? == TaskState::Absent {
            return Ok(());
        }

        let output = Command::new("schtasks")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output()
            .map_err(|error| {
                AevanError::Config(format!(
                    "cannot run schtasks.exe to delete the '{TASK_NAME}' task: {error}"
                ))
            })?;

        if !output.status.success() && !looks_absent(&output) {
            return Err(failure("delete", &output));
        }

        match status()? {
            TaskState::Absent => Ok(()),
            other => Err(AevanError::Config(format!(
                "the '{TASK_NAME}' task still reports {other:?} after schtasks /Delete"
            ))),
        }
    }

    pub fn status() -> AevanResult<TaskState> {
        let output = Command::new("schtasks")
            .args(["/Query", "/TN", TASK_NAME])
            .output()
            .map_err(|error| {
                AevanError::Config(format!(
                    "cannot run schtasks.exe to query the '{TASK_NAME}' task: {error}"
                ))
            })?;

        if output.status.success() {
            Ok(TaskState::Present)
        } else if output.status.code() == Some(EXIT_ABSENT) || looks_absent(&output) {
            Ok(TaskState::Absent)
        } else {
            Ok(TaskState::Unknown)
        }
    }

    fn resolve_principal(user: Option<&str>) -> AevanResult<String> {
        match user {
            Some(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
            Some(_) => Err(AevanError::Config(
                "the installer supplied an empty user for the 'Aevan' logon task; \
                 run the MSI as the user who owns the tunnel"
                    .into(),
            )),
            None => crate::pipe_security::current_user_sid().map_err(|error| {
                AevanError::Config(format!(
                    "cannot read the current user SID for the '{TASK_NAME}' task: {error}"
                ))
            }),
        }
    }

    fn require_elevation(action: &str) -> AevanResult<()> {
        match elevation() {
            Elevation::Elevated => Ok(()),
            Elevation::NotElevated | Elevation::Unknown => Err(AevanError::Privilege(format!(
                "{action} requires Administrator (exit code 6). Registering a per-user task \
                 with HighestAvailable is an elevated operation; re-run from an elevated \
                 prompt. The task is not a service and runs aevand as your own user."
            ))),
        }
    }

    fn write_utf16(path: &std::path::Path, text: &str) -> AevanResult<()> {
        let mut bytes = Vec::with_capacity(2 + text.len() * 2);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(path, bytes).map_err(|error| {
            AevanError::Config(format!(
                "cannot write the temporary task definition {}: {error}",
                path.display()
            ))
        })
    }

    fn ensure_success(output: Output, action: &str, principal: &str) -> AevanResult<()> {
        if output.status.success() {
            Ok(())
        } else {
            let error = failure(action, &output);
            match error {
                AevanError::Privilege(message) => Err(AevanError::Privilege(format!(
                    "{message}; the task principal was {principal}"
                ))),
                other => Err(other),
            }
        }
    }

    fn failure(action: &str, output: &Output) -> AevanError {
        let detail = [&output.stdout, &output.stderr]
            .into_iter()
            .map(|bytes| String::from_utf8_lossy(bytes).trim().to_owned())
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
        let code = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_owned());
        let message =
            format!("schtasks failed to {action} the '{TASK_NAME}' task (exit {code}): {detail}");
        if detail.to_ascii_lowercase().contains("access is denied") {
            AevanError::Privilege(message)
        } else {
            AevanError::Config(message)
        }
    }

    fn looks_absent(output: &Output) -> bool {
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .to_ascii_lowercase();
        text.contains("cannot find")
            || text.contains("does not exist")
            || text.contains("not found")
            || text.contains("no such")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use super::*;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::time::{SystemTime, UNIX_EPOCH};

            static NEXT: AtomicU64 = AtomicU64::new(0);
            let unique = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "aevan-autostart-{label}-{}-{nanos}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Default)]
    struct RecordingRunner {
        calls: RefCell<Vec<String>>,
    }

    impl RecordingRunner {
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Runner for RecordingRunner {
        fn run(&self, program: &Path, arguments: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("{} {}", program.display(), arguments.join(" ")));
            Ok(())
        }
    }

    #[test]
    fn xml_escaping_covers_the_five_markup_characters() {
        assert_eq!(
            xml_escape(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn task_xml_is_a_per_user_highest_logon_task() {
        let xml = task_xml(
            Path::new(r"C:\Program Files\aevan\aevand.exe"),
            r"S-1-5-21-100-200-300-1001",
        );

        assert!(xml.contains("<URI>\\Aevan</URI>"));
        assert!(xml.contains(r"<UserId>S-1-5-21-100-200-300-1001</UserId>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<Command>\"C:\\Program Files\\aevan\\aevand.exe\"</Command>"));
        assert!(xml.contains("<WorkingDirectory>C:\\Program Files\\aevan</WorkingDirectory>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(!xml.contains("<Service"));
    }

    #[test]
    fn task_xml_escapes_the_install_path_and_user() {
        let xml = task_xml(Path::new(r"C:\Tools & More\aevand.exe"), r"DOMAIN\a&b");
        assert!(xml.contains("C:\\Tools &amp; More\\aevand.exe"));
        assert!(xml.contains("<UserId>DOMAIN\\a&amp;b</UserId>"));
    }

    #[test]
    fn the_msi_defaults_start_at_login_on() {
        let wxs = include_str!("../../../packaging/windows/aevan.wxs");
        assert!(
            wxs.contains(r#"<Property Id="INSTALL_AUTOSTART" Value="1" />"#),
            "a fresh MSI install must leave the per-user logon task enabled"
        );
        assert!(
            wxs.contains(r#"Target="[INSTALLFOLDER]aevan.exe""#),
            "the Start menu shortcut must invoke the launcher"
        );
    }

    #[test]
    fn macos_login_item_enables_disables_and_reports_state() {
        let home = TempDir::new("macos-login");
        let executable = Path::new("/Applications/Aevan.app/Contents/MacOS/aevan-gui");
        let runner = RecordingRunner::default();

        assert_eq!(
            login_item_state(LoginItem::MacOs, home.path()).expect("state"),
            TaskState::Absent
        );
        install_login_item(LoginItem::MacOs, home.path(), executable, &runner).expect("install");

        let path = login_item_path(LoginItem::MacOs, home.path());
        assert!(path.ends_with("Library/LaunchAgents/com.github.kilisk.aevan.plist"));
        let plist = std::fs::read_to_string(&path).expect("read plist");
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains(GUI_LABEL));
        assert!(plist.contains("RunAtLoad"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("KeepAlive"));
        assert!(plist.contains("<false/>"));
        assert!(plist.contains(executable.to_string_lossy().as_ref()));

        assert_eq!(
            login_item_state(LoginItem::MacOs, home.path()).expect("state"),
            TaskState::Present
        );
        assert!(runner
            .calls()
            .iter()
            .any(|call| call.contains("launchctl load -w")));

        remove_login_item(LoginItem::MacOs, home.path(), &runner).expect("remove");
        assert_eq!(
            login_item_state(LoginItem::MacOs, home.path()).expect("state"),
            TaskState::Absent
        );
        assert!(runner
            .calls()
            .iter()
            .any(|call| call.contains("launchctl unload -w")));
    }

    #[test]
    fn linux_login_item_uses_the_xdg_autostart_entry() {
        let home = TempDir::new("linux-login");
        let executable = Path::new("/usr/bin/aevan-gui");
        let runner = RecordingRunner::default();

        assert_eq!(
            login_item_state(LoginItem::Linux, home.path()).expect("state"),
            TaskState::Absent
        );
        install_login_item(LoginItem::Linux, home.path(), executable, &runner).expect("install");

        let path = login_item_path(LoginItem::Linux, home.path());
        assert!(path.ends_with(".config/autostart/aevan.desktop"));
        let entry = std::fs::read_to_string(&path).expect("read desktop entry");
        assert!(entry.contains("[Desktop Entry]"));
        assert!(entry.contains("Type=Application"));
        assert!(entry.contains("Exec=aevan-gui"));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"));

        assert_eq!(
            login_item_state(LoginItem::Linux, home.path()).expect("state"),
            TaskState::Present
        );
        remove_login_item(LoginItem::Linux, home.path(), &runner).expect("remove");
        assert_eq!(
            login_item_state(LoginItem::Linux, home.path()).expect("state"),
            TaskState::Absent
        );
    }

    #[test]
    fn login_item_payloads_escape_spaces_and_markup() {
        let mac = login_item_payload(
            LoginItem::MacOs,
            Path::new("/Applications/Aevan & Co.app/Contents/MacOS/aevan-gui"),
        );
        assert!(mac.contains("Aevan &amp; Co.app"));
        assert!(!mac.contains("Aevan & Co.app"));

        let linux = login_item_payload(LoginItem::Linux, Path::new("/opt/Aevan Tools/Aevan"));
        assert!(linux.contains("Exec=\"/opt/Aevan Tools/Aevan\""));
    }
}
