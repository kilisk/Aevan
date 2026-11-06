//! Per-user logon autostart for `aevand`, implemented with Task Scheduler.
//!
//! The tunnel belongs to the logged-in user: profiles and the crash journal
//! live under that user's `%APPDATA%\aevan`. A machine-wide LocalSystem service
//! would read SYSTEM's profile store instead, so the daemon is registered as a
//! per-user task that starts at that user's logon with `HighestAvailable`.
//!
//! The task is registered by name (`Aevan`) with the installing user's SID, so
//! it is idempotent and can be removed without needing the original command
//! line. Registering a task with `HighestAvailable` requires Administrator;
//! the commands refuse with exit code 6 rather than creating a weaker task.

use std::path::Path;

use aevan_core::AevanResult;

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

#[cfg(not(windows))]
pub fn install(_user: Option<&str>) -> AevanResult<String> {
    Err(unsupported("installing the autostart task"))
}

#[cfg(windows)]
pub fn remove() -> AevanResult<()> {
    imp::remove()
}

#[cfg(not(windows))]
pub fn remove() -> AevanResult<()> {
    Err(unsupported("removing the autostart task"))
}

#[cfg(windows)]
pub fn status() -> AevanResult<TaskState> {
    imp::status()
}

#[cfg(not(windows))]
pub fn status() -> AevanResult<TaskState> {
    Err(unsupported("reading the autostart task"))
}

#[cfg(not(windows))]
fn unsupported(action: &str) -> aevan_core::AevanError {
    aevan_core::AevanError::Unsupported(format!(
        "{action} is only implemented on Windows; this build has no Task Scheduler"
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
    use std::path::Path;

    use super::{task_xml, xml_escape};

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
}
