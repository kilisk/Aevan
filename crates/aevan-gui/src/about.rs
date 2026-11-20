//! The fields shown and copied by Settings → About.

use aevan_core::{logging, paths};

use crate::view_model::ViewModel;

pub struct About {
    rows: [(&'static str, String); 8],
}

impl About {
    pub fn for_view_model(vm: &ViewModel) -> Self {
        let status = vm.status.as_ref();
        let daemon_version = status
            .and_then(|report| report.daemon_version.as_deref())
            .unwrap_or(if status.is_some() {
                "not reported"
            } else {
                "unavailable"
            });
        let endpoint = if status.is_some() {
            vm.endpoint.clone()
        } else {
            format!("{} (not confirmed)", vm.endpoint)
        };
        Self {
            rows: [
                ("Product", "Aevan".into()),
                ("Version", env!("CARGO_PKG_VERSION").into()),
                ("Build date (UTC)", crate::BUILD_DATE.into()),
                ("Build commit", crate::BUILD_COMMIT.into()),
                ("Daemon version", daemon_version.into()),
                ("Endpoint", endpoint),
                (
                    "Config directory",
                    paths::config_dir()
                        .ok()
                        .map_or_else(unavailable, |p| p.display().to_string()),
                ),
                (
                    "Log directory",
                    logging::log_dir().map_or_else(unavailable, |p| p.display().to_string()),
                ),
            ],
        }
    }

    pub fn rows(&self) -> &[(&'static str, String)] {
        &self.rows
    }

    pub fn diagnostics(&self, lines: &[String]) -> String {
        use std::fmt::Write as _;

        let mut report = String::new();
        for (label, value) in self.rows() {
            let _ = writeln!(report, "{label}: {value}");
        }
        let lines = &lines[lines.len().saturating_sub(logging::DIAGNOSTIC_LINES)..];
        if lines.is_empty() {
            report.push_str("\nNo aevan-gui log lines are available.\n");
        } else {
            let _ = writeln!(report, "\nLast {} lines of aevan-gui.log:", lines.len());
            report.push_str(&lines.join("\n"));
            report.push('\n');
        }
        report
    }
}

fn unavailable() -> String {
    "unavailable".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevan_core::ProfileStore;
    use aevan_daemon::StatusReport;

    #[test]
    fn diagnostics_match_the_about_rows_and_include_only_the_latest_fifty_lines() {
        let mut vm = ViewModel::new(&ProfileStore::default(), "answered.sock".into(), 0);
        vm.apply_status(StatusReport {
            state: "disconnected".into(),
            daemon_version: Some("0.0.42".into()),
            ..StatusReport::default()
        });
        vm.password.push_str("private-password-marker");
        vm.token.push_str("private-token-marker");
        let about = About::for_view_model(&vm);
        let lines: Vec<_> = (0..60).map(|i| format!("line-{i:02}")).collect();
        let report = about.diagnostics(&lines);
        for (label, value) in about.rows() {
            assert!(report
                .lines()
                .any(|line| line == format!("{label}: {value}")));
        }
        assert!(report.contains("Daemon version: 0.0.42\nEndpoint: answered.sock\n"));
        assert!(report.contains("Last 50 lines of aevan-gui.log:"));
        let included: Vec<_> = report
            .lines()
            .filter(|line| line.starts_with("line-"))
            .collect();
        assert_eq!(included, lines[10..]);
        assert!(!report.contains("private-"));
    }

    #[test]
    fn offline_diagnostics_do_not_claim_a_running_daemon_or_existing_log() {
        let vm = ViewModel::new(&ProfileStore::default(), "candidate.sock".into(), 0);
        let report = About::for_view_model(&vm).diagnostics(&[]);
        assert!(report.contains("Daemon version: unavailable"));
        assert!(report.contains("Endpoint: candidate.sock (not confirmed)"));
        assert!(report.contains("No aevan-gui log lines are available."));
    }
}
