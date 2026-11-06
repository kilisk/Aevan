//! A mockable command runner for the platform apply layer.
//!
//! Appliers never build a shell string: each command is a program plus an
//! argument vector. The real runner spawns the program directly, and
//! [`RecordingRunner`] records the exact vectors for offline tests. Neither
//! runner elevates; privilege is checked before an applier is created.

use std::cell::RefCell;
use std::process::Command;
use std::rc::Rc;

use crate::error::TunError;

/// The output of one command. This is [`std::process::Output`].
pub type Output = std::process::Output;

/// One recorded command invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCall {
    /// Program name, without a shell.
    pub program: String,
    /// Argument vector, exactly as passed to the program.
    pub args: Vec<String>,
}

impl CommandCall {
    /// Render the call for diagnostics and test failure messages.
    pub fn display(&self) -> String {
        let mut text = self.program.clone();
        for arg in &self.args {
            text.push(' ');
            text.push_str(arg);
        }
        text
    }
}

/// Run one program without a shell.
///
/// Implementations must not concatenate arguments into a shell string and must
/// not attempt elevation.
pub trait CommandRunner {
    /// Spawn `program` with `args` and collect its output.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, TunError>;
}

/// The real runner: spawn the program directly and collect stdout/stderr.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, TunError> {
        Command::new(program)
            .args(args)
            .output()
            .map_err(TunError::Io)
    }
}

/// A runner that records calls and reports success without spawning anything.
///
/// Clones share the same record, so a test can keep one handle while the
/// applier owns another.
#[derive(Debug, Default, Clone)]
pub struct RecordingRunner {
    calls: Rc<RefCell<Vec<CommandCall>>>,
}

impl RecordingRunner {
    /// Create an empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every call recorded so far, in order.
    pub fn calls(&self) -> Vec<CommandCall> {
        self.calls.borrow().clone()
    }

    /// The recorded argument vectors for one program, in order.
    pub fn args_for(&self, program: &str) -> Vec<Vec<String>> {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.program == program)
            .map(|call| call.args.clone())
            .collect()
    }

    fn record(&self, program: &str, args: &[&str]) {
        self.calls.borrow_mut().push(CommandCall {
            program: program.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        });
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, TunError> {
        self.record(program, args);
        Ok(success_output())
    }
}

fn success_output() -> Output {
    Output {
        status: success_status(),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[cfg(unix)]
fn success_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(windows)]
fn success_status() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(not(any(unix, windows)))]
fn success_status() -> std::process::ExitStatus {
    // No portable constructor is available. The platform fallback has no
    // applier anyway, so this value is never observable.
    use std::os::raw::c_int;
    let raw: c_int = 0;
    let _ = raw;
    panic!("no exit-status constructor for this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_runner_keeps_argument_vectors_separate() {
        let runner = RecordingRunner::new();
        let shared = runner.clone();
        let mut runner = runner;
        runner
            .run("netsh", &["interface", "ipv4", "add", "route"])
            .expect("recorded");
        runner.run("ip", &["addr", "add"]).expect("recorded");

        let calls = shared.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "netsh");
        assert_eq!(calls[0].args, vec!["interface", "ipv4", "add", "route"]);
        assert_eq!(shared.args_for("ip"), vec![vec!["addr", "add"]]);
    }

    #[test]
    fn the_display_form_is_not_a_shell_string() {
        let call = CommandCall {
            program: "netsh".into(),
            args: vec!["name=Aevan".into(), "address=10.0.0.1".into()],
        };
        assert_eq!(call.display(), "netsh name=Aevan address=10.0.0.1");
    }
}
