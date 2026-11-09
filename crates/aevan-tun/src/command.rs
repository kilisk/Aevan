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
    /// Bytes written to the child's standard input, if any.
    pub input: Vec<u8>,
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

    /// Spawn `program` with `args`, write `input` to its standard input and
    /// collect its output.
    ///
    /// The default ignores the input so a runner that cannot feed a child does
    /// not pretend it did. The real and recording runners implement it.
    fn run_with_input(
        &mut self,
        program: &str,
        args: &[&str],
        input: &[u8],
    ) -> Result<Output, TunError> {
        let _ = input;
        self.run(program, args)
    }
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

    fn run_with_input(
        &mut self,
        program: &str,
        args: &[&str],
        input: &[u8],
    ) -> Result<Output, TunError> {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(TunError::Io)?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input).map_err(TunError::Io)?;
        }
        child.wait_with_output().map_err(TunError::Io)
    }
}

#[derive(Debug, Clone)]
struct QueuedResponse {
    program: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    success: bool,
}

/// A runner that records calls and reports success without spawning anything.
///
/// Clones share the same record, so a test can keep one handle while the
/// applier owns another. [`RecordingRunner::respond`] queues a specific output
/// for the next call to a program; calls without a queued response succeed with
/// empty output.
#[derive(Debug, Default, Clone)]
pub struct RecordingRunner {
    calls: Rc<RefCell<Vec<CommandCall>>>,
    responses: Rc<RefCell<std::collections::VecDeque<QueuedResponse>>>,
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

    /// Queue a successful `stdout` for the next call to `program`.
    pub fn respond(&self, program: &str, stdout: &str) -> &Self {
        self.queue(program, stdout, "", true);
        self
    }

    /// Queue a failing `stderr` for the next call to `program`.
    pub fn respond_failure(&self, program: &str, stderr: &str) -> &Self {
        self.queue(program, "", stderr, false);
        self
    }

    fn queue(&self, program: &str, stdout: &str, stderr: &str, success: bool) {
        self.responses.borrow_mut().push_back(QueuedResponse {
            program: program.to_owned(),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            success,
        });
    }

    fn record(&self, program: &str, args: &[&str], input: &[u8]) {
        self.calls.borrow_mut().push(CommandCall {
            program: program.to_owned(),
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            input: input.to_vec(),
        });
    }

    fn take_response(&self, program: &str) -> Output {
        let mut responses = self.responses.borrow_mut();
        let index = responses
            .iter()
            .position(|response| response.program == program);
        let response = index.and_then(|index| responses.remove(index));
        match response {
            Some(response) => Output {
                status: exit_status(if response.success { 0 } else { 1 }),
                stdout: response.stdout,
                stderr: response.stderr,
            },
            None => success_output(),
        }
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, TunError> {
        self.record(program, args, &[]);
        Ok(self.take_response(program))
    }

    fn run_with_input(
        &mut self,
        program: &str,
        args: &[&str],
        input: &[u8],
    ) -> Result<Output, TunError> {
        self.record(program, args, input);
        Ok(self.take_response(program))
    }
}

fn success_output() -> Output {
    Output {
        status: exit_status(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[cfg(unix)]
fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code << 8)
}

#[cfg(windows)]
fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code as u32)
}

#[cfg(not(any(unix, windows)))]
fn exit_status(code: i32) -> std::process::ExitStatus {
    // No portable constructor is available. The platform fallback has no
    // applier anyway, so this value is never observable.
    let _ = code;
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
            input: Vec::new(),
        };
        assert_eq!(call.display(), "netsh name=Aevan address=10.0.0.1");
    }

    #[test]
    fn queued_responses_are_consumed_per_program() {
        let runner = RecordingRunner::new();
        runner.respond("networksetup", "There aren't any DNS Servers set on Wi-Fi.");
        runner.respond_failure("route", "no default route");

        let mut handle = runner.clone();
        let dns = handle
            .run("networksetup", &["-getdnsservers", "Wi-Fi"])
            .expect("dns");
        assert!(String::from_utf8_lossy(&dns.stdout).contains("aren't any"));
        let route = handle
            .run("route", &["-n", "get", "default"])
            .expect("route");
        assert!(!route.status.success());
        let fallback = handle.run("dscacheutil", &["-flushcache"]).expect("flush");
        assert!(fallback.status.success());
    }

    #[test]
    fn input_is_recorded_for_stdin_commands() {
        let runner = RecordingRunner::new();
        let mut handle = runner.clone();
        handle
            .run_with_input("resolvconf", &["-a", "aevan0"], b"nameserver 10.0.0.1\n")
            .expect("resolvconf");
        let calls = runner.calls();
        assert_eq!(calls[0].input, b"nameserver 10.0.0.1\n");
    }
}
