//! CLI commands that speak the daemon control protocol: `status`, `disconnect`
//! and `logs`.
//!
//! A missing daemon is a control-transport failure (exit 4) for `status` and
//! `logs`, and maps to exit 5 (`already disconnected`) for `disconnect`.

use std::time::Duration;

use aevan_core::{AevanError, AevanResult};
use aevan_daemon::client::{self, ClientError};
use aevan_daemon::{LogRecord, Request, Response};

use crate::common;

const STATUS_TIMEOUT: Duration = Duration::from_secs(10);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// `aevan status [--json]`.
pub fn status(json: bool) -> AevanResult<()> {
    let response = request(&Request::status(), Some(STATUS_TIMEOUT))?;
    common::print_status(&response.status.unwrap_or_default(), json);
    Ok(())
}

/// `aevan disconnect [profile|--all]`.
pub fn disconnect(profile: Option<&str>, all: bool, json: bool) -> AevanResult<()> {
    let request = Request::disconnect(profile.map(str::to_owned), all);
    match client::request(&request, Some(STATUS_TIMEOUT)) {
        Ok(response) if response.ok => {
            common::print_status(&response.status.unwrap_or_default(), json);
            Ok(())
        }
        Ok(response) => Err(response.into_error()),
        Err(error) if error.is_unavailable() => Err(AevanError::AlreadyInState(format!(
            "{error}; already disconnected"
        ))),
        Err(error) => Err(error.into_aevan()),
    }
}

/// `aevan reset`: retry crash recovery and report the three counts.
///
/// The daemon deletes the journal only when nothing is left undone. A genuine
/// failure is reported with every remaining step and the command to retry.
pub fn reset(json: bool) -> AevanResult<()> {
    let response = client::request(&Request::recover(), Some(RECOVERY_TIMEOUT))
        .map_err(ClientError::into_aevan)?;
    let report = response.recovery.clone().unwrap_or_default();

    if json {
        let document = serde_json::json!({
            "schema_version": common::SCHEMA_VERSION,
            "ok": response.ok && report.failed() == 0,
            "command": "reset",
            "recovery": report,
            "status": response.status,
            "error": response.error,
        });
        match serde_json::to_string_pretty(&document) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("aevan: cannot serialise the reset result: {error}"),
        }
    } else {
        if let Some(path) = &report.journal {
            println!("journal: {path}");
        }
        println!("rolled back: {}", report.rolled_back);
        println!("skipped (already absent): {}", report.skipped_absent);
        println!("failed: {}", report.failed());
        for failure in &report.failures {
            println!("  {}: {}", failure.step, failure.reason);
        }
        if report.failed() == 0 {
            if report.removed {
                println!("journal recovery complete; nothing left to undo");
            } else {
                println!("no journal is present");
            }
        }
    }

    if !response.ok {
        return Err(response.into_error());
    }
    if report.failed() > 0 {
        let remaining = report
            .failures
            .iter()
            .map(|failure| format!("{}: {}", failure.step, failure.reason))
            .collect::<Vec<_>>()
            .join("; ");
        let path = report.journal.as_deref().unwrap_or("the journal file");
        return Err(AevanError::Config(format!(
            "journal recovery is still incomplete ({remaining}); the journal is retained at {path}; fix the platform state and run `aevan reset` again"
        )));
    }
    Ok(())
}

/// `aevan shutdown`: ask the daemon to tear down and exit.
///
/// The daemon is normally elevated, so a normal shell cannot stop it with
/// taskkill; this is the only supported way to stop it from an ordinary
/// window. It disconnects first, so routes and DNS are restored.
pub fn shutdown(json: bool, if_running: bool) -> AevanResult<()> {
    match client::request(&Request::shutdown(), Some(STATUS_TIMEOUT)) {
        Ok(response) if response.ok => {
            if json {
                let document = serde_json::json!({
                    "schema_version": common::SCHEMA_VERSION,
                    "ok": true,
                    "command": "shutdown",
                });
                match serde_json::to_string_pretty(&document) {
                    Ok(text) => println!("{text}"),
                    Err(error) => eprintln!("aevan: cannot serialise the shutdown result: {error}"),
                }
            } else {
                println!("daemon: stopped");
            }
            Ok(())
        }
        Ok(response) => Err(response.into_error()),
        Err(error) if error.is_unavailable() && if_running => {
            if json {
                let document = serde_json::json!({
                    "schema_version": common::SCHEMA_VERSION,
                    "ok": true,
                    "command": "shutdown",
                    "daemon": "not running",
                });
                match serde_json::to_string_pretty(&document) {
                    Ok(text) => println!("{text}"),
                    Err(error) => eprintln!("aevan: cannot serialise the shutdown result: {error}"),
                }
            } else {
                println!("daemon: not running");
            }
            Ok(())
        }
        Err(error) if error.is_unavailable() => Err(AevanError::AlreadyInState(format!(
            "{error}; no daemon is running"
        ))),
        Err(error) => Err(error.into_aevan()),
    }
}

/// `aevan logs [--follow] [--level]`.
pub fn logs(follow: bool, level: &str, json: bool) -> AevanResult<()> {
    let request = Request::logs(follow, Some(level.to_owned()));
    let mut failure: Option<AevanError> = None;

    let result = client::stream_logs(&request, |response| {
        if !response.ok {
            failure = Some(response.into_error());
            return false;
        }
        if response.done == Some(true) {
            return false;
        }
        if let Some(record) = response.record {
            print_record(&record, json);
        }
        true
    });

    match result {
        Ok(()) => {}
        Err(error) => return Err(error.into_aevan()),
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn request(request: &Request, read_timeout: Option<Duration>) -> AevanResult<Response> {
    let response = client::request(request, read_timeout).map_err(ClientError::into_aevan)?;
    if response.ok {
        Ok(response)
    } else {
        Err(response.into_error())
    }
}

fn print_record(record: &LogRecord, json: bool) {
    if json {
        let document = serde_json::json!({
            "schema_version": common::SCHEMA_VERSION,
            "record": record,
        });
        match serde_json::to_string(&document) {
            Ok(text) => println!("{text}"),
            Err(error) => eprintln!("aevan: cannot serialise log record: {error}"),
        }
        return;
    }
    println!(
        "{} {:<5} {}: {}",
        record.timestamp_unix, record.level, record.target, record.message
    );
}
