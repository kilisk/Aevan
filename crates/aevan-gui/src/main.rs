#![deny(unsafe_code)]
#![cfg_attr(windows, windows_subsystem = "windows")]
//! `aevan-gui` — a native desktop client for the `aevand` daemon.
//!
//! The GUI is a **daemon client** and nothing more. It never opens a TLS
//! connection, never reads a credential from argv or the environment, and never
//! touches routes, DNS or the adapter. Every tunnel action is a versioned JSON
//! request on the local control endpoint, exactly as the CLI sends it.
//!
//! The window is `iced`; all state, transitions, formatting and poll scheduling
//! live in [`view_model`], which has no toolkit types and is unit-tested
//! offline.

mod app;
mod console;
mod daemon_bridge;
mod instance;
#[cfg(target_os = "macos")]
mod macos_service;
mod notifications;
// The service decision and its owner-only start log are compiled and tested
// everywhere; only the macOS daemon path calls them in the application.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod relaunch;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod start_log;
mod tray;
mod view_model;

use std::process::ExitCode;

use aevan_core::ProfileStore;

use crate::view_model::ViewModel;

const HELP: &str = "\
aevan-gui — native client for the aevand daemon

Usage: aevan-gui [OPTIONS]

Options:
      --headless           Print the resolved view-model state and exit without a window
      --json               Machine-readable output (with --headless)
      --unregister-daemon  Remove the macOS daemon registration and exit
  -V, --version            Print the version and exit
  -h, --help               Print this help and exit

The GUI never authenticates itself: it sends one connect request to aevand over
the local control socket and displays the status the daemon reports.
";

#[derive(Debug, Clone, Copy, Default)]
struct Args {
    headless: bool,
    json: bool,
    unregister_daemon: bool,
}

fn main() -> ExitCode {
    // A GUI-subsystem binary has no console, but it can still print into the
    // terminal that launched it. This must run before the first print.
    console::attach_parent_console();
    init_tracing();

    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("aevan-gui: {message}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };

    if args.unregister_daemon {
        return unregister_daemon();
    }

    if args.headless {
        return headless(args.json);
    }

    // One GUI per user: the first process keeps the endpoint and the window;
    // every later start asks it to show and exits without a window or tray.
    match instance::claim_and_serve() {
        Ok(aevan_instance::InstanceRole::Secondary) => return ExitCode::SUCCESS,
        Ok(aevan_instance::InstanceRole::Primary) => {}
        Err(error) => {
            eprintln!("aevan-gui: cannot start the single-instance endpoint: {error}");
            return ExitCode::FAILURE;
        }
    }

    let store = match ProfileStore::default_path().and_then(|path| ProfileStore::load(&path)) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("aevan-gui: {error}");
            return ExitCode::FAILURE;
        }
    };

    match app::run(store) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aevan-gui: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Send `tracing` events (including the Quit-anyway warning) to stderr.
///
/// A packaged macOS app may have no visible stderr, but a terminal launch and
/// the system log still receive the line; `RUST_LOG` can raise or lower it.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--version" | "-V" => {
                println!("aevan-gui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "--headless" => args.headless = true,
            "--json" => args.json = true,
            "--unregister-daemon" => args.unregister_daemon = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(args)
}

/// Remove the macOS daemon registration through ServiceManagement.
///
/// The uninstaller calls this before deleting the app bundle so the background
/// item does not outlive the app. It is idempotent.
fn unregister_daemon() -> ExitCode {
    #[cfg(target_os = "macos")]
    {
        match daemon_bridge::unregister_daemon_service() {
            Ok(()) => {
                println!("aevan-gui: removed the daemon registration");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("aevan-gui: cannot remove the daemon registration: {error}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("aevan-gui: --unregister-daemon is only available on macOS");
        ExitCode::FAILURE
    }
}

/// Print the resolved view-model state and exit.
///
/// The status probe is read-only and bounded. A missing daemon is a normal
/// outcome here and is reported in the document rather than as a process
/// failure, so CI can run this without elevation or a gateway.
fn headless(json: bool) -> ExitCode {
    let now = view_model::now_unix();
    let store = match ProfileStore::default_path().and_then(|path| ProfileStore::load(&path)) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("aevan-gui: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut vm = ViewModel::new(&store, daemon_bridge::endpoint(), now);
    if let Some(profile) = vm.selected.clone() {
        match daemon_bridge::totp_secret(&profile) {
            Ok(secret) => vm.set_totp_secret(&profile, secret),
            Err(error) => vm.apply_totp_error(error),
        }
    }
    match daemon_bridge::status() {
        Ok((status, endpoint)) => {
            vm.endpoint = endpoint;
            vm.apply_status(status);
        }
        Err(error) => vm.apply_client_error(error),
    }

    let document = serde_json::json!({
        "schema_version": 1,
        "binary": "aevan-gui",
        "version": env!("CARGO_PKG_VERSION"),
        "screen": vm.screen.name(),
        "state": vm.state.name(),
        "message": vm.state.message(),
        "selected": vm.selected,
        "endpoint": vm.endpoint,
        "log_level": vm.log_level.as_str(),
        "profiles": vm.profiles,
        "connection": vm.status,
    });

    if json {
        match serde_json::to_string_pretty(&document) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("aevan-gui: cannot serialise the headless state: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!(
            "screen: {}",
            document["screen"].as_str().unwrap_or("profiles")
        );
        println!("state: {}", document["state"].as_str().unwrap_or("unknown"));
        if let Some(message) = document["message"].as_str() {
            println!("message: {message}");
        }
        if let Some(selected) = document["selected"].as_str() {
            println!("selected: {selected}");
        }
        println!("endpoint: {}", document["endpoint"].as_str().unwrap_or(""));
        println!(
            "profiles: {}",
            document["profiles"]
                .as_array()
                .map(|profiles| profiles.len())
                .unwrap_or(0)
        );
    }
    ExitCode::SUCCESS
}
