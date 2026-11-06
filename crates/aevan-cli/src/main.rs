#![deny(unsafe_code)]
//! `aevan` — command-line interface.
//!
//! The CLI exposes the full command surface so the
//! contract is visible, and implements only `--version`, `--help` and
//! `doctor`. Every other command returns a typed [`AevanError::Unimplemented`]
//! with its scheduled milestone. No command authenticates or touches the TUN
//! device at M0.

mod auth_probe;
mod common;
mod config;
mod connect;
mod control;
mod doctor;
mod dump;
mod launcher;
mod login;
mod probe;
mod profile;
mod tty;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;

use aevan_core::{exit_code, AevanError, AevanResult};

#[derive(Debug, Parser)]
#[command(
    name = "aevan",
    version,
    about = "Aevan — a client for Ivanti Secure Access gateways",
    arg_required_else_help = false
)]
struct Cli {
    /// Emit stable machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    /// Enable debug logging. Request bodies, cookies and credentials are still
    /// never logged.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage connection profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Inspect the sign-in page and TLS chain without sending credentials.
    AuthProbe {
        /// Profile name (defaults to the selected profile).
        profile: Option<String>,
        /// Gateway URL to probe (overrides the profile URL).
        #[arg(long)]
        url: Option<String>,
    },
    /// Submit exactly one authentication attempt.
    Login {
        /// Profile name (defaults to the selected profile).
        profile: Option<String>,
        /// Read a one-time token from stdin.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Parse an NCP configuration, from a file/stdin or the last login.
    Config {
        /// Profile name (defaults to the selected profile).
        profile: Option<String>,
        /// Read the NCP body from this file, or `-` for stdin.
        #[arg(long)]
        from_file: Option<String>,
        /// Authenticate once and run the live oNCP handshake.
        #[arg(long)]
        live: bool,
        /// Write a redacted handshake dump to this directory.
        #[arg(long)]
        dump_dir: Option<String>,
        /// Keep the gateway session instead of logging out after the run.
        #[arg(long)]
        keep_session: bool,
    },
    /// Establish a tunnel.
    Connect {
        /// Profile name (defaults to the selected profile).
        profile: Option<String>,
        /// Read a one-time token from stdin.
        #[arg(long)]
        token_stdin: bool,
        /// Keep the connector in this process.
        #[arg(long)]
        foreground: bool,
        /// Do not use the daemon.
        #[arg(long)]
        no_daemon: bool,
        /// Authenticate and handshake, print what would be applied as JSON,
        /// and change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Report connection state.
    Status,
    /// Tear down a tunnel.
    Disconnect {
        /// Profile name (defaults to the selected profile).
        profile: Option<String>,
        /// Disconnect every profile.
        #[arg(long)]
        all: bool,
    },
    /// Retry crash recovery and clear a stale journal when nothing remains.
    Reset,
    /// Stop the daemon after a clean teardown. Works from a normal shell even
    /// when the daemon is elevated.
    Shutdown {
        /// Succeed when no daemon is running. Used by the MSI uninstall so a
        /// package removal is not blocked by an already-stopped daemon.
        #[arg(long)]
        if_running: bool,
    },
    /// Diagnose TLS, HTTP, the TUN device and privileges. Sends no credentials.
    Doctor {
        /// Gateway URL to probe (defaults to the selected profile).
        #[arg(long)]
        url: Option<String>,
        /// Profile whose URL should be probed.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show or follow the log.
    Logs {
        /// Follow new records.
        #[arg(long)]
        follow: bool,
        /// Minimum level.
        #[arg(long, default_value = "info")]
        level: String,
    },
    /// Print environment for shells and scripts.
    Env,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Add a profile.
    Add {
        /// Profile name.
        name: String,
        /// Gateway URL.
        #[arg(long)]
        url: String,
        /// Authentication realm.
        #[arg(long)]
        realm: String,
        /// Username (never a password).
        #[arg(long)]
        user: Option<String>,
        /// Split-tunnel mode.
        #[arg(long, value_enum)]
        split_tunnel: Option<profile::SplitTunnelChoice>,
    },
    /// List profiles.
    List,
    /// Show one profile.
    Show {
        /// Profile name.
        name: String,
    },
    /// Remove a profile.
    Rm {
        /// Profile name.
        name: String,
    },
}

#[derive(Debug, Serialize)]
struct ErrorReport<'a> {
    schema_version: u32,
    error: &'a str,
    exit_code: i32,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(&cli) {
        Ok(()) => ExitCode::from(exit_code::OK as u8),
        Err(error) => {
            if cli.json {
                let report = ErrorReport {
                    schema_version: doctor::SCHEMA_VERSION,
                    error: &error.to_string(),
                    exit_code: error.exit_code(),
                };
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{json}"),
                    Err(_) => eprintln!("aevan: {error}"),
                }
            } else {
                eprintln!("aevan: {error}");
            }
            ExitCode::from(error.exit_code() as u8)
        }
    }
}

fn run(cli: &Cli) -> AevanResult<()> {
    let Some(command) = &cli.command else {
        return launcher::launch();
    };
    match command {
        Command::Doctor { url, profile } => {
            doctor::run(url.as_deref(), profile.as_deref(), cli.json)
        }
        Command::Profile { command } => match command {
            ProfileCommand::Add {
                name,
                url,
                realm,
                user,
                split_tunnel,
            } => profile::add(name, url, realm, user.as_deref(), *split_tunnel, cli.json),
            ProfileCommand::List => profile::list(cli.json),
            ProfileCommand::Show { name } => profile::show(name, cli.json),
            ProfileCommand::Rm { name } => profile::rm(name, cli.json),
        },
        Command::AuthProbe { profile, url } => {
            auth_probe::run(url.as_deref(), profile.as_deref(), cli.json)
        }
        Command::Login {
            profile,
            token_stdin,
        } => login::run(profile.as_deref(), *token_stdin, cli.json),
        Command::Config {
            profile,
            from_file,
            live,
            dump_dir,
            keep_session,
        } => config::run(
            profile.as_deref(),
            from_file.as_deref(),
            *live,
            dump_dir.as_deref(),
            *keep_session,
            cli.json,
        ),
        Command::Connect {
            profile,
            token_stdin,
            foreground,
            no_daemon,
            dry_run,
        } => connect::run(
            profile.as_deref(),
            *token_stdin,
            *foreground,
            *no_daemon,
            *dry_run,
            cli.json,
        ),
        Command::Status => control::status(cli.json),
        Command::Disconnect { profile, all } => {
            control::disconnect(profile.as_deref(), *all, cli.json)
        }
        Command::Reset => control::reset(cli.json),
        Command::Shutdown { if_running } => control::shutdown(cli.json, *if_running),
        Command::Logs { follow, level } => control::logs(*follow, level, cli.json),
        Command::Env => Err(AevanError::Unimplemented("env (M5)")),
    }
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;

    let default = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
