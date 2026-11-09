//! Open a real TUN device and close it without sending anything.
//!
//! This is the device proof that CI runs under `sudo` on Ubuntu and macOS:
//! opening a `utun` or `/dev/net/tun` interface is the part that cannot be
//! exercised by offline unit tests. Success means the kernel created the
//! interface; no packet is sent and nothing on the host's network is changed.
//!
//! Exit codes:
//!
//! * `0` — the device opened and closed.
//! * `0` — an `Unsupported` or `Permission` error, but only when
//!   `AEVAN_TUN_SMOKE_ALLOW_SKIP=1` is set. Without that opt-in, a backend that
//!   cannot open a device is a visible failure.
//! * `1` — any other error, or a skip that was not allowed.

use std::net::IpAddr;
use std::process::ExitCode;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use aevan_tun::Device;
use aevan_tun::{DeviceConfig, TunError};

#[cfg(target_os = "linux")]
use aevan_tun::platform::LinuxTunDevice as SmokeDevice;
#[cfg(target_os = "macos")]
use aevan_tun::platform::UtunDevice as SmokeDevice;

fn config() -> DeviceConfig {
    DeviceConfig {
        name: None,
        address: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 199, 0, 1))),
        prefix_len: 24,
        mtu: 1396,
        routes: Vec::new(),
        dns: Vec::new(),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_and_close(config: DeviceConfig) -> Result<(String, Option<isize>), TunError> {
    let mut device = SmokeDevice::open(config)?;
    let name = device.name().to_owned();
    let handle = device.wait_handle();
    device.close()?;
    Ok((name, handle))
}

fn skip_allowed() -> bool {
    std::env::var("AEVAN_TUN_SMOKE_ALLOW_SKIP").as_deref() == Ok("1")
}

fn report(error: TunError) -> ExitCode {
    match error {
        TunError::Unsupported(reason) => {
            eprintln!("tun_smoke: backend unsupported: {reason}");
            if skip_allowed() {
                println!("tun_smoke: skipped (AEVAN_TUN_SMOKE_ALLOW_SKIP=1)");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "tun_smoke: set AEVAN_TUN_SMOKE_ALLOW_SKIP=1 to treat this as a skip; \
                     a backend that cannot open a device is a failure by default"
                );
                ExitCode::FAILURE
            }
        }
        TunError::Permission(reason) => {
            eprintln!("tun_smoke: permission denied: {reason}");
            if skip_allowed() {
                println!("tun_smoke: skipped (AEVAN_TUN_SMOKE_ALLOW_SKIP=1)");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "tun_smoke: set AEVAN_TUN_SMOKE_ALLOW_SKIP=1 to treat this as a skip; \
                     run the example under sudo to prove the backend"
                );
                ExitCode::FAILURE
            }
        }
        other => {
            eprintln!("tun_smoke: failed: {other}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let config = config();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        match open_and_close(config) {
            Ok((name, handle)) => {
                println!("tun_smoke: device opened");
                println!("  interface: {name}");
                println!("  wait_handle: {handle:?}");
                ExitCode::SUCCESS
            }
            Err(error) => report(error),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = config;
        report(TunError::Unsupported(
            "the tun_smoke example is wired for macOS utun and Linux /dev/net/tun only",
        ))
    }
}
