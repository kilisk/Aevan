//! Open a real TUN device and close it without sending anything.
//!
//! This is the device proof that CI runs under `sudo` on Ubuntu and macOS:
//! opening a `utun` or `/dev/net/tun` interface is the part that cannot be
//! exercised by offline unit tests. Success means the kernel created the
//! interface. Run `--linux-route` in a disposable network namespace to also
//! exercise address, MTU, route setup and teardown without sending packets.
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

#[cfg(target_os = "linux")]
fn linux_route_smoke() -> Result<(), TunError> {
    use std::net::Ipv4Addr;
    use std::process::Command;

    let destination = Ipv4Addr::new(198, 51, 100, 0);
    let mut device = SmokeDevice::open(config())?;
    device.set_addr(Ipv4Addr::new(192, 0, 2, 1).into(), 32)?;
    device.set_mtu(1396)?;
    device.set_routes(&[aevan_tun::Route::on_link(destination.into(), 24)?])?;
    let cidr = format!("{destination}/24");
    let lookup = || -> Result<String, TunError> {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "exact", &cidr])
            .output()?;
        if !output.status.success() {
            return Err(TunError::Io(std::io::Error::other(format!(
                "route lookup failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    let expected = format!("{cidr} dev {}", device.name());
    if !lookup()?.starts_with(&expected) {
        return Err(TunError::Io(std::io::Error::other(format!(
            "route did not use the kernel-assigned TUN interface: expected {expected}"
        ))));
    }
    device.close()?;
    if !lookup()?.trim().is_empty() {
        return Err(TunError::Io(std::io::Error::other(
            "route survived TUN teardown",
        )));
    }
    println!("tun_smoke: Linux address, MTU, route apply and teardown passed");
    Ok(())
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
    #[cfg(target_os = "linux")]
    if std::env::args().any(|arg| arg == "--linux-route") {
        return match linux_route_smoke() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => report(error),
        };
    }

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
