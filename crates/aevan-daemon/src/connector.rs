//! The shared connect orchestration: oNCP handshake, journal, apply, ESP loop and
//! teardown.
//!
//! Both `aevan connect --foreground` and the daemon call
//! [`connect_session`]. The caller supplies [`TunnelControl`] to observe the
//! connection, publish stats and request a stop; the actual login attempt is
//! performed by [`crate::auth`].
//!
//! Key material never leaves this module: the connected information and the
//! status report carry only address, MTU, route count and DNS servers.

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use aevan_core::{AevanError, AevanResult, Profile};
use aevan_nc::{
    client_config_reply, decode_attributes, esp_negotiation, handshake_live_session, EspKeys,
    EspLocalKeys, EspReadiness, EspSession, EspSessionConfig, EspSessionError, EspSessionMaterial,
    EspUdp, HandshakeAttempt, KmpMessageOwned, NcpConfig, RekeyPolicy, UdpEspTransport, KMP_CONFIG,
};
use aevan_proto::Url;
use aevan_tun::apply;
use aevan_tun::{
    platform, Applier, Change, Device, DeviceConfig, RealCommandRunner, Session, TunError,
};

use crate::auth::LoginSession;
use crate::journal::Journal;

/// Device name used when the configuration does not supply one.
pub const DEFAULT_DEVICE: &str = if cfg!(target_os = "windows") {
    "aevan"
} else if cfg!(target_os = "linux") {
    "aevan0"
} else {
    "utun0"
};

/// Timeout for the single oNCP handshake connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long an idle data plane waits for either source before checking timers.
///
/// The wait is bounded so keepalives and rekey deadlines still run, and a stop
/// request is observed within this interval even with no traffic.
const ESP_IDLE_TIMEOUT: Duration = Duration::from_millis(50);

/// How long the Unix channel-backed loop waits before checking its queue again.
///
/// The reader thread wakes this loop through the queue, not through a readiness
/// descriptor, so the wait is the latency bound for a queued packet. Ten
/// milliseconds keeps interactive traffic responsive without a busy spin. Only
/// the Unix channel path uses it.
const ESP_CHANNEL_IDLE_TIMEOUT: Duration = Duration::from_millis(10);

/// Fallback ESP UDP port when KMP 301 group 8 attr 4 is absent.
const DEFAULT_ESP_PORT: u16 = 4500;

/// Consecutive readable-but-empty device drains before the watchdog trips.
///
/// This is the Windows readiness watchdog; the Unix channel path replaces it
/// with [`DEVICE_CHANNEL_EMPTY_WARNING`].
const DEVICE_POLL_LIE_LIMIT: u32 = 100;

/// How long a connected device may go without producing a readable packet
/// before the loop warns.
const DEVICE_STALL_WARNING: Duration = Duration::from_secs(2);

/// How long the Unix reader channel may stay empty before the loop warns.
const DEVICE_CHANNEL_EMPTY_WARNING: Duration = Duration::from_secs(5);

/// Minimum spacing between channel-empty warnings.
const DEVICE_CHANNEL_WARNING_INTERVAL: Duration = Duration::from_secs(30);

/// Delay before retrying a device write that reported `WouldBlock`.
#[cfg(unix)]
const DEVICE_WRITE_RETRY_DELAY: Duration = Duration::from_millis(2);

/// Options for one connect attempt.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectOptions {
    /// Authenticate and handshake, report the plan, change nothing.
    pub dry_run: bool,
}

/// What a live tunnel looks like to the caller. No key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionInfo {
    /// Profile name.
    pub profile: String,
    /// Device name.
    pub device: String,
    /// Assigned address.
    pub address: Option<IpAddr>,
    /// Prefix length for the address.
    pub prefix_len: u8,
    /// Negotiated MTU.
    pub mtu: Option<u16>,
    /// Number of applied routes.
    pub route_count: usize,
    /// Applied DNS servers.
    pub dns: Vec<IpAddr>,
}

impl ConnectionInfo {
    fn from_plan(plan: &ApplyPlan, profile: &str) -> Self {
        Self {
            profile: profile.to_owned(),
            device: plan.device.clone(),
            address: plan.address,
            prefix_len: plan.prefix_len,
            mtu: plan.mtu,
            route_count: plan.routes.len(),
            dns: plan.dns.clone(),
        }
    }
}

/// Callbacks from the connector to its owner.
///
/// The foreground CLI uses these to print; the daemon uses them to update the
/// shared state machine and stats. Implementations must not block.
pub trait TunnelControl: Send + Sync {
    /// Whether teardown has been requested.
    fn should_stop(&self) -> bool;
    /// The handshake is about to start.
    fn connecting(&self) {}
    /// The dry-run plan is ready.
    fn planned(&self, _plan: &ApplyPlan) {}
    /// The tunnel is up.
    fn connected(&self, _info: &ConnectionInfo) {}
    /// Updated ESP byte counters.
    fn stats(&self, _bytes_in: u64, _bytes_out: u64) {}
}

/// The concrete configuration that would be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    /// Device name.
    pub device: String,
    /// Assigned address.
    pub address: Option<IpAddr>,
    /// Prefix length.
    pub prefix_len: u8,
    /// MTU.
    pub mtu: Option<u16>,
    /// Routes.
    pub routes: Vec<aevan_tun::Route>,
    /// DNS servers.
    pub dns: Vec<IpAddr>,
}

impl ApplyPlan {
    /// Build a plan from a decoded KMP 301 configuration.
    pub fn from_ncp(config: &NcpConfig, device: String) -> AevanResult<Self> {
        let (address, prefix_len) = if let Some(ipv4) = &config.ipv4 {
            let prefix_len = ipv4
                .prefix_len
                .or_else(|| {
                    ipv4.netmask
                        .map(|mask| u32::from(mask).leading_ones() as u8)
                })
                .unwrap_or(32);
            (Some(IpAddr::V4(ipv4.address)), prefix_len)
        } else if let Some(ipv6) = &config.ipv6 {
            (
                Some(IpAddr::V6(ipv6.address)),
                ipv6.prefix_len.unwrap_or(128),
            )
        } else {
            (None, 0)
        };

        let routes = config
            .split_routes
            .iter()
            .map(|route| aevan_tun::Route::on_link(route.network, route.prefix_len))
            .collect::<Result<Vec<_>, _>>()
            .map_err(tun_error)?;

        Ok(Self {
            device,
            address,
            prefix_len,
            mtu: config.mtu.filter(|mtu| *mtu != 0),
            routes,
            dns: config.dns.clone(),
        })
    }

    /// Device configuration for the platform backend.
    pub fn device_config(&self) -> DeviceConfig {
        DeviceConfig {
            name: Some(self.device.clone()),
            address: self.address,
            prefix_len: self.prefix_len,
            mtu: self.mtu.unwrap_or(0),
            routes: self.routes.clone(),
            dns: self.dns.clone(),
        }
    }

    /// Ordered setup changes.
    pub fn changes(&self) -> Vec<Change> {
        apply::plan(&self.device_config())
    }
}

/// Run one connect after a successful authentication.
///
/// The single authentication attempt has already happened in `session`. This
/// function performs exactly one oNCP handshake attempt, writes the journal
/// before the first change, applies the plan, runs ESP and always tears down.
pub fn connect_session<C: TunnelControl>(
    profile: &Profile,
    session: &mut LoginSession,
    control: &C,
    options: ConnectOptions,
    journal_path: Option<&Path>,
) -> AevanResult<()> {
    control.connecting();

    let disable_value = std::env::var("AEVAN_DISABLE_REKEY").ok();
    let rekey_disabled = disable_rekey_requested(disable_value.as_deref());
    if rekey_disabled {
        tracing::warn!(
            "AEVAN_DISABLE_REKEY is set: automatic ESP rekey is DISABLED for this tunnel; \
             the tunnel will keep using the initial SA until it is torn down"
        );
    }

    let gateway = parse_url(&profile.url)?;
    let cookie = session
        .client
        .cookie_jar_mut()
        .cookie_header_for_host(&gateway);

    // Exactly one handshake attempt: no Content-Length fallback and no retry.
    // The stream stays open for the KMP 302/303 replies and for the lifetime of
    // the ESP session.
    let mut handshake = handshake_live_session(
        &gateway,
        HANDSHAKE_TIMEOUT,
        &local_hostname(),
        cookie.as_deref(),
    )
    .map_err(|error| AevanError::Network(error.to_string()))?;

    let attempt = handshake.attempt().clone();
    let peer = handshake.peer_addr();

    let message = match attempt.message.as_ref() {
        Some(message) if message.number == KMP_CONFIG => message,
        _ => return Err(handshake_failure(&attempt)),
    };
    tracing::info!(
        direction = "inbound",
        message = message.number,
        bytes = message.record_length,
        "ESP initial exchange: KMP configuration"
    );

    let config = decode_config(message).ok_or_else(|| {
        AevanError::Unsupported("the KMP 301 configuration could not be decoded".into())
    })?;
    let plan = ApplyPlan::from_ncp(&config, DEFAULT_DEVICE.to_owned())?;

    if options.dry_run {
        control.planned(&plan);
        return Ok(());
    }
    if control.should_stop() {
        return Ok(());
    }

    let esp = EspSetup::negotiate(&config, &mut |bytes| handshake.write_all(bytes))?;

    let mut device = match platform::open(plan.device_config()) {
        Ok(device) => device,
        Err(error) => return Err(tun_error(error)),
    };
    // The kernel assigns the interface name (macOS hands out the next free
    // utun unit, unit 5 -> utun5), so the configured name is only a hint.
    // Everything that touches the interface, and the journal that undoes it,
    // must use the name the OS actually gave us.
    let interface = resolve_interface(device.name(), &plan.device);
    if interface != plan.device {
        tracing::info!(
            configured = %plan.device,
            assigned = %interface,
            "the OS assigned a different tunnel interface name"
        );
    }

    // Create the journal before the first change, under the assigned name.
    let mut journal = match journal_path {
        Some(path) => Some(Journal::create(path.to_owned(), interface.clone())?),
        None => None,
    };

    let applier = match apply::platform_applier(Box::new(RealCommandRunner), &interface) {
        Ok(applier) => applier,
        Err(error) => {
            let _ = device.close();
            if let Some(journal) = journal.take() {
                let _ = journal.remove();
            }
            return Err(tun_error(error));
        }
    };
    let mut guard = ConnectGuard::new(Some(device), Session::new(applier), journal.take());
    guard.apply_plan(&plan)?;
    control.connected(&ConnectionInfo::from_plan(&plan, &profile.name));

    let mut transport = UdpEspTransport::connect(peer, esp.udp_port)
        .map_err(|error| AevanError::Network(format!("ESP UDP socket: {error}")))?;
    // Ask for large socket buffers so a burst does not overflow the kernel
    // queue. A refusal is harmless and intentionally ignored.
    if let Some(handle) = transport.wait_handle() {
        platform::tune_udp_socket(handle);
    }
    let mut esp_session = EspSession::new(
        esp.material,
        esp.initial_iv,
        EspSessionConfig {
            keepalive_interval_seconds: esp.keepalive_seconds,
            peer_timeout: esp.peer_timeout,
            rekey_policy: effective_rekey_policy(esp.rekey_policy, rekey_disabled),
            rekey_grace: esp.rekey_grace,
            mtu: esp.mtu,
        },
        Instant::now(),
    );
    // The oNCP TLS stream stays open for the whole tunnel so a rekey can send a
    // new KMP 302/303 on the same channel that carried KMP 301.
    esp_session.set_kmp_channel(Box::new(handshake));

    // On Unix the tunnel descriptor is blocking and has one owner for reads:
    // a dedicated reader thread feeding a bounded channel. The ESP loop only
    // writes to the device.
    #[cfg(unix)]
    let mut reader = {
        let device = guard.device_ref()?;
        aevan_tun::platform::DeviceReader::spawn_device(device).map_err(AevanError::Io)?
    };

    let run = {
        #[cfg(unix)]
        {
            match reader.as_mut() {
                Some(reader) => {
                    let mut adapter = ChannelEspDevice {
                        inner: guard.device_mut()?,
                        reader,
                    };
                    run_esp(&mut esp_session, &mut transport, &mut adapter, control)
                }
                None => {
                    let mut adapter = TunEspDevice {
                        inner: guard.device_mut()?,
                    };
                    run_esp(&mut esp_session, &mut transport, &mut adapter, control)
                }
            }
        }
        #[cfg(not(unix))]
        {
            let mut adapter = TunEspDevice {
                inner: guard.device_mut()?,
            };
            run_esp(&mut esp_session, &mut transport, &mut adapter, control)
        }
    };

    // Wake and join the reader before rolling anything back. A reader that
    // refuses to stop is detached after a bounded wait, so it can never keep
    // the route/DNS rollback from running.
    #[cfg(unix)]
    if let Some(reader) = reader.as_mut() {
        reader.shutdown();
    }

    control.stats(esp_session.bytes_received(), esp_session.bytes_sent());

    let teardown = guard.teardown();
    match (run, teardown) {
        (Err(error), _) => Err(esp_session_error(error)),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The interface the tunnel actually owns.
///
/// The OS assigns it (macOS hands out the next free `utun` unit), so a
/// configured name is only a fallback for backends that honour it.
fn resolve_interface(assigned: Option<&str>, configured: &str) -> String {
    assigned
        .map(str::to_owned)
        .unwrap_or_else(|| configured.to_owned())
}

/// Run the ESP loop until stop, peer loss or an error.
fn run_esp<U, D, C>(
    session: &mut EspSession,
    udp: &mut U,
    device: &mut D,
    control: &C,
) -> Result<(), EspSessionError>
where
    U: aevan_nc::EspUdp,
    D: aevan_nc::EspDevice,
    C: TunnelControl,
{
    let sources = platform::WaitSources {
        udp: udp.wait_handle(),
        device: device.wait_handle(),
    };
    // A channel-backed device owns its descriptor in a reader thread. The ESP
    // loop must not poll that descriptor; it only drains the queue.
    let channel_backed = device.device_fd().is_some() && device.wait_handle().is_none();
    let interface = device.interface_name().map(str::to_owned);
    let idle_timeout = if cfg!(unix) && channel_backed {
        ESP_CHANNEL_IDLE_TIMEOUT
    } else {
        ESP_IDLE_TIMEOUT
    };
    tracing::debug!(
        device_fd = ?device.device_fd(),
        udp_fd = ?sources.udp,
        interface = %interface.as_deref().unwrap_or("tun"),
        channel_backed,
        "ESP loop starting"
    );

    let mut wait_sources = sources;
    let mut readiness = EspReadiness::default();
    let mut device_polling = true;
    let mut zero_device_drains = 0u32;
    let mut last_device_packet = Instant::now();
    let mut last_channel_warning: Option<Instant> = None;
    let mut last_stall_warning: Option<Instant> = None;
    let mut last_error: Option<String> = None;

    loop {
        if control.should_stop() {
            return Ok(());
        }
        let now = Instant::now();
        let device_was_readable = readiness.device;
        let report = session.poll_once_observed(udp, device, now, readiness)?;
        readiness = EspReadiness::default();
        control.stats(session.bytes_received(), session.bytes_sent());

        if let Some(kind) = report.device_error {
            last_error = Some(format!("{kind:?}"));
        }

        if report.device_packets > 0 {
            last_device_packet = now;
        }

        if channel_backed {
            // The queue being empty for a long time is the replacement for the
            // old readable-but-empty readiness watchdog: the reader thread, not
            // the ESP loop, decides when a packet exists.
            if report.device_packets == 0
                && now.duration_since(last_device_packet) >= DEVICE_CHANNEL_EMPTY_WARNING
                && last_channel_warning
                    .is_none_or(|at| now.duration_since(at) >= DEVICE_CHANNEL_WARNING_INTERVAL)
            {
                tracing::warn!(
                    interface = %interface.as_deref().unwrap_or("tun"),
                    fd = ?device.device_fd(),
                    empty_for = ?now.duration_since(last_device_packet),
                    last_error = ?last_error,
                    "tunnel device channel has been empty while the tunnel is connected"
                );
                last_channel_warning = Some(now);
            }
        } else if device_polling {
            if report.device_packets > 0 {
                last_device_packet = now;
                zero_device_drains = 0;
            } else if device_was_readable {
                zero_device_drains = zero_device_drains.saturating_add(1);
                if zero_device_drains >= DEVICE_POLL_LIE_LIMIT {
                    tracing::error!(
                        fd = ?sources.device,
                        consecutive = zero_device_drains,
                        "ESP device reports readable but drained zero packets; stopping device polling so the bounded sleep can reveal the difference"
                    );
                    session.set_device_polling(false);
                    device_polling = false;
                    wait_sources.device = None;
                }
            } else {
                zero_device_drains = 0;
            }

            if device_polling
                && now.duration_since(last_device_packet) >= DEVICE_STALL_WARNING
                && last_stall_warning
                    .is_none_or(|at| now.duration_since(at) >= DEVICE_STALL_WARNING)
            {
                tracing::warn!(
                    fd = ?sources.device,
                    last_poll = ?report,
                    last_error = ?last_error,
                    "ESP device produced no readable packets for 2s while the tunnel is connected"
                );
                last_stall_warning = Some(now);
            }
        }

        if !report.worked {
            // Nothing was ready. Wait for the socket (and, when the backend has
            // one, the device) with a bounded timeout so keepalives, rekey
            // timers and the stop flag are still serviced. The channel-backed
            // path uses the shorter timeout so a queued packet is never far
            // behind.
            if wait_sources.udp.is_some() || wait_sources.device.is_some() {
                match platform::wait_readable(wait_sources, idle_timeout) {
                    Ok(observed) => {
                        readiness = EspReadiness {
                            udp: observed.udp,
                            device: observed.device,
                        };
                    }
                    Err(error) => {
                        last_error = Some(error.to_string());
                        tracing::debug!(%error, "ESP readiness wait failed; using a bounded sleep");
                        std::thread::sleep(idle_timeout);
                    }
                }
            } else {
                std::thread::sleep(idle_timeout);
            }
        }
    }
}

fn parse_url(raw: &str) -> AevanResult<Url> {
    Url::parse(raw).map_err(|error| AevanError::Config(error.to_string()))
}

/// Whether `AEVAN_DISABLE_REKEY` asks for automatic rekey to be turned off.
///
/// Only the documented literal `1` (after trimming) enables the switch; every
/// other value, including an unset variable, leaves rekey enabled.
fn disable_rekey_requested(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() == "1")
}

/// Apply the environment switch to the negotiated rekey policy.
fn effective_rekey_policy(policy: RekeyPolicy, disabled: bool) -> RekeyPolicy {
    if disabled {
        RekeyPolicy::new(None, None, 0, 0)
    } else {
        policy
    }
}

fn decode_config(message: &KmpMessageOwned) -> Option<NcpConfig> {
    let attributes = decode_attributes(&message.payload).ok()?;
    NcpConfig::from_attributes(attributes).ok()
}

/// Hostname sent in the oNCP handshake.
pub fn local_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "aevan".to_owned())
}

/// Everything the ESP session needs after KMP 301.
struct EspSetup {
    material: EspSessionMaterial,
    initial_iv: [u8; 16],
    udp_port: u16,
    keepalive_seconds: u64,
    peer_timeout: Duration,
    rekey_policy: RekeyPolicy,
    rekey_grace: Duration,
    mtu: u16,
}

impl EspSetup {
    fn negotiate<S>(config: &NcpConfig, send: &mut S) -> AevanResult<Self>
    where
        S: FnMut(&[u8]) -> io::Result<()> + ?Sized,
    {
        let proposal = config
            .esp
            .as_ref()
            .ok_or_else(|| AevanError::Unsupported("KMP 301 has no ESP proposal".into()))?;
        let encryption = proposal
            .encryption
            .ok_or_else(|| AevanError::Unsupported("KMP 301 has no ESP encryption".into()))?;
        let authentication = proposal
            .authentication
            .ok_or_else(|| AevanError::Unsupported("KMP 301 has no ESP authentication".into()))?;
        let outbound_spi = proposal
            .outbound_spi
            .ok_or_else(|| AevanError::Unsupported("KMP 301 has no outbound SPI".into()))?;
        let key_block = config
            .esp_key_block()
            .ok_or_else(|| AevanError::Unsupported("KMP 301 has no ESP key block".into()))?;
        let outbound_keys = EspKeys::from_key_block(key_block, encryption, authentication)
            .map_err(|error| AevanError::Unsupported(format!("KMP 301 ESP keys: {error}")))?;

        let (local, initial_iv) = EspLocalKeys::generate_with_iv(encryption, authentication);

        let negotiation = esp_negotiation(&local);
        send(&negotiation)
            .map_err(|error| AevanError::Network(format!("sending KMP 302: {error}")))?;
        tracing::info!(
            direction = "outbound",
            message = 302,
            bytes = negotiation.len(),
            "ESP initial exchange: KMP message"
        );
        let reply = client_config_reply(config.mtu.unwrap_or(0));
        send(&reply).map_err(|error| AevanError::Network(format!("sending KMP 303: {error}")))?;
        tracing::info!(
            direction = "outbound",
            message = 303,
            bytes = reply.len(),
            "ESP initial exchange: KMP message"
        );

        let inbound_keys = EspKeys::new(
            encryption,
            authentication,
            local.encryption_key().clone(),
            local.hmac_key().clone(),
        )
        .map_err(|error| AevanError::Unsupported(format!("generated ESP keys: {error}")))?;

        let keepalive_seconds = config.fallback_timeout_secs.unwrap_or(15).max(1);
        // Start at 80 percent of the soft time lifetime: the margin is 20
        // percent. The byte lifetime has no margin, so it triggers as soon as
        // it is reached. Both decisions come from `RekeyPolicy::due`.
        let margin_seconds = proposal
            .lifetime_seconds
            .map_or(0, |seconds| u64::from(seconds) * 20 / 100);
        let rekey_policy = RekeyPolicy::from_esp_proposal(proposal, margin_seconds, 0);

        Ok(Self {
            material: EspSessionMaterial {
                outbound_spi,
                outbound_keys,
                inbound_spi: local.spi(),
                inbound_keys,
            },
            initial_iv,
            udp_port: proposal.udp_port.unwrap_or(DEFAULT_ESP_PORT),
            keepalive_seconds,
            peer_timeout: Duration::from_secs(keepalive_seconds * 3),
            rekey_policy,
            rekey_grace: Duration::from_secs(keepalive_seconds.saturating_mul(2)),
            mtu: config.mtu.unwrap_or(0),
        })
    }
}

fn esp_session_error(error: EspSessionError) -> AevanError {
    match error {
        EspSessionError::PeerUnresponsive(timeout) => AevanError::Network(format!(
            "the ESP peer stopped responding for {timeout:?}; the tunnel is down"
        )),
        EspSessionError::Io(error) => AevanError::Network(format!("ESP socket: {error}")),
        EspSessionError::Packet(error) => {
            AevanError::Unsupported(format!("ESP packet layer: {error}"))
        }
        EspSessionError::Device(error) => AevanError::Network(format!("ESP device: {error}")),
        EspSessionError::Rekey { stage, source } => AevanError::Network(format!(
            "ESP rekey failed during {stage}: {source}; the tunnel is down"
        )),
    }
}

fn handshake_failure(attempt: &HandshakeAttempt) -> AevanError {
    let status = match attempt.status {
        Some(byte) => format!("0x{byte:02x} (decimal {byte})"),
        None => "none".to_owned(),
    };
    let detail = attempt
        .failure
        .clone()
        .unwrap_or_else(|| "the gateway did not return a KMP 301 configuration".to_owned());
    tracing::error!(status = %status, detail = %detail, "oNCP handshake failed");
    AevanError::Unsupported(format!(
        "oNCP handshake failed after one attempt: status byte {status}; {detail}"
    ))
}

fn tun_error(error: TunError) -> AevanError {
    match error {
        TunError::Permission(message) => AevanError::Privilege(message.to_owned()),
        TunError::Unsupported(message) => AevanError::Unsupported(message.to_owned()),
        TunError::InvalidConfig(message) => AevanError::Config(message),
        TunError::Io(error) => AevanError::Io(error),
    }
}

/// Adapts the TUN device to the ESP session's packet interface.
struct TunEspDevice<'a> {
    inner: &'a mut Box<dyn Device>,
}

impl aevan_nc::EspDevice for TunEspDevice<'_> {
    fn interface_name(&self) -> Option<&str> {
        self.inner.name()
    }

    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.inner.recv(buffer) {
            Ok(length) => Ok(Some(length)),
            Err(TunError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(None)
            }
            Err(TunError::Io(error)) => Err(error),
            Err(error @ TunError::Unsupported(_)) => {
                Err(io::Error::new(io::ErrorKind::NotFound, error))
            }
            Err(error) => Err(io::Error::other(error)),
        }
    }

    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.inner
            .send(packet)
            .map(|_| ())
            .map_err(io::Error::other)
    }

    fn wait_handle(&self) -> Option<isize> {
        self.inner.wait_handle()
    }
}

/// Adapts a reader-thread queue plus the device's write side to the ESP
/// session.
///
/// The descriptor is read only by [`aevan_tun::platform::DeviceReader`]; this
/// adapter is the non-blocking consumer. Writes stay synchronous on the loop
/// thread and drop a packet rather than blocking the data plane when the
/// device's queue is full.
#[cfg(unix)]
struct ChannelEspDevice<'a> {
    inner: &'a mut Box<dyn Device>,
    reader: &'a mut aevan_tun::platform::DeviceReader,
}

#[cfg(unix)]
impl aevan_nc::EspDevice for ChannelEspDevice<'_> {
    fn recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        match self.reader.try_recv() {
            Some(packet) => {
                if packet.len() > buffer.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "tunnel packet of {} bytes exceeds the {}-byte device buffer",
                            packet.len(),
                            buffer.len()
                        ),
                    ));
                }
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok(Some(packet.len()))
            }
            None if self.reader.is_dead() => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the tunnel device reader stopped",
            )),
            None => Ok(None),
        }
    }

    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        for attempt in 0..2 {
            match self.inner.send(packet) {
                Ok(_) => return Ok(()),
                Err(TunError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    if attempt == 0 {
                        continue;
                    }
                    return Err(error);
                }
                Err(TunError::Io(error)) if would_block(&error) && attempt == 0 => {
                    std::thread::sleep(DEVICE_WRITE_RETRY_DELAY);
                }
                Err(TunError::Io(error)) if would_block(&error) => {
                    tracing::warn!(
                        interface = %self.reader.interface(),
                        fd = ?self.reader.fd(),
                        %error,
                        "tunnel device write would block; dropping the packet"
                    );
                    return Ok(());
                }
                Err(TunError::Io(error)) => return Err(error),
                Err(error) => return Err(io::Error::other(error)),
            }
        }
        Ok(())
    }

    fn wait_handle(&self) -> Option<isize> {
        // The reader owns the descriptor; the ESP loop must not poll it.
        None
    }

    fn device_fd(&self) -> Option<isize> {
        self.reader.fd()
    }

    fn interface_name(&self) -> Option<&str> {
        Some(self.reader.interface())
    }
}

#[cfg(unix)]
fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Owns the rollback session, the device and the journal.
struct ConnectGuard {
    session: Option<Session<Box<dyn Applier>>>,
    device: Option<Box<dyn Device>>,
    journal: Option<Journal>,
}

impl ConnectGuard {
    fn new(
        device: Option<Box<dyn Device>>,
        session: Session<Box<dyn Applier>>,
        journal: Option<Journal>,
    ) -> Self {
        Self {
            session: Some(session),
            device,
            journal,
        }
    }

    /// Apply every planned change, recording it in the journal first.
    fn apply_plan(&mut self, plan: &ApplyPlan) -> AevanResult<()> {
        let Self {
            session, journal, ..
        } = self;
        let Some(session) = session.as_mut() else {
            return Err(AevanError::Config("connect teardown already ran".into()));
        };
        for mut change in plan.changes() {
            // Capture the old DNS servers and the selected mechanism before
            // the journal write, so a hard kill can revert exactly.
            session.prepare(&mut change).map_err(tun_error)?;
            if let Some(journal) = journal.as_mut() {
                journal.record(&change)?;
            }
            let step = apply::step_name(&change);
            if let Err(error) = session.apply(change) {
                if let Some(journal) = journal.as_mut() {
                    let _ = journal.forget_last();
                }
                return Err(AevanError::Unsupported(format!(
                    "apply step '{step}' failed: {error}"
                )));
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn device_ref(&self) -> AevanResult<&dyn Device> {
        self.device
            .as_deref()
            .ok_or_else(|| AevanError::Config("connect has no open device".into()))
    }

    fn device_mut(&mut self) -> AevanResult<&mut Box<dyn Device>> {
        self.device
            .as_mut()
            .ok_or_else(|| AevanError::Config("connect has no open device".into()))
    }

    /// Roll back every applied change, close the device, then delete the
    /// journal. A failed rollback keeps the journal for the next daemon start.
    fn teardown(&mut self) -> AevanResult<()> {
        let mut first_error = None;
        let mut rollback_ok = true;
        if let Some(mut session) = self.session.take() {
            if let Err(error) = session.rollback() {
                rollback_ok = false;
                first_error = Some(tun_error(error));
            }
        }
        if let Some(mut device) = self.device.take() {
            if let Err(error) = device.close() {
                if first_error.is_none() {
                    first_error = Some(tun_error(error));
                }
            }
        }
        if rollback_ok {
            if let Some(journal) = self.journal.take() {
                if let Err(error) = journal.remove() {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_assigned_interface_name_wins_over_the_configured_one() {
        // macOS hands out the next free utun unit, so configuring the
        // requested name would configure an interface we do not own.
        assert_eq!(resolve_interface(Some("utun5"), "utun0"), "utun5");
        assert_eq!(resolve_interface(None, "utun0"), "utun0");
        assert_eq!(resolve_interface(Some("aevan"), "aevan"), "aevan");
    }

    use super::*;
    use std::cell::{Cell, RefCell};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::rc::Rc;

    use aevan_tun::{RollbackBackend, Route, RouteRecord};

    const KMP_301: &[u8] = include_bytes!("../../aevan-nc/tests/fixtures/ncp-config-kmp.bin");

    fn ncp() -> NcpConfig {
        NcpConfig::parse_binary(KMP_301).expect("fixture config")
    }

    #[derive(Clone, Default)]
    struct RecordingApplier {
        applied: Rc<RefCell<Vec<Change>>>,
        journal_path: Option<PathBuf>,
        saw_journal: Rc<Cell<bool>>,
    }

    impl RollbackBackend for RecordingApplier {
        fn apply(&mut self, change: &Change) -> Result<(), TunError> {
            if let Some(path) = &self.journal_path {
                if matches!(change, Change::SetAddr { .. }) {
                    self.saw_journal.set(path.exists());
                }
            }
            self.applied.borrow_mut().push(change.clone());
            Ok(())
        }
    }

    impl Applier for RecordingApplier {
        fn backend_name(&self) -> &'static str {
            "test-recording"
        }
    }

    fn sample_plan() -> ApplyPlan {
        let config = ncp();
        ApplyPlan::from_ncp(&config, "aevan".into()).expect("plan")
    }

    fn temp_path(label: &str) -> (PathBuf, PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aevan-connector-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("aevand.journal");
        (dir, path)
    }

    #[test]
    fn the_disable_rekey_switch_removes_the_rekey_policy() {
        let policy = RekeyPolicy::new(Some(1200), Some(64 * 1024 * 1024), 240, 0);
        assert_eq!(
            effective_rekey_policy(policy, true),
            RekeyPolicy::new(None, None, 0, 0)
        );
        assert_eq!(effective_rekey_policy(policy, false), policy);
        assert!(disable_rekey_requested(Some("1")));
        assert!(disable_rekey_requested(Some(" 1 ")));
        assert!(!disable_rekey_requested(Some("0")));
        assert!(!disable_rekey_requested(None));
    }

    #[test]
    fn the_synthetic_configuration_produces_the_expected_plan() {
        let plan = sample_plan();
        assert_eq!(plan.mtu, Some(1396));
        assert_eq!(
            plan.address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43)))
        );
        assert_eq!(plan.routes.len(), 4);
        assert_eq!(plan.dns.len(), 2);
        assert_eq!(plan.device, "aevan");
    }

    #[test]
    fn esp_setup_sends_302_then_303_and_keeps_keys_redacted() {
        let mut config = ncp();
        config.esp.as_mut().expect("ESP proposal").lifetime_seconds = Some(3600);
        let mut sent = Vec::new();
        let setup = EspSetup::negotiate(&config, &mut |bytes| {
            sent.push(bytes.to_vec());
            Ok(())
        })
        .expect("setup");

        assert_eq!(sent.len(), 2);
        let negotiation = aevan_nc::KmpFrame::parse_outbound(&sent[0]).expect("302");
        assert_eq!(negotiation.number, 302);
        assert_eq!(negotiation.payload.len(), 86);
        let reply = aevan_nc::KmpFrame::parse_outbound(&sent[1]).expect("303");
        assert_eq!(reply.number, 303);
        assert_eq!(setup.udp_port, 4500);
        assert_eq!(setup.material.outbound_spi, 0x1a2b_3c4d);
        // The fixture advertises a 3600 s lifetime; rekey starts at 80 percent.
        assert_eq!(setup.rekey_policy.lifetime_seconds, Some(3600));
        assert_eq!(setup.rekey_policy.margin_seconds, 720);
        assert_eq!(setup.rekey_grace, Duration::from_secs(30));
        assert_eq!(setup.mtu, 1396);

        let debug = format!("{:?}", setup.material);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("0, 1, 2, 3"));
    }

    #[test]
    fn the_journal_exists_before_the_first_apply_and_is_removed_after_teardown() {
        let (dir, path) = temp_path("ordering");
        let journal = Journal::create(path.clone(), "aevan").expect("journal");
        let applier = RecordingApplier {
            journal_path: Some(path.clone()),
            ..RecordingApplier::default()
        };
        let applied = applier.applied.clone();
        let saw_journal = applier.saw_journal.clone();

        let mut guard = ConnectGuard::new(None, Session::new(Box::new(applier)), Some(journal));
        guard.apply_plan(&sample_plan()).expect("apply");
        assert!(
            saw_journal.get(),
            "the journal must be on disk before apply"
        );
        assert!(path.exists());
        assert!(!applied.borrow().is_empty());

        guard.teardown().expect("teardown");
        assert!(!path.exists(), "clean teardown removes the journal");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[derive(Clone, Default)]
    struct ConflictApplier {
        applied: Rc<RefCell<Vec<Change>>>,
    }

    impl RollbackBackend for ConflictApplier {
        fn prepare(&mut self, change: &mut Change) -> Result<(), TunError> {
            if let Change::AddRoute(route) = change {
                *change = Change::ReplaceRoute {
                    route: route.clone(),
                    displaced: RouteRecord {
                        destination: route.destination,
                        prefix_len: route.prefix_len,
                        gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                        interface: "en0".into(),
                        flags: "UP,GATEWAY,DONE,STATIC".into(),
                        metric: 0,
                    },
                    restore: false,
                };
            }
            Ok(())
        }

        fn apply(&mut self, change: &Change) -> Result<(), TunError> {
            self.applied.borrow_mut().push(change.clone());
            Ok(())
        }
    }

    impl Applier for ConflictApplier {
        fn backend_name(&self) -> &'static str {
            "test-conflict"
        }
    }

    #[test]
    fn a_conflicting_route_is_journalled_before_it_is_replaced() {
        let (dir, path) = temp_path("conflict");
        let journal = Journal::create(path.clone(), "aevan").expect("journal");
        let applier = ConflictApplier::default();
        let mut guard = ConnectGuard::new(None, Session::new(Box::new(applier)), Some(journal));
        let route = Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route");
        let plan = ApplyPlan {
            device: "aevan".into(),
            address: None,
            prefix_len: 0,
            mtu: None,
            routes: vec![route],
            dns: Vec::new(),
        };

        guard.apply_plan(&plan).expect("apply");
        let document = crate::journal::load(&path).expect("load journal");
        let recorded = document
            .changes
            .iter()
            .find_map(|change| match change {
                crate::journal::JournalChange::ReplaceRoute { displaced, .. } => Some(displaced),
                _ => None,
            })
            .expect("the displaced route must be journalled");
        assert_eq!(recorded.interface, "en0");
        assert_eq!(recorded.flags, "UP,GATEWAY,DONE,STATIC");
        assert_eq!(
            recorded.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        guard.teardown().expect("teardown");
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn teardown_restores_dns_routes_mtu_then_address() {
        let applier = RecordingApplier::default();
        let applied = applier.applied.clone();
        let mut guard = ConnectGuard::new(None, Session::new(Box::new(applier)), None);
        let route = Route::on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("route");
        let dns = vec![IpAddr::V4(Ipv4Addr::new(10, 251, 3, 18))];
        let plan = ApplyPlan {
            device: "aevan".into(),
            address: Some(IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43))),
            prefix_len: 32,
            mtu: Some(1396),
            routes: vec![route.clone()],
            dns: dns.clone(),
        };

        guard.apply_plan(&plan).expect("apply");
        guard.teardown().expect("teardown");

        let applied = applied.borrow().clone();
        assert_eq!(applied.len(), 8, "four forward and four inverse changes");
        assert_eq!(
            applied[4],
            Change::SetDns {
                old: dns,
                new: Vec::new(),
                context: aevan_tun::DnsContext::Unspecified,
            }
        );
        assert_eq!(applied[5], Change::RemoveRoute(route));
        assert_eq!(
            applied[6],
            Change::SetMtu {
                old: Some(1396),
                new: None
            }
        );
        assert_eq!(
            applied[7],
            Change::SetAddr {
                old: Some((IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43)), 32)),
                new: None
            }
        );
    }

    #[cfg(unix)]
    mod blocking_reader {
        use super::*;
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Condvar, Mutex};
        use std::thread;
        use std::time::Instant;

        use aevan_nc::{
            EspAuthentication, EspDevice, EspEncryption, EspKeys, EspSessionMaterial, EspUdp,
            RekeyPolicy, SecretKey, ESP_IV_LEN,
        };
        use aevan_tun::platform::reader::PacketSource;
        use aevan_tun::NoopBackend;

        fn keys(encryption_byte: u8, hmac_byte: u8) -> EspKeys {
            EspKeys::new(
                EspEncryption::Aes128Cbc,
                EspAuthentication::HmacSha1,
                SecretKey::new(vec![encryption_byte; 16]),
                SecretKey::new(vec![hmac_byte; 20]),
            )
            .expect("test keys")
        }

        fn material() -> EspSessionMaterial {
            EspSessionMaterial {
                outbound_spi: 0x1111_2222,
                outbound_keys: keys(0x10, 0x20),
                inbound_spi: 0x3333_4444,
                inbound_keys: keys(0x30, 0x40),
            }
        }

        fn ipv4_packet(marker: u8) -> Vec<u8> {
            vec![
                0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0,
                marker, 10, 0, 0, 2,
            ]
        }

        #[cfg(target_os = "macos")]
        fn framed(packet: &[u8]) -> Vec<u8> {
            let mut frame = 2u32.to_be_bytes().to_vec();
            frame.extend_from_slice(packet);
            frame
        }

        #[cfg(not(target_os = "macos"))]
        fn framed(packet: &[u8]) -> Vec<u8> {
            packet.to_vec()
        }

        /// A device source that yields its queued packets and then blocks until
        /// shutdown wakes it.
        struct BlockingDevice {
            packets: Mutex<VecDeque<Vec<u8>>>,
            stopped: Arc<(Mutex<bool>, Condvar)>,
        }

        impl BlockingDevice {
            fn new(packets: Vec<Vec<u8>>) -> Self {
                Self {
                    packets: Mutex::new(packets.into()),
                    stopped: Arc::new((Mutex::new(false), Condvar::new())),
                }
            }
        }

        impl PacketSource for BlockingDevice {
            fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if let Some(packet) = self.packets.lock().expect("packets").pop_front() {
                    assert!(packet.len() <= buffer.len());
                    buffer[..packet.len()].copy_from_slice(&packet);
                    return Ok(packet.len());
                }
                let (lock, condition) = &*self.stopped;
                let mut stopped = lock.lock().expect("stopped");
                while !*stopped {
                    stopped = condition.wait(stopped).expect("stopped wait");
                }
                Ok(0)
            }

            fn wake_handle(&self) -> Box<dyn Fn() + Send + Sync> {
                let stopped = Arc::clone(&self.stopped);
                Box::new(move || {
                    let (lock, condition) = &*stopped;
                    *lock.lock().expect("stopped") = true;
                    condition.notify_all();
                })
            }
        }

        struct CountingUdp {
            sent: Arc<AtomicUsize>,
        }

        impl EspUdp for CountingUdp {
            fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
                self.sent.fetch_add(1, Ordering::SeqCst);
                Ok(packet.len())
            }

            fn recv(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        }

        struct StopAfter {
            sent: Arc<AtomicUsize>,
            target: usize,
        }

        impl TunnelControl for StopAfter {
            fn should_stop(&self) -> bool {
                self.sent.load(Ordering::SeqCst) >= self.target
            }
        }

        #[test]
        fn the_esp_loop_drains_both_channel_packets_without_waiting_for_the_reader() {
            let source =
                BlockingDevice::new(vec![framed(&ipv4_packet(1)), framed(&ipv4_packet(2))]);
            let mut reader = aevan_tun::platform::DeviceReader::spawn_source(
                Box::new(source),
                "utun-test".to_owned(),
                Some(11),
            )
            .expect("reader");

            let now = Instant::now();
            let mut session = EspSession::new(
                material(),
                [0x5a; ESP_IV_LEN],
                EspSessionConfig {
                    keepalive_interval_seconds: 30,
                    peer_timeout: Duration::from_secs(90),
                    rekey_policy: RekeyPolicy::new(None, None, 0, 0),
                    rekey_grace: Duration::from_secs(60),
                    mtu: 1396,
                },
                now,
            );
            let sent = Arc::new(AtomicUsize::new(0));
            let mut udp = CountingUdp {
                sent: Arc::clone(&sent),
            };
            let control = StopAfter {
                sent: Arc::clone(&sent),
                target: 2,
            };
            let mut device: Box<dyn Device> = Box::new(NoopBackend::default());

            let started = Instant::now();
            {
                let mut adapter = ChannelEspDevice {
                    inner: &mut device,
                    reader: &mut reader,
                };
                run_esp(&mut session, &mut udp, &mut adapter, &control).expect("ESP loop");
            }
            assert_eq!(sent.load(Ordering::SeqCst), 2, "both packets were sent");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the loop must not wait for the reader's blocking read"
            );

            let shutdown = Instant::now();
            assert!(reader.shutdown(), "shutdown must join the reader");
            assert!(
                shutdown.elapsed() < aevan_tun::platform::reader::JOIN_TIMEOUT,
                "the reader must stop promptly"
            );
        }

        #[test]
        fn an_empty_channel_is_quiet_and_a_stopped_reader_is_reported() {
            let source = BlockingDevice::new(Vec::new());
            let mut reader = aevan_tun::platform::DeviceReader::spawn_source(
                Box::new(source),
                "utun-test".to_owned(),
                None,
            )
            .expect("reader");
            // Force the reader to finish without a packet.
            reader.shutdown();

            let mut device: Box<dyn Device> = Box::new(NoopBackend::default());
            let mut adapter = ChannelEspDevice {
                inner: &mut device,
                reader: &mut reader,
            };
            let mut buffer = [0u8; 2048];
            let result = adapter.recv(&mut buffer);
            let quiet_or_stopped = match &result {
                Ok(None) => true,
                Err(error) => error.kind() == io::ErrorKind::BrokenPipe,
                Ok(Some(_)) => false,
            };
            assert!(
                quiet_or_stopped,
                "an empty queue is either quiet or reports the stopped reader"
            );
        }

        #[test]
        fn the_channel_adapter_copies_a_queued_packet() {
            let packet = ipv4_packet(9);
            let source = BlockingDevice::new(vec![framed(&packet)]);
            let mut reader = aevan_tun::platform::DeviceReader::spawn_source(
                Box::new(source),
                "utun-test".to_owned(),
                None,
            )
            .expect("reader");
            let mut device: Box<dyn Device> = Box::new(NoopBackend::default());
            let mut adapter = ChannelEspDevice {
                inner: &mut device,
                reader: &mut reader,
            };
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut buffer = [0u8; 2048];
            let mut received = None;
            while Instant::now() < deadline && received.is_none() {
                match adapter.recv(&mut buffer) {
                    Ok(Some(length)) => received = Some(buffer[..length].to_vec()),
                    Ok(None) => thread::sleep(Duration::from_millis(1)),
                    Err(error) => panic!("adapter read failed: {error}"),
                }
            }
            assert_eq!(received.as_deref(), Some(packet.as_slice()));
            assert!(reader.shutdown());
        }
    }

    #[test]
    fn a_panic_inside_the_connect_body_still_rolls_back() {
        let applier = RecordingApplier::default();
        let applied = applier.applied.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = ConnectGuard::new(None, Session::new(Box::new(applier)), None);
            let plan = ApplyPlan {
                device: "aevan".into(),
                address: Some(IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43))),
                prefix_len: 24,
                mtu: Some(1396),
                routes: Vec::new(),
                dns: Vec::new(),
            };
            guard.apply_plan(&plan).expect("apply");
            panic!("simulated panic in the connect body");
        }));

        assert!(result.is_err(), "the panic must propagate");
        let applied = applied.borrow().clone();
        assert_eq!(applied.len(), 4, "two forward and two inverse changes");
        assert_eq!(
            applied[2],
            Change::SetMtu {
                old: Some(1396),
                new: None
            }
        );
        assert_eq!(
            applied[3],
            Change::SetAddr {
                old: Some((IpAddr::V4(Ipv4Addr::new(10, 251, 98, 43)), 24)),
                new: None
            }
        );
    }
}
