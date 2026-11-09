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
    EspLocalKeys, EspSession, EspSessionConfig, EspSessionError, EspSessionMaterial, EspUdp,
    HandshakeAttempt, KmpMessageOwned, NcpConfig, RekeyPolicy, UdpEspTransport, KMP_CONFIG,
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

/// Fallback ESP UDP port when KMP 301 group 8 attr 4 is absent.
const DEFAULT_ESP_PORT: u16 = 4500;

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

    // Create the journal before the first change. Until changes are recorded it
    // is empty, so a crash at this point recovers by doing nothing.
    let mut journal = match journal_path {
        Some(path) => Some(Journal::create(path.to_owned(), plan.device.clone())?),
        None => None,
    };

    let mut device = match platform::open(plan.device_config()) {
        Ok(device) => device,
        Err(error) => {
            if let Some(journal) = journal.take() {
                let _ = journal.remove();
            }
            return Err(tun_error(error));
        }
    };
    let applier = match apply::platform_applier(Box::new(RealCommandRunner), &plan.device) {
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

    let run = {
        let mut adapter = TunEspDevice {
            inner: guard.device_mut()?,
        };
        run_esp(&mut esp_session, &mut transport, &mut adapter, control)
    };
    control.stats(esp_session.bytes_received(), esp_session.bytes_sent());

    let teardown = guard.teardown();
    match (run, teardown) {
        (Err(error), _) => Err(esp_session_error(error)),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
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

    loop {
        if control.should_stop() {
            return Ok(());
        }
        let worked = session.poll_once(udp, device, Instant::now())?;
        control.stats(session.bytes_received(), session.bytes_sent());
        if !worked {
            // Nothing was ready. Wait for either the socket or the device, with
            // a bounded timeout so keepalives, rekey timers and the stop flag
            // are still serviced.
            if sources.udp.is_some() || sources.device.is_some() {
                if let Err(error) = platform::wait_readable(sources, ESP_IDLE_TIMEOUT) {
                    tracing::debug!(%error, "ESP readiness wait failed; using a bounded sleep");
                    std::thread::sleep(ESP_IDLE_TIMEOUT);
                }
            } else {
                std::thread::sleep(ESP_IDLE_TIMEOUT);
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
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::rc::Rc;

    use aevan_tun::{RollbackBackend, Route};

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
