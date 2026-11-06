//! In-process tracing capture for the control protocol's `logs` command.
//!
//! The daemon installs [`LogLayer`] as a tracing subscriber layer. Records are
//! kept in a bounded ring for `logs` without `--follow` and broadcast to live
//! followers. Sensitive field names are redacted before a record leaves the
//! subscriber.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::protocol::LogRecord;
use crate::state::unix_now;

/// Number of records kept for a non-following `logs` request.
const HISTORY_CAPACITY: usize = 500;
/// Broadcast capacity for live followers.
const BROADCAST_CAPACITY: usize = 256;

/// A log severity, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Error.
    Error,
    /// Warning.
    Warn,
    /// Informational.
    Info,
    /// Debug.
    Debug,
    /// Trace.
    Trace,
}

impl Level {
    /// Parse a user-provided level name.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    fn from_tracing(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    pub(crate) fn parse_name(name: &str) -> Self {
        match name {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => Self::Info,
        }
    }
}

struct HubInner {
    next_seq: u64,
    history: VecDeque<LogRecord>,
}

/// Shared log buffer and broadcast channel.
#[derive(Clone)]
pub struct LogHub {
    inner: Arc<Mutex<HubInner>>,
    sender: broadcast::Sender<LogRecord>,
}

impl Default for LogHub {
    fn default() -> Self {
        Self::new()
    }
}

impl LogHub {
    /// An empty hub.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                next_seq: 1,
                history: VecDeque::with_capacity(HISTORY_CAPACITY),
            })),
            sender,
        }
    }

    /// Subscribe before reading history so no live record is missed.
    pub fn subscribe(&self) -> broadcast::Receiver<LogRecord> {
        self.sender.subscribe()
    }

    /// Records at or above `min` in severity, oldest first.
    pub fn history(&self, min: Level) -> Vec<LogRecord> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .history
            .iter()
            .filter(|record| Level::parse_name(&record.level) <= min)
            .cloned()
            .collect()
    }

    /// Add one record.
    pub fn record(&self, level: Level, target: &str, message: String) {
        let record = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let seq = inner.next_seq;
            inner.next_seq = inner.next_seq.saturating_add(1);
            let record = LogRecord {
                seq,
                timestamp_unix: unix_now(),
                level: level.as_str().to_owned(),
                target: target.to_owned(),
                message,
            };
            inner.history.push_back(record.clone());
            while inner.history.len() > HISTORY_CAPACITY {
                inner.history.pop_front();
            }
            record
        };
        let _ = self.sender.send(record);
    }
}

/// Tracing layer that feeds a [`LogHub`].
pub struct LogLayer {
    hub: LogHub,
}

impl LogLayer {
    /// Build a layer writing into `hub`.
    pub fn new(hub: LogHub) -> Self {
        Self { hub }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        self.hub.record(
            Level::from_tracing(metadata.level()),
            metadata.target(),
            visitor.render(),
        );
    }
}

#[derive(Default)]
struct Visitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl Visitor {
    fn push(&mut self, name: &str, value: String) {
        if name == "message" {
            self.message = value;
        } else if aevan_core::redact::is_sensitive_key(name) {
            self.fields
                .push((name.to_owned(), aevan_core::redact::REDACTED.to_owned()));
        } else {
            self.fields.push((name.to_owned(), value));
        }
    }

    fn render(&self) -> String {
        if self.fields.is_empty() {
            return self.message.clone();
        }
        let fields = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        if self.message.is_empty() {
            fields
        } else {
            format!("{} {fields}", self.message)
        }
    }
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), value.to_owned());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_and_order() {
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("nonsense"), None);
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
    }

    #[test]
    fn history_is_bounded_and_filtered() {
        let hub = LogHub::new();
        hub.record(Level::Info, "test", "visible".into());
        hub.record(Level::Debug, "test", "hidden".into());

        let info = hub.history(Level::Info);
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].message, "visible");
        assert_eq!(info[0].seq, 1);

        let all = hub.history(Level::Trace);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn subscribers_receive_new_records() {
        let hub = LogHub::new();
        let mut receiver = hub.subscribe();
        hub.record(Level::Info, "test", "live".into());
        let record = receiver.try_recv().expect("record");
        assert_eq!(record.message, "live");
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let hub = LogHub::new();
        hub.record(Level::Info, "test", "one".into());
        hub.record(Level::Info, "test", "two".into());
        let history = hub.history(Level::Info);
        assert_eq!(history[0].seq, 1);
        assert_eq!(history[1].seq, 2);
    }
}
