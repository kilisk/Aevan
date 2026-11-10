//! Bridge between the per-user single-instance endpoint and `iced`.
//!
//! The endpoint lives in `aevan-instance`. This module owns the one bounded
//! channel that turns a `show` line into an `iced` message, in the same style
//! the tray uses. Nothing here creates a window or a tray icon.

use std::sync::OnceLock;

use iced::futures::{SinkExt, Stream};
use tokio::sync::broadcast;

use crate::app::Message;

static EVENTS: OnceLock<broadcast::Sender<()>> = OnceLock::new();

fn events() -> &'static broadcast::Sender<()> {
    EVENTS.get_or_init(|| broadcast::channel(8).0)
}

/// Ask the application to raise and focus its window.
pub fn send_show() {
    let _ = events().send(());
}

/// The subscription that delivers `show` requests into `iced`.
pub fn subscription() -> iced::Subscription<Message> {
    iced::Subscription::run(stream)
}

fn stream() -> impl Stream<Item = Message> {
    let mut receiver = events().subscribe();
    iced::stream::channel(
        8,
        move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
            loop {
                match receiver.recv().await {
                    Ok(()) => {
                        if output.send(Message::InstanceShowRequested).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        },
    )
}

/// Claim the platform endpoint. A `Secondary` result means the caller must
/// exit without creating a window or tray.
pub fn claim_and_serve() -> std::io::Result<aevan_instance::InstanceRole> {
    aevan_instance::claim_and_serve(Box::new(send_show))
}
