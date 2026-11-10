//! System tray / menu-bar integration for `aevan-gui`.
//!
//! Windows and macOS expose the same menu (Status, Connect, Disconnect, Show
//! window, Quit) and forward clicks through one channel into the `iced`
//! [`Subscription`].
//!
//! * **Windows:** the tray runs on a dedicated `tao` event-loop thread, so tray
//!   messages never enter (or block) the `iced` event loop.
//! * **macOS:** an `NSStatusItem` must be created on the main thread, and iced
//!   owns the only event loop. The status item is built during iced setup and
//!   the returned [`Handle`] is stored by the app; menu events still arrive
//!   through the shared channel.
//! * **Linux:** deliberately tray-free. Shipping a tray would require
//!   GTK/libappindicator or a StatusNotifier host, which this project does not
//!   depend on. Linux users get the window-only client. `docs/GUI.md` records
//!   this choice.
//!
//! Tray creation is best-effort. If the platform refuses the icon (headless
//! session, missing permission, API refusal) the app logs once at info and
//! continues window-only.

use iced::Subscription;

use crate::app::Message;
use crate::view_model::TrayMenuState;

/// Events the tray forwards into the `iced` application.
///
/// Linux never constructs these; the `Message` variant carries the same
/// allowance.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayEvent {
    /// Left-click: open or focus the window.
    ShowWindow,
    /// Open the connect sheet and focus the window.
    Connect,
    /// Ask the daemon to disconnect.
    Disconnect,
    /// Close the application.
    Quit,
    /// A tray callback panicked; the message becomes a banner.
    InternalPanic(String),
}

/// A live tray, or an empty handle when the platform declined to create one.
///
/// The application stores this value for its lifetime. On macOS dropping it
/// removes the status item, which is why ownership lives in the app state.
pub struct Handle {
    #[cfg(target_os = "macos")]
    backend: macos::Handle,
}

/// Start the tray. Safe to call once on the main thread during setup.
///
/// Returns a handle even when no tray is available, so startup can never fail
/// because of the tray.
pub fn start() -> Handle {
    #[cfg(target_os = "macos")]
    {
        Handle {
            backend: macos::start(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(windows)]
        backend::start();
        Handle {}
    }
}

#[cfg(test)]
impl Handle {
    /// A handle that owns no platform tray, for offline app tests.
    pub fn for_test() -> Self {
        #[cfg(target_os = "macos")]
        {
            Handle {
                backend: macos::test_handle(),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Handle {}
        }
    }
}

impl Handle {
    /// Push the current menu enablement and status into the tray.
    pub fn sync(&self, state: &TrayMenuState) {
        #[cfg(windows)]
        backend::sync(state);
        #[cfg(target_os = "macos")]
        self.backend.sync(state);
        #[cfg(not(any(windows, target_os = "macos")))]
        let _ = state;
    }
}

/// The channel-backed tray subscription.
pub fn subscription() -> Subscription<Message> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        channel::subscription()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Subscription::none()
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod channel {
    use std::sync::OnceLock;

    use iced::futures::{SinkExt, Stream};
    use tokio::sync::broadcast;

    use super::TrayEvent;
    use crate::app::Message;

    static EVENTS: OnceLock<broadcast::Sender<TrayEvent>> = OnceLock::new();

    fn events() -> &'static broadcast::Sender<TrayEvent> {
        EVENTS.get_or_init(|| broadcast::channel(32).0)
    }

    pub fn send(event: TrayEvent) {
        let _ = events().send(event);
    }

    /// Turn a caught tray panic into a banner message.
    pub fn report_panic(payload: Box<dyn std::any::Any + Send>) {
        let detail = if let Some(text) = payload.downcast_ref::<&str>() {
            (*text).to_owned()
        } else if let Some(text) = payload.downcast_ref::<String>() {
            text.clone()
        } else {
            "an unknown panic".to_owned()
        };
        tracing::error!(%detail, "a tray callback panicked");
        let _ = events().send(TrayEvent::InternalPanic(detail));
    }

    pub fn subscription() -> iced::Subscription<Message> {
        iced::Subscription::run(stream)
    }

    fn stream() -> impl Stream<Item = Message> {
        let mut receiver = events().subscribe();
        iced::stream::channel(16, move |mut output| async move {
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        if output.send(Message::Tray(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }
}

#[cfg(windows)]
mod backend {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, OnceLock};

    use tao::event::{Event, StartCause};
    use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
    use tao::platform::windows::EventLoopBuilderExtWindows;
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    use super::channel;
    use super::TrayEvent;
    use crate::view_model::TrayMenuState;

    const STATUS_ID: &str = "aevan.status";
    const CONNECT_ID: &str = "aevan.connect";
    const DISCONNECT_ID: &str = "aevan.disconnect";
    const SHOW_ID: &str = "aevan.show";
    const QUIT_ID: &str = "aevan.quit";

    /// The Aevan tray glyph, embedded so the binary has no runtime asset path.
    const ICON_PNG: &[u8] = include_bytes!("../assets/aevan.png");

    #[derive(Clone)]
    enum Command {
        Sync(TrayMenuState),
    }

    static STARTED: AtomicBool = AtomicBool::new(false);
    static PROXY: OnceLock<EventLoopProxy<Command>> = OnceLock::new();
    static LAST_STATE: Mutex<Option<TrayMenuState>> = Mutex::new(None);

    pub fn start() {
        if STARTED.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = std::thread::Builder::new()
            .name("aevan-tray".to_owned())
            .spawn(|| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
                if let Err(payload) = result {
                    channel::report_panic(payload);
                }
            });
    }

    pub fn sync(state: &TrayMenuState) {
        if let Ok(mut last) = LAST_STATE.lock() {
            *last = Some(state.clone());
        }
        if let Some(proxy) = PROXY.get() {
            let _ = proxy.send_event(Command::Sync(state.clone()));
        }
    }

    fn run() {
        let mut builder = EventLoopBuilder::<Command>::with_user_event();
        builder.with_any_thread(true).with_dpi_aware(false);
        let event_loop = builder.build();
        let proxy = event_loop.create_proxy();
        let _ = PROXY.set(proxy);

        let status = MenuItem::with_id(
            STATUS_ID,
            "Status: starting",
            false,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let connect = MenuItem::with_id(
            CONNECT_ID,
            "Connect",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let disconnect = MenuItem::with_id(
            DISCONNECT_ID,
            "Disconnect",
            false,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let show = MenuItem::with_id(
            SHOW_ID,
            "Show window",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let quit = MenuItem::with_id(
            QUIT_ID,
            "Quit",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );

        let menu = Menu::new();
        let _ = menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &connect,
            &disconnect,
            &PredefinedMenuItem::separator(),
            &show,
            &quit,
        ]);

        let mut builder = TrayIconBuilder::new()
            .with_id("aevan")
            .with_tooltip("Aevan — disconnected")
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false);
        if let Some(icon) = load_icon() {
            builder = builder.with_icon(icon);
        }
        let tray = match builder.build() {
            Ok(tray) => tray,
            Err(_) => return,
        };

        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let id = event.id().0.as_str();
                match id {
                    CONNECT_ID => channel::send(TrayEvent::Connect),
                    DISCONNECT_ID => channel::send(TrayEvent::Disconnect),
                    SHOW_ID => channel::send(TrayEvent::ShowWindow),
                    QUIT_ID => channel::send(TrayEvent::Quit),
                    _ => {}
                }
            }));
            if let Err(payload) = result {
                channel::report_panic(payload);
            }
        }));
        TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    channel::send(TrayEvent::ShowWindow);
                }
            }));
            if let Err(payload) = result {
                channel::report_panic(payload);
            }
        }));

        if let Ok(last) = LAST_STATE.lock() {
            if let Some(state) = last.as_ref() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    apply(&tray, &status, &connect, &disconnect, state);
                }));
                if let Err(payload) = result {
                    channel::report_panic(payload);
                }
            }
        }

        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::NewEvents(StartCause::Init) => {}
                Event::UserEvent(Command::Sync(state)) => {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        apply(&tray, &status, &connect, &disconnect, &state);
                    }));
                    if let Err(payload) = result {
                        channel::report_panic(payload);
                    }
                }
                _ => {}
            }
        });
    }

    fn apply(
        tray: &tray_icon::TrayIcon,
        status: &MenuItem,
        connect: &MenuItem,
        disconnect: &MenuItem,
        state: &TrayMenuState,
    ) {
        status.set_text(format!("Status: {}", state.status));
        connect.set_enabled(state.connect_enabled);
        disconnect.set_enabled(state.disconnect_enabled);
        let _ = tray.set_tooltip(Some(format!("Aevan — {}", state.status)));
    }

    fn load_icon() -> Option<tray_icon::Icon> {
        use std::io::Cursor;

        let decoder = png::Decoder::new(Cursor::new(ICON_PNG));
        let mut reader = decoder.read_info().ok()?;
        let mut buffer = vec![0; reader.output_buffer_size()?];
        let info = reader.next_frame(&mut buffer).ok()?;
        let bytes = &buffer[..info.buffer_size()];
        tray_icon::Icon::from_rgba(bytes.to_vec(), info.width, info.height).ok()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    use tracing::info;
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{TrayIcon, TrayIconBuilder};

    use super::channel;
    use super::TrayEvent;
    use crate::view_model::TrayMenuState;

    const STATUS_ID: &str = "aevan.status";
    const CONNECT_ID: &str = "aevan.connect";
    const DISCONNECT_ID: &str = "aevan.disconnect";
    const SHOW_ID: &str = "aevan.show";
    const QUIT_ID: &str = "aevan.quit";

    /// The Aevan tray glyph, embedded so the binary has no runtime asset path.
    const ICON_PNG: &[u8] = include_bytes!("../assets/aevan.png");
    /// The alpha-only menu-bar template, generated from the glyph at build
    /// time. macOS renders this in the menu-bar's own colour instead of as an
    /// opaque white block.
    const TEMPLATE_PNG: &[u8] = include_bytes!("../assets/aevan-template.png");

    struct Backend {
        /// Dropping the icon removes the status item, so the app owns it.
        tray: TrayIcon,
        status: MenuItem,
        connect: MenuItem,
        disconnect: MenuItem,
    }

    pub struct Handle {
        backend: Option<Rc<RefCell<Backend>>>,
    }

    #[cfg(test)]
    pub fn test_handle() -> Handle {
        Handle { backend: None }
    }

    pub fn start() -> Handle {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)) {
            Ok(Ok(backend)) => Handle {
                backend: Some(Rc::new(RefCell::new(backend))),
            },
            Ok(Err(error)) => {
                info!(%error, "cannot create the macOS menu-bar item; running window-only");
                Handle { backend: None }
            }
            Err(_) => {
                info!("the macOS menu-bar item panicked while being created; running window-only");
                Handle { backend: None }
            }
        }
    }

    impl Handle {
        pub fn sync(&self, state: &TrayMenuState) {
            let Some(backend) = self.backend.as_ref() else {
                return;
            };
            if let Ok(mut backend) = backend.try_borrow_mut() {
                apply(&mut backend, state);
            }
        }
    }

    fn build() -> Result<Backend, tray_icon::Error> {
        let status = MenuItem::with_id(
            STATUS_ID,
            "Status: starting",
            false,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let connect = MenuItem::with_id(
            CONNECT_ID,
            "Connect",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let disconnect = MenuItem::with_id(
            DISCONNECT_ID,
            "Disconnect",
            false,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let show = MenuItem::with_id(
            SHOW_ID,
            "Show window",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );
        let quit = MenuItem::with_id(
            QUIT_ID,
            "Quit",
            true,
            None::<tray_icon::menu::accelerator::Accelerator>,
        );

        let menu = Menu::new();
        let _ = menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &connect,
            &disconnect,
            &PredefinedMenuItem::separator(),
            &show,
            &quit,
        ]);

        let mut builder = TrayIconBuilder::new()
            .with_id("aevan")
            .with_tooltip("Aevan — disconnected")
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(true);
        if let Some(icon) = load_icon(TEMPLATE_PNG) {
            builder = builder.with_icon_templated(icon);
        } else if let Some(icon) = load_icon(ICON_PNG) {
            // Fallback: show the real colour artwork rather than a blank block.
            builder = builder.with_icon(icon);
        }
        let tray = builder.build()?;

        MenuEvent::set_event_handler(Some(|event: MenuEvent| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let id = event.id().0.as_str();
                match id {
                    CONNECT_ID => channel::send(TrayEvent::Connect),
                    DISCONNECT_ID => channel::send(TrayEvent::Disconnect),
                    SHOW_ID => channel::send(TrayEvent::ShowWindow),
                    QUIT_ID => channel::send(TrayEvent::Quit),
                    _ => {}
                }
            }));
            if let Err(payload) = result {
                channel::report_panic(payload);
            }
        }));

        Ok(Backend {
            tray,
            status,
            connect,
            disconnect,
        })
    }

    fn apply(backend: &mut Backend, state: &TrayMenuState) {
        backend.status.set_text(format!("Status: {}", state.status));
        backend.connect.set_enabled(state.connect_enabled);
        backend.disconnect.set_enabled(state.disconnect_enabled);
        let _ = backend
            .tray
            .set_tooltip(Some(format!("Aevan — {}", state.status)));
    }

    fn load_icon(bytes: &'static [u8]) -> Option<tray_icon::Icon> {
        let decoder = png::Decoder::new(Cursor::new(bytes));
        let mut reader = decoder.read_info().ok()?;
        let mut buffer = vec![0; reader.output_buffer_size()?];
        let info = reader.next_frame(&mut buffer).ok()?;
        let bytes = &buffer[..info.buffer_size()];
        tray_icon::Icon::from_rgba(bytes.to_vec(), info.width, info.height).ok()
    }
}
