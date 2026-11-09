//! The `iced` shell. All behaviour lives in [`crate::view_model`]; this module
//! only renders it and turns widget messages into view-model transitions.

use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{
    window, Alignment, Background, Border, Color, Element, Length, Subscription, Task, Theme,
};

use aevan_core::ProfileStore;
use aevan_daemon::client::ClientError;
use aevan_daemon::StatusReport;

use crate::daemon_bridge;
use crate::notifications::{DesktopNotifier, Notifier};
use crate::tray::{self, TrayEvent};
use crate::view_model::{
    format_bytes, format_uptime, now_unix, poll_interval, render_address, render_dns, render_mtu,
    render_routes, split_tunnel_preview, tick_interval, ConnectCredentials, ConnectionState,
    DecodedTotpSecret, ProfileDot, QuitPlan, Screen, SecretField, TotpEnrolment, TrayMenuState,
    ViewModel,
};

/// A short banner colour for failures and notices.
const DANGER: Color = Color::from_rgb(0.91, 0.29, 0.35);
/// A short banner colour for transitions.
const WARNING: Color = Color::from_rgb(0.85, 0.62, 0.18);
/// A short banner colour for connected state.
const SUCCESS: Color = Color::from_rgb(0.28, 0.68, 0.36);
/// A short banner colour for neutral state.
const MUTED: Color = Color::from_rgb(0.55, 0.60, 0.66);

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    StatusPolled(Result<(StatusReport, String), ClientError>),
    SelectProfile(String),
    TotpLoaded {
        profile: String,
        secret: Option<Vec<u8>>,
    },
    ShowProfiles,
    ShowSettings,
    SettingsForProfile(String),
    BeginAddProfile,
    AddProfileName(String),
    AddProfileUrl(String),
    AddProfileRealm(String),
    AddProfileUsername(String),
    SaveProfile,
    CancelAddProfile,
    Back,
    Username(String),
    Password(SecretField),
    Token(SecretField),
    Connect,
    ConnectFinished(Result<StatusReport, ClientError>),
    Disconnect,
    DisconnectFinished(Result<StatusReport, ClientError>),
    RetryDaemon,
    RetryRecovery,
    RecoveryRetried(Result<StatusReport, ClientError>),
    ReloadProfiles,
    CycleLogLevel,
    TotpInput(SecretField),
    TotpValidate,
    TotpSave,
    TotpSaved {
        profile: String,
        secret: DecodedTotpSecret,
        result: Result<(), String>,
    },
    TotpRemove,
    TotpCancel,
    TotpRemoved {
        profile: String,
        result: Result<(), String>,
    },
    /// Tray menu events. Linux has no tray, so the variant is never
    /// constructed there and is allowed to stay dead.
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    Tray(TrayEvent),
    /// The window's close button was pressed: hide, do not quit.
    WindowCloseRequested(window::Id),
    /// Another `aevan-gui`/`aevan` start asked this instance to show itself.
    InstanceShowRequested,
    /// The explicit "Start daemon (Administrator)" action.
    StartDaemon,
    StartDaemonFinished(Result<(), String>),
    /// Quit from the tray or Cmd+Q.
    QuitRequested,
    QuitAnyway,
    CancelQuit,
    QuitReady,
    AutostartStatusLoaded(Result<aevan_daemon::autostart::TaskState, String>),
    SetAutostart,
    AutostartChanged(Result<aevan_daemon::autostart::TaskState, String>),
}

/// The iced application state.
pub struct App {
    vm: ViewModel,
    poll_in_flight: bool,
    notifier: Box<dyn Notifier>,
    tray: tray::Handle,
    tray_state: Option<TrayMenuState>,
}

/// Run the native window.
pub fn run(store: ProfileStore) -> iced::Result {
    let endpoint = daemon_bridge::endpoint();
    let mut vm = ViewModel::new(&store, endpoint, now_unix());
    // The macOS daemon is a keepalive system LaunchDaemon: Quit leaves it and
    // any live tunnel alone, and Disconnect is the explicit stop action.
    vm.leave_daemon_on_quit = cfg!(target_os = "macos");

    iced::application("Aevan", App::update, App::view)
        .subscription(App::subscription)
        .theme(|_| Theme::Dark)
        .window_size((760.0, 620.0))
        // Closing the window hides it; only the tray/menu-bar Quit item exits.
        .exit_on_close_request(false)
        .run_with(move || {
            let tray = tray::start();
            App::new(vm, tray)
        })
}

impl App {
    fn new(vm: ViewModel, tray: tray::Handle) -> (Self, Task<Message>) {
        let mut tasks = vec![poll_status_task(), autostart_status_task()];
        if let Some(profile) = vm.selected.clone() {
            tasks.push(load_totp_task(profile));
        }
        let mut app = Self {
            vm,
            poll_in_flight: true,
            notifier: Box::new(DesktopNotifier),
            tray,
            tray_state: None,
        };
        app.sync_tray();
        (app, Task::batch(tasks))
    }

    fn subscription(&self) -> Subscription<Message> {
        let interval = tick_interval(
            &self.vm.state,
            self.vm.screen,
            self.vm.has_totp(),
            self.vm.has_pending_totp(),
        );
        let tick = match interval {
            Some(interval) => iced::time::every(interval).map(|_| Message::Tick),
            None => Subscription::none(),
        };
        let close = window::close_requests().map(Message::WindowCloseRequested);
        #[cfg(target_os = "macos")]
        let quit = iced::keyboard::on_key_press(cmd_q);
        #[cfg(not(target_os = "macos"))]
        let quit = Subscription::none();
        Subscription::batch([
            tick,
            tray::subscription(),
            crate::instance::subscription(),
            close,
            quit,
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        let task = self.handle(message);
        self.vm.flush_notifications(self.notifier.as_ref());
        self.sync_tray();
        task
    }

    fn handle(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                self.vm.tick(now_unix());
                if poll_interval(&self.vm.state).is_some() && !self.poll_in_flight {
                    self.poll_in_flight = true;
                    return poll_status_task();
                }
            }
            Message::StatusPolled(result) => {
                self.poll_in_flight = false;
                match result {
                    Ok((status, endpoint)) => {
                        self.vm.endpoint = endpoint;
                        self.vm.apply_status(status);
                    }
                    Err(error) => self.vm.apply_client_error(error),
                }
            }
            Message::SelectProfile(name) => {
                self.vm.select_profile(&name, now_unix());
                if self.vm.selected.is_some() {
                    return load_totp_task(name);
                }
            }
            Message::TotpLoaded { profile, secret } => {
                self.vm.set_totp_secret(&profile, secret);
            }
            Message::ShowProfiles => {
                self.vm.screen = Screen::Profiles;
                self.vm.notice = None;
            }
            Message::ShowSettings => {
                self.vm.screen = Screen::Settings;
                self.vm.notice = None;
            }
            Message::SettingsForProfile(name) => {
                self.vm.select_for_settings(&name, now_unix());
                if self.vm.selected.is_some() {
                    return load_totp_task(name);
                }
            }
            Message::BeginAddProfile => self.vm.begin_add_profile(),
            Message::AddProfileName(value) => self.vm.set_add_profile_name(value),
            Message::AddProfileUrl(value) => self.vm.set_add_profile_url(value),
            Message::AddProfileRealm(value) => self.vm.set_add_profile_realm(value),
            Message::AddProfileUsername(value) => self.vm.set_add_profile_username(value),
            Message::CancelAddProfile => self.vm.cancel_add_profile(),
            Message::SaveProfile => {
                let loaded = ProfileStore::default_path()
                    .and_then(|path| ProfileStore::load(&path).map(|store| (path, store)));
                match loaded {
                    Ok((path, mut store)) => {
                        if self.vm.save_added_profile(&mut store, now_unix()).is_ok() {
                            if let Err(error) = store.save(&path) {
                                self.vm.notice = Some(format!(
                                    "the profile was added but could not be saved: {error}"
                                ));
                            }
                        }
                    }
                    Err(error) => self.vm.add_profile_error = Some(error.to_string()),
                }
            }
            Message::Back => {
                self.vm.screen = if self.vm.state == ConnectionState::Connected {
                    Screen::Connected
                } else {
                    Screen::Profiles
                };
                self.vm.notice = None;
            }
            Message::Username(value) => self.vm.username = value,
            Message::Password(value) => {
                self.vm.password = zeroize::Zeroizing::new(value.into_string());
            }
            Message::Token(value) => {
                self.vm.token = zeroize::Zeroizing::new(value.into_string());
            }
            Message::Connect => {
                self.vm.tick(now_unix());
                match self.vm.take_credentials() {
                    Ok(credentials) => return connect_task(credentials),
                    Err(message) => self.vm.notice = Some(message),
                }
            }
            Message::ConnectFinished(result) => match result {
                Ok(status) => self.vm.apply_status(status),
                Err(error) => self.vm.apply_client_error(error),
            },
            Message::Disconnect => {
                if let Some(profile) = self.vm.begin_disconnect() {
                    return disconnect_task(Some(profile));
                }
            }
            Message::DisconnectFinished(result) => {
                if self.vm.quit_after_disconnect {
                    if self.vm.quit_disconnect_finished(result) == QuitPlan::Exit {
                        return finish_quit(self.vm.started_daemon);
                    }
                } else {
                    match result {
                        Ok(status) => self.vm.apply_status(status),
                        Err(error) => self.vm.apply_client_error(error),
                    }
                }
            }
            Message::RetryDaemon => {
                if !self.poll_in_flight {
                    self.poll_in_flight = true;
                    return poll_status_task();
                }
            }
            Message::RetryRecovery => return recover_task(),
            Message::RecoveryRetried(result) => match result {
                Ok(status) => self.vm.apply_status(status),
                Err(error) => self.vm.apply_client_error(error),
            },
            Message::ReloadProfiles => {
                let loaded =
                    ProfileStore::default_path().and_then(|path| ProfileStore::load(&path));
                match loaded {
                    Ok(store) => {
                        self.vm.reload_profiles(&store, now_unix());
                        if let Some(profile) = self.vm.selected.clone() {
                            self.poll_in_flight = true;
                            return Task::batch([load_totp_task(profile), poll_status_task()]);
                        }
                        self.poll_in_flight = true;
                        return poll_status_task();
                    }
                    Err(error) => self.vm.notice = Some(error.to_string()),
                }
            }
            Message::CycleLogLevel => self.vm.log_level = self.vm.log_level.next(),
            Message::TotpInput(value) => self.vm.set_totp_input(value.into_string()),
            Message::TotpValidate => {
                if let Err(message) = self.vm.validate_totp_input() {
                    self.vm.notice = Some(message);
                }
            }
            Message::TotpSave => match self.vm.take_totp_enrolment() {
                Ok(enrolment) => return totp_save_task(enrolment),
                Err(message) => self.vm.notice = Some(message),
            },
            Message::TotpCancel => self.vm.set_totp_input(String::new()),
            Message::TotpSaved {
                profile,
                secret,
                result,
            } => match result {
                Ok(()) => self.vm.apply_totp_saved(&profile, secret.into_inner()),
                Err(message) => {
                    self.vm.notice = Some(format!("could not save the TOTP secret: {message}"));
                }
            },
            Message::TotpRemove => match self.vm.selected.clone() {
                Some(profile) => return totp_remove_task(profile),
                None => self.vm.notice = Some("select a profile first".to_owned()),
            },
            Message::TotpRemoved { profile, result } => match result {
                Ok(()) => self.vm.apply_totp_removed(&profile),
                Err(message) => {
                    self.vm.notice = Some(format!("could not remove the TOTP secret: {message}"));
                }
            },
            Message::Tray(TrayEvent::ShowWindow) => return focus_window(),
            Message::Tray(TrayEvent::Quit) => return self.handle(Message::QuitRequested),
            Message::Tray(TrayEvent::Connect) => {
                if let Some(profile) = self.vm.selected.clone() {
                    self.vm.select_profile(&profile, now_unix());
                    if self.vm.selected.is_some() {
                        return Task::batch([load_totp_task(profile), focus_window()]);
                    }
                }
                return focus_window();
            }
            Message::Tray(TrayEvent::Disconnect) => {
                if let Some(profile) = self.vm.begin_disconnect() {
                    return disconnect_task(Some(profile));
                }
            }
            Message::WindowCloseRequested(id) => {
                self.vm.window_closed();
                return window::change_mode(id, window::Mode::Hidden);
            }
            Message::InstanceShowRequested => return focus_window(),
            Message::StartDaemon => {
                if self.vm.begin_daemon_start() {
                    return start_daemon_task();
                }
            }
            Message::StartDaemonFinished(result) => match result {
                Ok(()) => {
                    self.vm.daemon_started();
                    if !self.poll_in_flight {
                        self.poll_in_flight = true;
                        return poll_status_task();
                    }
                }
                Err(message) => self.vm.daemon_start_failed(message),
            },
            Message::QuitRequested => return self.begin_quit(),
            Message::QuitAnyway => {
                if self.vm.quit_anyway() == QuitPlan::Exit {
                    return finish_quit(self.vm.started_daemon);
                }
            }
            Message::CancelQuit => self.vm.cancel_quit(),
            Message::QuitReady => return iced::exit(),
            Message::AutostartStatusLoaded(result) => self.vm.apply_autostart_status(result),
            Message::SetAutostart => {
                if let Some(enabled) = self.vm.begin_autostart_change() {
                    return autostart_change_task(enabled);
                }
            }
            Message::AutostartChanged(result) => self.vm.apply_autostart_change(result),
        }
        Task::none()
    }

    fn begin_quit(&mut self) -> Task<Message> {
        match self.vm.request_quit() {
            QuitPlan::Disconnect(profile) => disconnect_task(profile),
            QuitPlan::Confirm(_) => Task::none(),
            QuitPlan::Exit => finish_quit(self.vm.started_daemon),
        }
    }

    fn sync_tray(&mut self) {
        let state = self.vm.tray_menu();
        if self.tray_state.as_ref() != Some(&state) {
            self.tray.sync(&state);
            self.tray_state = Some(state);
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let header = row![
            text("Aevan").size(30),
            Space::with_width(Length::Fill),
            state_badge(&self.vm.state),
            navigation(),
        ]
        .align_y(Alignment::Center)
        .spacing(16);

        let content: Element<Message> = match self.vm.screen {
            Screen::Profiles => self.profiles_view(),
            Screen::Connect => self.connect_view(),
            Screen::Connected => self.connected_view(),
            Screen::Settings => self.settings_view(),
            Screen::AddProfile => self.add_profile_view(),
        };

        let banner = self
            .vm
            .notice
            .as_ref()
            .map(|notice| banner(notice, WARNING));

        let quit_confirmation = self.vm.quit_confirmation.as_ref().map(|reason| {
            container(
                column![
                    text("Could not disconnect before quitting")
                        .size(16)
                        .color(DANGER),
                    text(reason).size(13),
                    text("Quit anyway? The tunnel may still be partially torn down.")
                        .size(13)
                        .color(MUTED),
                    row![
                        button(text("Quit anyway").size(14))
                            .on_press(Message::QuitAnyway)
                            .style(button::danger)
                            .padding([6, 14]),
                        button(text("Cancel").size(14))
                            .on_press(Message::CancelQuit)
                            .style(button::secondary)
                            .padding([6, 14]),
                    ]
                    .spacing(8),
                ]
                .spacing(6),
            )
            .padding(12)
            .width(Length::Fill)
            .style(error_card)
        });

        let mut body = column![header].spacing(16).width(Length::Fill);
        if let Some(banner) = banner {
            body = body.push(banner);
        }
        if let Some(quit_confirmation) = quit_confirmation {
            body = body.push(quit_confirmation);
        }
        body = body.push(scrollable(content).height(Length::Fill));

        container(body)
            .padding(20)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn profiles_view(&self) -> Element<'_, Message> {
        let mut list = column![].spacing(10).width(Length::Fill);

        if self.vm.profiles.is_empty() {
            list = list.push(
                text("No profiles yet. Use the Add profile button above to create one.")
                    .color(MUTED),
            );
        }

        for profile in &self.vm.profiles {
            let dot = self.vm.profile_dot(&profile.name);
            let (red, green, blue) = dot.rgb();
            let active = self.vm.selected.as_deref() == Some(profile.name.as_str());
            let connected = dot == ProfileDot::Connected;

            let details = column![
                row![
                    text(&profile.name).size(18),
                    text(if active { "selected" } else { "" })
                        .size(12)
                        .color(MUTED),
                ]
                .spacing(8),
                text(&profile.url).size(12).color(MUTED),
                text(format!(
                    "realm {}  ·  split tunnel: {}",
                    profile.realm, profile.split_tunnel
                ))
                .size(12)
                .color(MUTED),
            ]
            .spacing(3)
            .width(Length::Fill);

            let actions = if connected {
                row![text("connected").size(13).color(SUCCESS)]
            } else if self.vm.can_connect() {
                row![
                    button(text("Connect").size(14))
                        .on_press(Message::SelectProfile(profile.name.clone()))
                        .padding([6, 14]),
                    button(text("Settings").size(14))
                        .on_press(Message::SettingsForProfile(profile.name.clone()))
                        .style(button::secondary)
                        .padding([6, 14]),
                ]
                .spacing(8)
            } else {
                row![text(state_label(&self.vm.state))
                    .size(13)
                    .color(state_color(&self.vm.state))]
            };

            let entry = row![
                column![
                    text("●").size(22).color(Color::from_rgb(
                        f32::from(red) / 255.0,
                        f32::from(green) / 255.0,
                        f32::from(blue) / 255.0,
                    )),
                    text(dot.label()).size(11).color(MUTED),
                ]
                .align_x(Alignment::Center)
                .width(Length::Fixed(70.0)),
                details,
                actions,
            ]
            .align_y(Alignment::Center)
            .spacing(12);

            list = list.push(container(entry).padding(14).width(Length::Fill).style(card));
        }

        let daemon_banner = match &self.vm.state {
            ConnectionState::DaemonUnavailable { message } => Some(
                container(
                    column![
                    text("Daemon unavailable").size(16).color(DANGER),
                    text(message).size(13),
                    text(
                        "Start the daemon with `aevand` (elevated on Windows or macOS), or use the Administrator action below."
                    )
                    .size(13)
                    .color(MUTED),
                    row![
                        button(text("Start daemon (Administrator)").size(14))
                            .on_press_maybe(
                                (!self.vm.daemon_start_busy).then_some(Message::StartDaemon)
                            )
                            .style(button::primary)
                            .padding([6, 14]),
                        button(text("Retry").size(14))
                            .on_press(Message::RetryDaemon)
                            .style(button::secondary)
                            .padding([6, 14]),
                    ]
                    .spacing(8),
                ]
                    .spacing(4),
                )
                .padding(12)
                .width(Length::Fill)
                .style(error_card)
                .into(),
            ),
            ConnectionState::RecoveryIncomplete { report } => Some(
                container(
                    column![
                        text("Journal recovery incomplete").size(16).color(WARNING),
                        text(format!(
                            "rolled back {} · already absent {} · failed {}",
                            report.rolled_back,
                            report.skipped_absent,
                            report.failed()
                        ))
                        .size(13),
                        text(
                            "The journal is retained until every step can be undone.                              Retry recovery after fixing the platform state."
                        )
                        .size(13)
                        .color(MUTED),
                        column(
                            report
                                .failures
                                .iter()
                                .map(|failure| {
                                    text(format!("{}: {}", failure.step, failure.reason))
                                        .size(12)
                                        .color(MUTED)
                                        .into()
                                })
                                .collect::<Vec<Element<'_, Message>>>()
                        )
                        .spacing(2),
                        row![button(text("Retry recovery").size(14))
                            .on_press(Message::RetryRecovery)
                            .style(button::secondary)
                            .padding([6, 14])],
                    ]
                    .spacing(6),
                )
                .padding(12)
                .width(Length::Fill)
                .style(warning_card)
                .into(),
            ),
            ConnectionState::Failed { reason } => {
                Some(banner(&format!("Last attempt failed: {reason}"), DANGER))
            }
            _ => None,
        };

        let mut view = column![
            row![
                text("Profiles").size(22),
                Space::with_width(Length::Fill),
                button(text("Add profile").size(14))
                    .on_press(Message::BeginAddProfile)
                    .style(button::primary)
                    .padding([6, 12]),
                button(text("Retry").size(14))
                    .on_press(Message::RetryDaemon)
                    .style(button::secondary)
                    .padding([6, 12]),
                button(text("Refresh").size(14))
                    .on_press(Message::ReloadProfiles)
                    .style(button::secondary)
                    .padding([6, 12]),
            ]
            .align_y(Alignment::Center)
            .spacing(8),
            text(format!("daemon: {}", self.vm.endpoint))
                .size(12)
                .color(MUTED),
        ]
        .spacing(12)
        .width(Length::Fill);

        if let Some(daemon_banner) = daemon_banner {
            view = view.push(daemon_banner);
        }
        view.push(list).into()
    }

    fn add_profile_view(&self) -> Element<'_, Message> {
        let mut form = column![
            text("Add profile").size(22),
            text(
                "Profiles hold no password or token. Aevan asks for credentials only when you connect, and secrets live in the OS keyring."
            )
            .size(12)
            .color(MUTED),
        ]
        .spacing(12)
        .width(Length::Fill);

        form = form.push(text("Name").size(12).color(MUTED)).push(
            text_input("profile name", &self.vm.add_profile.name)
                .on_input(Message::AddProfileName)
                .padding(8)
                .width(Length::Fill),
        );
        if let Some(error) = &self.vm.add_profile_errors.name {
            form = form.push(text(error.clone()).size(12).color(DANGER));
        }

        form = form.push(text("Gateway URL").size(12).color(MUTED)).push(
            text_input("https://vpn.example.net/realm", &self.vm.add_profile.url)
                .on_input(Message::AddProfileUrl)
                .padding(8)
                .width(Length::Fill),
        );
        if let Some(error) = &self.vm.add_profile_errors.url {
            form = form.push(text(error.clone()).size(12).color(DANGER));
        }

        form = form.push(text("Realm").size(12).color(MUTED)).push(
            text_input("authentication realm", &self.vm.add_profile.realm)
                .on_input(Message::AddProfileRealm)
                .padding(8)
                .width(Length::Fill),
        );
        if let Some(error) = &self.vm.add_profile_errors.realm {
            form = form.push(text(error.clone()).size(12).color(DANGER));
        }

        form = form.push(text("Username").size(12).color(MUTED)).push(
            text_input("username", &self.vm.add_profile.username)
                .on_input(Message::AddProfileUsername)
                .padding(8)
                .width(Length::Fill),
        );
        if let Some(error) = &self.vm.add_profile_errors.username {
            form = form.push(text(error.clone()).size(12).color(DANGER));
        }

        form = form
            .push(text("Password").size(12).color(MUTED))
            .push(
                text(
                    "Not stored. A password is requested only when you connect and is never written to the profile store."
                )
                .size(12)
                .color(MUTED),
            );

        if let Some(error) = &self.vm.add_profile_error {
            form = form.push(text(error.clone()).size(12).color(DANGER));
        }

        let actions = row![
            button(text("Save").size(15))
                .on_press_maybe(
                    self.vm
                        .can_save_add_profile()
                        .then_some(Message::SaveProfile)
                )
                .style(button::primary)
                .padding([8, 22]),
            button(text("Cancel").size(14))
                .on_press(Message::CancelAddProfile)
                .style(button::secondary)
                .padding([8, 14]),
        ]
        .spacing(8);

        form.push(actions).into()
    }

    fn connect_view(&self) -> Element<'_, Message> {
        let profile = self.vm.selected_profile();
        let profile_line = profile
            .map(|profile| format!("{}  ·  {}", profile.name, profile.url))
            .unwrap_or_else(|| "no profile selected".to_owned());

        let mut fields = column![
            text("Connect").size(22),
            text(profile_line).size(12).color(MUTED),
            text("Username").size(12).color(MUTED),
            text_input("username", &self.vm.username)
                .on_input(Message::Username)
                .padding(8)
                .width(Length::Fill),
            text("Password").size(12).color(MUTED),
            text_input("password", &self.vm.password)
                .secure(true)
                .on_input(|value| Message::Password(SecretField::new(value)))
                .padding(8)
                .width(Length::Fill),
        ]
        .spacing(6)
        .width(Length::Fill);

        match self.vm.totp_countdown() {
            Some(countdown) => {
                fields = fields
                    .push(text("One-time token").size(12).color(MUTED))
                    .push(
                        text_input("generated from the enrolled TOTP secret", &self.vm.token)
                            .on_input(|value| Message::Token(SecretField::new(value)))
                            .padding(8)
                            .width(Length::Fill),
                    )
                    .push(text(countdown).size(12).color(WARNING));
            }
            None => {
                fields = fields
                    .push(text("One-time token").size(12).color(MUTED))
                    .push(
                        text_input("token (leave empty if not required)", &self.vm.token)
                            .on_input(|value| Message::Token(SecretField::new(value)))
                            .padding(8)
                            .width(Length::Fill),
                    );
            }
        }

        match &self.vm.state {
            ConnectionState::Failed { reason } => {
                fields = fields.push(text(format!("failed: {reason}")).size(13).color(DANGER));
            }
            ConnectionState::DaemonUnavailable { message } => {
                fields = fields
                    .push(text(message).size(13).color(DANGER))
                    .push(
                        text(
                            "Start `aevand` (elevated on Windows or macOS), or use the Administrator action below.",
                        )
                        .size(12)
                        .color(MUTED),
                    )
                    .push(
                        button(text("Start daemon (Administrator)").size(14))
                            .on_press_maybe(
                                (!self.vm.daemon_start_busy).then_some(Message::StartDaemon),
                            )
                            .style(button::primary)
                            .padding([6, 14]),
                    );
            }
            ConnectionState::RecoveryIncomplete { report } => {
                fields = fields.push(
                    text(format!(
                        "journal recovery incomplete (failed {})",
                        report.failed()
                    ))
                    .size(13)
                    .color(WARNING),
                );
            }
            _ => {}
        }
        if matches!(
            self.vm.state,
            ConnectionState::Authenticating | ConnectionState::Connecting
        ) {
            fields = fields.push(
                text(format!("{}…", state_label(&self.vm.state)))
                    .size(13)
                    .color(WARNING),
            );
        }

        let connect_label = if !self.vm.can_connect() {
            format!("{}…", state_label(&self.vm.state))
        } else {
            "Connect".to_owned()
        };

        let actions = row![
            button(text(connect_label).size(15))
                .on_press_maybe(self.vm.can_connect().then_some(Message::Connect))
                .style(button::primary)
                .padding([8, 22]),
            button(text("Back").size(14))
                .on_press(Message::Back)
                .style(button::secondary)
                .padding([8, 14]),
        ]
        .spacing(8);

        column![fields, actions]
            .spacing(16)
            .width(Length::Fill)
            .into()
    }

    fn connected_view(&self) -> Element<'_, Message> {
        let status = self.vm.status.as_ref();
        let address = status
            .map(render_address)
            .unwrap_or_else(|| "waiting".into());
        let prefix = status
            .and_then(|status| status.prefix_len)
            .map(|prefix| prefix.to_string())
            .unwrap_or_else(|| "waiting".into());
        let device = status
            .and_then(|status| status.device.clone())
            .unwrap_or_else(|| "unknown".into());
        let mtu = status.map(render_mtu).unwrap_or_else(|| "waiting".into());
        let routes = status
            .map(render_routes)
            .unwrap_or_else(|| "waiting".into());
        let dns = status.map(render_dns).unwrap_or_else(|| "waiting".into());
        let bytes_in = status
            .map(|status| format_bytes(status.bytes_in))
            .unwrap_or_default();
        let bytes_out = status
            .map(|status| format_bytes(status.bytes_out))
            .unwrap_or_default();
        let uptime = status
            .map(|status| format_uptime(status.uptime_secs))
            .unwrap_or_default();
        let profile = self
            .vm
            .selected_profile()
            .map(|profile| profile.name.clone())
            .unwrap_or_else(|| "unknown".to_owned());

        let details = column![
            detail_row("Profile", &profile),
            detail_row("State", state_label(&self.vm.state)),
            detail_row("Address", &address),
            detail_row("Prefix", &prefix),
            detail_row("Device", &device),
            detail_row("MTU", &mtu),
            detail_row("Routes", &routes),
            detail_row("DNS", &dns),
            detail_row("Bytes in", &bytes_in),
            detail_row("Bytes out", &bytes_out),
            detail_row("Uptime", &uptime),
        ]
        .spacing(8)
        .width(Length::Fill);

        let actions = row![
            button(text("Disconnect").size(15))
                .on_press_maybe(self.vm.can_disconnect().then_some(Message::Disconnect))
                .style(button::danger)
                .padding([8, 22]),
            button(text("Profiles").size(14))
                .on_press(Message::ShowProfiles)
                .style(button::secondary)
                .padding([8, 14]),
        ]
        .spacing(8);

        column![text("Connected").size(22), details, actions]
            .spacing(18)
            .width(Length::Fill)
            .into()
    }

    fn settings_view(&self) -> Element<'_, Message> {
        let mut view = column![text("Settings").size(22)]
            .spacing(14)
            .width(Length::Fill);

        let enrolled = match self.vm.selected_profile() {
            Some(profile) => {
                view = view.push(detail_row("Profile", &profile.name));
                view = view.push(detail_row("Realm", &profile.realm));
                view = view.push(detail_row("Gateway", &profile.url));
                view = view.push(detail_row("Split tunnel", &split_tunnel_preview(profile)));
                view = view.push(detail_row(
                    "TOTP",
                    if profile.totp_enrolled {
                        "enrolled in the keyring"
                    } else {
                        "not enrolled"
                    },
                ));
                Some(profile.totp_enrolled)
            }
            None => {
                view = view.push(text("No profile selected.").color(MUTED));
                None
            }
        };

        view = view
            .push(detail_row("Log level", self.vm.log_level.as_str()))
            .push(
                button(
                    text(format!(
                        "Cycle log level (now {})",
                        self.vm.log_level.as_str()
                    ))
                    .size(14),
                )
                .on_press(Message::CycleLogLevel)
                .style(button::secondary)
                .padding([6, 14]),
            );
        view = view.push(detail_row("Start at login", &self.vm.autostart.label()));
        if let Some(enabled) = self.vm.autostart.toggle_target() {
            let label = if enabled {
                "Enable start at login"
            } else {
                "Disable start at login"
            };
            view = view.push(
                button(text(label).size(14))
                    .on_press_maybe((!self.vm.autostart_busy).then_some(Message::SetAutostart))
                    .style(button::secondary)
                    .padding([6, 14]),
            );
        }
        view = view.push(detail_row("Daemon endpoint", &self.vm.endpoint));

        if let Some(enrolled) = enrolled {
            view = view.push(text("TOTP enrolment").size(17));
            if enrolled {
                view = view.push(
                    text("The secret is stored only in the OS keyring and is not shown again.")
                        .size(12)
                        .color(MUTED),
                );
                view = view.push(
                    button(text("Remove from keyring").size(14))
                        .on_press(Message::TotpRemove)
                        .style(button::danger)
                        .padding([6, 14]),
                );
            } else {
                view = view.push(
                    text("Paste the base32 secret from your authenticator app. It is validated locally, shown only as a current code, then written to the OS keyring.")
                        .size(12)
                        .color(MUTED),
                );
                view = view.push(
                    text_input("base32 secret", &self.vm.totp_input)
                        .secure(true)
                        .on_input(|value| Message::TotpInput(SecretField::new(value)))
                        .padding(8)
                        .width(Length::Fill),
                );
                match (
                    self.vm.pending_totp_code(),
                    self.vm.pending_totp_countdown(),
                ) {
                    (Some(code), Some(countdown)) => {
                        view = view
                            .push(text(format!("Current code: {code}")).size(22))
                            .push(text(countdown).size(12).color(WARNING))
                            .push(
                                row![
                                    button(text("Save to keyring").size(14))
                                        .on_press(Message::TotpSave)
                                        .style(button::primary)
                                        .padding([6, 14]),
                                    button(text("Cancel").size(14))
                                        .on_press(Message::TotpCancel)
                                        .style(button::secondary)
                                        .padding([6, 14]),
                                ]
                                .spacing(8),
                            );
                    }
                    _ => {
                        view = view.push(
                            button(text("Validate secret").size(14))
                                .on_press(Message::TotpValidate)
                                .style(button::primary)
                                .padding([6, 14]),
                        );
                    }
                }
            }
        }

        view = view.push(
            button(text("Back").size(14))
                .on_press(Message::Back)
                .style(button::secondary)
                .padding([6, 14]),
        );

        view.into()
    }
}

fn detail_row(label: &str, value: &str) -> Element<'static, Message> {
    row![
        text(label.to_owned())
            .size(13)
            .color(MUTED)
            .width(Length::Fixed(130.0)),
        text(value.to_owned()).size(14),
    ]
    .spacing(10)
    .into()
}

fn navigation() -> Element<'static, Message> {
    let nav = row![
        button(text("Profiles").size(13))
            .on_press(Message::ShowProfiles)
            .style(button::text)
            .padding([4, 8]),
        button(text("Settings").size(13))
            .on_press(Message::ShowSettings)
            .style(button::text)
            .padding([4, 8]),
    ]
    .spacing(4);
    nav.into()
}

fn state_label(state: &ConnectionState) -> &'static str {
    match state {
        ConnectionState::Disconnected => "disconnected",
        ConnectionState::Authenticating => "authenticating",
        ConnectionState::Connecting => "connecting",
        ConnectionState::Connected => "connected",
        ConnectionState::Disconnecting => "disconnecting",
        ConnectionState::RecoveryIncomplete { .. } => "recovery incomplete",
        ConnectionState::Failed { .. } => "failed",
        ConnectionState::DaemonUnavailable { .. } => "daemon unavailable",
    }
}

fn state_color(state: &ConnectionState) -> Color {
    match state {
        ConnectionState::Connected => SUCCESS,
        ConnectionState::Authenticating
        | ConnectionState::Connecting
        | ConnectionState::Disconnecting
        | ConnectionState::RecoveryIncomplete { .. } => WARNING,
        ConnectionState::Failed { .. } | ConnectionState::DaemonUnavailable { .. } => DANGER,
        ConnectionState::Disconnected => MUTED,
    }
}

fn state_badge(state: &ConnectionState) -> Element<'static, Message> {
    text(state_label(state).to_owned())
        .size(13)
        .color(state_color(state))
        .into()
}

fn banner(message: &str, color: Color) -> Element<'static, Message> {
    container(text(message.to_owned()).size(13).color(color))
        .padding(10)
        .width(Length::Fill)
        .style(move |_theme: &Theme| container::Style {
            background: Some(Background::Color(Color::from_rgba(
                color.r, color.g, color.b, 0.12,
            ))),
            border: Border {
                color: Color::from_rgba(color.r, color.g, color.b, 0.35),
                width: 1.0,
                radius: 6.0.into(),
            },
            ..container::Style::default()
        })
        .into()
}

fn card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.04))),
        border: Border {
            color: Color::from_rgba(1.0, 1.0, 1.0, 0.10),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..container::Style::default()
    }
}

fn warning_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(
            WARNING.r, WARNING.g, WARNING.b, 0.10,
        ))),
        border: Border {
            color: Color::from_rgba(WARNING.r, WARNING.g, WARNING.b, 0.40),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..container::Style::default()
    }
}

fn error_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(
            DANGER.r, DANGER.g, DANGER.b, 0.10,
        ))),
        border: Border {
            color: Color::from_rgba(DANGER.r, DANGER.g, DANGER.b, 0.40),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..container::Style::default()
    }
}

fn poll_status_task() -> Task<Message> {
    Task::perform(
        async {
            tokio::task::spawn_blocking(daemon_bridge::status)
                .await
                .unwrap_or_else(|error| {
                    Err(ClientError::Transport(format!(
                        "the status worker stopped: {error}"
                    )))
                })
        },
        Message::StatusPolled,
    )
}

fn load_totp_task(profile: String) -> Task<Message> {
    Task::perform(
        async move {
            let requested = profile.clone();
            let secret = tokio::task::spawn_blocking(move || daemon_bridge::totp_secret(&profile))
                .await
                .ok()
                .flatten();
            (requested, secret)
        },
        |(profile, secret)| Message::TotpLoaded { profile, secret },
    )
}

fn connect_task(credentials: ConnectCredentials) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || daemon_bridge::connect(credentials))
                .await
                .unwrap_or_else(|error| {
                    Err(ClientError::Transport(format!(
                        "the connect worker stopped: {error}"
                    )))
                })
        },
        Message::ConnectFinished,
    )
}

fn recover_task() -> Task<Message> {
    Task::perform(
        async {
            tokio::task::spawn_blocking(daemon_bridge::recover)
                .await
                .unwrap_or_else(|error| {
                    Err(ClientError::Transport(format!(
                        "the recovery worker stopped: {error}"
                    )))
                })
        },
        Message::RecoveryRetried,
    )
}

fn disconnect_task(profile: Option<String>) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || daemon_bridge::disconnect(profile))
                .await
                .unwrap_or_else(|error| {
                    Err(ClientError::Transport(format!(
                        "the disconnect worker stopped: {error}"
                    )))
                })
        },
        Message::DisconnectFinished,
    )
}

fn focus_window() -> Task<Message> {
    // A window hidden by its close button has to be shown again before it can
    // take focus. The tray and the single-instance endpoint share this path.
    iced::window::get_latest().and_then(|id| {
        Task::batch([
            iced::window::change_mode(id, window::Mode::Windowed),
            iced::window::gain_focus(id),
        ])
    })
}

#[cfg(target_os = "macos")]
fn cmd_q(key: iced::keyboard::Key, modifiers: iced::keyboard::Modifiers) -> Option<Message> {
    match key {
        iced::keyboard::Key::Character(character)
            if modifiers.command() && character.as_str().eq_ignore_ascii_case("q") =>
        {
            Some(Message::QuitRequested)
        }
        _ => None,
    }
}

fn start_daemon_task() -> Task<Message> {
    Task::perform(
        async {
            tokio::task::spawn_blocking(daemon_bridge::start_daemon)
                .await
                .unwrap_or_else(|error| Err(format!("the daemon-start worker stopped: {error}")))
        },
        Message::StartDaemonFinished,
    )
}

fn autostart_status_task() -> Task<Message> {
    Task::perform(
        async {
            tokio::task::spawn_blocking(daemon_bridge::autostart_status)
                .await
                .unwrap_or_else(|error| Err(format!("the autostart worker stopped: {error}")))
        },
        Message::AutostartStatusLoaded,
    )
}

fn autostart_change_task(enabled: bool) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || daemon_bridge::set_autostart(enabled))
                .await
                .unwrap_or_else(|error| Err(format!("the autostart worker stopped: {error}")))
        },
        Message::AutostartChanged,
    )
}

/// Stop a daemon this GUI started, then exit.
///
/// macOS never stops the daemon here: it is a keepalive system LaunchDaemon
/// and Quit must leave it (and any tunnel) alone. Disconnect is the explicit
/// teardown action.
fn finish_quit(shutdown_daemon: bool) -> Task<Message> {
    let shutdown_daemon = shutdown_daemon && !cfg!(target_os = "macos");
    Task::perform(
        async move {
            if shutdown_daemon {
                let _ = tokio::task::spawn_blocking(daemon_bridge::shutdown).await;
            }
        },
        |_| Message::QuitReady,
    )
}

fn totp_save_task(enrolment: TotpEnrolment) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || daemon_bridge::save_totp_secret(enrolment))
                .await
                .unwrap_or_else(|error| Err(format!("the keyring worker stopped: {error}")))
        },
        |result| match result {
            Ok((profile, secret)) => Message::TotpSaved {
                profile,
                secret: DecodedTotpSecret::new(secret),
                result: Ok(()),
            },
            Err(message) => Message::TotpSaved {
                profile: String::new(),
                secret: DecodedTotpSecret::new(Vec::new()),
                result: Err(message),
            },
        },
    )
}

fn totp_remove_task(profile: String) -> Task<Message> {
    let requested = profile.clone();
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || daemon_bridge::remove_totp_secret(&profile))
                .await
                .unwrap_or_else(|error| Err(format!("the keyring worker stopped: {error}")))
        },
        move |result| Message::TotpRemoved {
            profile: requested.clone(),
            result,
        },
    )
}
