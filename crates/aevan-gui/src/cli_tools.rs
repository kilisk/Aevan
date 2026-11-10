//! Install the bundled `aevan`/`aevand` binaries on `PATH`.
//!
//! The macOS DMG ships all three binaries inside `Aevan.app`. This module
//! creates `/usr/local/bin/{aevan,aevand}` symlinks behind one native
//! administrator prompt, reports the current state, and removes them again.
//! Elevation is shared with the existing unsigned-build fallback in
//! [`crate::macos_elevate`]; there is no second prompt mechanism here.
//!
//! The decision logic and the generated shell are pure and unit-tested. Real
//! execution is injected through [`ScriptRunner`], so tests run the same shell
//! against temporary paths without asking for administrator approval.

use std::path::{Path, PathBuf};

/// The binaries linked into `INSTALL_DIR`.
pub const TOOL_NAMES: [&str; 2] = ["aevan", "aevand"];

/// Directory that is normally on the user's `PATH`.
pub const INSTALL_DIR: &str = "/usr/local/bin";

/// What one destination path currently is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    /// Nothing exists at the path.
    Missing,
    /// A symlink, with its current target.
    Symlink(PathBuf),
    /// A regular file or another non-symlink object.
    File,
}

/// File-system view used by the link logic.
///
/// Tests replace this with an in-memory host; production uses [`RealLinkHost`].
pub trait LinkHost {
    /// Inspect one link destination.
    fn inspect(&self, path: &Path) -> LinkKind;
    /// Whether a target exists.
    fn exists(&self, path: &Path) -> bool;
}

/// The real file system.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealLinkHost;

impl LinkHost for RealLinkHost {
    fn inspect(&self, path: &Path) -> LinkKind {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => std::fs::read_link(path)
                .map(LinkKind::Symlink)
                .unwrap_or(LinkKind::File),
            Ok(_) => LinkKind::File,
            Err(_) => LinkKind::Missing,
        }
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// Where the bundle copies live and where the links are created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Usually `/usr/local/bin`.
    pub link_dir: PathBuf,
    /// `Aevan.app/Contents/MacOS`.
    pub bundle_dir: PathBuf,
}

impl Layout {
    /// Build a layout from explicit paths.
    pub fn new(link_dir: impl Into<PathBuf>, bundle_dir: impl Into<PathBuf>) -> Self {
        Self {
            link_dir: link_dir.into(),
            bundle_dir: bundle_dir.into(),
        }
    }

    /// The link path for one tool.
    pub fn link(&self, tool: &str) -> PathBuf {
        self.link_dir.join(tool)
    }

    /// The bundle path for one tool.
    pub fn target(&self, tool: &str) -> PathBuf {
        self.bundle_dir.join(tool)
    }

    /// The layout of the running app bundle.
    ///
    /// A `cargo run` binary outside `Contents/MacOS` is refused so a developer
    /// build can never rewrite `/usr/local/bin` to point into `target/`.
    pub fn from_current_exe() -> Result<Self, String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot locate the Aevan executable: {error}"))?;
        let macos_dir = executable
            .parent()
            .ok_or_else(|| "the Aevan executable has no parent directory".to_owned())?;
        let at_macos = macos_dir
            .file_name()
            .is_some_and(|name| name.to_string_lossy() == "MacOS");
        let at_contents = macos_dir
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name.to_string_lossy() == "Contents");
        let at_app = macos_dir
            .parent()
            .and_then(|path| path.parent())
            .and_then(|path| path.file_name())
            .is_some_and(|name| name.to_string_lossy().ends_with(".app"));
        if !(at_macos && at_contents && at_app) {
            return Err(
                "the command-line tools are installed from Aevan.app; run the packaged app"
                    .to_owned(),
            );
        }
        Ok(Self::new(INSTALL_DIR, macos_dir))
    }
}

/// State of one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolState {
    /// No link exists.
    Missing,
    /// Our link points at the current bundle copy.
    Ours {
        /// Link path.
        path: PathBuf,
        /// Bundle target.
        target: PathBuf,
    },
    /// Our link exists but points at an older bundle or a missing copy.
    Stale {
        /// Link path.
        path: PathBuf,
        /// Current target.
        target: PathBuf,
    },
    /// A non-Aevan file or symlink occupies the path.
    Foreign {
        /// Link path.
        path: PathBuf,
        /// Symlink target, or `None` for a regular file.
        target: Option<PathBuf>,
    },
}

/// Summary shown in Settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliToolsState {
    /// Neither link exists.
    NotInstalled,
    /// Both links point at the running bundle.
    Installed {
        /// The `aevan` link path.
        path: PathBuf,
    },
    /// Both links are ours, but at least one points at an old bundle.
    Stale {
        /// The first stale link.
        path: PathBuf,
        /// The old target.
        target: PathBuf,
    },
    /// At least one path is occupied by something that is not our link.
    PointsElsewhere {
        /// The first conflicting path.
        path: PathBuf,
        /// Its target, or `None` for a regular file.
        target: Option<PathBuf>,
    },
}

impl CliToolsState {
    /// Human-readable state for the Settings row.
    pub fn label(&self) -> String {
        match self {
            Self::NotInstalled => "not installed".to_owned(),
            Self::Installed { path } => format!("installed at {}", path.display()),
            Self::Stale { path, target } => format!(
                "installed but pointing at an old bundle: {} -> {}",
                path.display(),
                target.display()
            ),
            Self::PointsElsewhere { path, target } => match target {
                Some(target) => format!(
                    "installed but pointing elsewhere: {} -> {}",
                    path.display(),
                    target.display()
                ),
                None => format!(
                    "installed but pointing elsewhere: {} is a regular file",
                    path.display()
                ),
            },
        }
    }

    /// One-line fix-it message shown at launch when the links are stale.
    pub fn fix_it(&self) -> Option<&'static str> {
        matches!(self, Self::Stale { .. }).then_some(
            "Command-line tools point at an old Aevan bundle; use Install command-line tools in Settings.",
        )
    }

    /// Whether the links are ours but point at an old bundle.
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

fn looks_like_our_link(target: &Path, tool: &str) -> bool {
    let text = target.to_string_lossy().replace('\\', "/");
    let Some(index) = text.find(".app/Contents/MacOS/") else {
        return false;
    };
    let app = text[..index].rsplit('/').next().unwrap_or_default();
    text.ends_with(&format!("/Contents/MacOS/{tool}"))
        && app.starts_with("Aevan")
        && !app.is_empty()
}

/// State of one tool.
pub fn tool_state(host: &dyn LinkHost, layout: &Layout, tool: &str) -> ToolState {
    let path = layout.link(tool);
    match host.inspect(&path) {
        LinkKind::Missing => ToolState::Missing,
        LinkKind::File => ToolState::Foreign { path, target: None },
        LinkKind::Symlink(target) => {
            let expected = layout.target(tool);
            if target == expected {
                if host.exists(&target) {
                    ToolState::Ours { path, target }
                } else {
                    ToolState::Stale { path, target }
                }
            } else if looks_like_our_link(&target, tool) {
                ToolState::Stale { path, target }
            } else {
                ToolState::Foreign {
                    path,
                    target: Some(target),
                }
            }
        }
    }
}

/// Summarise both tools for the Settings row.
pub fn state(host: &dyn LinkHost, layout: &Layout) -> CliToolsState {
    let states: Vec<ToolState> = TOOL_NAMES
        .iter()
        .map(|tool| tool_state(host, layout, tool))
        .collect();

    if let Some(ToolState::Foreign { path, target }) = states
        .iter()
        .find(|state| matches!(state, ToolState::Foreign { .. }))
    {
        return CliToolsState::PointsElsewhere {
            path: path.clone(),
            target: target.clone(),
        };
    }
    if let Some(ToolState::Stale { path, target }) = states
        .iter()
        .find(|state| matches!(state, ToolState::Stale { .. }))
    {
        return CliToolsState::Stale {
            path: path.clone(),
            target: target.clone(),
        };
    }
    if states
        .iter()
        .all(|state| matches!(state, ToolState::Ours { .. }))
    {
        return CliToolsState::Installed {
            path: layout.link(TOOL_NAMES[0]),
        };
    }
    CliToolsState::NotInstalled
}

fn refusal(path: &Path) -> String {
    format!(
        "refusing to overwrite {}: it is not an Aevan symlink",
        path.display()
    )
}

/// Refuse before prompting when a destination is not one of our links.
pub fn preflight(host: &dyn LinkHost, layout: &Layout) -> Result<(), String> {
    for tool in TOOL_NAMES {
        if let ToolState::Foreign { path, .. } = tool_state(host, layout, tool) {
            return Err(refusal(&path));
        }
    }
    Ok(())
}

fn shell_quote(value: &Path) -> String {
    crate::macos_elevate::shell_quote(&value.to_string_lossy())
}

/// Build the one shell script that installs or refreshes both links.
fn install_script(layout: &Layout) -> String {
    let mut script = String::from("set -eu\n");
    script.push_str(&format!(
        "/bin/mkdir -p {}\n",
        shell_quote(&layout.link_dir)
    ));
    for tool in TOOL_NAMES {
        let link = layout.link(tool);
        let target = layout.target(tool);
        let link_q = shell_quote(&link);
        let target_q = shell_quote(&target);
        let message = shell_quote(Path::new(&refusal(&link)));
        script.push_str(&format!("if [ -e {link_q} ] || [ -L {link_q} ]; then\n"));
        script.push_str(&format!(
            "  if [ ! -L {link_q} ]; then echo {message} >&2; exit 1; fi\n"
        ));
        script.push_str(&format!("  current=$(/usr/bin/readlink {link_q})\n"));
        script.push_str("  case \"$current\" in\n");
        script.push_str(&format!("    */Aevan*.app/Contents/MacOS/{tool}) ;;\n"));
        script.push_str(&format!("    *) echo {message} >&2; exit 1 ;;\n"));
        script.push_str("  esac\nfi\n");
        script.push_str(&format!("/bin/ln -sfn {target_q} {link_q}\n"));
    }
    script
}

/// Build the one shell script that removes both links.
fn remove_script(layout: &Layout) -> String {
    let mut script = String::from("set -eu\n");
    for tool in TOOL_NAMES {
        let link = layout.link(tool);
        let link_q = shell_quote(&link);
        let message = shell_quote(Path::new(&refusal(&link)));
        script.push_str(&format!("if [ -L {link_q} ]; then\n"));
        script.push_str(&format!("  current=$(/usr/bin/readlink {link_q})\n"));
        script.push_str("  case \"$current\" in\n");
        script.push_str(&format!(
            "    */Aevan*.app/Contents/MacOS/{tool}) /bin/rm -f {link_q} ;;\n"
        ));
        script.push_str(&format!("    *) echo {message} >&2; exit 1 ;;\n"));
        script.push_str("  esac\n");
        script.push_str(&format!(
            "elif [ -e {link_q} ]; then echo {message} >&2; exit 1; fi\n"
        ));
    }
    script
}

/// Runs one privileged shell script. Tests inject a recorder or `/bin/sh`.
pub trait ScriptRunner {
    /// Run `script` with administrator approval.
    fn run(&self, script: &str) -> Result<(), String>;
}

/// The real macOS runner, using the existing fallback elevation module.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealScriptRunner;

#[cfg(target_os = "macos")]
impl ScriptRunner for RealScriptRunner {
    fn run(&self, script: &str) -> Result<(), String> {
        crate::macos_elevate::run_with_administrator(
            script,
            "the administrator approval did not update the command-line tools",
        )
    }
}

#[cfg(not(target_os = "macos"))]
impl ScriptRunner for RealScriptRunner {
    fn run(&self, _script: &str) -> Result<(), String> {
        Err("command-line tool installation is only available on macOS".to_owned())
    }
}

/// Install or refresh both links behind one administrator prompt.
pub fn install(
    host: &dyn LinkHost,
    layout: &Layout,
    runner: &dyn ScriptRunner,
) -> Result<(), String> {
    preflight(host, layout)?;
    runner.run(&install_script(layout))
}

/// Remove both links behind one administrator prompt.
pub fn remove(
    host: &dyn LinkHost,
    layout: &Layout,
    runner: &dyn ScriptRunner,
) -> Result<(), String> {
    preflight(host, layout)?;
    runner.run(&remove_script(layout))
}

/// Current state of the real `/usr/local/bin` links, when running in a bundle.
pub fn current_state() -> Option<CliToolsState> {
    Layout::from_current_exe()
        .ok()
        .map(|layout| state(&RealLinkHost, &layout))
}

/// Install against the running bundle and return the refreshed state.
pub fn install_current() -> Result<CliToolsState, String> {
    let layout = Layout::from_current_exe()?;
    install(&RealLinkHost, &layout, &RealScriptRunner)?;
    Ok(state(&RealLinkHost, &layout))
}

/// Remove against the running bundle and return the refreshed state.
pub fn remove_current() -> Result<CliToolsState, String> {
    let layout = Layout::from_current_exe()?;
    remove(&RealLinkHost, &layout, &RealScriptRunner)?;
    Ok(state(&RealLinkHost, &layout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct FakeHost {
        links: Rc<RefCell<HashMap<PathBuf, LinkKind>>>,
        existing: Rc<RefCell<HashSet<PathBuf>>>,
    }

    impl FakeHost {
        fn link(&self, path: &Path, target: &Path) {
            self.links
                .borrow_mut()
                .insert(path.to_path_buf(), LinkKind::Symlink(target.to_path_buf()));
            self.existing.borrow_mut().insert(target.to_path_buf());
        }

        fn file(&self, path: &Path) {
            self.links
                .borrow_mut()
                .insert(path.to_path_buf(), LinkKind::File);
        }
    }

    impl LinkHost for FakeHost {
        fn inspect(&self, path: &Path) -> LinkKind {
            self.links
                .borrow()
                .get(path)
                .cloned()
                .unwrap_or(LinkKind::Missing)
        }

        fn exists(&self, path: &Path) -> bool {
            self.existing.borrow().contains(path)
        }
    }

    fn layout() -> Layout {
        Layout::new("/usr/local/bin", "/Applications/Aevan.app/Contents/MacOS")
    }

    fn old_layout() -> Layout {
        Layout::new(
            "/usr/local/bin",
            "/Users/me/Desktop/Aevan.app/Contents/MacOS",
        )
    }

    #[test]
    fn missing_links_are_not_installed() {
        assert_eq!(
            state(&FakeHost::default(), &layout()),
            CliToolsState::NotInstalled
        );
    }

    #[test]
    fn links_to_the_current_bundle_are_installed() {
        let host = FakeHost::default();
        let layout = layout();
        for tool in TOOL_NAMES {
            host.link(&layout.link(tool), &layout.target(tool));
        }
        let state = state(&host, &layout);
        assert_eq!(
            state,
            CliToolsState::Installed {
                path: PathBuf::from("/usr/local/bin/aevan")
            }
        );
        assert!(state
            .label()
            .replace('\\', "/")
            .contains("/usr/local/bin/aevan"));
        assert!(state.fix_it().is_none());
    }

    #[test]
    fn links_to_an_old_bundle_are_stale_and_offer_a_fix() {
        let host = FakeHost::default();
        let old = old_layout();
        for tool in TOOL_NAMES {
            host.link(&old.link(tool), &old.target(tool));
        }
        let state = state(&host, &layout());
        assert!(matches!(state, CliToolsState::Stale { .. }), "{state:?}");
        assert_eq!(
            state.fix_it(),
            Some(
                "Command-line tools point at an old Aevan bundle; use Install command-line tools in Settings."
            )
        );
    }

    #[test]
    fn a_foreign_symlink_or_regular_file_points_elsewhere() {
        let host = FakeHost::default();
        let layout = layout();
        host.link(&layout.link("aevan"), Path::new("/opt/homebrew/bin/aevan"));
        host.file(&layout.link("aevand"));
        let state = state(&host, &layout);
        assert!(matches!(state, CliToolsState::PointsElsewhere { .. }));
        assert!(state.label().contains("pointing elsewhere"));
    }

    #[test]
    fn preflight_refuses_a_foreign_file_without_running_a_command() {
        let host = FakeHost::default();
        let layout = layout();
        host.file(&layout.link("aevan"));
        let error = preflight(&host, &layout).expect_err("must refuse");
        let error = error.replace('\\', "/");
        assert!(error.contains("/usr/local/bin/aevan"), "{error}");
        assert!(error.contains("not an Aevan symlink"), "{error}");
    }

    #[derive(Default)]
    struct RecordingRunner {
        scripts: RefCell<Vec<String>>,
    }

    impl ScriptRunner for RecordingRunner {
        fn run(&self, script: &str) -> Result<(), String> {
            self.scripts.borrow_mut().push(script.to_owned());
            Ok(())
        }
    }

    #[test]
    fn the_install_script_links_both_temp_targets_in_one_script() {
        let host = FakeHost::default();
        let layout = Layout::new(
            std::env::temp_dir().join("aevan-links"),
            std::env::temp_dir().join("Aevan.app/Contents/MacOS"),
        );
        let runner = RecordingRunner::default();
        install(&host, &layout, &runner).expect("install");
        let scripts = runner.scripts.borrow();
        assert_eq!(scripts.len(), 1, "one administrator prompt only");
        let script = &scripts[0];
        assert_eq!(script.matches("ln -sfn").count(), 2);
        assert!(script.contains(&layout.target("aevan").to_string_lossy().into_owned()));
        assert!(script.contains(&layout.target("aevand").to_string_lossy().into_owned()));
    }

    #[test]
    fn the_remove_script_removes_both_temp_targets_in_one_script() {
        let host = FakeHost::default();
        let layout = Layout::new(
            std::env::temp_dir().join("aevan-links"),
            std::env::temp_dir().join("Aevan.app/Contents/MacOS"),
        );
        let runner = RecordingRunner::default();
        remove(&host, &layout, &runner).expect("remove");
        let scripts = runner.scripts.borrow();
        assert_eq!(scripts.len(), 1, "one administrator prompt only");
        assert_eq!(scripts[0].matches("rm -f").count(), 2);
    }

    #[cfg(unix)]
    struct ShellRunner;

    #[cfg(unix)]
    impl ScriptRunner for ShellRunner {
        fn run(&self, script: &str) -> Result<(), String> {
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .output()
                .map_err(|error| error.to_string())?;
            if output.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
            }
        }
    }

    #[cfg(unix)]
    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aevan-cli-tools-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn install_and_remove_create_real_symlinks_against_temporary_paths() {
        let root = temp_root("link");
        let bundle = root.join("Aevan.app/Contents/MacOS");
        let links = root.join("bin");
        std::fs::create_dir_all(&bundle).expect("bundle dir");
        std::fs::create_dir_all(&links).expect("link dir");
        for tool in TOOL_NAMES {
            std::fs::write(bundle.join(tool), b"binary").expect("bundle copy");
        }
        let layout = Layout::new(&links, &bundle);
        let host = RealLinkHost;

        install(&host, &layout, &ShellRunner).expect("install");
        for tool in TOOL_NAMES {
            assert_eq!(
                std::fs::read_link(layout.link(tool)).expect("symlink"),
                layout.target(tool)
            );
        }
        assert_eq!(
            state(&host, &layout),
            CliToolsState::Installed {
                path: layout.link(TOOL_NAMES[0])
            }
        );

        // Idempotent: a second install leaves the same links.
        install(&host, &layout, &ShellRunner).expect("second install");
        remove(&host, &layout, &ShellRunner).expect("remove");
        for tool in TOOL_NAMES {
            assert!(!layout.link(tool).exists());
        }
        assert_eq!(state(&host, &layout), CliToolsState::NotInstalled);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn the_shell_refuses_to_overwrite_a_real_file() {
        let root = temp_root("file");
        let bundle = root.join("Aevan.app/Contents/MacOS");
        let links = root.join("bin");
        std::fs::create_dir_all(&bundle).expect("bundle dir");
        std::fs::create_dir_all(&links).expect("link dir");
        for tool in TOOL_NAMES {
            std::fs::write(bundle.join(tool), b"binary").expect("bundle copy");
        }
        std::fs::write(links.join("aevan"), b"someone else's file").expect("foreign file");

        let layout = Layout::new(&links, &bundle);
        let error = install(&RealLinkHost, &layout, &ShellRunner).expect_err("must refuse");
        assert!(error.contains("not an Aevan symlink"), "{error}");
        assert_eq!(
            std::fs::read(links.join("aevan")).expect("foreign file intact"),
            b"someone else's file"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
