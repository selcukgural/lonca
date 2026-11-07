//! The sandbox `lonca run` puts an agent in: Lonca's own, so that an agent
//! with no hooks at all can be held to it. Unlike the verifier's, which runs
//! a project's own build, this one assumes the process inside is hostile.
//!
//! A [`Jail`] is a description; [`Jail::definition`] turns it into what the
//! operating system reads, and that text's digest is what a human signs.
//! Everything else on the machine is refused, so what is forgotten here stays
//! closed. A container backend is one more [`Sandbox`] arm.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use lonca_core::canonical::sha256_hex;

use crate::Sandbox;

/// Where one sandbox ends. Paths are absolute and fully resolved, since both
/// sandboxes compare them with the real path of what is opened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Jail {
    /// The agent's working directory: read and write.
    pub workspace: PathBuf,
    /// Scratch roots and the run's own directories: read and write.
    pub writable: Vec<PathBuf>,
    /// Trees the agent reads besides the system's: its own program.
    pub readable: Vec<PathBuf>,
    /// Closed whatever else is allowed: Lonca's stores and keys.
    pub secrets: Vec<PathBuf>,
    /// The daemon's socket, the one socket outside that can be reached.
    pub socket: PathBuf,
    /// The loopback port of the network proxy, the one way out.
    pub proxy_port: Option<u16>,
    /// Linux: the agent has no network at all, and the socket that takes
    /// the place of the proxy, one the launcher relays to it.
    pub relay: Option<PathBuf>,
    /// macOS: the command may listen on loopback and connect to it. Seatbelt
    /// can not tell its own listener from the machine's, so this opens every
    /// local service as well, some of which run things outside the sandbox.
    /// A human's choice, shown by [`Jail::name`]. On Linux loopback is the
    /// sandbox's own and always there.
    pub loopback: bool,
}

/// Mach services a command needs to start and that open no way out: name
/// lookups, notifications, certificates. Keychain, DNS and Launch Services
/// (which would start a process outside the sandbox) are not among them.
/// What every program needs to start on macOS. Everything else on the
/// machine is closed: other workspaces hold session tokens, and there is no
/// list of what a home directory or a shared disk may hold.
const MAC_SYSTEM: [&str; 13] = [
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/opt",
    "/private/etc",
    "/private/var/select",
    "/private/var/db/timezone",
    "/private/var/db/dyld",
    "/private/var/db/xcode_select_link",
    "/Library/Apple",
    "/Library/Developer",
    "/Library/Frameworks",
];

/// Single names: a link's own name, a directory's list, a device.
const MAC_LITERALS: [&str; 11] = [
    "/",
    "/etc",
    "/var",
    "/tmp",
    "/private",
    "/dev",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/dtracehelper",
];

/// The same on Linux. A name that is missing is passed over.
const LINUX_SYSTEM: [&str; 8] = [
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt",
];

const MACH_SERVICES: [&str; 3] = [
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.notification_center",
    "com.apple.trustd.agent",
];

fn quoted(p: &Path) -> String {
    let text = String::from_utf8_lossy(p.as_os_str().as_bytes());
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `(subpath "a") (subpath "b")`.
fn subpaths<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> String {
    let each = paths
        .into_iter()
        .map(|p| format!("(subpath {})", quoted(p)));
    each.collect::<Vec<_>>().join(" ")
}

impl Jail {
    /// The trees the agent may write.
    fn writes(&self) -> impl Iterator<Item = &PathBuf> {
        std::iter::once(&self.workspace).chain(&self.writable)
    }

    /// Every directory above a tree the agent uses: `stat` on each of them
    /// is how a path is resolved, and it tells nothing of what is beside it.
    fn ancestors(&self) -> BTreeSet<&Path> {
        let trees = self.writes().chain(&self.readable);
        let trees = trees.chain(std::iter::once(&self.socket));
        trees.flat_map(|t| t.ancestors().skip(1)).collect()
    }

    /// The Seatbelt profile. The last rule that matches wins, so the order
    /// here is the meaning: `secrets` come after everything that opens.
    pub fn seatbelt(&self) -> String {
        let mut out = String::from(
            "(version 1)\n(deny default)\n\
             (allow process-fork)\n(allow process-exec*)\n\
             (allow process-info* (target same-sandbox))\n\
             (allow signal (target same-sandbox))\n\
             (allow sysctl-read)\n(allow file-ioctl)\n\
             (allow ipc-posix-sem)\n\
             (allow ipc-posix-shm-read* ipc-posix-shm-write-data ipc-posix-shm-write-create)\n",
        );
        for name in MACH_SERVICES {
            out += &format!("(allow mach-lookup (global-name \"{name}\"))\n");
        }
        let system = MAC_SYSTEM.map(PathBuf::from);
        out += &format!("(allow file-read* {})\n", subpaths(&system));
        let names = MAC_LITERALS.map(|p| format!("(literal \"{p}\")"));
        out += &format!("(allow file-read* {})\n", names.join(" "));
        for dir in self.ancestors() {
            out += &format!("(allow file-read-metadata (literal {}))\n", quoted(dir));
        }
        let reads = subpaths(self.writes().chain(&self.readable));
        out += &format!("(allow file-read* {reads})\n");
        let writes = subpaths(self.writes());
        out += &format!("(allow file-write* {writes})\n");
        out += "(allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\") \
                (literal \"/dev/dtracehelper\"))\n";
        if !self.secrets.is_empty() {
            let closed = subpaths(&self.secrets);
            out += &format!("(deny file-read* file-write* {closed})\n");
        }
        // Network rules look at the address, and the agent's own sockets
        // are at paths it may write anyway.
        let socket = quoted(&self.socket);
        out += &format!("(allow network-outbound (literal {socket}))\n");
        out += &format!("(allow file-read-metadata (literal {socket}))\n");
        out += &format!("(allow network-bind network-outbound {writes})\n");
        if let Some(port) = self.proxy_port {
            out += &format!("(allow network-outbound (remote ip \"localhost:{port}\"))\n");
        }
        if self.loopback {
            out += "(allow network-bind network-inbound network-outbound \
                    (local ip \"localhost:*\"))\n";
        }
        out
    }

    /// The bubblewrap arguments. Each mount covers what came before it, so
    /// here too the order is the meaning.
    pub fn bwrap_args(&self) -> Vec<OsString> {
        let mut out: Vec<OsString> = Vec::new();
        let mut flag = |flag: &str, paths: &[&Path]| {
            out.push(flag.into());
            out.extend(paths.iter().map(|p| p.as_os_str().to_owned()));
        };
        flag("--unshare-all", &[]);
        flag("--die-with-parent", &[]);
        flag("--new-session", &[]);
        for dir in LINUX_SYSTEM {
            flag("--ro-bind-try", &[Path::new(dir), Path::new(dir)]);
        }
        flag("--dev", &[Path::new("/dev")]);
        flag("--proc", &[Path::new("/proc")]);
        flag("--tmpfs", &[Path::new("/tmp")]);
        for dir in &self.readable {
            flag("--ro-bind", &[dir, dir]);
        }
        for dir in &self.secrets {
            flag("--tmpfs", &[dir]);
        }
        for dir in self.writes() {
            flag("--bind", &[dir, dir]);
        }
        flag("--bind", &[&self.socket, &self.socket]);
        if let Some(relay) = &self.relay {
            flag("--bind", &[relay, relay]);
        }
        // What bubblewrap starts from is an empty tree that takes writes.
        for dir in &self.secrets {
            flag("--remount-ro", &[dir]);
        }
        flag("--remount-ro", &[Path::new("/")]);
        flag("--chdir", &[&self.workspace]);
        out
    }

    /// The kind of sandbox as the log names it: what a reader of the log
    /// has to know about it, which a digest does not say.
    pub fn name(&self, sandbox: Sandbox) -> String {
        match (sandbox, self.loopback) {
            (Sandbox::Seatbelt, true) => format!("{}-loopback", sandbox.name()),
            _ => sandbox.name().to_string(),
        }
    }

    /// What the operating system is given, as bytes to sign; `None` for a
    /// sandbox this can not be enforced by.
    pub fn definition(&self, sandbox: Sandbox) -> Option<Vec<u8>> {
        match sandbox {
            Sandbox::Seatbelt => Some(self.seatbelt().into_bytes()),
            Sandbox::Bubblewrap => {
                let args = self.bwrap_args();
                let bytes = args.iter().map(|a| a.as_bytes());
                Some(bytes.collect::<Vec<_>>().join(&0u8))
            }
            Sandbox::None => None,
        }
    }

    /// The digest of [`Jail::definition`].
    pub fn digest(&self, sandbox: Sandbox) -> Option<String> {
        self.definition(sandbox).map(|d| sha256_hex(&d))
    }

    /// `argv` in the sandbox, or `None` when there is no sandbox to run it
    /// in: `lonca run` never falls back to running it bare.
    pub fn command(&self, sandbox: Sandbox, argv: &[OsString]) -> Option<Command> {
        let mut c = match sandbox {
            Sandbox::Seatbelt => {
                let mut c = Command::new("/usr/bin/sandbox-exec");
                c.arg("-p").arg(self.seatbelt());
                c
            }
            Sandbox::Bubblewrap => {
                let mut c = Command::new(sandbox.program()?);
                c.args(self.bwrap_args()).arg("--");
                c
            }
            Sandbox::None => return None,
        };
        c.args(argv).current_dir(&self.workspace);
        Some(c)
    }
}

/// Whether `dir` may be opened by being on `PATH`: not a tree that holds
/// something closed, such as the home directory itself.
pub fn may_expose(dir: &OsStr, closed: &[PathBuf]) -> bool {
    let dir = Path::new(dir);
    dir.is_absolute() && !closed.iter().any(|c| c.starts_with(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jail() -> Jail {
        Jail {
            workspace: "/w/ws".into(),
            writable: vec!["/w/scratch".into()],
            readable: vec!["/h/.local/bin".into()],
            secrets: vec!["/h/.lonca".into()],
            socket: "/h/.lonca/s.sock".into(),
            proxy_port: Some(1234),
            relay: None,
            loopback: false,
        }
    }

    /// The position of `what` in `text`, which must hold it.
    fn at(text: &str, what: &str) -> usize {
        text.find(what)
            .unwrap_or_else(|| panic!("no {what} in {text}"))
    }

    #[test]
    fn a_seatbelt_profile_refuses_by_default_and_closes_in_order() {
        let p = jail().seatbelt();
        assert!(p.starts_with("(version 1)\n(deny default)\n"), "{p}");
        assert!(!p.contains("(allow default)"), "{p}");
        // Only the system opens by itself, and the stores close last of all.
        assert!(!p.contains("(allow file-read*)"), "{p}");
        assert!(!p.contains("(subpath \"/h\")"), "{p}");
        for dir in MAC_SYSTEM {
            at(&p, &format!("(subpath \"{dir}\")"));
        }
        for name in MAC_LITERALS {
            at(&p, &format!("(literal \"{name}\")"));
        }
        assert!(!p.contains("(subpath \"/dev\")"), "{p}");
        let open = at(&p, "(allow file-read* (subpath \"/System\")");
        let bin = at(
            &p,
            "(allow file-read* (subpath \"/w/ws\") (subpath \"/w/scratch\") \
             (subpath \"/h/.local/bin\"))\n",
        );
        let store = at(
            &p,
            "(deny file-read* file-write* (subpath \"/h/.lonca\"))\n",
        );
        assert!(open < bin && bin < store, "{p}");
        // Writes reach the workspace and the scratch roots, nothing else.
        assert_eq!(p.matches("(allow file-write* ").count(), 1, "{p}");
        at(
            &p,
            "(allow file-write* (subpath \"/w/ws\") (subpath \"/w/scratch\"))\n",
        );
    }

    #[test]
    fn a_seatbelt_profile_has_one_way_out() {
        let p = jail().seatbelt();
        at(
            &p,
            "(allow network-outbound (literal \"/h/.lonca/s.sock\"))\n",
        );
        at(
            &p,
            "(allow network-outbound (remote ip \"localhost:1234\"))\n",
        );
        at(
            &p,
            "(allow network-bind network-outbound (subpath \"/w/ws\") (subpath \"/w/scratch\"))\n",
        );
        assert_eq!(p.matches("(allow network").count(), 3, "{p}");
        let closed = Jail {
            proxy_port: None,
            ..jail()
        };
        assert!(!closed.seatbelt().contains("remote ip"));
    }

    #[test]
    fn loopback_is_closed_unless_a_human_opened_it_and_then_it_shows() {
        let j = jail();
        assert!(!j.seatbelt().contains("localhost:*"));
        assert_eq!(j.name(Sandbox::Seatbelt), "seatbelt");
        let open = Jail {
            loopback: true,
            ..jail()
        };
        at(
            &open.seatbelt(),
            "(allow network-bind network-inbound network-outbound (local ip \"localhost:*\"))\n",
        );
        assert_eq!(open.name(Sandbox::Seatbelt), "seatbelt-loopback");
        assert_ne!(j.digest(Sandbox::Seatbelt), open.digest(Sandbox::Seatbelt));
        // Linux has it either way, so there it says nothing.
        assert_eq!(open.name(Sandbox::Bubblewrap), "bwrap");
        assert_eq!(open.bwrap_args(), j.bwrap_args());
    }

    #[test]
    fn a_seatbelt_profile_shows_the_way_to_a_tree_and_nothing_beside_it() {
        let p = jail().seatbelt();
        for dir in ["/", "/w", "/h", "/h/.local"] {
            at(
                &p,
                &format!("(allow file-read-metadata (literal \"{dir}\"))\n"),
            );
        }
        assert!(!p.contains("(literal \"/h/.local/bin\")"), "{p}");
    }

    #[test]
    fn a_seatbelt_profile_names_only_the_harmless_services() {
        let p = jail().seatbelt();
        assert_eq!(p.matches("(allow mach-lookup").count(), MACH_SERVICES.len());
        for name in MACH_SERVICES {
            at(&p, &format!("(global-name \"{name}\")"));
        }
    }

    #[test]
    fn nothing_closed_writes_no_rule_for_it() {
        let open = Jail {
            secrets: vec![],
            ..jail()
        };
        let p = open.seatbelt();
        assert!(!p.contains("(deny file"), "{p}");
    }

    #[test]
    fn a_path_can_not_end_the_string_it_is_quoted_in() {
        let evil = Path::new("/w/a\") (allow default) (\"\\");
        assert_eq!(quoted(evil), "\"/w/a\\\") (allow default) (\\\"\\\\\"");
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        let each = args.iter().map(|a| a.to_string_lossy().into_owned());
        each.collect()
    }

    #[test]
    fn bwrap_has_no_network_and_mounts_in_order() {
        let a = strings(&jail().bwrap_args());
        let pos = |what: &[&str]| {
            a.windows(what.len())
                .position(|w| w == what)
                .unwrap_or_else(|| panic!("no {what:?} in {a:?}"))
        };
        pos(&["--unshare-all"]);
        pos(&["--die-with-parent"]);
        pos(&["--new-session"]);
        pos(&["--dev", "/dev"]);
        pos(&["--proc", "/proc"]);
        pos(&["--chdir", "/w/ws"]);
        assert!(!a.windows(3).any(|w| w == ["--ro-bind", "/", "/"]), "{a:?}");
        let usr = pos(&["--ro-bind-try", "/usr", "/usr"]);
        let tmp = pos(&["--tmpfs", "/tmp"]);
        let bin = pos(&["--ro-bind", "/h/.local/bin", "/h/.local/bin"]);
        let store = pos(&["--tmpfs", "/h/.lonca"]);
        let ws = pos(&["--bind", "/w/ws", "/w/ws"]);
        let scratch = pos(&["--bind", "/w/scratch", "/w/scratch"]);
        let socket = pos(&["--bind", "/h/.lonca/s.sock", "/h/.lonca/s.sock"]);
        assert!(usr < tmp && tmp < bin && bin < store);
        assert!(store < ws && ws < scratch && scratch < socket);
        assert!(socket < pos(&["--remount-ro", "/h/.lonca"]));
        assert!(socket < pos(&["--remount-ro", "/"]));
        assert!(!a.iter().any(|x| x == "--share-net"), "{a:?}");
    }

    #[test]
    fn bwrap_takes_the_relay_in_only_when_there_is_one() {
        let without = strings(&jail().bwrap_args());
        assert!(!without.iter().any(|x| x == "/run/relay.sock"));
        let with = Jail {
            relay: Some("/run/relay.sock".into()),
            ..jail()
        };
        let args = strings(&with.bwrap_args());
        let want = ["--bind", "/run/relay.sock", "/run/relay.sock"];
        assert!(args.windows(3).any(|w| w == want), "{args:?}");
    }

    #[test]
    fn what_is_signed_is_what_is_run() {
        let j = jail();
        assert_eq!(
            j.definition(Sandbox::Seatbelt).unwrap(),
            j.seatbelt().into_bytes()
        );
        let bwrap = j.definition(Sandbox::Bubblewrap).unwrap();
        assert!(bwrap.windows(14).any(|w| w == b"--unshare-all\0"));
        assert_eq!(
            j.digest(Sandbox::Seatbelt).unwrap(),
            sha256_hex(j.seatbelt().as_bytes())
        );
        let other = Jail {
            proxy_port: Some(1),
            ..jail()
        };
        assert_ne!(j.digest(Sandbox::Seatbelt), other.digest(Sandbox::Seatbelt));
    }

    #[test]
    fn no_sandbox_means_nothing_runs() {
        let j = jail();
        assert!(j.definition(Sandbox::None).is_none());
        assert!(j.digest(Sandbox::None).is_none());
        assert!(j.command(Sandbox::None, &["/bin/sh".into()]).is_none());
    }

    #[test]
    fn a_command_goes_through_the_sandbox_in_the_workspace() {
        let j = jail();
        let argv = ["/bin/echo".into(), "hi".into()];
        let c = j.command(Sandbox::Seatbelt, &argv).unwrap();
        assert_eq!(c.get_program(), "/usr/bin/sandbox-exec");
        assert_eq!(c.get_current_dir(), Some(Path::new("/w/ws")));
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy()).collect();
        assert_eq!(args[..1], ["-p"]);
        assert_eq!(args[1], j.seatbelt());
        assert_eq!(args[2..], ["/bin/echo", "hi"]);
    }

    #[test]
    fn path_entries_that_hold_something_closed_stay_closed() {
        let closed = [PathBuf::from("/h"), PathBuf::from("/h/.lonca")];
        assert!(may_expose(OsStr::new("/usr/bin"), &closed));
        assert!(may_expose(OsStr::new("/h/.cargo/bin"), &closed));
        assert!(!may_expose(OsStr::new("/h"), &closed));
        assert!(!may_expose(OsStr::new("/"), &closed));
        assert!(!may_expose(OsStr::new("relative/bin"), &closed));
    }
}
