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
    pub socket: Option<PathBuf>,
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
    /// macOS: a Mach name nothing provides, allowed so that a process can
    /// be told to be in this sandbox from outside it.
    pub mark: Option<String>,
    /// Linux: a directory on disk to mount at `/tmp`, where what is written
    /// counts against the disk and goes with the run. Without one `/tmp` is
    /// a memory file system, which no process is charged for.
    pub tmp: Option<PathBuf>,
    /// Linux: the same for `/dev/shm`, which is where POSIX shared memory
    /// and semaphores live. With one, the rest of `/dev`, a memory file
    /// system as well, is read-only.
    pub shm: Option<PathBuf>,
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

const MACH_SERVICES: [&str; 2] = [
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.notification_center",
];

/// The service that judges a certificate for the Security framework. Only
/// a sandbox with a way out has a certificate to judge, so only that one
/// may ask it. It runs outside the sandbox and may fetch what a certificate
/// names (an issuer, a revocation answer) by itself, past the proxy: a
/// known limit of an isolated session on macOS (threat model).
const MACH_TRUST: &str = "com.apple.trustd.agent";

/// What `/opt` and `/usr` hold besides programs, where Homebrew installs:
/// the data directories of local databases and services, and their
/// configuration, passwords included. Closed after the system's trees are
/// opened; a `read` of the policy opens one again, coming later.
const MAC_SERVICES_DATA: [&str; 4] = [
    "/opt/homebrew/var",
    "/opt/homebrew/etc",
    "/usr/local/var",
    "/usr/local/etc",
];

/// What of those a program needs all the same: the certificates its TLS
/// library trusts.
const MAC_CERTIFICATES: &str =
    r"^/(opt/homebrew|usr/local)/etc/(openssl[^/]*|ca-certificates)(/|$)";

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
        let trees = trees.chain(&self.socket);
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
        let way_out = self.proxy_port.is_some() || self.relay.is_some();
        let trust = way_out.then_some(MACH_TRUST);
        for name in MACH_SERVICES.into_iter().chain(trust) {
            out += &format!("(allow mach-lookup (global-name \"{name}\"))\n");
        }
        if let Some(mark) = &self.mark {
            let mark = quoted(Path::new(mark));
            out += &format!("(allow mach-lookup (global-name {mark}))\n");
        }
        let system = MAC_SYSTEM.map(PathBuf::from);
        out += &format!("(allow file-read* {})\n", subpaths(&system));
        let data = MAC_SERVICES_DATA.map(PathBuf::from);
        out += &format!("(deny file-read* {})\n", subpaths(&data));
        out += &format!("(allow file-read* (regex #\"{MAC_CERTIFICATES}\"))\n");
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
        if let Some(socket) = &self.socket {
            let socket = quoted(socket);
            out += &format!("(allow network-outbound (literal {socket}))\n");
            out += &format!("(allow file-read-metadata (literal {socket}))\n");
        }
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
        if let Some(shm) = &self.shm {
            flag("--bind", &[shm, Path::new("/dev/shm")]);
        }
        flag("--proc", &[Path::new("/proc")]);
        match &self.tmp {
            Some(tmp) => flag("--bind", &[tmp, Path::new("/tmp")]),
            None => flag("--tmpfs", &[Path::new("/tmp")]),
        }
        for dir in &self.readable {
            flag("--ro-bind", &[dir, dir]);
        }
        for dir in &self.secrets {
            flag("--tmpfs", &[dir]);
        }
        for dir in self.writes() {
            flag("--bind", &[dir, dir]);
        }
        if let Some(socket) = &self.socket {
            flag("--bind", &[socket, socket]);
        }
        if let Some(relay) = &self.relay {
            flag("--bind", &[relay, relay]);
        }
        // What bubblewrap starts from is an empty tree that takes writes.
        for dir in &self.secrets {
            flag("--remount-ro", &[dir]);
        }
        if self.shm.is_some() {
            flag("--remount-ro", &[Path::new("/dev")]);
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

/// A name for the sandbox of the run in `dir`, whose name is random, where it
/// takes one to find what is left in a sandbox: see [`Jail::mark`].
pub fn mark_of(sandbox: Sandbox, what: &str, dir: &Path) -> Option<String> {
    let name = dir.file_name().unwrap_or_default().to_string_lossy();
    (sandbox == Sandbox::Seatbelt).then(|| format!("lonca.{what}.{name}"))
}

/// Whether `dir` may be opened by being on `PATH`: not a tree that holds
/// something closed, such as the home directory itself.
pub fn may_expose(dir: &OsStr, closed: &[PathBuf]) -> bool {
    let dir = Path::new(dir);
    dir.is_absolute() && !closed.iter().any(|c| c.starts_with(dir))
}

/// The closed tree that `tree` holds or lies in.
pub fn holding_secrets<'a>(tree: &Path, secrets: &'a [PathBuf]) -> Option<&'a PathBuf> {
    secrets
        .iter()
        .find(|s| tree.starts_with(s) || s.starts_with(tree))
}

/// The trees a program needs of what is closed: the directories on `PATH`,
/// and the directories of `programs`, each as it is named and as it really
/// is, since a link on `PATH` leads elsewhere.
///
/// Nothing under `writable` is followed: a link the agent made there would
/// open whatever it points at, the next time a sandbox is built.
pub fn program_trees(
    path: &OsStr,
    programs: &[PathBuf],
    closed: &[PathBuf],
    writable: &[PathBuf],
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |dir: Option<PathBuf>| {
        let Some(named) = dir else {
            return;
        };
        let Ok(dir) = named.canonicalize() else {
            return;
        };
        let inside = |p: &Path| writable.iter().any(|w| p.starts_with(w));
        if !inside(&named)
            && !inside(&dir)
            && may_expose(dir.as_os_str(), closed)
            && !out.contains(&dir)
        {
            out.push(dir);
        }
    };
    for dir in std::env::split_paths(path) {
        add(Some(dir));
    }
    for program in programs {
        add(program.parent().map(Path::to_path_buf));
        let real = program.canonicalize().ok();
        add(real.and_then(|p| p.parent().map(Path::to_path_buf)));
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_seatbelt_marks_a_sandbox_and_the_mark_is_the_runs_alone() {
        let dir = Path::new("/scratch/verify-abc");
        let marked = mark_of(Sandbox::Seatbelt, "verify", dir);
        assert_eq!(marked.as_deref(), Some("lonca.verify.verify-abc"));
        assert_eq!(mark_of(Sandbox::Bubblewrap, "verify", dir), None);
        assert_eq!(mark_of(Sandbox::None, "verify", dir), None);
    }

    use super::*;

    fn jail() -> Jail {
        Jail {
            workspace: "/w/ws".into(),
            writable: vec!["/w/scratch".into()],
            readable: vec!["/h/.local/bin".into()],
            secrets: vec!["/h/.lonca".into()],
            socket: Some("/h/.lonca/s.sock".into()),
            proxy_port: Some(1234),
            relay: None,
            loopback: false,
            mark: None,
            tmp: None,
            shm: None,
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
            mark: None,
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

    /// `/opt` and `/usr` are open for the programs in them. Where Homebrew
    /// keeps the data and the configuration of local services is closed
    /// again, but for the certificates; a `read` of the policy, which comes
    /// later, opens what it names.
    #[test]
    fn a_seatbelt_profile_closes_what_local_services_keep() {
        let open = Jail {
            readable: vec!["/usr/local/var/cache".into()],
            ..jail()
        };
        let p = open.seatbelt();
        let system = at(&p, "(allow file-read* (subpath \"/System\")");
        let closed = at(
            &p,
            "(deny file-read* (subpath \"/opt/homebrew/var\") (subpath \"/opt/homebrew/etc\") \
             (subpath \"/usr/local/var\") (subpath \"/usr/local/etc\"))\n",
        );
        let certificates = at(
            &p,
            "(allow file-read* (regex #\"^/(opt/homebrew|usr/local)/etc/",
        );
        let named = at(&p, "(subpath \"/usr/local/var/cache\"))\n");
        assert!(
            system < closed && closed < certificates && certificates < named,
            "{p}"
        );
    }

    /// The profile is one Seatbelt takes, and it does what it says, on the
    /// files of this machine: a regular expression in it is not checked by
    /// anything else.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_sandbox_takes_the_profile_and_closes_what_it_says() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().canonicalize().unwrap();
        let jail = Jail {
            workspace: ws.clone(),
            writable: vec![],
            readable: vec![],
            secrets: vec![],
            socket: None,
            proxy_port: None,
            ..jail()
        };
        let run = |script: &str| {
            let argv: [OsString; 3] = ["/bin/sh".into(), "-c".into(), script.into()];
            let mut c = jail.command(Sandbox::Seatbelt, &argv).unwrap();
            c.current_dir(&ws).output().unwrap()
        };
        let out = run("echo in > f && cat f && ls /usr/bin >/dev/null");
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{said}");
        assert_eq!(out.stdout, b"in\n");
        // Where a closed directory exists here, it does not list.
        for closed in MAC_SERVICES_DATA {
            if Path::new(closed).is_dir() {
                let out = run(&format!("ls {closed}"));
                assert!(!out.status.success(), "{closed} lists");
            }
        }
        // A certificate store under one of them reads.
        for store in [
            "/opt/homebrew/etc/ca-certificates",
            "/usr/local/etc/ca-certificates",
        ] {
            if Path::new(store).is_dir() {
                let out = run(&format!("ls {store}"));
                assert!(out.status.success(), "{store} does not list");
            }
        }
    }

    #[test]
    fn a_seatbelt_profile_names_only_the_harmless_services() {
        let p = jail().seatbelt();
        // A way out, so a certificate to judge.
        assert_eq!(
            p.matches("(allow mach-lookup").count(),
            MACH_SERVICES.len() + 1
        );
        at(&p, &format!("(global-name \"{MACH_TRUST}\")"));
        let shut = Jail {
            proxy_port: None,
            ..jail()
        };
        let shut = shut.seatbelt();
        assert!(
            !shut.contains(MACH_TRUST),
            "no way out, nobody to trust: {shut}"
        );
        assert_eq!(
            shut.matches("(allow mach-lookup").count(),
            MACH_SERVICES.len()
        );
        let marked = Jail {
            mark: Some("lonca.run.x".into()),
            ..jail()
        };
        let line = "(allow mach-lookup (global-name \"lonca.run.x\"))\n";
        assert!(marked.seatbelt().contains(line));
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
        // The one that is always there closes what local services keep.
        assert_eq!(p.matches("(deny file").count(), 1, "{p}");
        assert!(!p.contains("(deny file-read* file-write*"), "{p}");
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
    fn bwrap_puts_tmp_on_disk_only_when_told_where() {
        let memory = strings(&jail().bwrap_args());
        let tmpfs = ["--tmpfs", "/tmp"];
        assert!(memory.windows(2).any(|w| w == tmpfs), "{memory:?}");
        let disk = Jail {
            tmp: Some("/w/run/tmp".into()),
            ..jail()
        };
        let args = strings(&disk.bwrap_args());
        assert!(!args.windows(2).any(|w| w == tmpfs), "{args:?}");
        let bound = ["--bind", "/w/run/tmp", "/tmp"];
        let at = args.windows(3).position(|w| w == bound);
        let usr = args
            .windows(3)
            .position(|w| w == ["--ro-bind-try", "/usr", "/usr"]);
        assert!(at.is_some() && usr < at, "{args:?}");
        // The rest is as it was: nothing else moved for it.
        let without = |a: &[String]| {
            let mut a = a.to_vec();
            let i = a.windows(3).position(|w| w == bound).unwrap();
            a.drain(i..i + 3);
            a
        };
        let mut plain = memory.clone();
        let i = plain.windows(2).position(|w| w == tmpfs).unwrap();
        plain.drain(i..i + 2);
        assert_eq!(without(&args), plain);
        // Seatbelt has no `/tmp` of its own to give.
        assert_eq!(disk.seatbelt(), jail().seatbelt());
    }

    #[test]
    fn bwrap_puts_shared_memory_on_disk_and_closes_the_rest_of_dev() {
        let plain = strings(&jail().bwrap_args());
        assert!(!plain.iter().any(|a| a == "/dev/shm"), "{plain:?}");
        assert!(!plain.windows(2).any(|w| w == ["--remount-ro", "/dev"]));
        let disk = Jail {
            shm: Some("/w/run/shm".into()),
            ..jail()
        };
        let a = strings(&disk.bwrap_args());
        let pos = |what: &[&str]| {
            a.windows(what.len())
                .position(|w| w == what)
                .unwrap_or_else(|| panic!("no {what:?} in {a:?}"))
        };
        let dev = pos(&["--dev", "/dev"]);
        let shm = pos(&["--bind", "/w/run/shm", "/dev/shm"]);
        let closed = pos(&["--remount-ro", "/dev"]);
        let root = pos(&["--remount-ro", "/"]);
        assert!(dev < shm && shm < closed && closed < root, "{a:?}");
        assert_eq!(disk.seatbelt(), jail().seatbelt());
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
    fn a_program_brings_its_directories_and_nothing_that_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let bin = home.join(".local/bin");
        let versions = home.join(".local/share/tool/1.0");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&versions).unwrap();
        std::fs::write(versions.join("tool"), "").unwrap();
        std::os::unix::fs::symlink(versions.join("tool"), bin.join("tool")).unwrap();
        let closed = [home.clone()];
        let path = std::env::join_paths([&home, &bin, Path::new("/no/such/dir")]).unwrap();
        let got = program_trees(&path, &[bin.join("tool")], &closed, &[]);
        assert_eq!(got, [bin.clone(), versions]);
        // What the agent can write leads nowhere, by name or by what it is.
        let scratch = root.join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        std::os::unix::fs::symlink(&bin, scratch.join("bin")).unwrap();
        let path = std::env::join_paths([scratch.join("bin")]).unwrap();
        assert!(program_trees(&path, &[], &closed, std::slice::from_ref(&scratch)).is_empty());
        let path = std::env::join_paths([&bin]).unwrap();
        assert!(program_trees(&path, &[], &closed, &[bin]).is_empty());
    }

    #[test]
    fn a_tree_touches_a_secret_from_above_or_from_below() {
        let secrets = [PathBuf::from("/h/.lonca"), PathBuf::from("/k")];
        assert_eq!(
            holding_secrets(Path::new("/h/.lonca/x"), &secrets),
            Some(&secrets[0])
        );
        assert_eq!(
            holding_secrets(Path::new("/h"), &secrets),
            Some(&secrets[0])
        );
        assert_eq!(
            holding_secrets(Path::new("/k"), &secrets),
            Some(&secrets[1])
        );
        assert_eq!(holding_secrets(Path::new("/h/other"), &secrets), None);
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
