//! Evidence producers. The Gatekeeper runs build and test commands itself,
//! in a sandbox, on the merged tree; the agent's own reports are ignored.
//!
//! Results are nondeterministic by nature, so they are recorded as
//! [`Attestation`]s in the operation log and never recomputed on replay.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use lonca_core::canonical::sha256_hex;
use lonca_core::ops::{Attestation, CheckKind, CheckResult};
use lonca_core::{FileMap, FileMode, GitId, Result, Store};
use lonca_policy::config::Verification;
use lonca_symbols::engine::{ENGINE_CURRENT, reads_text};
use lonca_symbols::{Lang, parse};

pub mod jail;
mod process;
pub mod sweep;

use jail::Jail;

const BWRAP: [&str; 3] = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sandbox {
    /// macOS Seatbelt (`sandbox-exec`).
    Seatbelt,
    /// Linux bubblewrap.
    Bubblewrap,
    None,
}

impl Sandbox {
    pub fn detect() -> Self {
        let exists = |p: &str| Path::new(p).exists();
        if cfg!(target_os = "macos") && exists("/usr/bin/sandbox-exec") {
            Sandbox::Seatbelt
        } else if BWRAP.iter().any(|p| exists(p)) {
            Sandbox::Bubblewrap
        } else {
            Sandbox::None
        }
    }

    /// The program that holds a command in this sandbox, by absolute path:
    /// `PATH` is the environment's to change.
    pub fn program(self) -> Option<&'static str> {
        match self {
            Sandbox::Seatbelt => Some("/usr/bin/sandbox-exec"),
            Sandbox::Bubblewrap => BWRAP.iter().copied().find(|p| Path::new(p).exists()),
            Sandbox::None => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Sandbox::Seatbelt => "seatbelt",
            Sandbox::Bubblewrap => "bwrap",
            Sandbox::None => "none",
        }
    }
}

pub struct Verifier {
    pub sandbox: Sandbox,
    /// Directory under which work trees are created.
    pub scratch: PathBuf,
}

impl Verifier {
    pub fn new(scratch: PathBuf) -> Self {
        Self {
            sandbox: Sandbox::detect(),
            scratch,
        }
    }

    /// Ends what the verifications of a daemon that stopped in the middle of
    /// them left running, and takes their directories away, which only their
    /// run would have. Under Seatbelt or with no sandbox a command outlives
    /// the daemon, and with nothing timing it; under bubblewrap it went with
    /// it. With no sandbox nothing tells its processes, so only the directory
    /// goes. Returns how many it found.
    ///
    /// It ends whatever runs in those sandboxes, so it is only for a daemon
    /// that knows it is the one on this directory, before it verifies.
    pub fn clear_left_over(&self) -> usize {
        let Ok(entries) = fs::read_dir(&self.scratch) else {
            return 0;
        };
        let mut found = 0;
        for entry in entries.flatten() {
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if !is_dir || !entry.file_name().as_bytes().starts_with(b"verify-") {
                continue;
            }
            found += 1;
            let dir = entry.path();
            if let Some(mark) = jail::mark_of(self.sandbox, "verify", &dir) {
                sweep::end_what_is_left(&mark);
            }
            if let Err(e) = process::remove_tree(&dir) {
                eprintln!("lonca: verify: removing {}: {e}", dir.display());
            }
        }
        found
    }

    /// What the grammars make of every file the change touched. It passes: a
    /// grammar is older than its language, so a parse error may be syntax it
    /// does not know yet, and from symbol engine 17 no language takes one for
    /// a mistake. The files a grammar could not read are named in `unread`,
    /// for the person the proposal waits for (`unread_files` in its facts);
    /// whether the code is right is for the build and the tests to say.
    pub fn syntax(
        &self,
        store: &Store,
        files: &FileMap,
        touched: &[String],
        subject: &GitId,
    ) -> Result<Attestation> {
        let mut unread = Vec::new();
        for p in touched {
            let (Some(lang), Some(e)) = (Lang::detect(p), files.get(p)) else {
                continue;
            };
            let bytes = store.read_blob(&e.blob)?;
            // Past its size or its budget a file goes by its lines, and
            // bytes that are no text are not parsed at all.
            let read = std::str::from_utf8(&bytes)
                .map(|t| !reads_text(ENGINE_CURRENT, lang, t) || !parse(lang, t).has_error)
                .unwrap_or(false);
            if !read {
                unread.push(p.clone());
            }
        }
        let mut details = BTreeMap::new();
        details.insert("files_checked".into(), touched.len().to_string());
        if !unread.is_empty() {
            details.insert("unread".into(), unread.join(","));
        }
        Ok(Attestation {
            check: CheckKind::Syntax,
            result: CheckResult::Pass,
            subject_tree: subject.clone(),
            details,
            env: "tree-sitter".into(),
            log: None,
            producer: "lonca-verify/syntax".into(),
        })
    }

    /// Runs the configured build and test commands on `files`, then the
    /// named checks in `cfg.checks`, in name order. One with no command (a
    /// name the policy no longer defines) does not run: there is nothing
    /// to pass it.
    pub fn run(
        &self,
        store: &Store,
        files: &FileMap,
        subject: &GitId,
        cfg: &Verification,
    ) -> Result<Vec<Attestation>> {
        let mut out = Vec::new();
        let builtin = [
            (CheckKind::Build, &cfg.build),
            (CheckKind::Tests, &cfg.test),
            (CheckKind::Extended, &cfg.on_signature_change),
        ];
        let builtin = builtin
            .into_iter()
            .filter_map(|(k, c)| c.as_ref().map(|c| (k, None, c)));
        let named = cfg.checks.iter().filter(|(_, c)| !c.trim().is_empty());
        let named = named.map(|(n, c)| (CheckKind::Named, Some(n), c));
        let steps: Vec<(CheckKind, Option<&String>, &String)> = builtin.chain(named).collect();
        if steps.is_empty() {
            return Ok(out);
        }
        fs::create_dir_all(&self.scratch)?;
        let work = tempfile::Builder::new()
            .prefix("verify-")
            .tempdir_in(&self.scratch)?;
        let root = work.path().canonicalize()?;
        let _gone = Gone(&root);
        materialize(store, files, &root.join("tree"))?;
        let identity = self.identify(&root, cfg);
        let mut failed = false;
        for (kind, name, cmd) in steps {
            let named = || {
                let name = name.map(|n| ("name".to_string(), n.clone()));
                let mut d: BTreeMap<_, _> = name.into_iter().collect();
                d.extend(identity.lines.clone());
                d
            };
            if failed {
                out.push(attestation(
                    kind,
                    CheckResult::Skipped,
                    subject,
                    named(),
                    self.env(cmd, &identity),
                    None,
                ));
                continue;
            }
            let started = Instant::now();
            let mut attempts = 0;
            let (result, details, log) = loop {
                attempts += 1;
                let run = self.exec(cmd, &root, Duration::from_secs(cfg.timeout_seconds), cfg);
                let done = run.0 == CheckResult::Pass || attempts > cfg.retries;
                if done {
                    break run;
                }
            };
            let mut details = details;
            details.extend(named());
            let took = started.elapsed().as_millis().to_string();
            details.insert("duration_ms".into(), took);
            details.insert("attempts".into(), attempts.to_string());
            details.insert("sandbox".into(), self.sandbox.name().into());
            let log_id = store.write_blob(log.as_bytes())?;
            failed = result != CheckResult::Pass;
            out.push(attestation(
                kind,
                result,
                subject,
                details,
                self.env(cmd, &identity),
                Some(log_id),
            ));
        }
        Ok(out)
    }

    /// The sandbox a command runs in, from this process's environment.
    fn jail(&self, tree: &Path, writable: Vec<PathBuf>, cfg: &Verification) -> Jail {
        let env = |name: &str| std::env::var_os(name).map(PathBuf::from);
        let home = env("HOME");
        let named = [
            env("LONCA_HOME"),
            env("LONCA_HUMANS"),
            home.as_ref().map(|h| h.join(".lonca")),
            home.as_ref().map(|h| h.join(".config/lonca")),
        ];
        let real = |p: PathBuf| p.canonicalize().ok();
        let secrets = named.into_iter().flatten().filter_map(real).collect();
        let store = self.scratch.parent().and_then(|p| real(p.to_path_buf()));
        let passed: Vec<PathBuf> = cfg.env_passthrough.iter().filter_map(|n| env(n)).collect();
        let path = command_path(cfg);
        let closed = Closed {
            secrets,
            store,
            home,
        };
        held_jail(tree, writable, &closed, &path, &passed, cfg)
    }

    /// The digest of the environment a command ran in: the sandbox, the
    /// command, and what [`Self::identify`] found.
    fn env(&self, cmd: &str, identity: &Identity) -> String {
        let mut bytes = Vec::new();
        for part in [
            self.sandbox.name().as_bytes(),
            cmd.as_bytes(),
            identity.digest.as_bytes(),
        ] {
            field(&mut bytes, part);
        }
        sha256_hex(&bytes)
    }

    /// What names the environment of this run's commands: their `PATH`, the
    /// policy's fixed values, the names passed through that the daemon has
    /// (never their values: they may be secrets), and each
    /// `verification.identify` command with what it printed and how it
    /// ended. Each runs once, as the checks do, for at most
    /// [`IDENTIFY_SECONDS`]; one that fails is recorded, and the checks run
    /// all the same.
    fn identify(&self, root: &Path, cfg: &Verification) -> Identity {
        let mut bytes = Vec::new();
        field(&mut bytes, command_path(cfg).as_bytes());
        for (name, value) in &cfg.env {
            if !lonca_policy::config::env_name_forbidden(name) {
                field(&mut bytes, format!("env {name}={value}").as_bytes());
            }
        }
        let passed = passed_through(cfg);
        for (name, _) in &passed {
            field(&mut bytes, format!("passed {name}").as_bytes());
        }
        let secrets: Vec<&OsString> = passed.iter().map(|(_, v)| v).collect();
        let timeout = Duration::from_secs(cfg.timeout_seconds.min(IDENTIFY_SECONDS));
        let mut lines = BTreeMap::new();
        for (n, cmd) in cfg.identify.iter().enumerate() {
            let (result, details, log) = self.exec(cmd, root, timeout, cfg);
            // The log starts with the environment header, which is no output.
            let output = log.split_once('\n').map(|(_, o)| o).unwrap_or("");
            let output = hide(output, &secrets);
            let error = match result {
                CheckResult::Pass => None,
                CheckResult::Fail => {
                    Some(format!("exit {}", details.get("exit").map_or("?", |e| e)))
                }
                _ => Some(
                    details
                        .get("error")
                        .cloned()
                        .unwrap_or_else(|| "error".into()),
                ),
            };
            field(&mut bytes, cmd.as_bytes());
            field(&mut bytes, error.as_deref().unwrap_or("").as_bytes());
            field(&mut bytes, output.as_bytes());
            lines.insert(format!("env.{n}.command"), readable(cmd));
            lines.insert(format!("env.{n}.output"), readable(&output));
            if let Some(error) = error {
                lines.insert(format!("env.{n}.error"), error);
            }
        }
        Identity {
            digest: sha256_hex(&bytes),
            lines,
        }
    }

    /// Runs one command. The environment is cleared and rebuilt: PATH, a
    /// scratch HOME, LANG, LONCA_VERIFY, then the names the policy passes
    /// through (copied from the daemon's environment; absent ones are
    /// skipped) and the fixed values it sets. The log starts with the
    /// names that were set, never their values, so a failure explains
    /// itself.
    fn exec(
        &self,
        cmd: &str,
        root: &Path,
        timeout: Duration,
        cfg: &Verification,
    ) -> (CheckResult, BTreeMap<String, String>, String) {
        let tree = root.join("tree");
        let home = root.join("home");
        let tmp = root.join("tmp");
        let shm = root.join("shm");
        let _ = fs::create_dir_all(&home);
        let _ = fs::create_dir_all(&tmp);
        let _ = fs::create_dir_all(&shm);
        let mut jail = self.jail(&tree, vec![home.clone(), tmp.clone()], cfg);
        jail.mark = jail::mark_of(self.sandbox, "verify", root);
        jail.tmp = Some(tmp.clone());
        jail.shm = Some(shm);
        let argv: [OsString; 3] = ["/bin/sh".into(), "-c".into(), cmd.into()];
        let mut command = jail.command(self.sandbox, &argv).unwrap_or_else(|| {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(cmd);
            c
        });
        command
            .current_dir(&tree)
            .env_clear()
            .env("PATH", command_path(cfg))
            .env("HOME", &home)
            .env("TMPDIR", &tmp)
            .env("LANG", "C.UTF-8")
            .env("LONCA_VERIFY", "1");
        let mut passed: Vec<String> = Vec::new();
        for (name, v) in passed_through(cfg) {
            command.env(&name, v);
            passed.push(name);
        }
        for (name, value) in &cfg.env {
            if lonca_policy::config::env_name_forbidden(name) {
                continue;
            }
            command.env(name, value);
            passed.push(format!("{name}="));
        }
        let header = format!(
            "lonca verify: sandbox {}, env PATH HOME TMPDIR LANG LONCA_VERIFY{}{}\n",
            self.sandbox.name(),
            if passed.is_empty() { "" } else { " " },
            passed.join(" ")
        );
        let mut details = BTreeMap::new();
        let room = (cfg.keep_free_bytes > 0).then_some(process::Room {
            dir: &self.scratch,
            keep: cfg.keep_free_bytes,
        });
        if room.as_ref().is_some_and(process::Room::is_short) {
            details.insert("error".into(), "disk_space".into());
            return (CheckResult::Error, details, header + &short(cfg));
        }
        let running = match process::start(command, cfg) {
            Ok(r) => r,
            Err(e) => {
                details.insert("error".into(), format!("spawn: {e}"));
                return (CheckResult::Error, details, header);
            }
        };
        let ended = process::watch(running, timeout, room.as_ref(), jail.mark.as_deref());
        let mut log = format!("{header}{}", String::from_utf8_lossy(&ended.output));
        let left = ended.left.is_some();
        details.extend(ended.left);
        let result = match ended.status {
            None if ended.out_of_room => {
                details.insert("error".into(), "disk_space".into());
                log += &short(cfg);
                CheckResult::Error
            }
            None => {
                details.insert("error".into(), "timeout".into());
                CheckResult::Error
            }
            Some(s) => {
                details.insert(
                    "exit".into(),
                    s.code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into()),
                );
                details.extend(s.signal().map(|n| ("signal".into(), n.to_string())));
                outcome(s.success(), left)
            }
        };
        (result, details, log)
    }
}

/// The longest an identify command may take, if `timeout_seconds` is longer.
pub const IDENTIFY_SECONDS: u64 = 10;

/// The longest line of an identify command's output the details keep.
const IDENTIFY_LINE_CHARS: usize = 200;

/// What `verification.identify` found for a run: a digest for every
/// check's `env`, and the readable lines for its details.
struct Identity {
    digest: String,
    lines: BTreeMap<String, String>,
}

/// One part of a digest's input, its length first so no two lists of
/// parts run together into the same bytes.
fn field(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(part.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(part);
}

/// The names of `env_passthrough` the daemon has, with their values: what
/// reaches the commands. The sandbox's own names are never passed (nothing
/// else can be written to `TMPDIR`), nor the forbidden ones, even from a
/// config that skipped the parser.
fn passed_through(cfg: &Verification) -> Vec<(String, OsString)> {
    let allowed = |n: &&String| !lonca_policy::config::env_name_forbidden(n) && *n != "TMPDIR";
    let named = cfg.env_passthrough.iter().filter(allowed);
    named
        .filter_map(|n| std::env::var_os(n).map(|v| (n.clone(), v)))
        .collect()
}

/// `text` with each value passed through (`hidden`, four bytes or more)
/// as `***`: neither the digest nor the details may hold one.
fn hide(text: &str, hidden: &[&OsString]) -> String {
    let mut text = text.to_string();
    for value in hidden {
        let value = value.to_string_lossy();
        if value.len() >= 4 {
            text = text.replace(value.as_ref(), "***");
        }
    }
    text
}

/// The first line of `text` that has something on it, for a person to
/// read in the log: control characters become `?`, and it is cut at
/// [`IDENTIFY_LINE_CHARS`].
fn readable(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let shown = line.chars().map(|c| if c.is_control() { '?' } else { c });
    shown.take(IDENTIFY_LINE_CHARS).collect()
}

/// Removes a run's directory when the run ends, however it ends, before its
/// `TempDir` tries and fails on what a command closed.
struct Gone<'a>(&'a Path);

impl Drop for Gone<'_> {
    fn drop(&mut self) {
        if let Err(e) = process::remove_tree(self.0) {
            eprintln!("lonca: verify: removing {}: {e}", self.0.display());
        }
    }
}

/// The log's last line for a command the disk stopped, or kept from starting.
fn short(cfg: &Verification) -> String {
    let keep = cfg.keep_free_bytes;
    format!("\nlonca verify: stopped: less than {keep} bytes free on the disk (keep_free_bytes)\n")
}

/// What a command that ended comes to. What is still running can change the
/// tree and the outcome, so a pass can not stand on it.
fn outcome(success: bool, left: bool) -> CheckResult {
    match (success, left) {
        (_, true) => CheckResult::Error,
        (true, false) => CheckResult::Pass,
        (false, false) => CheckResult::Fail,
    }
}

/// The commands' `PATH`: the policy's, or else the daemon's.
fn command_path(cfg: &Verification) -> OsString {
    if cfg.path.is_empty() {
        std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into())
    } else {
        std::env::join_paths(&cfg.path).unwrap_or_default()
    }
}

/// What stays closed to a command.
struct Closed {
    /// Lonca's keys and stores.
    secrets: Vec<PathBuf>,
    /// The daemon's directory. It holds the run's own tree, so it can not be
    /// closed as a whole: nothing that is opened may touch it.
    store: Option<PathBuf>,
    home: Option<PathBuf>,
}

/// The sandbox of a command. It is the agent's code that runs, so this is the
/// agent's own sandbox, with no way out at all: no socket, no proxy, and of
/// what is closed only what the policy names.
fn held_jail(
    tree: &Path,
    writable: Vec<PathBuf>,
    closed: &Closed,
    path: &OsStr,
    passed: &[PathBuf],
    cfg: &Verification,
) -> Jail {
    let home = closed.home.as_deref();
    let real = home.and_then(|h| h.canonicalize().ok());
    let stores: Vec<PathBuf> = closed
        .secrets
        .iter()
        .chain(&closed.store)
        .cloned()
        .collect();
    let held: Vec<PathBuf> = stores.iter().chain(&real).cloned().collect();
    let mut readable = jail::program_trees(path, &[], &held, &[tree.to_path_buf()]);
    readable.extend(opened(cfg, passed, home, &stores, real.as_deref()));
    Jail {
        workspace: tree.to_path_buf(),
        writable,
        readable,
        secrets: stores
            .into_iter()
            .filter(|s| !tree.starts_with(s))
            .collect(),
        ..Default::default()
    }
}

/// What the policy opens for reading: `verification.read`, and the directories
/// in `passed`, the values of `env_passthrough`, as they really are. What holds
/// or lies in something closed stays closed, and so does the home directory as
/// a whole, which is what `HOME` in `env_passthrough` would otherwise open.
fn opened(
    cfg: &Verification,
    passed: &[PathBuf],
    home: Option<&Path>,
    closed: &[PathBuf],
    real_home: Option<&Path>,
) -> Vec<PathBuf> {
    let named = cfg.read.iter().filter_map(|p| match p.strip_prefix("~/") {
        Some(rest) => home.map(|h| h.join(rest)),
        None => Some(PathBuf::from(p)),
    });
    let passed = passed.iter().filter(|p| p.is_absolute() && p.is_dir());
    let mut out = Vec::new();
    for p in named.chain(passed.cloned()) {
        let Ok(p) = p.canonicalize() else {
            continue;
        };
        let holds_home = real_home.is_some_and(|h| h.starts_with(&p));
        if !holds_home && jail::holding_secrets(&p, closed).is_none() && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

fn attestation(
    check: CheckKind,
    result: CheckResult,
    subject: &GitId,
    details: BTreeMap<String, String>,
    env: String,
    log: Option<GitId>,
) -> Attestation {
    Attestation {
        check,
        result,
        subject_tree: subject.clone(),
        details,
        env,
        log,
        producer: "lonca-verify".into(),
    }
}

/// Writes `files` below `dir`. Symlinks are written as plain files holding
/// their target so a tree can never point the verifier outside `dir`.
pub fn materialize(store: &Store, files: &FileMap, dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    for (path, entry) in files {
        lonca_core::paths::validate_repo_path(path)?;
        if entry.mode == FileMode::Submodule {
            continue;
        }
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, store.read_blob(&entry.blob)?)?;
        #[cfg(unix)]
        if entry.mode == FileMode::Executable {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use lonca_symbols::engine::MAX_READ;

    use super::*;
    use lonca_core::FileEntry;
    #[cfg(target_os = "macos")]
    use std::os::unix::process::CommandExt;

    fn setup(files: &[(&str, &str)]) -> (tempfile::TempDir, Store, FileMap, GitId) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("s.git")).unwrap();
        let mut map = FileMap::new();
        for (p, t) in files {
            map.insert(
                p.to_string(),
                FileEntry {
                    mode: FileMode::Regular,
                    blob: store.write_blob(t.as_bytes()).unwrap(),
                },
            );
        }
        let tree = store.write_tree(&map).unwrap();
        (dir, store, map, tree)
    }

    fn cfg(build: Option<&str>, test: Option<&str>) -> Verification {
        Verification {
            build: build.map(String::from),
            test: test.map(String::from),
            timeout_seconds: 20,
            ..Default::default()
        }
    }

    #[test]
    fn what_is_left_running_stands_in_the_way_of_a_pass() {
        assert_eq!(outcome(true, false), CheckResult::Pass);
        assert_eq!(outcome(false, false), CheckResult::Fail);
        assert_eq!(outcome(true, true), CheckResult::Error);
        assert_eq!(outcome(false, true), CheckResult::Error);
    }

    #[test]
    fn pass_fail_and_skip_after_failure() {
        let (dir, store, files, tree) = setup(&[("ok.txt", "yes\n")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let r = v
            .run(
                &store,
                &files,
                &tree,
                &cfg(Some("test -f ok.txt"), Some("exit 3")),
            )
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Pass);
        assert_eq!(r[1].result, CheckResult::Fail);
        assert_eq!(r[1].details["exit"], "3");
        let r = v
            .run(&store, &files, &tree, &cfg(Some("false"), Some("true")))
            .unwrap();
        assert_eq!(
            (r[0].result, r[1].result),
            (CheckResult::Fail, CheckResult::Skipped)
        );
    }

    /// Named checks run after the built-in ones, in name order, each named
    /// in its evidence; one with no command does not run; and a failure
    /// skips what comes after, by name too.
    #[test]
    fn named_checks_run_after_the_built_in_ones() {
        let (dir, store, files, tree) = setup(&[("ok.txt", "yes\n")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(Some("true"), None);
        c.checks.insert("e2e".into(), "exit 4".into());
        c.checks.insert("api".into(), "test -f ok.txt".into());
        c.checks.insert("gone".into(), " ".into());
        c.checks.insert("zz".into(), "true".into());
        let r = v.run(&store, &files, &tree, &c).unwrap();
        let seen: Vec<_> = r
            .iter()
            .map(|a| (a.check, a.details.get("name").cloned(), a.result))
            .collect();
        let named = |n: &str| Some(n.to_string());
        assert_eq!(
            seen,
            [
                (CheckKind::Build, None, CheckResult::Pass),
                (CheckKind::Named, named("api"), CheckResult::Pass),
                (CheckKind::Named, named("e2e"), CheckResult::Fail),
                (CheckKind::Named, named("zz"), CheckResult::Skipped),
            ]
        );
        assert_eq!(r[2].details["exit"], "4");
        assert!(r[2].log.is_some());
        assert_eq!(r[3].log, None);
        // Only the named ones: there is still a tree to run them on.
        let mut only = cfg(None, None);
        only.checks.insert("api".into(), "test -f ok.txt".into());
        let r = v.run(&store, &files, &tree, &only).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].result, CheckResult::Pass);
        // A name with no command alone runs nothing.
        let mut none = cfg(None, None);
        none.checks.insert("gone".into(), String::new());
        assert!(v.run(&store, &files, &tree, &none).unwrap().is_empty());
    }

    #[test]
    fn timeout_is_an_error() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("sleep 5"));
        c.timeout_seconds = 1;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Error);
        assert_eq!(r[0].details["error"], "timeout");
    }

    /// What a check took is every attempt's time, so a quota sees retries.
    #[test]
    fn duration_is_every_attempt() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("sleep 0.3; exit 1"));
        c.retries = 2;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Fail);
        assert_eq!(r[0].details["attempts"], "3");
        let ms: u64 = r[0].details["duration_ms"].parse().unwrap();
        assert!((900..60_000).contains(&ms), "{ms}");
    }

    fn log_of(store: &Store, a: &Attestation) -> String {
        String::from_utf8(store.read_blob(a.log.as_ref().unwrap()).unwrap()).unwrap()
    }

    /// Both ways of leaving something behind that keeps the output open.
    #[test]
    fn what_a_command_leaves_running_does_not_hold_the_run() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let c = cfg(None, Some("(sleep 1000000 &); exit 0"));
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let mut c = cfg(None, Some("(sleep 1000000 &); sleep 1000000"));
        c.timeout_seconds = 1;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Error);
        assert_eq!(r[0].details["error"], "timeout");
    }

    /// Bare, because a sandbox ends this some other way: the group is what
    /// is under test.
    #[test]
    fn nothing_in_the_group_outlives_the_command() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        let (exited, timed_out) = (dir.path().join("exited"), dir.path().join("timed-out"));
        let after =
            |file: &Path, end: &str| format!("(sleep 1; touch '{}') & {end}", file.display());
        let c = cfg(None, Some(&after(&exited, "exit 0")));
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let mut c = cfg(None, Some(&after(&timed_out, "sleep 1000000")));
        c.timeout_seconds = 0;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].details["error"], "timeout");
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!exited.exists(), "it ran on after the command exited");
        assert!(!timed_out.exists(), "it ran on after the timeout");
    }

    /// With no sandbox, what left the group can not be reached. It still
    /// must not hold anything up, and the result is the command's own.
    #[test]
    fn what_left_the_group_is_waited_for_only_briefly() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        let cmd = "exec /usr/bin/perl -MPOSIX -e 'fork and exit; POSIX::setsid(); sleep 20'";
        if !Path::new("/usr/bin/perl").exists() {
            return;
        }
        let started = Instant::now();
        let r = v.run(&store, &files, &tree, &cfg(None, Some(cmd))).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        assert!(started.elapsed() < Duration::from_secs(12));
    }

    /// The leader of a group can move to another one, and leave nothing in
    /// its own for a kill to reach, unless it leads a session.
    #[test]
    fn a_command_can_not_take_itself_out_of_reach() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        if !Path::new("/usr/bin/perl").exists() {
            return;
        }
        let cmd = "exec /usr/bin/perl -MPOSIX -e '\
                   my $c = fork; if (!$c) { POSIX::setpgid(0, 0); sleep 20; exit } \
                   select(undef, undef, undef, 0.2); POSIX::setpgid(0, $c); sleep 20'";
        let mut c = cfg(None, Some(cmd));
        c.timeout_seconds = 1;
        let started = Instant::now();
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert!(started.elapsed() < Duration::from_secs(12), "{:?}", r[0]);
        assert_eq!(r[0].details["error"], "timeout");
    }

    /// A process whose program is gone has no path, and is no zombie.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_sandbox_finds_what_deleted_its_own_program() {
        let (dir, store, mut files, _) = setup(&[("a", "")]);
        let source = dir.path().join("tool.c");
        fs::write(
            &source,
            "#include <stdio.h>\n#include <unistd.h>\n\
             int main(int c, char **v) {\n\
               unlink(v[0]);\n\
               if (fork()) return 0;\n\
               setsid();\n\
               FILE *f = fopen(\"pid\", \"w\");\n\
               fprintf(f, \"%d\", getpid());\n\
               fclose(f);\n\
               sleep(30);\n\
             }\n",
        )
        .unwrap();
        let built = dir.path().join("tool");
        let cc = std::process::Command::new("/usr/bin/cc")
            .arg(&source)
            .arg("-o")
            .arg(&built)
            .output();
        if !cc.is_ok_and(|o| o.status.success()) {
            eprintln!("no compiler; skipping");
            return;
        }
        files.insert(
            "tool".into(),
            FileEntry {
                mode: FileMode::Executable,
                blob: store.write_blob(&fs::read(&built).unwrap()).unwrap(),
            },
        );
        let tree = store.write_tree(&files).unwrap();
        let v = Verifier::new(dir.path().join("scratch"));
        let name = format!("left-{}", std::process::id());
        // The command fails unless that process is alive.
        let cmd = format!("./tool {name} && sleep 1 && kill -0 \"$(cat pid)\"");
        let r = v
            .run(&store, &files, &tree, &cfg(None, Some(&cmd)))
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{}", log_of(&store, &r[0]));
        let found = std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", &name])
            .output()
            .unwrap();
        let _ = std::process::Command::new("/usr/bin/pkill")
            .args(["-f", &name])
            .status();
        assert!(found.stdout.is_empty(), "still running");
    }

    /// Only Seatbelt can leave something running out of the group.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_sandbox_keeps_nothing_that_left_the_group() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let name = format!("left-by-{}", dir.path().display());
        let cmd = format!(
            "exec /usr/bin/perl -MPOSIX -e 'fork and exit; POSIX::setsid(); sleep 30' '{name}'"
        );
        let r = v
            .run(&store, &files, &tree, &cfg(None, Some(&cmd)))
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        assert!(!r[0].details.contains_key("left_running"), "{:?}", r[0]);
        let found = std::process::Command::new("/usr/bin/pgrep")
            .args(["-f", &name])
            .output()
            .unwrap();
        assert!(found.stdout.is_empty(), "still running");
    }

    #[test]
    fn the_log_has_the_streams_as_they_were_written() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let cmd = "echo 1 >&2; echo 2; echo 3 >&2; echo 4";
        let r = v.run(&store, &files, &tree, &cfg(None, Some(cmd))).unwrap();
        assert!(log_of(&store, &r[0]).ends_with("\n1\n2\n3\n4\n"));
    }

    #[test]
    fn the_log_has_both_streams_and_only_the_end_of_them() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let cmd = "echo out; echo err >&2; head -c 200000 /dev/zero | tr '\\0' x; echo; echo last";
        let r = v.run(&store, &files, &tree, &cfg(None, Some(cmd))).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        assert!(log.ends_with("x\nlast\n"), "{}", &log[log.len() - 40..]);
        assert!(!log.contains("out\n"), "the beginning is gone");
        let r = v
            .run(
                &store,
                &files,
                &tree,
                &cfg(None, Some("echo out; echo err >&2")),
            )
            .unwrap();
        let log = log_of(&store, &r[0]);
        assert!(log.contains("out\n") && log.contains("err\n"), "{log}");
        assert!(log.len() < 64 * 1024 + 1024);
    }

    #[test]
    fn the_limits_reach_the_command() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("ulimit -t; ulimit -n"));
        c.limit_cpu_seconds = 7;
        c.limit_open_files = 64;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        assert!(
            log_of(&store, &r[0]).ends_with("\n7\n64\n"),
            "{:?}",
            log_of(&store, &r[0])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_limits_processes_and_address_space_too() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("cat /proc/self/limits"));
        c.limit_processes = 2000;
        c.limit_address_bytes = 1 << 34;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        let limit = |name: &str| {
            let line = log.lines().find(|l| l.starts_with(name));
            line.and_then(|l| l[name.len()..].split_whitespace().next().map(String::from))
        };
        assert_eq!(limit("Max processes").as_deref(), Some("2000"), "{log}");
        let bytes = (1u64 << 34).to_string();
        assert_eq!(limit("Max address space"), Some(bytes), "{log}");
    }

    /// A writer that does not ignore the signal ends with it. `exec`, and
    /// bare, for the signal to be the leader's own: a shell or bubblewrap
    /// turns it into the exit code 128 + its number.
    #[test]
    fn a_file_at_its_limit_ends_the_writer_and_the_evidence_says_how() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        let cmd = "exec dd if=/dev/zero of=big bs=1024 count=1024";
        let mut c = cfg(None, Some(cmd));
        c.limit_file_bytes = 64 * 1024;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Fail, "{:?}", r[0]);
        assert_eq!(r[0].details["exit"], "signal");
        assert_eq!(r[0].details["signal"], libc::SIGXFSZ.to_string());
    }

    #[test]
    fn a_file_stops_at_its_limit_with_efbig() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let cmd = "trap '' XFSZ; dd if=/dev/zero of=big bs=1024 count=1024 2>&1";
        let mut c = cfg(None, Some(cmd));
        c.limit_file_bytes = 64 * 1024;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_ne!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        assert!(log.contains("File too large"), "{log}");
    }

    /// The limit counts the account, so on a Mac 512 is below what the
    /// person at it runs already, and the bomb forks next to nothing.
    #[test]
    fn a_fork_bomb_stays_inside_its_limits() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("b() { b | b; }; b"));
        c.limit_processes = 512;
        c.timeout_seconds = 2;
        let started = Instant::now();
        let r = v.run(&store, &files, &tree, &c).unwrap();
        // It can die out at the limit, or be killed at the timeout.
        assert!(started.elapsed() < Duration::from_secs(15), "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        assert!(log.contains("fork"), "nothing was refused: {log}");
    }

    /// macOS has the limit now, and the account keeps its share of it. On
    /// Linux `linux_limits_processes_and_address_space_too` reads it.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_limits_processes_and_leaves_the_account_its_share() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(None, Some("ulimit -u"));
        // Below the share of any Mac: a GitHub runner's `kern.maxprocperuid`
        // is far below a desktop's, and a limit above the share is cut to it.
        c.limit_processes = 300;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert!(log_of(&store, &r[0]).ends_with("\n300\n"), "{:?}", r[0]);
        c.limit_processes = Verification::default().limit_processes;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        let log = log_of(&store, &r[0]);
        let got: u64 = log.lines().last().unwrap().parse().expect(&log);
        let most = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.maxprocperuid"])
            .output()
            .unwrap();
        let most: u64 = String::from_utf8_lossy(&most.stdout)
            .trim()
            .parse()
            .unwrap();
        assert!(got <= most - process::KEEP_PROCESSES, "{log}");
        assert!(got > 0, "{log}");
    }

    #[test]
    fn a_command_does_not_start_on_a_disk_with_no_room() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        let ran = dir.path().join("ran");
        let mut c = cfg(None, Some(&format!("touch '{}'", ran.display())));
        c.keep_free_bytes = u64::MAX;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Error, "{:?}", r[0]);
        assert_eq!(r[0].details["error"], "disk_space");
        assert!(log_of(&store, &r[0]).ends_with("(keep_free_bytes)\n"));
        assert!(!ran.exists(), "it ran");
        // Not watched, it runs.
        c.keep_free_bytes = 0;
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        assert!(ran.exists());
    }

    /// The command writes until the disk is 16 MiB further down, and then
    /// sleeps: only the watch can end it before its timeout.
    #[test]
    fn a_command_that_fills_the_disk_is_stopped() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        fs::create_dir_all(&v.scratch).unwrap();
        let free = process::free_bytes(&v.scratch).unwrap();
        let cmd = "echo started; i=0; while [ $i -lt 64 ]; do \
                   dd if=/dev/zero of=f$i bs=1048576 count=4 2>/dev/null; sync; \
                   i=$((i+1)); done; sleep 60";
        let mut c = cfg(None, Some(cmd));
        c.keep_free_bytes = free - (16 << 20);
        c.timeout_seconds = 60;
        let started = Instant::now();
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert!(started.elapsed() < Duration::from_secs(30), "{:?}", r[0]);
        assert_eq!(r[0].result, CheckResult::Error, "{:?}", r[0]);
        assert_eq!(r[0].details["error"], "disk_space", "{:?}", r[0]);
        assert!(!r[0].details.contains_key("exit"), "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        assert!(
            log.contains("\nstarted\n"),
            "the watch stopped it, not the start: {log}"
        );
    }

    /// When memory runs out the command goes first, and its `/tmp` is on
    /// disk, where the watch sees it, and goes with the run.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puts_the_command_first_for_the_oom_killer_and_tmp_on_disk() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let cmd = "cat /proc/self/oom_score_adj; echo x > /tmp/probe; ls \"$TMPDIR\"";
        let r = v.run(&store, &files, &tree, &cfg(None, Some(cmd))).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let log = log_of(&store, &r[0]);
        let lines: Vec<&str> = log.lines().skip(1).collect();
        assert_eq!(lines.first(), Some(&"1000"), "{log}");
        if v.sandbox != Sandbox::Bubblewrap {
            let _ = fs::remove_file("/tmp/probe");
            return;
        }
        assert_eq!(lines.get(1), Some(&"probe"), "{log}");
        // Shared memory is on disk as well, it still works, and nothing
        // else of `/dev` takes a write.
        let cmd = "stat -f -c %T /tmp /dev/shm; touch /dev/shm/s && echo shm; \
                   touch /dev/x 2>/dev/null || echo closed; echo y > /dev/null && echo null";
        let r = v.run(&store, &files, &tree, &cfg(None, Some(cmd))).unwrap();
        let log = log_of(&store, &r[0]);
        let lines: Vec<&str> = log.lines().skip(1).collect();
        assert_eq!(lines.len(), 5, "{log}");
        assert!(lines[..2].iter().all(|l| *l != "tmpfs"), "{log}");
        assert_eq!(lines[2..], ["shm", "closed", "null"], "{log}");
    }

    #[test]
    fn what_an_earlier_daemon_left_is_cleared_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().canonicalize().unwrap().join("scratch");
        let left = scratch.join("verify-left");
        fs::create_dir_all(left.join("tree/deep")).unwrap();
        fs::write(left.join("tree/deep/file"), "x").unwrap();
        let bundle = scratch.join("demo-b1.bundle");
        fs::write(&bundle, "").unwrap();
        let other = scratch.join("other");
        fs::create_dir(&other).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, scratch.join("verify-link")).unwrap();
        // A run that closed what it wrote goes too.
        let closed = scratch.join("verify-closed");
        fs::create_dir_all(closed.join("tree/d")).unwrap();
        fs::write(closed.join("tree/d/f"), "x").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let none = fs::Permissions::from_mode(0o000);
            fs::set_permissions(closed.join("tree/d"), none).unwrap();
        }
        let v = Verifier::new(scratch.clone());
        // On a Mac, something of that run is still going, out of its group.
        #[cfg(target_os = "macos")]
        let mut running = {
            let jail = Jail {
                workspace: left.clone(),
                mark: jail::mark_of(Sandbox::Seatbelt, "verify", &left),
                ..Default::default()
            };
            let argv = [
                "/bin/sh".into(),
                "-c".into(),
                "touch ready; exec /bin/sleep 30".into(),
            ];
            let mut c = jail.command(Sandbox::Seatbelt, &argv).unwrap();
            let child = c.process_group(0).spawn().unwrap();
            let started = Instant::now();
            while !left.join("ready").exists() && started.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(left.join("ready").exists(), "the sandbox never started");
            child
        };
        assert_eq!(v.clear_left_over(), 2);
        assert!(!left.exists() && !closed.exists());
        assert!(bundle.exists() && other.exists() && elsewhere.exists());
        let link = fs::symlink_metadata(scratch.join("verify-link"));
        assert!(link.is_ok(), "a link is not followed");
        #[cfg(target_os = "macos")]
        {
            let started = Instant::now();
            let status = loop {
                if let Some(status) = running.try_wait().unwrap() {
                    break Some(status);
                }
                if started.elapsed() > Duration::from_secs(5) {
                    let _ = running.kill();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            assert_eq!(status.and_then(|s| s.signal()), Some(libc::SIGKILL));
        }
        assert_eq!(Verifier::new(dir.path().join("none")).clear_left_over(), 0);
    }

    #[test]
    fn the_policy_names_the_path() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let tools = dir.path().canonicalize().unwrap().join("tools");
        fs::create_dir_all(&tools).unwrap();
        let tool = tools.join("the-tool");
        fs::write(&tool, "#!/bin/sh\necho from-the-tool\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut c = cfg(None, Some("the-tool; echo \"$PATH\""));
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert!(!log_of(&store, &r[0]).contains("from-the-tool"));
        let daemon = std::env::var("PATH").unwrap();
        assert!(
            log_of(&store, &r[0]).contains(&daemon),
            "the daemon's by default"
        );
        c.path = vec![tools.display().to_string(), "/usr/bin".into()];
        let r = v.run(&store, &files, &tree, &c).unwrap();
        let log = log_of(&store, &r[0]);
        assert!(log.contains("from-the-tool"), "on it, and readable: {log}");
        assert!(
            log.ends_with(&format!("\n{}:/usr/bin\n", tools.display())),
            "{log}"
        );
    }

    #[test]
    fn sandbox_blocks_network_and_outside_writes() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        if v.sandbox == Sandbox::None {
            eprintln!("no sandbox on this machine; skipping");
            return;
        }
        let outside = dirs_home().join(format!("lonca-sandbox-probe-{}", std::process::id()));
        let cmd = format!("touch '{}'", outside.display());
        let r = v
            .run(&store, &files, &tree, &cfg(None, Some(&cmd)))
            .unwrap();
        assert_eq!(
            r[0].result,
            CheckResult::Fail,
            "write outside the work dir must fail"
        );
        assert!(!outside.exists());
        let r = v
            .run(
                &store,
                &files,
                &tree,
                &cfg(None, Some("touch inside.txt && test -f inside.txt")),
            )
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let net = "/usr/bin/curl -sS -m 3 https://example.com >/dev/null";
        let r = v.run(&store, &files, &tree, &cfg(None, Some(net))).unwrap();
        assert_ne!(r[0].result, CheckResult::Pass, "network must be blocked");
        assert_eq!(r[0].details["sandbox"], v.sandbox.name());
    }

    /// The code a change brings runs here, so what it can reach matters as
    /// much as in `lonca run`.
    #[test]
    fn proposed_code_is_held_like_the_agent_that_wrote_it() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("store/scratch"));
        if v.sandbox == Sandbox::None {
            return;
        }
        // Something real in the home directory, not on the way to a directory
        // on PATH: those are mounted, so the home itself can be listed, and
        // shows nothing else. This test must not write there.
        let path: Vec<PathBuf> =
            std::env::split_paths(&std::env::var_os("PATH").unwrap()).collect();
        let held = fs::read_dir(dirs_home())
            .unwrap()
            .flatten()
            .map(|e| e.path());
        let held = held
            .into_iter()
            .find(|p| !path.iter().any(|d| d.starts_with(p)));
        if let Some(held) = held {
            let probe = format!("test -e '{}'", held.display());
            let mut c = cfg(None, Some(&probe));
            c.env_passthrough = vec!["HOME".into()];
            let r = v.run(&store, &files, &tree, &c).unwrap();
            assert_eq!(
                r[0].result,
                CheckResult::Fail,
                "{} stays closed",
                held.display()
            );
            let shown = format!("ls -A '{}'", dirs_home().display());
            let mut c = cfg(None, Some(&shown));
            c.env_passthrough = vec!["HOME".into()];
            let r = v.run(&store, &files, &tree, &c).unwrap();
            let log =
                String::from_utf8(store.read_blob(r[0].log.as_ref().unwrap()).unwrap()).unwrap();
            let name = held.file_name().unwrap().to_string_lossy();
            assert!(!log.lines().any(|l| l == name), "{name} is listed: {log}");
        }
        let store_file = dir.path().join("store/key");
        fs::create_dir_all(store_file.parent().unwrap()).unwrap();
        fs::write(&store_file, "secret").unwrap();
        let probe = format!("cat {}", store_file.display());
        let mut c = cfg(None, Some(&probe));
        c.read = vec![dir.path().join("store").display().to_string()];
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Fail, "the store stays closed");
        let r = v
            .run(
                &store,
                &files,
                &tree,
                &cfg(None, Some("echo x > \"$TMPDIR/t\"")),
            )
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
    }

    #[test]
    fn the_policy_opens_a_tree_for_reading() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("store/scratch"));
        if v.sandbox == Sandbox::None {
            return;
        }
        let tool = dir.path().join("tool");
        fs::create_dir_all(&tool).unwrap();
        fs::write(tool.join("config"), "x").unwrap();
        let probe = format!("cat {}/config", tool.display());
        let mut c = cfg(None, Some(&probe));
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Fail, "closed until named");
        c.read = vec![tool.display().to_string()];
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
    }

    #[test]
    fn what_is_opened_is_named_exists_and_stays_off_what_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let cargo = home.join(".cargo");
        let store = root.join("store");
        fs::create_dir_all(&cargo).unwrap();
        fs::create_dir_all(store.join("sub")).unwrap();
        let c = Verification {
            read: vec![
                "~/.cargo".into(),
                store.display().to_string(),
                store.join("sub").display().to_string(),
                root.display().to_string(),
                home.display().to_string(),
                "/no/such/tree".into(),
                cargo.display().to_string(),
            ],
            ..Default::default()
        };
        let closed = [store.clone()];
        let got = opened(&c, &[], Some(&home), &closed, Some(&home));
        assert_eq!(got, std::slice::from_ref(&cargo));
        // With no home known, `~` means nothing.
        assert!(
            opened(&c, &[], None, &closed, None)
                .iter()
                .all(|p| p != &root.join(".cargo"))
        );
    }

    #[test]
    fn a_value_passed_opens_only_if_it_is_an_absolute_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let file = root.join("file");
        fs::write(&file, "x").unwrap();
        let c = Verification::default();
        // `src` is a directory where the tests run, and only there.
        let passed = [root.clone(), file, PathBuf::from("src")];
        assert_eq!(opened(&c, &passed, None, &[], None), [root]);
    }

    #[test]
    fn a_jail_closes_what_does_not_hold_the_tree_and_keeps_every_read_off_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let store = root.join("store");
        let tree = store.join("scratch/verify/tree");
        let keys = root.join("keys");
        let home = root.join("home");
        let bin = home.join(".cargo/bin");
        for d in [&tree, &keys, &bin] {
            fs::create_dir_all(d).unwrap();
        }
        let closed = Closed {
            secrets: vec![keys.clone(), store.clone()],
            store: Some(store.clone()),
            home: Some(home.clone()),
        };
        let path = std::env::join_paths([&bin, &home, &store]).unwrap();
        let c = Verification {
            read: vec![keys.display().to_string(), store.display().to_string()],
            ..Default::default()
        };
        let writable = vec![store.join("w")];
        let passed = std::slice::from_ref(&home);
        let j = held_jail(&tree, writable.clone(), &closed, &path, passed, &c);
        assert_eq!(j.workspace, tree);
        assert_eq!(j.writable, writable);
        assert_eq!(
            j.secrets,
            [keys],
            "the store holds the tree: closing it closes that"
        );
        assert_eq!(
            j.readable,
            [bin],
            "not the home, not the store, not the keys"
        );
        assert_eq!(j.socket, None);
        assert_eq!(j.proxy_port, None);
        assert_eq!(j.relay, None);
        assert!(!j.loopback);
    }

    /// The names a policy could never set still must not pass, and `TMPDIR`
    /// stays the sandbox's when a policy lists it.
    #[test]
    #[allow(unsafe_code, reason = "a test sets the environment the verifier reads")]
    fn what_passes_stops_at_the_forbidden_and_at_tmpdir() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let outer = std::env::temp_dir();
        // SAFETY: the value set is the one in force, or a name nothing reads.
        unsafe {
            std::env::set_var("TMPDIR", &outer);
            std::env::set_var("CARGO_BUILD_RUSTC", "/no/such/rustc");
        }
        let probe = format!(
            "test -z \"$CARGO_BUILD_RUSTC\" && test \"$TMPDIR\" != '{}'",
            outer.display()
        );
        let mut c = cfg(None, Some(&probe));
        c.env_passthrough = vec!["CARGO_BUILD_RUSTC".into(), "TMPDIR".into()];
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
    }

    /// `env` follows what the identify commands print, the `PATH` and the
    /// policy's fixed values, and not a value passed through; the details
    /// name each command with its first line.
    #[test]
    #[allow(unsafe_code, reason = "a test sets the environment the verifier reads")]
    fn the_environment_digest_follows_the_toolchain_and_not_a_passed_value() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let tools = dir.path().canonicalize().unwrap().join("tools");
        fs::create_dir_all(&tools).unwrap();
        let tool = tools.join("mytool");
        let version = |n: &str| {
            let text = format!("#!/bin/sh\necho \"mytool {n} (built today)\"\necho second line\n");
            fs::write(&tool, text).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        };
        version("1.0");
        let mut c = cfg(Some("true"), Some("test -f a"));
        c.path = vec![
            tools.display().to_string(),
            "/usr/bin".into(),
            "/bin".into(),
        ];
        c.identify = vec!["mytool --version".into()];
        let env_of = |c: &Verification| {
            let r = v.run(&store, &files, &tree, c).unwrap();
            assert!(r.iter().all(|a| a.result == CheckResult::Pass), "{r:?}");
            assert_ne!(r[0].env, r[1].env, "the command is part of it");
            r
        };
        let first = env_of(&c);
        let d = &first[0].details;
        assert_eq!(d["env.0.command"], "mytool --version");
        assert_eq!(d["env.0.output"], "mytool 1.0 (built today)");
        assert!(!d.contains_key("env.0.error"));
        assert_eq!(
            first[1].details["env.0.output"], d["env.0.output"],
            "on every check"
        );
        assert_eq!(
            env_of(&c)[0].env,
            first[0].env,
            "the same environment, the same digest"
        );

        version("2.0");
        let r = env_of(&c);
        assert_eq!(r[0].details["env.0.output"], "mytool 2.0 (built today)");
        assert_ne!(r[0].env, first[0].env, "another toolchain");
        version("1.0");

        let mut moved = c.clone();
        moved.path.push("/usr/sbin".into());
        assert_ne!(env_of(&moved)[0].env, first[0].env, "another PATH");

        let mut fixed = c.clone();
        fixed.env.insert("FIXED_FOR_IDENTIFY".into(), "a".into());
        let a = env_of(&fixed)[0].env.clone();
        fixed.env.insert("FIXED_FOR_IDENTIFY".into(), "b".into());
        assert_ne!(env_of(&fixed)[0].env, a, "another fixed value");
        assert_ne!(a, first[0].env, "a fixed value is part of it");

        // SAFETY: only this test reads or writes this name.
        unsafe { std::env::set_var("PROBE_IDENTIFY_PASSED", "first-secret") };
        let mut passed = c.clone();
        passed.env_passthrough = vec!["PROBE_IDENTIFY_PASSED".into()];
        passed.identify = vec!["echo \"key $PROBE_IDENTIFY_PASSED\"".into()];
        let a = env_of(&passed);
        assert_eq!(
            a[0].details["env.0.output"], "key ***",
            "a passed value is never shown"
        );
        unsafe { std::env::set_var("PROBE_IDENTIFY_PASSED", "other-secret") };
        let b = env_of(&passed);
        assert_eq!(b[0].env, a[0].env, "a passed value is not part of it");
        unsafe { std::env::remove_var("PROBE_IDENTIFY_PASSED") };
        assert_ne!(env_of(&passed)[0].env, a[0].env, "whether it is passed is");
    }

    /// An identify command that fails or takes too long is recorded as such,
    /// and the checks run all the same.
    #[test]
    fn a_failing_identify_command_is_recorded_and_the_checks_run() {
        let (dir, store, files, tree) = setup(&[("ok.txt", "yes\n")]);
        let v = Verifier::new(dir.path().join("scratch"));
        let mut c = cfg(Some("test -f ok.txt"), Some("exit 3"));
        c.timeout_seconds = 1;
        c.identify = vec![
            "echo 'no such tool' >&2; exit 127".into(),
            "sleep 5".into(),
            "printf 'tool\\033[31m 1\\n'".into(),
        ];
        let started = Instant::now();
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout holds"
        );
        assert_eq!(
            (r[0].result, r[1].result),
            (CheckResult::Pass, CheckResult::Fail)
        );
        let d = &r[1].details;
        assert_eq!(d["env.0.error"], "exit 127");
        assert_eq!(d["env.0.output"], "no such tool");
        assert_eq!(d["env.1.error"], "timeout");
        assert_eq!(d["env.1.output"], "");
        assert_eq!(
            d["env.2.output"], "tool?[31m 1",
            "no terminal control reaches a reader"
        );
        assert!(!d.contains_key("env.2.error"));
        assert_eq!(d["exit"], "3", "the check's own details stay");
        c.build = Some("false".into());
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[1].result, CheckResult::Skipped);
        assert_eq!(
            r[1].details["env.0.error"], "exit 127",
            "a skipped check names it too"
        );
    }

    #[test]
    fn a_readable_line_is_the_first_one_short_and_hides_passed_values() {
        let secret = OsString::from("hunter22");
        let short = OsString::from("abc");
        assert_eq!(readable("\n  \n  v22.1.0  \nmore"), "v22.1.0");
        assert_eq!(readable(""), "");
        assert_eq!(readable("a\tb"), "a?b");
        assert_eq!(
            hide("k=hunter22 abc\nhunter22", &[&secret, &short]),
            "k=*** abc\n***"
        );
        let long = "é".repeat(IDENTIFY_LINE_CHARS + 5);
        assert_eq!(readable(&long).chars().count(), IDENTIFY_LINE_CHARS);
        let mut a = Vec::new();
        field(&mut a, b"ab");
        field(&mut a, b"c");
        let mut b = Vec::new();
        field(&mut b, b"a");
        field(&mut b, b"bc");
        assert_ne!(a, b, "parts do not run together");
        assert_eq!(a, b"2:ab1:c");
    }

    fn dirs_home() -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap())
    }

    /// Only listed names reach the command; fixed values too; forbidden
    /// names never, even if a policy object carries them; the log says
    /// which names were set and never a value.
    #[test]
    #[allow(unsafe_code, reason = "a test sets the environment the verifier reads")]
    fn the_environment_is_deny_by_default_and_named_in_the_log() {
        let (dir, store, files, tree) = setup(&[("a", "")]);
        let v = Verifier::new(dir.path().join("scratch"));
        // SAFETY: tests in this module that read the environment run
        // single-threaded with respect to this variable.
        unsafe { std::env::set_var("PROBE_FOR_VERIFY_TEST", "s3cr3t-value") };
        let probe = "test -n \"$PROBE_FOR_VERIFY_TEST\" && test \"$FIXED\" = 42";
        let r = v
            .run(&store, &files, &tree, &cfg(None, Some(probe)))
            .unwrap();
        assert_eq!(r[0].result, CheckResult::Fail, "nothing passes unasked");
        let log = String::from_utf8(store.read_blob(r[0].log.as_ref().unwrap()).unwrap()).unwrap();
        assert!(log.starts_with("lonca verify: sandbox "), "{log}");
        assert!(
            log.contains("env PATH HOME TMPDIR LANG LONCA_VERIFY\n"),
            "{log}"
        );

        let mut c = cfg(None, Some(probe));
        c.env_passthrough = vec![
            "PROBE_FOR_VERIFY_TEST".into(),
            "PROBE_ABSENT_FOR_VERIFY_TEST".into(),
        ];
        c.env.insert("FIXED".into(), "42".into());
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
        let log = String::from_utf8(store.read_blob(r[0].log.as_ref().unwrap()).unwrap()).unwrap();
        assert!(
            log.contains("LONCA_VERIFY PROBE_FOR_VERIFY_TEST FIXED=\n"),
            "{log}"
        );
        assert!(!log.contains("s3cr3t") && !log.contains("42"), "{log}");

        // A forbidden name in a config object that skipped the parser.
        let mut c = cfg(
            None,
            Some("test -z \"$LD_PRELOAD\" && test -z \"$RUSTFLAGS\""),
        );
        c.env_passthrough = vec!["LD_PRELOAD".into()];
        c.env.insert("RUSTFLAGS".into(), "-C x".into());
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(r[0].result, CheckResult::Pass, "{:?}", r[0]);
    }

    /// A Rust crate under rustup verifies with the passthrough list from
    /// the guide and nothing else. Without a sandbox: the point is the
    /// environment, and the sandbox has its own test.
    #[test]
    fn a_rust_crate_verifies_under_rustup_with_the_documented_passthrough() {
        if std::process::Command::new("cargo")
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("no cargo; skipping");
            return;
        }
        let (dir, store, files, tree) = setup(&[
            (
                "Cargo.toml",
                "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
            ),
            (
                "src/lib.rs",
                "pub fn two() -> u32 { 2 }\n#[cfg(test)] mod t { #[test] fn ok() { assert_eq!(super::two(), 2); } }\n",
            ),
        ]);
        let v = Verifier {
            sandbox: Sandbox::None,
            scratch: dir.path().join("scratch"),
        };
        let bare = v
            .run(
                &store,
                &files,
                &tree,
                &cfg(Some("cargo build --offline"), None),
            )
            .unwrap();
        let mut c = cfg(Some("cargo build --offline"), Some("cargo test --offline"));
        c.timeout_seconds = 600;
        c.env_passthrough = ["HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"]
            .into_iter()
            .map(String::from)
            .collect();
        c.read = vec!["~/.cargo".into(), "~/.rustup".into()];
        let r = v.run(&store, &files, &tree, &c).unwrap();
        assert_eq!(
            (r[0].result, r[1].result),
            (CheckResult::Pass, CheckResult::Pass),
            "{:?}",
            r
        );
        if bare[0].result != CheckResult::Pass {
            // Under rustup, the bare run is the failure the guide explains.
            let log =
                String::from_utf8(store.read_blob(bare[0].log.as_ref().unwrap()).unwrap()).unwrap();
            assert!(
                log.contains("env PATH HOME TMPDIR LANG LONCA_VERIFY\n"),
                "{log}"
            );
        }
    }

    /// A parse error does not fail the check in any language: the files a
    /// grammar could not read are named, and the check passes.
    #[test]
    fn syntax_names_what_no_grammar_could_read_and_passes() {
        let (dir, store, files, tree) = setup(&[
            ("a.rs", "fn ok() {}\n"),
            ("b.rs", "fn bad( {\n"),
            ("c.md", "x"),
            ("d.kt", "class C { fun f() = 1 }\n"),
            ("e.cs", "class C { void F(C c) { c?.X = 1; } int X; }\n"),
        ]);
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v
            .syntax(&store, &files, &["a.rs".into(), "c.md".into()], &tree)
            .unwrap();
        assert_eq!(a.result, CheckResult::Pass);
        assert_eq!(a.details["files_checked"], "2");
        assert!(!a.details.contains_key("unread"), "{:?}", a.details);
        let all = ["a.rs", "b.rs", "c.md", "d.kt", "e.cs", "gone.rs"].map(String::from);
        let a = v.syntax(&store, &files, &all, &tree).unwrap();
        assert_eq!(a.result, CheckResult::Pass);
        assert_eq!(a.details["unread"], "b.rs,d.kt,e.cs");
        assert_eq!(a.check, CheckKind::Syntax);
        assert_eq!(a.subject_tree, tree);
    }

    /// A file past the limit goes by its lines, whatever a grammar would say.
    #[test]
    fn syntax_leaves_a_file_past_the_limit_to_its_lines() {
        let fill = |len: usize| format!("fn bad( {{\n{}\n", "/".repeat(len - 11));
        let (at, past) = (fill(MAX_READ), fill(MAX_READ + 1));
        let (dir, store, files, tree) =
            setup(&[("at.rs", at.as_str()), ("past.rs", past.as_str())]);
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v
            .syntax(&store, &files, &["past.rs".into()], &tree)
            .unwrap();
        assert!(!a.details.contains_key("unread"));
        let a = v.syntax(&store, &files, &["at.rs".into()], &tree).unwrap();
        assert_eq!(a.details["unread"], "at.rs");
    }

    /// So does a file the grammar does not get through within its budget.
    #[test]
    fn syntax_leaves_a_file_past_the_parse_budget_to_its_lines() {
        let filler = |n: usize| format!("fn f() {{ {} }}\n", "-!-a;".repeat(n));
        let (within, past) = (format!("fn bad( {{\n{}", filler(1)), filler(30_000));
        let past = format!("fn bad( {{\n{past}");
        let (dir, store, files, tree) =
            setup(&[("within.rs", within.as_str()), ("past.rs", past.as_str())]);
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v
            .syntax(&store, &files, &["past.rs".into()], &tree)
            .unwrap();
        assert!(!a.details.contains_key("unread"));
        let a = v
            .syntax(&store, &files, &["within.rs".into()], &tree)
            .unwrap();
        assert_eq!(a.details["unread"], "within.rs");
    }

    /// Bytes that are no text are not read by a grammar.
    #[test]
    fn syntax_names_a_file_that_is_no_text() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("s.git")).unwrap();
        let mut files = FileMap::new();
        let blob = store.write_blob(b"\xff fn a() {}\n").unwrap();
        let mode = FileMode::Regular;
        files.insert("a.rs".into(), FileEntry { blob, mode });
        let tree = store.write_tree(&files).unwrap();
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v.syntax(&store, &files, &["a.rs".into()], &tree).unwrap();
        assert_eq!(a.result, CheckResult::Pass);
        assert_eq!(a.details["unread"], "a.rs");
    }
}
