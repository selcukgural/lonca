//! Evidence producers. The Gatekeeper runs build and test commands itself,
//! in a sandbox, on the merged tree; the agent's own reports are ignored.
//!
//! Results are nondeterministic by nature, so they are recorded as
//! [`Attestation`]s in the operation log and never recomputed on replay.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lonca_core::canonical::sha256_hex;
use lonca_core::ops::{Attestation, CheckKind, CheckResult};
use lonca_core::{FileMap, FileMode, GitId, Result, Store};
use lonca_policy::config::Verification;
use lonca_symbols::{Lang, parse};

pub mod jail;

use jail::Jail;

const OUTPUT_TAIL: usize = 64 * 1024;

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

    /// Static syntax check of every supported file that the change touched.
    pub fn syntax(
        &self,
        store: &Store,
        files: &FileMap,
        touched: &[String],
        subject: &GitId,
    ) -> Result<Attestation> {
        let mut bad = Vec::new();
        for p in touched {
            let (Some(lang), Some(e)) = (Lang::detect(p), files.get(p)) else {
                continue;
            };
            // A grammar that can not read valid code must not refuse it.
            if !lang.is_strict() {
                continue;
            }
            let bytes = store.read_blob(&e.blob)?;
            let ok = std::str::from_utf8(&bytes)
                .map(|t| !parse(lang, t).has_error)
                .unwrap_or(false);
            if !ok {
                bad.push(p.clone());
            }
        }
        let mut details = BTreeMap::new();
        details.insert("files_checked".into(), touched.len().to_string());
        if !bad.is_empty() {
            details.insert("errors".into(), bad.join(","));
        }
        Ok(Attestation {
            check: CheckKind::Syntax,
            result: if bad.is_empty() {
                CheckResult::Pass
            } else {
                CheckResult::Fail
            },
            subject_tree: subject.clone(),
            details,
            env: "tree-sitter".into(),
            log: None,
            producer: "lonca-verify/syntax".into(),
        })
    }

    /// Runs the configured build and test commands on `files`.
    pub fn run(
        &self,
        store: &Store,
        files: &FileMap,
        subject: &GitId,
        cfg: &Verification,
    ) -> Result<Vec<Attestation>> {
        let mut out = Vec::new();
        let steps: Vec<(CheckKind, &String)> = [
            (CheckKind::Build, &cfg.build),
            (CheckKind::Tests, &cfg.test),
            (CheckKind::Extended, &cfg.on_signature_change),
        ]
        .into_iter()
        .filter_map(|(k, c)| c.as_ref().map(|c| (k, c)))
        .collect();
        if steps.is_empty() {
            return Ok(out);
        }
        fs::create_dir_all(&self.scratch)?;
        let work = tempfile::Builder::new()
            .prefix("verify-")
            .tempdir_in(&self.scratch)?;
        let root = work.path().canonicalize()?;
        materialize(store, files, &root.join("tree"))?;
        let mut failed = false;
        for (kind, cmd) in steps {
            if failed {
                out.push(attestation(
                    kind,
                    CheckResult::Skipped,
                    subject,
                    BTreeMap::new(),
                    self.env(cmd),
                    None,
                ));
                continue;
            }
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
            details.insert("attempts".into(), attempts.to_string());
            details.insert("sandbox".into(), self.sandbox.name().into());
            let log_id = store.write_blob(log.as_bytes())?;
            failed = result != CheckResult::Pass;
            out.push(attestation(
                kind,
                result,
                subject,
                details,
                self.env(cmd),
                Some(log_id),
            ));
        }
        Ok(out)
    }

    /// The sandbox a command runs in. It is the agent's code that runs, so
    /// this is the same sandbox as the agent's own, with no way out at all:
    /// no socket, no proxy, and of what is closed only what the policy
    /// names. `tree` and `writable` are this run's.
    fn jail(&self, tree: &Path, writable: Vec<PathBuf>, cfg: &Verification) -> Jail {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let mut secrets: Vec<PathBuf> = [
            std::env::var_os("LONCA_HOME").map(PathBuf::from),
            std::env::var_os("LONCA_HUMANS").map(PathBuf::from),
            home.as_ref().map(|h| h.join(".lonca")),
            home.as_ref().map(|h| h.join(".config/lonca")),
        ]
        .into_iter()
        .flatten()
        .filter_map(|p| p.canonicalize().ok())
        .collect();
        // The store holds this run's tree, so it can not be closed as a
        // whole here; `opened` keeps every read off it.
        let store = self.scratch.parent().and_then(|p| p.canonicalize().ok());
        let real = home.as_ref().and_then(|h| h.canonicalize().ok());
        let mut stores = secrets.clone();
        stores.extend(store);
        secrets.retain(|s| !tree.starts_with(s));
        let closed: Vec<PathBuf> = stores.iter().cloned().chain(real.clone()).collect();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut readable = jail::program_trees(&path, &[], &closed, &[tree.to_path_buf()]);
        readable.extend(opened(cfg, home.as_deref(), &stores, real.as_deref()));
        Jail {
            workspace: tree.to_path_buf(),
            writable,
            readable,
            secrets,
            ..Default::default()
        }
    }

    fn env(&self, cmd: &str) -> String {
        sha256_hex(format!("{}\0{cmd}", self.sandbox.name()).as_bytes())
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
        let _ = fs::create_dir_all(&home);
        let _ = fs::create_dir_all(&tmp);
        let jail = self.jail(&tree, vec![home.clone(), tmp.clone()], cfg);
        let argv: [OsString; 3] = ["/bin/sh".into(), "-c".into(), cmd.into()];
        let mut command = jail.command(self.sandbox, &argv).unwrap_or_else(|| {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(cmd);
            c
        });
        command
            .current_dir(&tree)
            .env_clear()
            .env(
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            )
            .env("HOME", &home)
            .env("TMPDIR", &tmp)
            .env("LANG", "C.UTF-8")
            .env("LONCA_VERIFY", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut passed: Vec<String> = Vec::new();
        for name in &cfg.env_passthrough {
            // The sandbox's own: nothing else can be written.
            if lonca_policy::config::env_name_forbidden(name) || name == "TMPDIR" {
                continue;
            }
            if let Some(v) = std::env::var_os(name) {
                command.env(name, v);
                passed.push(name.clone());
            }
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
        let started = Instant::now();
        let mut details = BTreeMap::new();
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                details.insert("error".into(), format!("spawn: {e}"));
                return (CheckResult::Error, details, header);
            }
        };
        let mut so = child.stdout.take().expect("piped");
        let mut se = child.stderr.take().expect("piped");
        let t_out = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = so.read_to_end(&mut v);
            v
        });
        let t_err = std::thread::spawn(move || {
            let mut v = Vec::new();
            let _ = se.read_to_end(&mut v);
            v
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break None,
            }
        };
        let mut log = t_out.join().unwrap_or_default();
        log.extend(t_err.join().unwrap_or_default());
        let start = log.len().saturating_sub(OUTPUT_TAIL);
        let log = format!("{header}{}", String::from_utf8_lossy(&log[start..]));
        details.insert(
            "duration_ms".into(),
            started.elapsed().as_millis().to_string(),
        );
        let result = match status {
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
                if s.success() {
                    CheckResult::Pass
                } else {
                    CheckResult::Fail
                }
            }
        };
        (result, details, log)
    }
}

/// What the policy opens for reading: `verification.read`, and directories
/// it passes through the environment, as they really are. What holds or lies
/// in something closed stays closed, and so does the home directory as a
/// whole, which is what `HOME` in `env_passthrough` would otherwise open.
fn opened(
    cfg: &Verification,
    home: Option<&Path>,
    closed: &[PathBuf],
    real_home: Option<&Path>,
) -> Vec<PathBuf> {
    let named = cfg.read.iter().filter_map(|p| match p.strip_prefix("~/") {
        Some(rest) => home.map(|h| h.join(rest)),
        None => Some(PathBuf::from(p)),
    });
    let passed = cfg.env_passthrough.iter();
    let passed = passed.filter_map(|n| std::env::var_os(n).map(PathBuf::from));
    let mut out = Vec::new();
    for p in named.chain(passed.filter(|p| p.is_absolute() && p.is_dir())) {
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
    use super::*;
    use lonca_core::FileEntry;

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
        let got = opened(&c, Some(&home), &closed, Some(&home));
        assert_eq!(got, std::slice::from_ref(&cargo));
        // With no home known, `~` means nothing.
        assert!(
            opened(&c, None, &closed, None)
                .iter()
                .all(|p| p != &root.join(".cargo"))
        );
    }

    fn dirs_home() -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap())
    }

    /// Only listed names reach the command; fixed values too; forbidden
    /// names never, even if a policy object carries them; the log says
    /// which names were set and never a value.
    #[test]
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

    #[test]
    fn syntax_check() {
        let (dir, store, files, tree) = setup(&[
            ("a.rs", "fn ok() {}\n"),
            ("b.rs", "fn bad( {\n"),
            ("c.md", "x"),
        ]);
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v
            .syntax(&store, &files, &["a.rs".into(), "c.md".into()], &tree)
            .unwrap();
        assert_eq!(a.result, CheckResult::Pass);
        let a = v
            .syntax(&store, &files, &["a.rs".into(), "b.rs".into()], &tree)
            .unwrap();
        assert_eq!(a.result, CheckResult::Fail);
        assert_eq!(a.details["errors"], "b.rs");
    }

    /// A grammar that can not read a file says nothing about the file.
    #[test]
    fn syntax_passes_what_a_lenient_grammar_can_not_read() {
        let unread = "class C { fun f() = 1 }\n";
        let (dir, store, files, tree) = setup(&[("a.kt", unread)]);
        assert!(parse(Lang::detect("a.kt").unwrap(), unread).has_error);
        let v = Verifier::new(dir.path().join("scratch"));
        let a = v.syntax(&store, &files, &["a.kt".into()], &tree).unwrap();
        assert_eq!(a.result, CheckResult::Pass);
    }
}
