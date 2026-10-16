//! Evidence producers. The Gatekeeper runs build and test commands itself,
//! in a sandbox, on the merged tree; the agent's own reports are ignored.
//!
//! Results are nondeterministic by nature, so they are recorded as
//! [`Attestation`]s in the operation log and never recomputed on replay.

use std::collections::BTreeMap;
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

const OUTPUT_TAIL: usize = 64 * 1024;

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
        } else if ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
            .iter()
            .any(|p| exists(p))
        {
            Sandbox::Bubblewrap
        } else {
            Sandbox::None
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

/// Seatbelt profile: no network, writes only inside the work directory and
/// the system temp directories, no reads of common credential stores.
pub fn seatbelt_profile(workdir: &Path, home: Option<&Path>) -> String {
    let q = |p: &Path| {
        p.display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let mut secrets = String::new();
    if let Some(h) = home {
        for d in [
            ".ssh",
            ".aws",
            ".gnupg",
            ".config/gh",
            ".docker",
            ".kube",
            ".netrc",
            ".lonca",
        ] {
            secrets.push_str(&format!(
                "(deny file-read* (subpath \"{}\"))\n",
                q(&h.join(d))
            ));
        }
    }
    format!(
        "(version 1)\n(allow default)\n(deny network*)\n(allow network* (remote unix-socket))\n{secrets}(deny file-write*)\n(allow file-write* (subpath \"{w}\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\") (literal \"/dev/null\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))\n",
        w = q(workdir)
    )
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
                let run = self.exec(cmd, &root, Duration::from_secs(cfg.timeout_seconds));
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

    fn env(&self, cmd: &str) -> String {
        sha256_hex(format!("{}\0{cmd}", self.sandbox.name()).as_bytes())
    }

    fn exec(
        &self,
        cmd: &str,
        root: &Path,
        timeout: Duration,
    ) -> (CheckResult, BTreeMap<String, String>, String) {
        let tree = root.join("tree");
        let home = root.join("home");
        let _ = fs::create_dir_all(&home);
        let real_home = std::env::var_os("HOME").map(PathBuf::from);
        let mut command = match self.sandbox {
            Sandbox::Seatbelt => {
                let mut c = Command::new("/usr/bin/sandbox-exec");
                c.arg("-p")
                    .arg(seatbelt_profile(root, real_home.as_deref()))
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(cmd);
                c
            }
            Sandbox::Bubblewrap => {
                let mut c = Command::new("bwrap");
                c.args([
                    "--ro-bind",
                    "/",
                    "/",
                    "--dev",
                    "/dev",
                    "--proc",
                    "/proc",
                    "--tmpfs",
                    "/tmp",
                ])
                .arg("--bind")
                .arg(root)
                .arg(root)
                .args([
                    "--unshare-net",
                    "--die-with-parent",
                    "--new-session",
                    "/bin/sh",
                    "-c",
                    cmd,
                ]);
                c
            }
            Sandbox::None => {
                let mut c = Command::new("/bin/sh");
                c.arg("-c").arg(cmd);
                c
            }
        };
        command
            .current_dir(&tree)
            .env_clear()
            .env(
                "PATH",
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            )
            .env("HOME", &home)
            .env("LANG", "C.UTF-8")
            .env("LONCA_VERIFY", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut details = BTreeMap::new();
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                details.insert("error".into(), format!("spawn: {e}"));
                return (CheckResult::Error, details, String::new());
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
        let log = String::from_utf8_lossy(&log[start..]).into_owned();
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

    fn dirs_home() -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap())
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
}
