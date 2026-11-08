//! How the daemon runs `git`, the one program it starts for network
//! transport (fetch, push) and for a few plumbing reads.
//!
//! Git reads configuration from the environment, the system, the user's
//! home and the repository, and any of them can change which remote it talks
//! to (`url.<x>.insteadOf`), what it runs (`core.sshCommand`, a credential
//! helper, hooks) or where it connects (`http.proxy`). In cooperative mode
//! that is the developer's configuration, which agents running as the
//! developer can write. So the child gets an environment built here and
//! nothing else: no system configuration, a home of the daemon's own
//! (`<daemon home>/git-home`, where an administrator may put credentials), no
//! hooks, and a time limit after which its whole process group is killed.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long a git command may run before it is killed (network included).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// Transports git may use: no `ext::`, no `fd::`, no plain `git://`.
const PROTOCOLS: &str = "file:https:ssh";

/// What the environment of a git child may carry from the daemon's.
/// `SSH_AUTH_SOCK` lets a cooperative daemon push with the developer's
/// agent, as the developer's own `git push` would; nothing else passes.
const PASSED: &[&str] = &["PATH", "SSH_AUTH_SOCK", "LANG", "LC_ALL", "TMPDIR"];

#[derive(Clone, Debug)]
pub struct Git {
    /// The program (`git`, or a path).
    pub bin: String,
    /// `HOME` of the child: the daemon's own git home.
    pub home: PathBuf,
    pub timeout: Duration,
}

/// Why a git command did not succeed.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// It could not be started.
    Start(String),
    /// It ran past its time and was killed with its group.
    Timeout(Duration),
    /// It exited unsuccessfully; what it said on stderr.
    Exit(String),
}

impl Git {
    /// The environment of every git child, from the daemon's own `env`.
    pub fn env(
        &self,
        env: impl Iterator<Item = (OsString, OsString)>,
    ) -> Vec<(OsString, OsString)> {
        let mut out: Vec<(OsString, OsString)> =
            env.filter(|(k, _)| PASSED.iter().any(|p| k == p)).collect();
        let fixed = [
            ("HOME", self.home.as_os_str().to_owned()),
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            ("GIT_TERMINAL_PROMPT", "0".into()),
            ("GIT_ALLOW_PROTOCOL", PROTOCOLS.into()),
        ];
        out.extend(fixed.into_iter().map(|(k, v)| (OsString::from(k), v)));
        out
    }

    /// Runs `git --git-dir <dir> <args>` and returns its stdout.
    pub fn run(&self, dir: &Path, args: &[&str]) -> Result<String, Failure> {
        std::fs::create_dir_all(&self.home).map_err(|e| Failure::Start(e.to_string()))?;
        let mut cmd = Command::new(&self.bin);
        cmd.env_clear()
            .envs(self.env(std::env::vars_os()))
            .current_dir(&self.home)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "credential.interactive=never",
            ])
            .arg("--git-dir")
            .arg(dir)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own group, so a timeout reaches ssh and the remote
            // helpers it started too.
            .process_group(0);
        let mut child = cmd.spawn().map_err(|e| Failure::Start(e.to_string()))?;
        let read = |mut r: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = r.read_to_end(&mut buf);
                buf
            })
        };
        let out = child.stdout.take().map(|o| read(Box::new(o)));
        let err = child.stderr.take().map(|e| read(Box::new(e)));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() >= self.timeout => {
                    let group = child.id() as libc::pid_t;
                    crate::sys::kill_group(group, libc::SIGKILL);
                    let _ = child.wait();
                    return Err(Failure::Timeout(self.timeout));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(Failure::Start(e.to_string())),
            }
        };
        let join = |t: Option<std::thread::JoinHandle<Vec<u8>>>| {
            t.and_then(|t| t.join().ok()).unwrap_or_default()
        };
        let (out, err) = (join(out), join(err));
        if !status.success() {
            return Err(Failure::Exit(
                String::from_utf8_lossy(&err).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

/// A branch name as git takes one: `git check-ref-format --branch`, after
/// Lonca's own narrower test. Run with the same clean environment.
pub fn branch_ok(git: &Git, name: &str) -> bool {
    let mut cmd = Command::new(&git.bin);
    cmd.env_clear()
        .envs(git.env(std::env::vars_os()))
        .args(["check-ref-format", "--branch", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, timeout: Duration) -> Git {
        Git {
            bin: "git".into(),
            home: dir.join("git-home"),
            timeout,
        }
    }

    #[test]
    fn the_environment_passes_little_and_fixes_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let g = git(dir.path(), DEFAULT_TIMEOUT);
        let from = [
            ("PATH", "/usr/bin"),
            ("HOME", "/Users/dev"),
            ("GIT_SSH_COMMAND", "evil"),
            ("GIT_CONFIG_GLOBAL", "/tmp/evil"),
            ("GIT_CONFIG_COUNT", "1"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
            ("GIT_DIR", "/elsewhere"),
        ];
        let env = g.env(from.iter().map(|(k, v)| (k.into(), v.into())));
        let get = |k: &str| {
            env.iter()
                .filter(|(n, _)| n == k)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("PATH"), ["/usr/bin"]);
        assert_eq!(get("SSH_AUTH_SOCK"), ["/tmp/agent"]);
        assert_eq!(get("HOME"), [g.home.to_string_lossy().into_owned()]);
        assert_eq!(get("GIT_CONFIG_NOSYSTEM"), ["1"]);
        assert_eq!(get("GIT_ALLOW_PROTOCOL"), ["file:https:ssh"]);
        for gone in [
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "GIT_DIR",
        ] {
            assert!(get(gone).is_empty(), "{gone}");
        }
    }

    #[test]
    fn a_command_past_its_time_is_killed_with_its_group() {
        let dir = tempfile::tempdir().unwrap();
        // A "git" that never ends, and leaves a child that would not either.
        let fake = dir.path().join("slow-git");
        std::fs::write(&fake, "#!/bin/sh\nsleep 30 &\nsleep 30\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut g = git(dir.path(), Duration::from_millis(300));
        g.bin = fake.to_string_lossy().into_owned();
        let started = Instant::now();
        let r = g.run(dir.path(), &["fetch"]);
        assert_eq!(r, Err(Failure::Timeout(Duration::from_millis(300))));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn what_git_says_comes_back() {
        let dir = tempfile::tempdir().unwrap();
        let g = git(dir.path(), DEFAULT_TIMEOUT);
        let repo = dir.path().join("r.git");
        let init = Command::new("git")
            .args(["init", "-q", "--bare"])
            .arg(&repo)
            .status()
            .unwrap();
        assert!(init.success());
        assert_eq!(
            g.run(&repo, &["rev-parse", "--is-bare-repository"])
                .unwrap(),
            "true\n"
        );
        let Err(Failure::Exit(said)) = g.run(&repo, &["no-such-command"]) else {
            panic!("an unknown command fails");
        };
        assert!(said.contains("no-such-command"), "{said}");
        assert!(branch_ok(&g, "main") && branch_ok(&g, "feature/x"));
        assert!(!branch_ok(&g, "a..b") && !branch_ok(&g, "-x") && !branch_ok(&g, "x.lock"));
    }
}
