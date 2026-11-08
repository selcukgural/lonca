//! `lonca doctor`: one command that shows the setup problems most first runs
//! hit. It changes nothing, and it prints no token, no key and no path to one.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use lonca_core::oplog::{SignedOp, verify_chain};
use lonca_daemon::Client;
use lonca_daemon::hooks::{Inspection, inspect};
use lonca_daemon::service::PROTOCOL;
use lonca_daemon::trust::Trust;
use lonca_policy::config::{CONFIG_FILE, DEFAULT_POLICY, PolicyBundle};
use lonca_policy::harness::built_in;
use lonca_verify::Sandbox;
use serde::Serialize;
use serde_json::{Value, json};

use crate::ctx;
use crate::workspace;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Pass,
    Warn,
    Fail,
}

impl Level {
    fn word(self) -> &'static str {
        match self {
            Level::Pass => "pass",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
    /// What to do about it, for anything that does not pass.
    pub hint: Option<String>,
}

fn pass(name: impl Into<String>, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Pass,
        detail: detail.into(),
        hint: None,
    }
}

fn warn(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Warn,
        detail: detail.into(),
        hint: Some(hint.into()),
    }
}

fn fail(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Fail,
        detail: detail.into(),
        hint: Some(hint.into()),
    }
}

/// A failed check: exit 1, once everything has been printed.
#[derive(Debug)]
pub struct ChecksFailed(pub usize);

impl std::fmt::Display for ChecksFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} check(s) failed", self.0)
    }
}

impl std::error::Error for ChecksFailed {}

const REINSTALL: &str = "run the hardened installer again";

const LOG_PAGE: usize = 256;

fn mode_check(trust: &std::io::Result<Trust>) -> Check {
    match trust {
        Ok(t) if t.is_hardened() => pass("mode", format!("hardened: daemon uid {}", t.uid())),
        Ok(_) => pass("mode", "cooperative: the daemon runs as you"),
        Err(e) => fail("mode", e.to_string(), REINSTALL),
    }
}

fn socket_check(trust: &Trust, path: &Path) -> Check {
    match trust.check_socket(path) {
        Ok(()) => pass(
            "socket",
            format!("{} belongs to the daemon", path.display()),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail(
            "socket",
            format!("no socket at {}", path.display()),
            "start `lonca daemon`, or set LONCA_SOCKET",
        ),
        Err(e) => fail("socket", e.to_string(), REINSTALL),
    }
}

/// A different version is a warning: the protocol number is what breaks.
fn version_check(ping: &Value) -> Check {
    let version = ping["version"].as_str().unwrap_or("unknown");
    if ping["protocol"].as_u64() != Some(u64::from(PROTOCOL)) {
        return fail(
            "daemon",
            format!("protocol {}, this CLI speaks {PROTOCOL}", ping["protocol"]),
            "use the same release for the CLI and the daemon",
        );
    }
    let mine = env!("CARGO_PKG_VERSION");
    if version != mine {
        return warn(
            "daemon",
            format!("daemon {version}, CLI {mine}"),
            "use the same release for the CLI and the daemon",
        );
    }
    pass("daemon", format!("version {version}, protocol {PROTOCOL}"))
}

/// In cooperative mode hooks are an extra: without them a session counts as
/// unobserved and a human reviews every change. In hardened mode they are
/// what the mode is.
/// Where the daemon says its proxy listens.
fn proxy_port_of(ping: &Value) -> Option<u16> {
    let addr = ping["proxy"].as_str()?.parse::<std::net::SocketAddr>();
    addr.ok().map(|a| a.port())
}

fn hooks_check(ins: &Inspection, hardened: bool) -> Check {
    if ins.managed_hooks && ins.locked_sandbox && ins.hook_binary_protected {
        return pass("hooks", "locked by managed settings");
    }
    let detail = if ins.notes.is_empty() {
        "hooks or sandbox are not locked".to_string()
    } else {
        ins.notes.join("; ")
    };
    if hardened {
        fail("hooks", detail, REINSTALL)
    } else {
        warn(
            "hooks",
            detail,
            "sessions count as unobserved until the hardened installer has run",
        )
    }
}

/// A hardened daemon does not start without a sandbox (`--allow-unsandboxed`
/// is the exception, and a failed check here is how it stays visible).
fn sandbox_check(sandbox: Sandbox, hardened: bool) -> Check {
    match sandbox {
        Sandbox::None if hardened => fail(
            "sandbox",
            "no sandbox found: verification runs unsandboxed",
            "install bubblewrap",
        ),
        Sandbox::None => warn(
            "sandbox",
            "no sandbox found: verification would run unsandboxed",
            "install bubblewrap",
        ),
        s => pass("sandbox", s.name()),
    }
}

/// An agent that runs as you can use a sudo that asks for nothing, which
/// would take it past the boundary of a hardened install.
fn sudo_check(without_password: bool) -> Check {
    if without_password {
        return warn(
            "sudo",
            "sudo runs without a password here: sessions count as unobserved",
            "use `Defaults timestamp_timeout=0`, or a non-admin account for daily work",
        );
    }
    pass("sudo", "sudo asks for a password")
}

/// A hardened install that serves a repository with weaker settings.
fn hardened_check(repo: &str, status: &Value) -> Option<Check> {
    let list = status["below_hardened"].as_array()?;
    let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
    if names.is_empty() {
        return None;
    }
    Some(warn(
        format!("settings {repo}"),
        format!("below the hardened profile: {}", names.join(", ")),
        "a human changes them with `lonca policy set`",
    ))
}

fn on_path(program: &str, path: Option<&std::ffi::OsStr>) -> bool {
    let dirs = path.map(std::env::split_paths);
    dirs.into_iter()
        .flatten()
        .any(|d| d.join(program).is_file())
}

fn tools_checks(path: Option<&std::ffi::OsStr>) -> Vec<Check> {
    let git = if on_path("git", path) {
        pass("git", "found")
    } else {
        fail("git", "git is not on PATH", "install git")
    };
    let lsof = if on_path("lsof", path) {
        pass("lsof", "found")
    } else {
        warn(
            "lsof",
            "lsof is not on PATH: network use can not be attributed to a session",
            "install lsof",
        )
    };
    vec![git, lsof]
}

/// A quick audit, as far as it goes from outside the store: the hash chain
/// and every signature, up to the head the daemon reports.
fn audit_check(repo: &str, ops: &[SignedOp], head: Option<&str>) -> Check {
    let name = format!("log {repo}");
    match verify_chain(ops) {
        Ok(hash) if Some(hash.as_str()) == head => {
            pass(name, format!("{} entries verify", ops.len()))
        }
        Ok(_) => fail(
            name,
            "the log ends before the head the daemon reports",
            "run `lonca-audit verify`",
        ),
        Err(e) => fail(name, e.to_string(), "run `lonca-audit verify`"),
    }
}

/// Can this human do what the repository asks of a human?
fn human_check(repo: &str, human: &str, status: &Value, require_presence: bool) -> Check {
    let name = format!("human {repo}");
    let Some(key) = status["humans"].get(human) else {
        return warn(
            name,
            format!("{human} is not enrolled"),
            "an enrolled human runs `lonca human enroll`",
        );
    };
    if require_presence && key["alg"] != "p256-se" {
        return warn(
            name,
            format!("{human} has a file key; this repository requires presence"),
            "use a Secure Enclave key: `lonca human rotate --secure-enclave`",
        );
    }
    pass(name, format!("{human} is enrolled"))
}

fn presence_required(c: &mut Client, status: &Value) -> Result<bool> {
    let policy = serde_json::from_value(status["policy"].clone())?;
    let files = workspace::fetch(c, &policy, None)?;
    let Some(f) = files.iter().find(|f| f.path == CONFIG_FILE) else {
        return Ok(false);
    };
    use base64::Engine;
    let text = base64::engine::general_purpose::STANDARD
        .decode(f.content_b64.clone().unwrap_or_default())?;
    let bundle = PolicyBundle::parse(&String::from_utf8(text)?, DEFAULT_POLICY);
    let bundle = bundle.map_err(|e| anyhow!(e))?;
    Ok(bundle.config.approvals.require_presence)
}

/// In pages: an answer is one line, and a line has a cap.
fn whole_log(c: &mut Client) -> Result<Vec<SignedOp>> {
    let mut ops = Vec::new();
    loop {
        let params = json!({"from": ops.len(), "limit": LOG_PAGE});
        let page: Vec<SignedOp> = serde_json::from_value(ctx::call(c, "log", params)?)?;
        if page.is_empty() {
            return Ok(ops);
        }
        ops.extend(page);
    }
}

fn repository_checks(human: &str, repo: &str) -> Result<Vec<Check>> {
    let mut c = ctx::human_client(Some(repo), human)?;
    let status = ctx::call(&mut c, "status", json!({}))?;
    let ops = whole_log(&mut c)?;
    let presence = presence_required(&mut c, &status)?;
    let mut out = vec![
        audit_check(repo, &ops, status["head_hash"].as_str()),
        human_check(repo, human, &status, presence),
    ];
    out.extend(hardened_check(repo, &status));
    if let Some(reason) = status["frozen"].as_str() {
        out.push(warn(
            format!("frozen {repo}"),
            reason.to_string(),
            "a human runs `lonca unfreeze`",
        ));
    }
    Ok(out)
}

/// A Secure Enclave key signs a login with a prompt, and a session that is
/// about to end would be renewed by one.
fn would_prompt(enclave_key: bool, session_expires_ms: Option<i64>, now_ms: i64) -> bool {
    enclave_key && !session_expires_ms.is_some_and(|e| e > now_ms + 30_000)
}

/// Nothing here prompts: a Secure Enclave key without a live session is
/// asked to log in first. The errors stay out of the output, since a login
/// failure names the directory of the keys.
/// What the security log holds for the last day ([`security.events`]):
/// counts by kind; a freeze, an integrity alarm or a write behind the
/// daemon's back is a warning.
fn security_check(c: &mut lonca_daemon::Client) -> Check {
    let Ok(r) = ctx::call(c, "security.events", json!({})) else {
        return warn(
            "security events",
            "the daemon did not answer security.events",
            "upgrade the daemon",
        );
    };
    let counts = r["counts"].as_object().cloned().unwrap_or_default();
    if counts.is_empty() {
        return pass("security events", "none in the last 24 hours");
    }
    let said: Vec<String> = counts.iter().map(|(k, n)| format!("{k} {n}")).collect();
    let detail = format!("last 24 hours: {}", said.join(", "));
    let grave = [
        "freeze",
        "integrity_alarm",
        "unmediated_import",
        "reconcile_error",
    ];
    if grave.iter().any(|k| counts.contains_key(*k)) {
        warn(
            "security events",
            detail,
            "read the daemon's security.log, and `lonca log` for the entries",
        )
    } else {
        pass("security events", detail)
    }
}

fn humans_checks() -> Vec<Check> {
    let Ok(human) = ctx::default_human() else {
        return vec![warn(
            "human",
            "no human identity",
            "run `lonca human keygen <name>`",
        )];
    };
    let session = ctx::read_session(&human).map(|s| s.expires_ms);
    if would_prompt(ctx::se_key_path(&human).exists(), session, ctx::now_ms()) {
        return vec![warn(
            "human",
            format!("{human} has no session, and opening one would prompt"),
            "run `lonca human login`, then `lonca doctor` again",
        )];
    }
    let Ok(mut c) = ctx::human_client(None, &human) else {
        return vec![warn(
            "human",
            format!("{human} could not open a session"),
            "check `lonca human whoami`; no repository may know this human yet",
        )];
    };
    let repos = ctx::call(&mut c, "repo.list", json!({}));
    let repos: Vec<String> = repos
        .ok()
        .and_then(|r| serde_json::from_value(r).ok())
        .unwrap_or_default();
    let mut out = vec![pass("human", human.clone()), security_check(&mut c)];
    for repo in repos {
        match repository_checks(&human, &repo) {
            Ok(checks) => out.extend(checks),
            Err(_) => out.push(fail(
                format!("repository {repo}"),
                "could not be read",
                "run `lonca status --repo` on it",
            )),
        }
    }
    out
}

fn print(checks: &[Check]) {
    for c in checks {
        println!("{}  {}: {}", c.level.word(), c.name, c.detail);
        if let Some(hint) = &c.hint {
            println!("      {hint}");
        }
    }
}

/// `{"ok", "mode", "checks"}`: `ok` is false when a check failed, and a
/// warning leaves it true.
fn report(mode: Option<&str>, checks: &[Check]) -> Value {
    json!({
        "ok": !checks.iter().any(|c| c.level == Level::Fail),
        "mode": mode,
        "checks": checks,
    })
}

pub fn run(managed_settings: Option<PathBuf>, as_json: bool) -> Result<()> {
    let trust = Trust::load();
    let mut checks = vec![mode_check(&trust)];
    let path = std::env::var_os("PATH");
    let mut reachable = false;
    let mut proxy_port = None;
    if let Ok(t) = &trust {
        let socket = ctx::socket();
        checks.push(socket_check(t, &socket));
        match Client::connect(&socket) {
            Ok(mut c) => match c.call("ping", json!({})) {
                Ok(ping) => {
                    reachable = true;
                    proxy_port = proxy_port_of(&ping);
                    checks.push(version_check(&ping));
                }
                Err(e) => checks.push(fail("daemon", e.to_string(), "restart the daemon")),
            },
            Err(e) => checks.push(fail("daemon", e.to_string(), "start `lonca daemon`")),
        }
        for locked in built_in().values().filter_map(|p| p.locked.as_ref()) {
            let named = || locked.file_here().map(PathBuf::from);
            if let Some(file) = managed_settings.clone().or_else(named) {
                let ins = inspect(locked, &file, t.is_hardened(), proxy_port);
                checks.push(hooks_check(&ins, t.is_hardened()));
            }
        }
    }
    let hardened = trust.as_ref().is_ok_and(Trust::is_hardened);
    checks.push(sandbox_check(Sandbox::detect(), hardened));
    if hardened {
        checks.push(sudo_check(crate::hook::sudo_without_password()));
    }
    checks.extend(tools_checks(path.as_deref()));
    if reachable {
        checks.extend(humans_checks());
    }
    let mode = trust.as_ref().ok().map(|t| {
        if t.is_hardened() {
            "hardened"
        } else {
            "cooperative"
        }
    });
    if as_json {
        ctx::print_json(&report(mode, &checks))?;
    } else {
        print(&checks);
    }
    match checks.iter().filter(|c| c.level == Level::Fail).count() {
        0 => Ok(()),
        n => Err(ChecksFailed(n).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonca_core::GitId;
    use lonca_core::keys::KeyPair;
    use lonca_core::ops::{Actor, Decision, HumanKey, Op};

    fn levels(checks: &[Check]) -> Vec<(&str, Level)> {
        checks.iter().map(|c| (c.name.as_str(), c.level)).collect()
    }

    #[test]
    fn a_problem_says_what_to_do_about_it() {
        assert_eq!(pass("x", "fine").hint, None);
        assert_eq!(warn("x", "d", "h").hint.as_deref(), Some("h"));
        assert_eq!(warn("x", "d", "h").level, Level::Warn);
        assert_eq!(fail("x", "d", "h").level, Level::Fail);
        assert_eq!(pass("x", "d").level.word(), "pass");
        assert_eq!(warn("x", "d", "h").level.word(), "warn");
        assert_eq!(fail("x", "d", "h").level.word(), "fail");
    }

    #[test]
    fn a_warning_leaves_the_report_ok_and_a_failure_does_not() {
        let w = warn("a", "d", "h");
        let f = fail("b", "d", "h");
        assert_eq!(report(None, &[pass("x", "y"), w.clone()])["ok"], true);
        let r = report(Some("hardened"), &[w, f]);
        assert_eq!(r["ok"], false);
        assert_eq!(r["mode"], "hardened");
        assert_eq!(r["checks"][1]["level"], "fail");
    }

    #[test]
    fn mode_names_the_daemon_uid_or_says_cooperative() {
        let hardened = mode_check(&Ok(Trust::hardened(280)));
        assert_eq!(hardened.level, Level::Pass);
        assert!(hardened.detail.contains("280"), "{}", hardened.detail);
        let plain = mode_check(&Ok(Trust::cooperative()));
        assert!(plain.detail.starts_with("cooperative"), "{}", plain.detail);
        let broken = mode_check(&Err(std::io::Error::other("bad file")));
        assert_eq!(broken.level, Level::Fail);
    }

    #[test]
    fn the_protocol_number_breaks_and_the_version_warns() {
        let v = env!("CARGO_PKG_VERSION");
        let at = |version: &str, protocol: u32| json!({"version": version, "protocol": protocol});
        assert_eq!(version_check(&at(v, PROTOCOL)).level, Level::Pass);
        assert_eq!(version_check(&at("0.0.0", PROTOCOL)).level, Level::Warn);
        assert_eq!(version_check(&at(v, PROTOCOL + 1)).level, Level::Fail);
        assert_eq!(version_check(&json!({})).level, Level::Fail);
    }

    #[test]
    fn the_proxy_is_where_the_daemon_says() {
        let port = |proxy: Value| proxy_port_of(&json!({"proxy": proxy}));
        assert_eq!(port(json!("127.0.0.1:8471")), Some(8471));
        assert_eq!(port(json!("p")), None);
        assert_eq!(port(Value::Null), None);
    }

    #[test]
    fn hooks_are_required_only_in_hardened_mode() {
        let locked = Inspection {
            managed_hooks: true,
            locked_sandbox: true,
            hook_binary_protected: true,
            ..Default::default()
        };
        assert_eq!(hooks_check(&locked, true).level, Level::Pass);
        assert_eq!(hooks_check(&locked, false).level, Level::Pass);
        for open in [
            Inspection {
                managed_hooks: false,
                ..locked.clone()
            },
            Inspection {
                locked_sandbox: false,
                ..locked.clone()
            },
            Inspection {
                hook_binary_protected: false,
                ..locked.clone()
            },
        ] {
            assert_eq!(hooks_check(&open, true).level, Level::Fail);
            assert_eq!(hooks_check(&open, false).level, Level::Warn);
        }
        let noted = Inspection {
            notes: vec!["no managed settings".into()],
            ..Default::default()
        };
        assert_eq!(hooks_check(&noted, false).detail, "no managed settings");
    }

    #[test]
    fn no_sandbox_is_a_warning() {
        assert_eq!(sandbox_check(Sandbox::None, false).level, Level::Warn);
        assert_eq!(sandbox_check(Sandbox::None, true).level, Level::Fail);
        assert_eq!(sandbox_check(Sandbox::Seatbelt, true).level, Level::Pass);
        assert_eq!(sandbox_check(Sandbox::Bubblewrap, false).detail, "bwrap");
        assert_eq!(sudo_check(true).level, Level::Warn);
        assert_eq!(sudo_check(false).level, Level::Pass);
    }

    #[test]
    fn git_is_needed_and_lsof_is_wanted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().as_os_str();
        assert_eq!(
            levels(&tools_checks(Some(path))),
            [("git", Level::Fail), ("lsof", Level::Warn)]
        );
        assert_eq!(
            levels(&tools_checks(None)),
            [("git", Level::Fail), ("lsof", Level::Warn)]
        );
        std::fs::write(dir.path().join("git"), "").unwrap();
        std::fs::write(dir.path().join("lsof"), "").unwrap();
        assert_eq!(
            levels(&tools_checks(Some(path))),
            [("git", Level::Pass), ("lsof", Level::Pass)]
        );
    }

    fn one_entry() -> Vec<SignedOp> {
        let key = KeyPair::generate();
        let id = GitId("a".repeat(40));
        let entry = lonca_core::oplog::OpEntry {
            format: lonca_core::oplog::FORMAT_CURRENT,
            seq: 0,
            prev: lonca_core::oplog::GENESIS_PREV.into(),
            time_ms: 1,
            actor: Actor::Human {
                name: "ayse".into(),
            },
            op: Op::RepoInit {
                repo: "demo".into(),
                daemon_key: key.public_hex(),
                human: "ayse".into(),
                human_key: HumanKey {
                    alg: "ed25519".into(),
                    public: "00".into(),
                },
                policy: id.clone(),
                trunk: id,
            },
            evidence: vec![],
            facts: None,
            symbols_engine: None,
            decision: Decision::allow(),
            human: None,
        };
        vec![SignedOp::sign(entry, &key)]
    }

    #[test]
    fn a_log_verifies_up_to_the_head_the_daemon_reports() {
        let ops = one_entry();
        let head = ops[0].hash.clone();
        let good = audit_check("demo", &ops, Some(&head));
        assert_eq!(good.level, Level::Pass, "{good:?}");
        assert_eq!(good.name, "log demo");
        assert!(good.detail.starts_with("1 entries"), "{}", good.detail);
        let short = audit_check("demo", &ops, Some("other"));
        assert_eq!(short.level, Level::Fail);
        assert!(short.detail.contains("before the head"), "{}", short.detail);
        assert_eq!(audit_check("demo", &[], Some(&head)).level, Level::Fail);
    }

    #[test]
    fn a_human_who_can_not_satisfy_the_repository_is_told() {
        let status = json!({"humans": {
            "file": {"alg": "ed25519"}, "enclave": {"alg": "p256-se"},
        }});
        let level = |human, presence| human_check("demo", human, &status, presence).level;
        assert_eq!(level("file", false), Level::Pass);
        assert_eq!(level("enclave", true), Level::Pass);
        assert_eq!(level("file", true), Level::Warn);
        assert_eq!(level("nobody", false), Level::Warn);
    }

    #[test]
    fn only_an_enclave_key_without_a_live_session_would_prompt() {
        let now = 1_000_000;
        assert!(!would_prompt(false, None, now), "a file key never does");
        assert!(would_prompt(true, None, now));
        assert!(!would_prompt(true, Some(now + 30_001), now));
        assert!(would_prompt(true, Some(now + 30_000), now), "about to end");
        assert!(would_prompt(true, Some(now), now));
    }

    #[test]
    fn the_failure_counts_what_failed() {
        assert_eq!(ChecksFailed(2).to_string(), "2 check(s) failed");
    }
}
