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

/// Worst last: a category shows the worst of its checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Pass,
    Warn,
    Fail,
}

impl Level {
    fn mark(self) -> &'static str {
        match self {
            Level::Pass => "✓",
            Level::Warn => "!",
            Level::Fail => "✗",
        }
    }

    /// The ANSI colour: green, yellow, red.
    fn colour(self) -> &'static str {
        match self {
            Level::Pass => "32",
            Level::Warn => "33",
            Level::Fail => "31",
        }
    }
}

/// Where a check is shown in text: checks about one thing under one
/// heading. A check without a group is a heading of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Group {
    Daemon,
    Tools,
    Human,
    Repository(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
    /// What to do about it, for anything that does not pass.
    pub hint: Option<String>,
    /// Text only: `--json` keeps the flat list of names.
    #[serde(skip)]
    pub group: Option<Group>,
}

impl Check {
    fn in_group(mut self, group: Group) -> Self {
        self.group = Some(group);
        self
    }

    fn title(&self) -> String {
        match &self.group {
            Some(Group::Daemon) => "Daemon".into(),
            Some(Group::Tools) => "Tools".into(),
            Some(Group::Human) => "Human".into(),
            Some(Group::Repository(r)) => format!("Repository {r}"),
            None => {
                let mut chars = self.name.chars();
                let first = chars.next().map(|f| f.to_uppercase().collect::<String>());
                first.unwrap_or_default() + chars.as_str()
            }
        }
    }

    /// The name under its heading: `log demo` is `log` under
    /// `Repository demo`.
    fn label(&self) -> &str {
        match &self.group {
            Some(Group::Repository(r)) => self
                .name
                .strip_suffix(r.as_str())
                .and_then(|s| s.strip_suffix(' '))
                .unwrap_or(&self.name),
            _ => &self.name,
        }
    }
}

fn pass(name: impl Into<String>, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Pass,
        detail: detail.into(),
        hint: None,
        group: None,
    }
}

fn warn(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Warn,
        detail: detail.into(),
        hint: Some(hint.into()),
        group: None,
    }
}

fn fail(name: impl Into<String>, detail: impl Into<String>, hint: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        level: Level::Fail,
        detail: detail.into(),
        hint: Some(hint.into()),
        group: None,
    }
}

/// A failed check: exit 1, once everything has been printed. `reported`:
/// the text summary already said so, and `main` adds nothing to stderr.
#[derive(Debug)]
pub struct ChecksFailed {
    pub failed: usize,
    pub reported: bool,
}

impl std::fmt::Display for ChecksFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} check(s) failed", self.failed)
    }
}

/// The error is failed checks the output has already summed up.
pub fn reported(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<ChecksFailed>().is_some_and(|f| f.reported))
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
    vec![git.in_group(Group::Tools), lsof.in_group(Group::Tools)]
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
    let presence = key["alg"]
        .as_str()
        .is_some_and(lonca_policy::human::proves_presence);
    if require_presence && !presence {
        return warn(
            name,
            format!("{human} has a file key; this repository requires presence"),
            "use a key that proves presence: `lonca human rotate --secure-enclave` (Mac) \
             or `--security-key` (a FIDO security key)",
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
    let group = || Group::Repository(repo.to_string());
    Ok(out.into_iter().map(|c| c.in_group(group())).collect())
}

/// Whether this human's signatures prove presence, and with what.
fn presence_check(human: &str) -> Check {
    presence_of(
        ctx::key_kind(human),
        ctx::se_helper().is_ok(),
        ctx::ssh_keygen_found(),
    )
}

/// `enclave`: the `lonca-se` helper is here; `ssh_keygen`: so is OpenSSH's
/// key program, which signs with a FIDO security key.
fn presence_of(kind: Option<ctx::KeyKind>, enclave: bool, ssh_keygen: bool) -> Check {
    use ctx::KeyKind;
    let name = "presence";
    match kind {
        Some(KeyKind::SecureEnclave) if enclave => pass(
            name,
            "Secure Enclave key: every signature asks for Touch ID or the password",
        ),
        Some(KeyKind::SecureEnclave) => fail(
            name,
            "Secure Enclave key, and no lonca-se helper to sign with",
            "put lonca-se next to lonca, or set LONCA_SE",
        ),
        Some(KeyKind::SecurityKey) if ssh_keygen => {
            pass(name, "security key: every signature asks for a touch")
        }
        Some(KeyKind::SecurityKey) => fail(
            name,
            "security key, and no ssh-keygen to sign with",
            "install OpenSSH 8.2 or later, or set LONCA_SSH_KEYGEN",
        ),
        Some(KeyKind::File) | None => {
            let mut ways = vec![];
            if enclave {
                ways.push("the Secure Enclave (`lonca human rotate --secure-enclave`)");
            }
            if ssh_keygen {
                ways.push("a FIDO security key (`lonca human rotate --security-key`)");
            }
            let available = match ways.is_empty() {
                true => "nothing here can (no lonca-se helper, no ssh-keygen)".to_string(),
                false => format!("available here: {}", ways.join(", ")),
            };
            pass(
                name,
                format!("file key: its signatures do not prove presence; {available}"),
            )
        }
    }
}

/// A key that proves presence signs a login with a prompt (Touch ID, a
/// touch), and a session that is about to end would be renewed by one.
fn would_prompt(presence_key: bool, session_expires_ms: Option<i64>, now_ms: i64) -> bool {
    presence_key && !session_expires_ms.is_some_and(|e| e > now_ms + 30_000)
}

/// Nothing here prompts: a key that proves presence without a live session is
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
    let mut out = human_and_repositories();
    for c in out.iter_mut().filter(|c| c.group.is_none()) {
        c.group = Some(Group::Human);
    }
    out
}

fn human_and_repositories() -> Vec<Check> {
    let Ok(human) = ctx::default_human() else {
        return vec![warn(
            "human",
            "no human identity",
            "run `lonca human keygen <name>`",
        )];
    };
    let session = ctx::read_session(&human).map(|s| s.expires_ms);
    let prompts = ctx::key_kind(&human).is_some_and(ctx::KeyKind::prompts);
    if would_prompt(prompts, session, ctx::now_ms()) {
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
    let mut out = vec![
        pass("human", human.clone()),
        presence_check(&human),
        security_check(&mut c),
    ];
    for repo in repos {
        match repository_checks(&human, &repo) {
            Ok(checks) => out.extend(checks),
            Err(_) => out.push(
                fail(
                    format!("repository {repo}"),
                    "could not be read",
                    "run `lonca status --repo` on it",
                )
                .in_group(Group::Repository(repo)),
            ),
        }
    }
    out
}

/// ANSI colour on a terminal, unless `NO_COLOR` is set (no-color.org) or
/// the terminal is `dumb`. A pipe gets plain text.
#[derive(Clone, Copy)]
struct Paint(bool);

impl Paint {
    fn detect() -> Self {
        use std::io::IsTerminal;
        let set = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
        let dumb = std::env::var_os("TERM").is_some_and(|t| t == "dumb");
        Paint(!set("NO_COLOR") && !dumb && std::io::stdout().is_terminal())
    }

    fn wrap(self, code: &str, text: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn level(self, level: Level, text: &str) -> String {
        self.wrap(level.colour(), text)
    }

    fn bold(self, text: &str) -> String {
        self.wrap("1", text)
    }

    fn dim(self, text: &str) -> String {
        self.wrap("2", text)
    }

    /// The commands in a hint, between backticks, in cyan. An unpaired
    /// backtick leaves the text as it is.
    fn commands(self, text: &str) -> String {
        if !self.0 || text.matches('`').count() % 2 == 1 {
            return text.to_string();
        }
        let parts = text.split('`').enumerate();
        let span = |(i, p): (usize, &str)| {
            if i % 2 == 1 {
                self.wrap("36", &format!("`{p}`"))
            } else {
                p.to_string()
            }
        };
        parts.map(span).collect()
    }
}

/// What reaches the terminal from elsewhere (an error, a freeze reason a
/// human wrote, a repository's name) carries no escape sequence.
fn plain(text: &str) -> String {
    crate::advise::printable(text, 2000)
}

/// Checks next to each other under the same heading, in order.
fn categories(checks: &[Check]) -> Vec<(String, Vec<&Check>)> {
    let mut out: Vec<(String, Vec<&Check>)> = Vec::new();
    for c in checks {
        let title = c.title();
        match out.last_mut() {
            Some((last, items)) if *last == title => items.push(c),
            _ => out.push((title, vec![c])),
        }
    }
    out
}

fn worst<'a>(checks: impl IntoIterator<Item = &'a Check>) -> Level {
    checks
        .into_iter()
        .map(|c| c.level)
        .max()
        .unwrap_or(Level::Pass)
}

/// As `flutter doctor` does: a heading per category marked with its worst
/// check. A check of its own (no group) that passes takes one line; a
/// group lists its checks by name. What to do follows each problem, and
/// the last line says how many categories have issues.
fn render(checks: &[Check], paint: Paint) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let version = format!("(lonca {}):", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(
        s,
        "{} {}\n",
        paint.bold("Doctor summary"),
        paint.dim(&version)
    );
    let cats = categories(checks);
    for (title, items) in &cats {
        let level = worst(items.iter().copied());
        let head = paint.level(level, &format!("[{}]", level.mark()));
        let title = paint.bold(&plain(title));
        if let [only] = items.as_slice()
            && only.level == Level::Pass
            && only.group.is_none()
        {
            let _ = writeln!(s, "{head} {title}: {}", plain(&only.detail));
            continue;
        }
        let _ = writeln!(s, "{head} {title}");
        for c in items {
            let mark = paint.level(c.level, c.level.mark());
            let detail = paint.commands(&plain(&c.detail));
            if c.group.is_none() {
                let _ = writeln!(s, "    {mark} {detail}");
            } else {
                let _ = writeln!(s, "    {mark} {}: {detail}", plain(c.label()));
            }
            if let Some(hint) = &c.hint {
                let hint = paint.commands(&plain(hint));
                let _ = writeln!(s, "      {} {hint}", paint.dim("→"));
            }
        }
    }
    let troubled = cats
        .iter()
        .filter(|(_, items)| worst(items.iter().copied()) != Level::Pass);
    let n = troubled.count();
    let level = worst(checks);
    let said = match n {
        0 => "No issues found.".to_string(),
        1 => "Doctor found issues in 1 category.".to_string(),
        n => format!("Doctor found issues in {n} categories."),
    };
    let _ = writeln!(
        s,
        "\n{}",
        paint.level(level, &format!("{} {said}", level.mark()))
    );
    s
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
        checks.push(socket_check(t, &socket).in_group(Group::Daemon));
        let daemon = match Client::connect(&socket) {
            Ok(mut c) => match c.call("ping", json!({})) {
                Ok(ping) => {
                    reachable = true;
                    proxy_port = proxy_port_of(&ping);
                    version_check(&ping)
                }
                Err(e) => fail("daemon", e.to_string(), "restart the daemon"),
            },
            Err(e) => fail("daemon", e.to_string(), "start `lonca daemon`"),
        };
        checks.push(daemon.in_group(Group::Daemon));
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
        out!("{}", render(&checks, Paint::detect()));
    }
    match checks.iter().filter(|c| c.level == Level::Fail).count() {
        0 => Ok(()),
        failed => Err(ChecksFailed {
            failed,
            reported: !as_json,
        }
        .into()),
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
            "touch": {"alg": "sk-p256"}, "touch2": {"alg": "sk-ed25519"},
            "odd": {"alg": 7},
        }});
        let level = |human, presence| human_check("demo", human, &status, presence).level;
        assert_eq!(level("file", false), Level::Pass);
        assert_eq!(level("enclave", true), Level::Pass);
        assert_eq!(level("touch", true), Level::Pass);
        assert_eq!(level("touch2", true), Level::Pass);
        assert_eq!(level("file", true), Level::Warn);
        assert_eq!(level("odd", true), Level::Warn);
        assert_eq!(level("odd", false), Level::Pass);
        assert_eq!(level("nobody", false), Level::Warn);
        let hint = human_check("demo", "file", &status, true).hint.unwrap();
        assert!(hint.contains("--secure-enclave") && hint.contains("--security-key"));
    }

    #[test]
    fn presence_names_the_key_and_what_this_machine_could_use() {
        use ctx::KeyKind::{File, SecureEnclave, SecurityKey};
        let of = |kind, enclave, ssh| {
            let c = presence_of(kind, enclave, ssh);
            assert_eq!(c.name, "presence");
            (c.level, c.detail, c.hint.unwrap_or_default())
        };
        let (level, detail, _) = of(Some(SecureEnclave), true, false);
        assert_eq!(level, Level::Pass);
        assert!(detail.contains("Touch ID"), "{detail}");
        let (level, _, hint) = of(Some(SecureEnclave), false, true);
        assert_eq!(level, Level::Fail);
        assert!(hint.contains("LONCA_SE"), "{hint}");
        let (level, detail, _) = of(Some(SecurityKey), false, true);
        assert_eq!(level, Level::Pass);
        assert!(detail.contains("a touch"), "{detail}");
        let (level, _, hint) = of(Some(SecurityKey), true, false);
        assert_eq!(level, Level::Fail);
        assert!(hint.contains("LONCA_SSH_KEYGEN"), "{hint}");

        // A file key, or none yet: never a problem by itself, and the
        // report says what could prove presence here.
        for kind in [Some(File), None] {
            let (level, detail, _) = of(kind, true, true);
            assert_eq!(level, Level::Pass);
            assert!(
                detail.contains("--secure-enclave") && detail.contains("--security-key"),
                "{detail}"
            );
            let (_, detail, _) = of(kind, true, false);
            assert!(
                detail.contains("--secure-enclave") && !detail.contains("--security-key"),
                "{detail}"
            );
            let (_, detail, _) = of(kind, false, true);
            assert!(
                !detail.contains("--secure-enclave") && detail.contains("--security-key"),
                "{detail}"
            );
            let (level, detail, _) = of(kind, false, false);
            assert_eq!(level, Level::Pass);
            assert!(detail.contains("nothing here can"), "{detail}");
        }
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
    fn text_groups_checks_under_headings_as_flutter_doctor_does() {
        let checks = vec![
            pass("mode", "cooperative: the daemon runs as you"),
            fail(
                "socket",
                "no socket at /x/lonca.sock",
                "start `lonca daemon`",
            )
            .in_group(Group::Daemon),
            fail("daemon", "no such file", "start `lonca daemon`").in_group(Group::Daemon),
            warn(
                "hooks",
                "no managed settings",
                "sessions count as unobserved",
            ),
            pass("sandbox", "seatbelt"),
            pass("git", "found").in_group(Group::Tools),
            pass("lsof", "found").in_group(Group::Tools),
            pass("log demo", "3 entries verify").in_group(Group::Repository("demo".into())),
        ];
        let want = format!(
            "Doctor summary (lonca {}):

[✓] Mode: cooperative: the daemon runs as you
[✗] Daemon
    ✗ socket: no socket at /x/lonca.sock
      → start `lonca daemon`
    ✗ daemon: no such file
      → start `lonca daemon`
[!] Hooks
    ! no managed settings
      → sessions count as unobserved
[✓] Sandbox: seatbelt
[✓] Tools
    ✓ git: found
    ✓ lsof: found
[✓] Repository demo
    ✓ log: 3 entries verify

✗ Doctor found issues in 2 categories.
",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(render(&checks, Paint(false)), want);

        let fine = render(&[pass("mode", "m")], Paint(false));
        assert!(fine.ends_with("\n✓ No issues found.\n"), "{fine}");
        let one = render(
            &[warn("lsof", "d", "h").in_group(Group::Tools)],
            Paint(false),
        );
        assert!(
            one.ends_with("\n! Doctor found issues in 1 category.\n"),
            "{one}"
        );
    }

    #[test]
    fn colour_marks_the_level_and_the_commands_and_nothing_else_gets_in() {
        let p = Paint(true);
        assert_eq!(p.level(Level::Pass, "✓"), "\x1b[32m✓\x1b[0m");
        assert_eq!(p.level(Level::Warn, "!"), "\x1b[33m!\x1b[0m");
        assert_eq!(p.level(Level::Fail, "✗"), "\x1b[31m✗\x1b[0m");
        assert_eq!(
            p.commands("run `a` or `b`"),
            "run \x1b[36m`a`\x1b[0m or \x1b[36m`b`\x1b[0m"
        );
        assert_eq!(p.commands("one ` only"), "one ` only");
        assert_eq!(Paint(false).commands("run `a`"), "run `a`");
        let reason =
            warn("frozen demo", "hold \x1b[2Jon", "h").in_group(Group::Repository("demo".into()));
        let text = render(&[reason], p);
        assert!(!text.contains("\x1b[2J"), "{text:?}");
        assert!(text.contains("frozen: hold [2Jon"), "{text:?}");
    }

    #[test]
    fn the_failure_counts_what_failed() {
        let e = ChecksFailed {
            failed: 2,
            reported: false,
        };
        assert_eq!(e.to_string(), "2 check(s) failed");
        assert!(!reported(&e.into()));
        let e = ChecksFailed {
            failed: 1,
            reported: true,
        };
        assert!(reported(&anyhow::Error::from(e).context("doctor")));
    }
}
