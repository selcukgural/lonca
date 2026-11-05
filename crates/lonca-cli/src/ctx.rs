//! Where things are: the daemon socket, human keys, the current workspace.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{HumanSignature, Op};
use lonca_daemon::Client;
use lonca_daemon::service::HUMAN_SESSION_DEFAULT_MS;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn lonca_home() -> PathBuf {
    std::env::var_os("LONCA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".lonca"))
}

pub fn socket() -> PathBuf {
    std::env::var_os("LONCA_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| lonca_home().join("lonca.sock"))
}

/// Human keys live with the user, never in the daemon's home.
pub fn humans_dir() -> PathBuf {
    std::env::var_os("LONCA_HUMANS")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config/lonca/humans"))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- errors and exit codes

/// The daemon could not be reached. Exit code 2.
#[derive(Debug)]
pub struct Unreachable(pub String);

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unreachable {}

/// An error the daemon answered to a method: `method: code: message`.
/// Exit code 1, or 2 when the connection itself failed (`io`).
#[derive(Debug)]
pub struct MethodError {
    pub method: String,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}: {}", self.method, self.code, self.message)
    }
}

impl std::error::Error for MethodError {}

/// An operation the daemon logged and refused (`outcome: deny`). The
/// message carries the reason codes. Exit code 1.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "denied: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// Exit codes a runner reads (docs/protocol.md, "CLI for runners"):
/// 1 the daemon refused (an error code, or a denied decision), 2 the
/// daemon is unreachable or answered nonsense, 3 everything that never
/// reached the daemon (usage, no workspace, nothing to propose).
pub fn exit_code(e: &anyhow::Error) -> u8 {
    for cause in e.chain() {
        if let Some(c) = cause.downcast_ref::<MethodError>() {
            return if c.code == "io" { 2 } else { 1 };
        }
        if cause.downcast_ref::<Refused>().is_some()
            || cause
                .downcast_ref::<crate::doctor::ChecksFailed>()
                .is_some()
        {
            return 1;
        }
        if cause.downcast_ref::<Unreachable>().is_some() {
            return 2;
        }
    }
    3
}

/// What a proposal's decision means for the proposer: `queued` (allowed,
/// the merge queue takes it), `pending` (escalated, a human decides),
/// `denied` (logged and refused).
pub fn proposal_status(r: &Value) -> &'static str {
    match r["decision"]["outcome"].as_str() {
        Some("allow") => "queued",
        Some("escalate") => "pending",
        _ => "denied",
    }
}

/// Errors with a denied decision; prints nothing.
pub fn denied(r: &Value) -> Result<()> {
    if r["decision"]["outcome"] == "deny" {
        let reasons: Vec<&str> = r["decision"]["reasons"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        bail!(Refused(reasons.join(", ")));
    }
    Ok(())
}

/// The structured reasons of an answer (#48); an answer without any has
/// none, so `details` is always an array in a command's JSON.
pub fn details(r: &Value) -> Value {
    r.get("details").cloned().unwrap_or_else(|| json!([]))
}

pub fn connect() -> Result<Client> {
    let s = socket();
    Client::connect(&s).map_err(|e| {
        let hint = match e.kind() {
            ErrorKind::PermissionDenied => "",
            _ => " (is `lonca daemon` running?)",
        };
        anyhow!(Unreachable(format!(
            "cannot reach the Lonca daemon at {}{hint}: {e}",
            s.display()
        )))
    })
}

pub fn call(c: &mut Client, method: &str, params: Value) -> Result<Value> {
    c.call(method, params).map_err(|e| {
        anyhow!(MethodError {
            method: method.to_string(),
            code: e.0.code,
            message: e.0.message,
        })
    })
}

/// One line of JSON on stdout, for runners.
pub fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    Ok(())
}

pub fn default_human() -> Result<String> {
    if let Ok(h) = std::env::var("LONCA_HUMAN") {
        return Ok(h);
    }
    let f = humans_dir().join("default");
    std::fs::read_to_string(&f)
        .map(|s| s.trim().to_string())
        .with_context(|| "no human identity; run `lonca human keygen <name>` or set LONCA_HUMAN")
}

pub fn human_key_path(name: &str) -> PathBuf {
    humans_dir().join(format!("{name}.key"))
}

pub fn human_key(name: &str) -> Result<KeyPair> {
    let p = human_key_path(name);
    KeyPair::load(&p).map_err(|e| anyhow!("human key {}: {e}", p.display()))
}

/// Secure Enclave key blob of a human, if they use one.
pub fn se_key_path(name: &str) -> PathBuf {
    humans_dir().join(format!("{name}.se"))
}

/// The `lonca-se` helper: `$LONCA_SE`, else next to this executable.
pub fn se_helper() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LONCA_SE") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe()?;
    let p = exe.with_file_name("lonca-se");
    if p.exists() {
        Ok(p)
    } else {
        bail!("lonca-se helper not found (build packaging/macos/build-lonca-se.sh or set LONCA_SE)")
    }
}

fn run_helper(args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    use std::io::Write;
    let mut child = std::process::Command::new(se_helper()?)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(stdin.unwrap_or_default())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("lonca-se: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn se_keygen(name: &str) -> Result<String> {
    se_keygen_at(&se_key_path(name))
}

/// Creates a Secure Enclave key whose blob is stored at `p`.
pub fn se_keygen_at(p: &Path) -> Result<String> {
    std::fs::create_dir_all(humans_dir())?;
    run_helper(&["keygen", &p.to_string_lossy()], None)
}

pub fn se_public_at(p: &Path) -> Result<String> {
    run_helper(&["public", &p.to_string_lossy()], None)
}

/// The public key a human signs with.
pub fn human_public(name: &str) -> Result<lonca_core::ops::HumanKey> {
    let se = se_key_path(name);
    if se.exists() {
        let public = se_public_at(&se)?;
        return Ok(lonca_core::ops::HumanKey {
            alg: "p256-se".into(),
            public,
        });
    }
    Ok(lonca_core::ops::HumanKey {
        alg: "ed25519".into(),
        public: human_key(name)?.public_hex(),
    })
}

/// What the Touch ID prompt says: generated from the operation being signed.
pub fn describe(repo: &str, op: &Op) -> String {
    let what = match op {
        Op::RepoInit { .. } => "create the repository".to_string(),
        Op::HumanEnroll { human, .. } => format!("enroll {human} as a human"),
        Op::HumanRotate { human, .. } => format!("REPLACE the key of {human}"),
        Op::HumanRevoke { human, .. } => format!("REVOKE {human} and end their sessions"),
        Op::HumanRecoveryKey { human, .. } => format!("set a recovery key for {human}"),
        Op::HumanRecover { human, .. } => format!("RECOVER {human} with the recovery key"),
        Op::DaemonRotate { key } => format!("REPLACE the daemon key with {}", short_key(key)),
        Op::DaemonRecover { key } => format!(
            "HAND the repository to daemon key {} (approve only for your own daemon)",
            short_key(key)
        ),
        Op::PolicyUpdate { .. } => "change the repository policy".to_string(),
        Op::SessionStart {
            agent,
            scope,
            continues,
            ..
        } => {
            let paths = scope.paths.join(", ");
            match continues {
                None => format!("start agent {agent} on {paths}"),
                Some(c) if c.widen => {
                    format!("WIDEN session {} as agent {agent} on {paths}", c.session)
                }
                Some(c) => format!("continue session {} as agent {agent} on {paths}", c.session),
            }
        }
        Op::SessionEnd { session, .. } => format!("end session {session}"),
        Op::CapRevoke { session, .. } => format!("revoke session {session}"),
        Op::LeaseRelease { set } => format!("release lease set {set}"),
        Op::ChangePropose { change, .. } => format!("propose change {}", change.short()),
        Op::ChangeWithdraw { change } => format!("withdraw change {}", change.short()),
        Op::Approve { target_seq, .. } => format!("APPROVE operation #{target_seq}"),
        Op::Reject { target_seq, .. } => format!("REJECT operation #{target_seq}"),
        Op::ImportExternal { remote, .. } => format!("import from {remote}"),
        Op::BridgePush { remote, .. } => format!("push to {remote}"),
        Op::Freeze { .. } => "freeze the repository".to_string(),
        Op::Unfreeze { .. } => "unfreeze the repository".to_string(),
        Op::Redact { blob, .. } => format!("redact {}", blob.short()),
        other => other.kind().as_str().to_string(),
    };
    format!("Lonca ({repo}): {what}")
}

/// The first 16 hex digits, as `lonca daemon` prints its key.
fn short_key(k: &str) -> &str {
    k.get(..16).unwrap_or(k)
}

pub fn sign(human: &str, repo: &str, op: &Op) -> Result<HumanSignature> {
    let se = se_key_path(human);
    if se.exists() {
        let nonce = lonca_core::canonical::nonce();
        let issued_ms = now_ms();
        let msg = lonca_policy::human::intent_bytes(repo, op, &nonce, issued_ms);
        let sig = run_helper(
            &["sign", &se.to_string_lossy(), &describe(repo, op)],
            Some(&msg),
        )?;
        return Ok(HumanSignature {
            human: human.to_string(),
            nonce,
            issued_ms,
            sig,
        });
    }
    let key = human_key(human)?;
    Ok(lonca_policy::human::sign_ed25519(
        &key,
        human,
        repo,
        op,
        now_ms(),
    ))
}

// ---------------------------------------------------------------- human sessions

/// A human session kept between commands (`<humans>/<name>.session`,
/// 0600). Anything running as the developer can read it, agents
/// included: that is why it is short, and why it can only read, prepare
/// and run the queue, never sign (docs/decisions.md, "Daemon
/// authentication").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub expires_ms: i64,
}

pub fn session_path(name: &str) -> PathBuf {
    humans_dir().join(format!("{name}.session"))
}

pub fn read_session(name: &str) -> Option<Session> {
    let bytes = std::fs::read(session_path(name)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_session(name: &str, s: &Session) -> Result<()> {
    std::fs::create_dir_all(humans_dir())?;
    let p = session_path(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&p)
        .with_context(|| format!("cannot write {}", p.display()))?
        .write_all(&serde_json::to_vec(s)?)?;
    Ok(())
}

pub fn clear_session(name: &str) -> Result<()> {
    let p = session_path(name);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", p.display())),
    }
}

/// `1h`, `30m`, `90s`, else milliseconds.
pub fn describe_ms(ms: i64) -> String {
    if ms > 0 && ms % 3_600_000 == 0 {
        format!("{}h", ms / 3_600_000)
    } else if ms > 0 && ms % 60_000 == 0 {
        format!("{}m", ms / 60_000)
    } else if ms > 0 && ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

/// What the Touch ID prompt says for a login.
pub fn describe_login(human: &str, repo: Option<&str>, ttl_ms: i64) -> String {
    let scope = match repo {
        Some(r) => format!(" to {r}"),
        None => String::new(),
    };
    format!(
        "Lonca: sign in as {human}{scope} for {} (reads and prepares only)",
        describe_ms(ttl_ms)
    )
}

/// The keys a human may sign in with: the current one, and the one a
/// rotation or recovery left waiting (`<name>.next.se|key`) when it was
/// interrupted after some repositories had already taken it.
fn login_keys(human: &str) -> Vec<(PathBuf, bool)> {
    let dir = humans_dir();
    [
        (se_key_path(human), true),
        (human_key_path(human), false),
        (dir.join(format!("{human}.next.se")), true),
        (dir.join(format!("{human}.next.key")), false),
    ]
    .into_iter()
    .filter(|(p, _)| p.exists())
    .collect()
}

/// Signs a login intent with the key at `path`: the Secure Enclave
/// helper (presence) or a file key.
fn sign_login_with(
    path: &Path,
    secure_enclave: bool,
    human: &str,
    repo: Option<&str>,
    ttl_ms: i64,
) -> Result<HumanSignature> {
    if secure_enclave {
        let nonce = lonca_core::canonical::nonce();
        let issued_ms = now_ms();
        let msg = lonca_policy::human::login_bytes(repo, human, ttl_ms, &nonce, issued_ms);
        let sig = run_helper(
            &[
                "sign",
                &path.to_string_lossy(),
                &describe_login(human, repo, ttl_ms),
            ],
            Some(&msg),
        )?;
        return Ok(HumanSignature {
            human: human.to_string(),
            nonce,
            issued_ms,
            sig,
        });
    }
    let key = KeyPair::load(path).map_err(|e| anyhow!("human key {}: {e}", path.display()))?;
    Ok(lonca_policy::human::sign_login_ed25519(
        &key,
        human,
        repo,
        ttl_ms,
        now_ms(),
    ))
}

/// Opens a human session on the daemon (against `c.repo` when set) and
/// keeps it for the next commands. The client carries it from here on.
/// Tries the current key first, then a waiting next key.
pub fn login(c: &mut Client, human: &str, ttl_ms: i64) -> Result<Session> {
    let repo = c.repo.clone();
    let keys = login_keys(human);
    if keys.is_empty() {
        bail!(
            "no key for {human} in {} (run `lonca human keygen {human}`, or `lonca human recover` with the recovery key)",
            humans_dir().display()
        );
    }
    c.token = None;
    let mut last = None;
    let mut r = Value::Null;
    for (path, se) in keys {
        let sig = sign_login_with(&path, se, human, repo.as_deref(), ttl_ms)?;
        match call(c, "human.login", json!({"sig": sig, "ttl_ms": ttl_ms})) {
            Ok(v) => {
                r = v;
                last = None;
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    if let Some(e) = last {
        return Err(e);
    }
    let s = Session {
        token: r["token"]
            .as_str()
            .context("human.login returned no token")?
            .to_string(),
        expires_ms: r["expires_ms"]
            .as_i64()
            .context("human.login returned no expires_ms")?,
    };
    write_session(human, &s)?;
    c.token = Some(s.token.clone());
    Ok(s)
}

/// A client with a human session for `repo` (or, with none, for any
/// repository the human is enrolled in): the kept session if the daemon
/// still accepts it, else a fresh login. A file key never prompts; a
/// Secure Enclave key prompts once per session.
pub fn human_client(repo: Option<&str>, human: &str) -> Result<Client> {
    let mut c = connect()?;
    c.repo = repo.map(String::from);
    if let Some(s) = read_session(human)
        && s.expires_ms > now_ms() + 30_000
    {
        c.token = Some(s.token);
        if let Ok(who) = c.call("whoami", json!({}))
            && who["human"] == human
            && let Some(repos) = who["repos"].as_array()
            && match repo {
                Some(r) => repos.iter().any(|x| x == r),
                None => !repos.is_empty(),
            }
        {
            return Ok(c);
        }
    }
    login(&mut c, human, HUMAN_SESSION_DEFAULT_MS)?;
    Ok(c)
}

/// Parses `90s`, `30m`, `2h`, `1d` or plain milliseconds.
pub fn duration_ms(s: &str) -> Result<i64> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num.parse().with_context(|| format!("bad duration {s:?}"))?;
    let mul = match unit {
        "" | "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => bail!("bad duration unit in {s:?}"),
    };
    Ok(n * mul)
}

pub fn absolute(p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(continues: Option<lonca_core::ops::Continuation>) -> Op {
        Op::SessionStart {
            session: "new".into(),
            agent: "claude".into(),
            model: None,
            task: String::new(),
            scope: lonca_core::ops::Scope {
                paths: vec!["src/**".into(), "docs/**".into()],
                symbols: None,
                ops: vec![],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: 1,
            continues,
        }
    }

    /// What Touch ID shows is what is being signed: continuing is not
    /// starting, and widening says so.
    #[test]
    fn the_prompt_tells_a_start_from_a_continuation() {
        let continued = |widen| {
            let session = "old".to_string();
            start(Some(lonca_core::ops::Continuation { session, widen }))
        };
        assert_eq!(
            describe("demo", &start(None)),
            "Lonca (demo): start agent claude on src/**, docs/**"
        );
        assert_eq!(
            describe("demo", &continued(false)),
            "Lonca (demo): continue session old as agent claude on src/**, docs/**"
        );
        assert_eq!(
            describe("demo", &continued(true)),
            "Lonca (demo): WIDEN session old as agent claude on src/**, docs/**"
        );
    }

    #[test]
    fn a_proposal_status_follows_the_decision() {
        let r = |o: &str| json!({"decision": {"outcome": o}});
        assert_eq!(proposal_status(&r("allow")), "queued");
        assert_eq!(proposal_status(&r("escalate")), "pending");
        assert_eq!(proposal_status(&r("deny")), "denied");
        assert_eq!(proposal_status(&json!({})), "denied");
    }

    #[test]
    fn the_login_prompt_names_the_human_the_repository_and_the_length() {
        assert_eq!(
            describe_login("ayse", Some("demo"), 3_600_000),
            "Lonca: sign in as ayse to demo for 1h (reads and prepares only)"
        );
        assert_eq!(
            describe_login("ayse", None, 90_000),
            "Lonca: sign in as ayse for 90s (reads and prepares only)"
        );
        assert_eq!(describe_ms(30 * 60_000), "30m");
        assert_eq!(describe_ms(1_500), "1500ms");
        assert_eq!(describe_ms(0), "0ms");
    }

    #[test]
    fn the_touch_id_prompt_names_the_repository_and_the_key_change() {
        let key = lonca_core::ops::HumanKey {
            alg: "ed25519".into(),
            public: "00".into(),
        };
        let rotate = Op::HumanRotate {
            human: "ayse".into(),
            key,
        };
        let text = describe("demo", &rotate);
        assert!(text.contains("demo"), "{text}");
        assert!(text.contains("REPLACE the key of ayse"), "{text}");
        let key = "0123456789abcdef".repeat(4);
        let text = describe("demo", &Op::DaemonRotate { key: key.clone() });
        assert!(
            text.ends_with("REPLACE the daemon key with 0123456789abcdef"),
            "{text}"
        );
        let text = describe("demo", &Op::DaemonRecover { key });
        assert!(
            text.contains("HAND the repository to daemon key 0123456789abcdef ("),
            "{text}"
        );
        assert_eq!(short_key("abc"), "abc");
    }
}
