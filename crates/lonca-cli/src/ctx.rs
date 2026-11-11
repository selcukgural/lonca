//! Where things are: the daemon socket, human keys, the current workspace.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{HumanKey, HumanSignature, LogPoint, Op};
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
        if let Some(advice) = r["advice"].as_str() {
            errln!("{advice}");
        }
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

/// The whole id of the change `id` names: the id itself, or a prefix the
/// daemon finds exactly one change for (`pending` and `log` show 12 letters).
pub fn resolve_change(c: &mut Client, id: &str) -> Result<String> {
    if id.len() == 32 {
        return Ok(id.to_string());
    }
    let r = call(c, "change.resolve", serde_json::json!({"prefix": id}))?;
    r["change"]
        .as_str()
        .map(str::to_string)
        .context("change.resolve: no change in the answer")
}

/// One line of JSON on stdout, for runners.
pub fn print_json(v: &Value) -> Result<()> {
    outln!("{}", serde_json::to_string(v)?);
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

/// Creates a Secure Enclave key whose blob is stored at `p`.
pub fn se_keygen_at(p: &Path) -> Result<String> {
    std::fs::create_dir_all(humans_dir())?;
    run_helper(&["keygen", &p.to_string_lossy()], None)
}

pub fn se_public_at(p: &Path) -> Result<String> {
    run_helper(&["public", &p.to_string_lossy()], None)
}

/// Where a human's key lives, which is how it signs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyKind {
    /// A file: anything running as the human can sign.
    File,
    /// The Secure Enclave, through `lonca-se`: Touch ID or the password.
    SecureEnclave,
    /// A FIDO security key, through `ssh-keygen`: a touch.
    SecurityKey,
}

impl KeyKind {
    /// In the order a human's key is looked for.
    pub const ALL: [KeyKind; 3] = [KeyKind::SecureEnclave, KeyKind::SecurityKey, KeyKind::File];

    /// The extension of the key's file in the humans directory.
    pub fn ext(self) -> &'static str {
        match self {
            KeyKind::File => "key",
            KeyKind::SecureEnclave => "se",
            KeyKind::SecurityKey => "sk",
        }
    }

    /// Whether signing asks the person for something.
    pub fn prompts(self) -> bool {
        self != KeyKind::File
    }

    /// The flag that asks for this kind of key.
    pub fn flag(self) -> &'static str {
        match self {
            KeyKind::File => "neither flag",
            KeyKind::SecureEnclave => "--secure-enclave",
            KeyKind::SecurityKey => "--security-key",
        }
    }
}

/// The file of a human's key of one kind.
pub fn key_path(name: &str, kind: KeyKind) -> PathBuf {
    humans_dir().join(format!("{name}.{}", kind.ext()))
}

/// The kind of key a human has here, if any.
pub fn key_kind(name: &str) -> Option<KeyKind> {
    KeyKind::ALL
        .into_iter()
        .find(|k| key_path(name, *k).exists())
}

/// The type of security key `ssh-keygen` makes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum SkType {
    /// ECDSA P-256: every FIDO and U2F key has it.
    Ecdsa,
    /// Ed25519: FIDO2 keys with newer firmware.
    Ed25519,
}

/// The key a keygen, a rotation or a recovery makes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NewKey {
    File,
    SecureEnclave,
    SecurityKey(SkType),
}

impl NewKey {
    /// From `--secure-enclave` and `--security-key[=type]`.
    pub fn from_flags(secure_enclave: bool, security_key: Option<SkType>) -> NewKey {
        match (secure_enclave, security_key) {
            (true, _) => NewKey::SecureEnclave,
            (false, Some(ty)) => NewKey::SecurityKey(ty),
            (false, None) => NewKey::File,
        }
    }

    pub fn kind(self) -> KeyKind {
        match self {
            NewKey::File => KeyKind::File,
            NewKey::SecureEnclave => KeyKind::SecureEnclave,
            NewKey::SecurityKey(_) => KeyKind::SecurityKey,
        }
    }

    /// The key at `path`, made now unless an earlier run made it.
    pub fn at(self, path: &Path, name: &str) -> Result<HumanKey> {
        if !path.exists() {
            match self {
                NewKey::SecureEnclave => {
                    se_keygen_at(path)?;
                }
                NewKey::SecurityKey(ty) => return sk_keygen_at(path, ty, name),
                NewKey::File => {
                    KeyPair::load_or_create(path, crate::sys::current_uid())?;
                }
            }
        }
        public_at(path, self.kind())
    }
}

/// `ssh-keygen`: `$LONCA_SSH_KEYGEN`, else the one on the PATH.
fn ssh_keygen() -> std::ffi::OsString {
    std::env::var_os("LONCA_SSH_KEYGEN").unwrap_or_else(|| "ssh-keygen".into())
}

/// Whether there is an `ssh-keygen` to run.
pub fn ssh_keygen_found() -> bool {
    let program = PathBuf::from(ssh_keygen());
    if program.components().count() > 1 {
        return program.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(&program).is_file()))
}

fn ssh_keygen_failed(e: &std::io::Error) -> anyhow::Error {
    anyhow!(
        "ssh-keygen could not be run ({e}): a security key signs through OpenSSH 8.2 or \
         later; install it or set LONCA_SSH_KEYGEN"
    )
}

/// Makes a security key credential for Lonca; its handle (useless
/// without the device) is stored at `p`. The person touches the key.
pub fn sk_keygen_at(p: &Path, ty: SkType, name: &str) -> Result<HumanKey> {
    std::fs::create_dir_all(humans_dir())?;
    let ty = match ty {
        SkType::Ecdsa => "ecdsa-sk",
        SkType::Ed25519 => "ed25519-sk",
    };
    errln!("making a key on your security key: touch it when it blinks");
    let application = format!("application={}", lonca_policy::human::sk::APPLICATION);
    let status = std::process::Command::new(ssh_keygen())
        .args(["-q", "-t", ty, "-O", &application, "-N", "", "-C"])
        .arg(format!("lonca:{name}"))
        .arg("-f")
        .arg(p)
        .status()
        .map_err(|e| ssh_keygen_failed(&e))?;
    if !status.success() {
        bail!(
            "ssh-keygen made no key: is a security key plugged in, and is this OpenSSH \
             built with FIDO support?"
        );
    }
    // The handle file holds the public key too.
    let mut public = p.as_os_str().to_owned();
    public.push(".pub");
    let _ = std::fs::remove_file(public);
    sk_public_at(p)
}

/// The public key of the security key credential stored at `p`.
pub fn sk_public_at(p: &Path) -> Result<HumanKey> {
    let out = std::process::Command::new(ssh_keygen())
        .arg("-y")
        .arg("-f")
        .arg(p)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| ssh_keygen_failed(&e))?;
    if !out.status.success() {
        bail!(
            "ssh-keygen -y {}: {}",
            p.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    sk_public(&String::from_utf8_lossy(&out.stdout))
}

/// The human key in an OpenSSH public key line.
fn sk_public(line: &str) -> Result<HumanKey> {
    use base64::Engine;
    use lonca_policy::human::sk;
    let blob = line.split_whitespace().nth(1).unwrap_or_default();
    let blob = base64::engine::general_purpose::STANDARD.decode(blob);
    let Some((kind, public)) = blob.ok().and_then(|b| sk::parse_public_blob(&b)) else {
        bail!(
            "not a security key made for Lonca (ssh-keygen -t ecdsa-sk -O application={})",
            sk::APPLICATION
        );
    };
    Ok(HumanKey {
        alg: kind.alg().into(),
        public: hex::encode(public),
    })
}

/// Signs `msg` with the security key whose handle is at `p`. `what` is
/// shown first: the device itself shows nothing, so the terminal says
/// what the touch is for.
fn sk_sign(p: &Path, msg: &[u8], what: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Stdio;
    errln!("{what}\ntouch your security key to sign");
    let mut child = std::process::Command::new(ssh_keygen())
        .args(["-Y", "sign", "-n", lonca_policy::human::sk::NAMESPACE, "-f"])
        .arg(p)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| ssh_keygen_failed(&e))?;
    child.stdin.take().expect("piped").write_all(msg)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ssh-keygen did not sign: no touch, or the security key is not plugged in");
    }
    sk_signature(&String::from_utf8_lossy(&out.stdout))
}

/// The signature inside the armor `ssh-keygen -Y sign` prints, in hex.
fn sk_signature(armored: &str) -> Result<String> {
    use base64::Engine;
    let mut lines = armored.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some("-----BEGIN SSH SIGNATURE-----") {
        bail!("ssh-keygen printed no signature");
    }
    let body: String = lines
        .take_while(|l| *l != "-----END SSH SIGNATURE-----")
        .collect();
    let blob = base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("ssh-keygen printed no signature")?;
    Ok(hex::encode(blob))
}

/// The public key stored at `path`, a key of `kind`.
pub fn public_at(path: &Path, kind: KeyKind) -> Result<HumanKey> {
    Ok(match kind {
        KeyKind::SecureEnclave => HumanKey {
            alg: "p256-se".into(),
            public: se_public_at(path)?,
        },
        KeyKind::SecurityKey => sk_public_at(path)?,
        KeyKind::File => HumanKey {
            alg: "ed25519".into(),
            public: KeyPair::load(path, crate::sys::current_uid())
                .map_err(|e| anyhow!("human key {}: {e}", path.display()))?
                .public_hex(),
        },
    })
}

/// The public key a human signs with.
pub fn human_public(name: &str) -> Result<HumanKey> {
    let kind = key_kind(name).unwrap_or(KeyKind::File);
    public_at(&key_path(name, kind), kind)
}

/// Signs `msg` with the key at `path`. A key that proves presence asks
/// for it, saying `what` it is for; a file key signs.
fn sign_with(path: &Path, kind: KeyKind, msg: &[u8], what: &str) -> Result<String> {
    match kind {
        KeyKind::SecureEnclave => run_helper(&["sign", &path.to_string_lossy(), what], Some(msg)),
        KeyKind::SecurityKey => sk_sign(path, msg, what),
        KeyKind::File => Ok(KeyPair::load(path, crate::sys::current_uid())
            .map_err(|e| anyhow!("human key {}: {e}", path.display()))?
            .sign_hex(msg)),
    }
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
        Op::DaemonRecover { key, recover } => format!(
            "HAND the repository to daemon key {}{} (approve only for your own daemon)",
            short_key(key),
            match recover {
                Some(r) => format!(" and RECOVER {} with the recovery key", r.human),
                None => String::new(),
            }
        ),
        Op::PolicyUpdate { .. } => "change the repository policy".to_string(),
        Op::SessionStart {
            agent,
            scope,
            continues,
            harness,
            ..
        } => {
            let paths = scope.paths.join(", ");
            let what = match continues {
                None => format!("start agent {agent} on {paths}"),
                Some(c) if c.widen => {
                    format!("WIDEN session {} as agent {agent} on {paths}", c.session)
                }
                Some(c) => format!("continue session {} as agent {agent} on {paths}", c.session),
            };
            // The human vouches for it: a level is read for this name.
            match harness {
                Some(h) => format!("{what}, under {h}"),
                None => what,
            }
        }
        Op::SessionEnd { session, .. } => format!("end session {session}"),
        Op::CapRevoke { session, .. } => format!("revoke session {session}"),
        Op::LeaseRelease { set } => format!("release lease set {set}"),
        Op::ChangePropose { change, .. } => format!("propose change {}", change.short()),
        Op::ChangeWithdraw { change } => format!("withdraw change {}", change.short()),
        Op::Approve {
            target_seq, checks, ..
        } if !checks.is_empty() => {
            format!(
                "APPROVE operation #{target_seq}, owing checks {}",
                checks.join(", ")
            )
        }
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

/// The head of `repo`'s log, for a signature to name: a signature is for
/// the log its signer saw (log format 33). None while there is no log.
pub fn head(c: &mut Client, repo: &str) -> Result<Option<LogPoint>> {
    let was = c.repo.replace(repo.to_string());
    let r = call(c, "log.head", json!({}));
    c.repo = was;
    Ok(serde_json::from_value(r?["at"].clone())?)
}

/// Signs `op` as `human` for the log of `repo` as the daemon behind `c`
/// has it now; a genesis is signed for no log.
pub fn sign(c: &mut Client, human: &str, repo: &str, op: &Op) -> Result<HumanSignature> {
    let at = match op {
        Op::RepoInit { .. } => None,
        _ => head(c, repo)?,
    };
    let kind = key_kind(human).unwrap_or(KeyKind::File);
    let nonce = lonca_core::canonical::nonce();
    let issued_ms = now_ms();
    let msg = lonca_policy::human::intent_bytes(repo, op, &nonce, issued_ms, at.as_ref());
    let sig = sign_with(&key_path(human, kind), kind, &msg, &describe(repo, op))?;
    Ok(HumanSignature {
        human: human.to_string(),
        nonce,
        issued_ms,
        sig,
        at,
    })
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

/// The session, if there is one `lonca` left (`lonca_client::session`): a
/// file another user owns, or that others may read, is not used, and the
/// next login writes it again with the right mode.
pub fn read_session(name: &str) -> Option<Session> {
    let s = lonca_client::session::read_session(&session_path(name)).ok()??;
    Some(Session {
        token: s.token,
        expires_ms: s.expires_ms,
    })
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
    let mut file = opts
        .open(&p)
        .with_context(|| format!("cannot write {}", p.display()))?;
    // The mode on `open` only counts for a new file: an old one keeps its own.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&serde_json::to_vec(s)?)?;
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
/// rotation or recovery left waiting (`<name>.next.<ext>`) when it was
/// interrupted after some repositories had already taken it.
fn login_keys(human: &str) -> Vec<(PathBuf, KeyKind)> {
    let next = format!("{human}.next");
    [human, next.as_str()]
        .into_iter()
        .flat_map(|name| KeyKind::ALL.map(|k| (key_path(name, k), k)))
        .filter(|(p, _)| p.exists())
        .collect()
}

/// Signs a login intent with the key at `path`.
fn sign_login_with(
    path: &Path,
    kind: KeyKind,
    human: &str,
    repo: Option<&str>,
    ttl_ms: i64,
) -> Result<HumanSignature> {
    let nonce = lonca_core::canonical::nonce();
    let issued_ms = now_ms();
    let msg = lonca_policy::human::login_bytes(repo, human, ttl_ms, &nonce, issued_ms);
    let sig = sign_with(path, kind, &msg, &describe_login(human, repo, ttl_ms))?;
    Ok(HumanSignature {
        human: human.to_string(),
        nonce,
        issued_ms,
        sig,
        at: None,
    })
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
    for (path, kind) in keys {
        let sig = sign_login_with(&path, kind, human, repo.as_deref(), ttl_ms)?;
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

/// `p` as the log names a directory: absolute, links resolved as far as
/// the path exists, no `.` or `..`.
pub fn resolved(p: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut flat = PathBuf::new();
    for c in absolute(p)?.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                flat.pop();
            }
            c => flat.push(c),
        }
    }
    let mut rest = Vec::new();
    let mut there = flat.as_path();
    loop {
        if let Ok(real) = std::fs::canonicalize(there) {
            return Ok(rest.iter().rev().fold(real, |at, name| at.join(name)));
        }
        match (there.parent(), there.file_name()) {
            (Some(up), Some(name)) => {
                rest.push(name.to_os_string());
                there = up;
            }
            _ => return Ok(flat),
        }
    }
}

/// Where the log places a session.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Placed {
    pub repo: String,
    pub session: String,
    pub workspace: Option<String>,
    pub active: bool,
}

/// The session the log places at `path` (its workspace is that directory
/// or holds it), or the live one a hook's harness session is bound to. The
/// answer is the log's: no file of the workspace is read for it.
pub fn placed(c: &mut Client, path: &Path, hook: Option<(&str, &Value)>) -> Result<Option<Placed>> {
    let path = resolved(path)?;
    let mut params = json!({"path": path});
    if let Some((harness, input)) = hook {
        // The harness's name for its session is one of the short strings
        // at the top of its input; which one, its profile says.
        let short = |(k, v): (&String, &Value)| {
            let v = v.as_str().filter(|v| v.len() <= 256)?;
            Some((k.clone(), json!(v)))
        };
        let fields: serde_json::Map<String, Value> = input
            .as_object()
            .map(|o| o.iter().filter_map(short).take(32).collect())
            .unwrap_or_default();
        params["harness"] = json!(harness);
        params["fields"] = Value::Object(fields);
    }
    let r = match call(c, "session.where", params) {
        Ok(r) => r,
        // A daemon from before format 30, not restarted yet: its log
        // places no session, and it says so of none.
        Err(e) if matches!(e.downcast_ref::<MethodError>(), Some(m) if m.code == "unknown_method") =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if r.get("session").is_none() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(r)?))
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
            harness: None,
            workspace: None,
        }
    }

    /// The name a level is read for is part of what is being signed.
    #[test]
    fn the_prompt_names_the_harness() {
        let mut op = start(None);
        if let Op::SessionStart { harness, .. } = &mut op {
            *harness = Some("codex".into());
        }
        assert!(describe("demo", &op).ends_with("on src/**, docs/**, under codex"));
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
        let text = describe(
            "demo",
            &Op::DaemonRecover {
                key: key.clone(),
                recover: None,
            },
        );
        assert!(
            text.contains("HAND the repository to daemon key 0123456789abcdef ("),
            "{text}"
        );
        let recover = Some(lonca_core::ops::Recovery {
            human: "ayse".into(),
            key: lonca_core::ops::HumanKey {
                alg: "ed25519".into(),
                public: "02".into(),
            },
        });
        let text = describe("demo", &Op::DaemonRecover { key, recover });
        assert!(
            text.contains(
                "HAND the repository to daemon key 0123456789abcdef and RECOVER ayse with the \
                 recovery key ("
            ),
            "{text}"
        );
        assert_eq!(short_key("abc"), "abc");
    }
}
