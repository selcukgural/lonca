//! Security events outside the operation log (issue #56).
//!
//! The operation log records every decided operation, denials included.
//! Much of what an attacker tries never reaches a decision: a refused peer, a
//! bad token, an oversized or malformed request, a request over its rate, a
//! hook refusal, an error while reconciling refs. Those land here, as one JSON
//! object per line in `<home>/security.log` (mode 0600), together with the
//! events a human should hear of at once: freezes and integrity alarms.
//!
//! An event carries what happened and to whom, never a token, a request body
//! or file contents: its fields are fixed, its free text is short, has no
//! control characters, and anything shaped like a Lonca token is masked. The
//! daemon writes events around decisions, never inside `decide()`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Past this size the log moves to `security.log.1` (replacing the one
/// there) and a new one starts: about twice this much is kept, and
/// [`KEEP_OF_KIND`] of every kind besides.
pub const ROTATE_BYTES: u64 = 8 << 20;

/// The latest events of each kind that stay however many of the other
/// kinds come after them. Some kinds any caller can cause as often as it
/// likes (a line that is no request, a bad token); they push out their own
/// kind and no other, so a freeze or a taint is not lost under them.
pub const KEEP_OF_KIND: usize = 256;

/// The longest free text of an event, in characters.
const MAX_DETAIL: usize = 300;

/// How long a notification command may run.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// What kind of thing happened. The names are the `kind` field.
pub mod kind {
    /// A connection from a uid the socket does not serve.
    pub const REFUSED_PEER: &str = "refused_peer";
    /// `unauthenticated` or `forbidden`.
    pub const AUTH_FAILURE: &str = "auth_failure";
    /// A line past its method's limit.
    pub const OVERSIZED: &str = "oversized_request";
    /// A line that is not a request.
    pub const MALFORMED: &str = "malformed_request";
    pub const RATE_LIMITED: &str = "rate_limited";
    /// An isolated session's token used outside its sandbox.
    pub const OUTSIDE_SANDBOX: &str = "outside_sandbox";
    /// A harness hook refused a tool call.
    pub const HOOK_DENIED: &str = "hook_denied";
    /// `reconcile()` failed for a repository.
    pub const RECONCILE_ERROR: &str = "reconcile_error";
    /// A ref changed behind the daemon's back (`import.unmediated`).
    pub const UNMEDIATED: &str = "unmediated_import";
    /// A repository froze.
    pub const FREEZE: &str = "freeze";
    /// The auditor asked for a freeze (`--freeze-flag`).
    pub const INTEGRITY_ALARM: &str = "integrity_alarm";
    /// A session was tainted by the daemon.
    pub const TAINT: &str = "taint";
    /// A bind whose hook reports sudo without a password.
    pub const SUDO_WITHOUT_PASSWORD: &str = "sudo_without_password";
    /// A session got a new token (`session.rotate`).
    pub const TOKEN_ROTATED: &str = "token_rotated";
    /// A call to `lonca mcp` came with no before-tool event: the session's
    /// hooks are not running (#190).
    pub const UNHOOKED: &str = "unhooked";
    /// A tunnel through the proxy whose TLS client asked the server for
    /// another name than the host it was let through for.
    pub const MISNAMED_TUNNEL: &str = "misnamed_tunnel";

    /// Every kind, for `docs/decisions.md` and the tests.
    pub const ALL: [&str; 16] = [
        REFUSED_PEER,
        AUTH_FAILURE,
        OVERSIZED,
        MALFORMED,
        RATE_LIMITED,
        OUTSIDE_SANDBOX,
        HOOK_DENIED,
        RECONCILE_ERROR,
        UNMEDIATED,
        FREEZE,
        INTEGRITY_ALARM,
        TAINT,
        SUDO_WITHOUT_PASSWORD,
        TOKEN_ROTATED,
        UNHOOKED,
        MISNAMED_TUNNEL,
    ];

    /// The kinds a human is told of as they happen.
    pub fn alarming(k: &str) -> bool {
        matches!(k, FREEZE | INTEGRITY_ALARM)
    }
}

/// One security event.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub time_ms: i64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The uid of the peer, where the socket told it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// The error code answered, where there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Short words on what happened: never a request, a token or content.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl Event {
    pub fn new(time_ms: i64, kind: &str) -> Self {
        Self {
            time_ms,
            kind: kind.into(),
            ..Self::default()
        }
    }

    pub fn repo(mut self, repo: &str) -> Self {
        self.repo = Some(clean(repo, 64));
        self
    }

    pub fn session(mut self, session: &str) -> Self {
        self.session = Some(clean(session, 64));
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = Some(clean(method, 64));
        self
    }

    pub fn uid(mut self, uid: Option<u32>) -> Self {
        self.uid = uid;
        self
    }

    pub fn code(mut self, code: &str) -> Self {
        self.code = Some(clean(code, 64));
        self
    }

    pub fn detail(mut self, detail: &str) -> Self {
        self.detail = clean(detail, MAX_DETAIL);
        self
    }
}

/// Text fit for an event: no control characters, at most `max`
/// characters, and every `lonca_…` token masked, in case a message ever
/// quotes one.
pub fn clean(text: &str, max: usize) -> String {
    let kept: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(max)
        .collect();
    mask_tokens(&kept)
}

fn mask_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("lonca_") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + "lonca_".len()..];
        let tail = tail.strip_prefix("h_").unwrap_or(tail);
        let hex = tail.bytes().take_while(u8::is_ascii_hexdigit).count();
        if hex >= 16 {
            out.push_str("lonca_[token]");
            rest = &tail[hex..];
        } else {
            out.push_str("lonca_");
            rest = &rest[at + "lonca_".len()..];
        }
    }
    out.push_str(rest);
    out
}

/// What happens when a human must hear of an event at once.
#[derive(Clone, Debug)]
pub enum Notify {
    /// Nothing: the event is in the log and `lonca status` shows a freeze.
    Off,
    /// The desktop's notification (macOS `osascript`, Linux `notify-send`),
    /// where there is one.
    Desktop,
    /// This program, given the event as one JSON line on its stdin (a
    /// webhook, a pager: outside the core).
    Command(PathBuf),
}

/// The security log of one daemon.
pub struct SecurityLog {
    path: PathBuf,
    rotate_bytes: u64,
    notify: Notify,
    write: Mutex<()>,
}

impl SecurityLog {
    pub fn new(home: &Path, notify: Notify) -> Self {
        Self {
            path: home.join("security.log"),
            rotate_bytes: ROTATE_BYTES,
            notify,
            write: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records `event`. Failing to write is said on stderr, the daemon's only
    /// other voice; it never stops the request that caused it.
    pub fn record(&self, event: Event) {
        let alarming = kind::alarming(&event.kind);
        if let Err(e) = self.append(&event) {
            eprintln!("lonca: security log {}: {e}", self.path.display());
        }
        if alarming {
            self.tell(&event);
        }
    }

    fn append(&self, event: &Event) -> std::io::Result<()> {
        let _held = self.write.lock().unwrap_or_else(|e| e.into_inner());
        if fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.rotate_bytes) {
            self.rotate()?;
        }
        let mut f = private(true).open(&self.path)?;
        let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
        line.push(b'\n');
        f.write_all(&line)
    }

    /// Moves the log to `security.log.1`. The file that was there is given
    /// up, but for the latest events of each kind that the two files would
    /// no longer hold [`KEEP_OF_KIND`] of: those go first in the new one.
    /// Called with the write lock held.
    fn rotate(&self) -> std::io::Result<()> {
        let older = self.path.with_extension("log.1");
        let full = fs::read(&self.path)?;
        let kind_of = |line: &str| {
            let kind = serde_json::from_str::<Event>(line).ok()?.kind;
            kind::ALL.iter().position(|k| *k == kind)
        };
        // How many of each kind are still wanted from the file given up.
        let mut wanted = [KEEP_OF_KIND; kind::ALL.len()];
        for k in String::from_utf8_lossy(&full).lines().filter_map(kind_of) {
            wanted[k] = wanted[k].saturating_sub(1);
        }
        let old = fs::read_to_string(&older).unwrap_or_default();
        let mut carried: Vec<&str> = Vec::new();
        for line in old.lines().rev() {
            if let Some(k) = kind_of(line)
                && wanted[k] > 0
            {
                wanted[k] -= 1;
                carried.push(line);
            }
        }
        // Written beside it and moved over it: a daemon that stops midway
        // leaves the old file or the new one. If it stops before the last
        // step, the events of the full file are in both until the next
        // rotation.
        let new = self.path.with_extension("log.1.new");
        let _ = fs::remove_file(&new);
        let mut f = private(false).open(&new)?;
        for line in carried.iter().rev() {
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.write_all(&full)?;
        drop(f);
        fs::rename(&new, &older)?;
        fs::remove_file(&self.path)
    }

    /// The events at `since_ms` or later, oldest first, from both files.
    pub fn read_since(&self, since_ms: i64) -> Vec<Event> {
        let _held = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for p in [self.path.with_extension("log.1"), self.path.clone()] {
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            let events = text
                .lines()
                .filter_map(|l| serde_json::from_str::<Event>(l).ok());
            out.extend(events.filter(|e| e.time_ms >= since_ms));
        }
        out
    }

    /// Tells a human, without waiting for it: a notification is best effort
    /// and runs on a thread of its own, killed after a few seconds.
    fn tell(&self, event: &Event) {
        let message = format!(
            "{}{}: {}",
            event.kind,
            event
                .repo
                .as_ref()
                .map(|r| format!(" in {r}"))
                .unwrap_or_default(),
            event.detail
        );
        let line = serde_json::to_string(event).unwrap_or_default();
        let notify = self.notify.clone();
        std::thread::spawn(move || {
            let child = match notify {
                Notify::Off => return,
                Notify::Desktop => desktop(&message),
                Notify::Command(p) => command(&p, &line),
            };
            if let Some(mut child) = child {
                let started = std::time::Instant::now();
                while started.elapsed() < NOTIFY_TIMEOUT {
                    if child.try_wait().ok().flatten().is_some() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
            }
        });
    }
}

/// How the log's files are opened: the daemon's alone, to add to (`true`)
/// or as a new file.
fn private(append: bool) -> fs::OpenOptions {
    let mut opts = fs::OpenOptions::new();
    if append {
        opts.create(true).append(true);
    } else {
        opts.create_new(true).write(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts
}

fn desktop(message: &str) -> Option<std::process::Child> {
    use std::process::{Command, Stdio};
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/osascript");
        // The text goes in as an argument, never into the script.
        c.args([
            "-e",
            "on run argv",
            "-e",
            "display notification (item 1 of argv) with title \"Lonca\"",
            "-e",
            "end run",
            message,
        ]);
        c
    } else {
        let mut c = Command::new("notify-send");
        c.args(["--app-name=Lonca", "Lonca", message]);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().ok()
}

fn command(program: &Path, line: &str) -> Option<std::process::Child> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{line}");
    }
    Some(child)
}

/// Counts of `events` by kind.
pub fn summary(events: &[Event]) -> std::collections::BTreeMap<String, usize> {
    let mut out = std::collections::BTreeMap::new();
    for e in events {
        *out.entry(e.kind.clone()).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_holds_no_token_and_no_control() {
        let token = format!("lonca_{}", "ab".repeat(32));
        let human = format!("lonca_h_{}", "cd".repeat(32));
        let said = clean(&format!("a {token} b {human}\x1b[2J\nc lonca_x"), 300);
        assert_eq!(said, "a lonca_[token] b lonca_[token] [2J c lonca_x");
        assert_eq!(clean("abcdef", 3), "abc");
    }

    #[test]
    fn events_go_to_a_private_file_that_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SecurityLog::new(dir.path(), Notify::Off);
        log.rotate_bytes = 200;
        for i in 0..10 {
            log.record(
                Event::new(i, kind::AUTH_FAILURE)
                    .method("status")
                    .code("unauthenticated"),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(log.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(dir.path().join("security.log.1").exists());
        let all = log.read_since(0);
        assert!(!all.is_empty() && all.len() <= 10);
        assert!(
            all.windows(2).all(|w| w[0].time_ms < w[1].time_ms),
            "oldest first"
        );
        assert_eq!(log.read_since(9).len(), 1);
        assert_eq!(summary(&all)[kind::AUTH_FAILURE], all.len());
    }

    #[test]
    fn a_flood_of_one_kind_pushes_out_no_other_kind() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SecurityLog::new(dir.path(), Notify::Off);
        log.rotate_bytes = 2000;
        log.record(Event::new(1, kind::FREEZE).repo("demo").detail("moved"));
        log.record(Event::new(2, kind::TAINT).session("s1"));
        // Many rotations' worth of what any caller can cause.
        let flood = 5000;
        for i in 0..flood {
            log.record(Event::new(10 + i, kind::MALFORMED).detail("not a request"));
        }
        log.record(Event::new(10 + flood, kind::TAINT).session("s2"));
        let all = log.read_since(0);
        let of = |k: &str| all.iter().filter(|e| e.kind == k).collect::<Vec<_>>();
        assert_eq!(of(kind::FREEZE).len(), 1, "the freeze is still there");
        assert_eq!(of(kind::FREEZE)[0].repo.as_deref(), Some("demo"));
        let taints: Vec<_> = of(kind::TAINT).iter().map(|e| e.time_ms).collect();
        assert_eq!(taints, [2, 10 + flood]);
        // The flood keeps its latest, and no more than its share and what
        // two files of this size hold.
        let noise = of(kind::MALFORMED);
        assert_eq!(noise.last().unwrap().time_ms, 9 + flood);
        assert!(noise.len() >= KEEP_OF_KIND, "{}", noise.len());
        assert!(
            noise.len() <= KEEP_OF_KIND + 2 * 2000 / 50,
            "{}",
            noise.len()
        );
        assert!(
            all.windows(2).all(|w| w[0].time_ms < w[1].time_ms),
            "oldest first, each once"
        );
        // Both files are the daemon's alone, and nothing else is left.
        #[cfg(unix)]
        for name in ["security.log", "security.log.1"] {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(name)).unwrap().permissions();
            assert_eq!(mode.mode() & 0o777, 0o600, "{name}");
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn a_kind_keeps_its_latest_and_a_line_that_is_no_event_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SecurityLog::new(dir.path(), Notify::Off);
        log.rotate_bytes = 400;
        // More of one kind than is kept, then a flood of another.
        let many = KEEP_OF_KIND as i64 + 40;
        for i in 0..many {
            log.record(Event::new(i, kind::HOOK_DENIED));
        }
        fs::write(
            dir.path().join("security.log.1"),
            "not an event\n{\"time_ms\":0,\"kind\":\"made_up\"}\n",
        )
        .unwrap();
        for i in 0..2000 {
            log.record(Event::new(many + i, kind::AUTH_FAILURE));
        }
        let all = log.read_since(0);
        let denied: Vec<_> = all.iter().filter(|e| e.kind == kind::HOOK_DENIED).collect();
        assert!(denied.len() <= KEEP_OF_KIND, "{}", denied.len());
        assert_eq!(denied.last().unwrap().time_ms, many - 1, "the latest");
        assert!(all.iter().all(|e| e.kind != "made_up"));
        let text = fs::read_to_string(dir.path().join("security.log.1")).unwrap();
        assert!(!text.contains("not an event"), "{text}");
    }

    #[test]
    fn an_alarm_runs_the_notify_command_with_the_event() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("told");
        let script = dir.path().join("notify.sh");
        fs::write(&script, format!("#!/bin/sh\ncat > {}\n", out.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let log = SecurityLog::new(dir.path(), Notify::Command(script));
        log.record(Event::new(1, kind::AUTH_FAILURE));
        log.record(
            Event::new(2, kind::FREEZE)
                .repo("demo")
                .detail("refs/heads/main moved"),
        );
        let mut told = String::new();
        for _ in 0..200 {
            told = fs::read_to_string(&out).unwrap_or_default();
            if told.ends_with('\n') {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let event: Event = serde_json::from_str(told.trim()).unwrap();
        assert_eq!(event.kind, kind::FREEZE);
        assert_eq!(event.repo.as_deref(), Some("demo"));
    }
}
