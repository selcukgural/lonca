//! What one client can not do to the others: the socket's limits, the
//! session rate, and what `log` and `queue.run` cost.

mod common;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering as Ord;
use std::time::{Duration, Instant};

use common::*;
use lonca_daemon::Client;
use lonca_daemon::limits::{Limits, SHORT_LINE, open_files};
use lonca_daemon::protocol::Response;
use lonca_daemon::server::{Access, bind, serve_with};
use lonca_daemon::trust::Trust;

const SOON: Duration = Duration::from_millis(150);

fn served_with(e: &Env, access: Access, limits: Limits) -> PathBuf {
    let sock = e.root.join("s");
    let listener = bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || serve_with(listener, svc, access, limits));
    sock
}

fn served(e: &Env, limits: Limits) -> PathBuf {
    served_with(e, Access::default(), limits)
}

/// A connection that sends what the test says, when it says.
struct Raw(BufReader<UnixStream>);

impl Raw {
    fn open(sock: &Path) -> Self {
        let s = UnixStream::connect(sock).unwrap();
        // Refused on macOS if the daemon has closed it already.
        let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
        Self(BufReader::new(s))
    }

    fn send(&mut self, bytes: &[u8]) {
        let mut s: &UnixStream = self.0.get_ref();
        s.write_all(bytes).unwrap();
    }

    fn answer(&mut self) -> Response {
        let mut line = String::new();
        self.0.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
    }

    fn code(&mut self) -> String {
        self.answer().error.unwrap().code
    }

    fn closed(&mut self) -> bool {
        matches!(self.0.read_line(&mut String::new()), Ok(0))
    }

    /// Asks the daemon how it is.
    fn refused(&mut self) -> Value {
        self.send(b"{\"id\":1,\"method\":\"ping\"}\n");
        self.answer().result["refused"].clone()
    }
}

/// A line of exactly `len` bytes.
fn line_of(method: &str, id: u64, auth: &str, len: usize) -> Vec<u8> {
    let head = format!(r#"{{"id":{id},"method":"{method}",{auth}"params":{{"p":""#);
    let tail = "\"}}\n";
    let mut out = head.into_bytes();
    out.resize(len + 1 - tail.len(), b'x');
    out.extend_from_slice(tail.as_bytes());
    assert_eq!(out.len(), len + 1);
    out
}

fn human_auth(e: &mut Env) -> String {
    let token = e.login().unwrap();
    format!(r#""repo":"demo","token":"{token}","#)
}

// ---------------------------------------------------------------- connections

#[test]
fn a_thousand_idle_connections_do_not_stop_a_ping() {
    let e = Env::new();
    let limits = Limits::for_files(open_files());
    let sock = served(&e, limits.clone());
    let mut idle = Vec::new();
    for _ in 0..1000 {
        let open = || UnixStream::connect(&sock);
        let conn = open().or_else(|_| {
            // The backlog is short and this loop is fast.
            std::thread::sleep(Duration::from_millis(50));
            open()
        });
        idle.push(conn.unwrap());
    }
    let mut c = Client::connect(&sock).unwrap();
    let r = c.call("ping", json!({})).unwrap();
    assert_eq!(r["protocol"], 1);
    assert!(limits.per_uid < 1000, "the cap is what this test is about");
    assert!(r["refused"]["evicted"].as_u64().unwrap() > 0, "{r}");
    assert_eq!(r["refused"]["busy"], 0, "{r}");
}

#[test]
fn a_connection_that_is_cut_for_a_new_one_is_told_to_send_again() {
    let e = Env::new();
    let limits = Limits {
        connections: 1,
        per_uid: 1,
        ..Limits::default()
    };
    let sock = served(&e, limits);
    let mut quiet = Raw::open(&sock);
    quiet.refused();
    let mut next = Raw::open(&sock);
    assert_eq!(next.refused()["evicted"], 1);
    let told = quiet.answer();
    assert_eq!((told.id, told.error.unwrap().code.as_str()), (0, "closed"));
    assert!(quiet.closed());
}

#[test]
fn with_every_connection_at_work_a_new_one_is_refused() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(
        &e,
        Limits {
            connections: 1,
            per_uid: 1,
            ..Limits::default()
        },
    );
    let mut working = Raw::open(&sock);
    let held = r#""params":{"from":1000,"wait_ms":1500}}"#;
    working.send(format!("{{\"id\":5,\"method\":\"log\",{auth}{held}\n").as_bytes());
    std::thread::sleep(Duration::from_millis(300));
    let mut late = Raw::open(&sock);
    assert_eq!(late.code(), "busy");
    assert!(late.closed());
    assert_eq!(e.svc.counters.busy.load(Ord::Relaxed), 1);
    assert_eq!(working.answer().id, 5, "the request held was not cut");
}

/// A runner's `events.watch` is a connection at work like any other: it
/// counts against the limits while it waits, and is answered at its end.
#[test]
fn a_waiting_watch_holds_its_place_and_no_more() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(
        &e,
        Limits {
            connections: 2,
            per_uid: 2,
            ..Limits::default()
        },
    );
    let held = r#""params":{"wait_ms":1500}}"#;
    let mut first = Raw::open(&sock);
    first.send(format!("{{\"id\":5,\"method\":\"events.watch\",{auth}{held}\n").as_bytes());
    let mut second = Raw::open(&sock);
    second.send(format!("{{\"id\":6,\"method\":\"events.watch\",{auth}{held}\n").as_bytes());
    std::thread::sleep(Duration::from_millis(300));
    let mut late = Raw::open(&sock);
    assert_eq!(late.code(), "busy");
    assert!(late.closed());
    for (mut w, id) in [(first, 5), (second, 6)] {
        let a = w.answer();
        assert_eq!(a.id, id, "the watch held was not cut");
        assert!(a.ok, "{:?}", a.error);
        assert_eq!(a.result["events"], json!([]));
    }
}

#[test]
fn a_uid_that_is_not_listed_gets_nothing() {
    let e = Env::new();
    let nobody = Access {
        allowed_uids: Some(vec![]),
        ..Access::default()
    };
    let sock = served_with(&e, nobody, Limits::default());
    let mut c = Raw::open(&sock);
    assert!(c.closed());
}

#[test]
fn a_listed_uid_is_served() {
    let e = Env::new();
    let me = lonca_daemon::sys::current_uid();
    let listed = Access {
        allowed_uids: Some(vec![me]),
        ..Access::default()
    };
    let sock = served_with(&e, listed, Limits::default());
    Raw::open(&sock).refused();
}

// ---------------------------------------------------------------- time

#[test]
fn a_client_that_says_nothing_is_closed_and_told_to_send_again() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            idle: SOON,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    let told = c.answer();
    assert_eq!((told.id, told.error.unwrap().code.as_str()), (0, "closed"));
    assert!(c.closed());
    let refused = Raw::open(&sock).refused();
    assert_eq!(refused["idle"], 1, "{refused}");
    assert_eq!(refused["slow"], 0, "{refused}");
}

#[test]
fn a_slow_loris_is_dropped_after_the_timeout() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            line: Duration::from_millis(400),
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    let started = Instant::now();
    let dripping = c.0.get_ref().try_clone().unwrap();
    std::thread::spawn(move || {
        // A byte at a time: each one in time, the line never.
        let mut s = &dripping;
        while s.write_all(b"x").is_ok() {
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    assert_eq!(c.code(), "timeout");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(started.elapsed() >= Duration::from_millis(400));
    let refused = Raw::open(&sock).refused();
    assert_eq!(refused["slow"], 1, "{refused}");
    assert_eq!(refused["idle"], 0, "{refused}");
}

#[test]
fn half_a_line_and_then_nothing_is_dropped_as_well() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            line: SOON,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.send(b"{\"id\":1,");
    assert_eq!(c.code(), "timeout");
    assert!(c.closed());
}

#[test]
fn time_between_requests_is_not_time_for_a_line() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            line: SOON,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.refused();
    std::thread::sleep(SOON * 3);
    c.refused();
}

#[test]
fn a_client_sends_again_on_a_new_connection_when_closed_for_quiet() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            idle: SOON,
            ..Limits::default()
        },
    );
    let mut c = Client::connect(&sock).unwrap();
    c.call("ping", json!({})).unwrap();
    std::thread::sleep(SOON * 3);
    let r = c.call("ping", json!({})).unwrap();
    assert_eq!(r["refused"]["idle"], 1, "{r}");
}

/// A daemon that answers each connection with what it is told, once.
fn scripted(sock: &Path, answers: &[&str]) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(sock).unwrap();
    let answers: Vec<String> = answers.iter().map(|a| a.to_string()).collect();
    std::thread::spawn(move || {
        for (a, conn) in answers.iter().zip(listener.incoming()) {
            let mut s = conn.unwrap();
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line).unwrap();
            writeln!(s, "{a}").unwrap();
        }
    })
}

const CLOSED: &str = r#"{"id":0,"ok":false,"error":{"code":"closed","message":"m"}}"#;

fn client_of(sock: &Path) -> Client {
    Client::connect_to(sock, &Trust::cooperative()).unwrap()
}

#[test]
fn a_request_that_was_written_but_not_read_goes_again() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let d = scripted(&sock, &[CLOSED, r#"{"id":1,"ok":true,"result":7}"#]);
    assert_eq!(client_of(&sock).call("ping", json!({})).unwrap(), 7);
    d.join().unwrap();
}

#[test]
fn a_second_close_is_the_callers() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let d = scripted(&sock, &[CLOSED, CLOSED]);
    let e = client_of(&sock).call("ping", json!({})).unwrap_err();
    assert_eq!(e.0.code, "closed");
    d.join().unwrap();
}

#[test]
fn only_the_daemons_closing_line_goes_again() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    // Another code on id 0, and the code on a request's own id: both are
    // answers, and a request that may have run is not sent twice. A client
    // for each: the server closes after each answer, and a request sent as
    // that happens can end either way.
    let d = scripted(
        &sock,
        &[
            r#"{"id":0,"ok":false,"error":{"code":"invalid","message":"m"}}"#,
            r#"{"id":1,"ok":false,"error":{"code":"closed","message":"m"}}"#,
        ],
    );
    let code = || client_of(&sock).call("ping", json!({})).unwrap_err().0.code;
    assert_eq!(code(), "invalid");
    assert_eq!(code(), "closed");
    d.join().unwrap();
}

#[test]
fn a_connection_that_ends_without_a_word_is_not_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s");
    let listener = UnixListener::bind(&sock).unwrap();
    let d = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        BufReader::new(&s).read_line(&mut String::new()).unwrap();
        drop(s);
        listener
    });
    let e = client_of(&sock).call("ping", json!({})).unwrap_err();
    assert_eq!(e.0.code, "io");
    assert_eq!(e.0.message, "daemon closed the connection");
    d.join().unwrap();
}

// ---------------------------------------------------------------- line length

#[test]
fn a_megabyte_of_status_is_refused_and_the_connection_goes_on() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    c.send(&line_of("status", 9, &auth, 1024 * 1024));
    let r = c.answer();
    assert_eq!((r.id, r.error.unwrap().code.as_str()), (9, "too_large"));
    assert_eq!(c.refused()["too_large"], 1);
}

#[test]
fn a_short_line_ends_at_its_limit() {
    let e = Env::new();
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    assert_eq!(SHORT_LINE, 65536, "docs/protocol.md says 64 KiB");
    c.send(&line_of("ping", 2, "", SHORT_LINE));
    assert!(c.answer().ok, "exactly the limit");
    c.send(&line_of("ping", 3, "", SHORT_LINE + 1));
    assert_eq!(c.code(), "too_large", "a byte past it");
}

#[test]
fn a_line_is_measured_in_a_chunk_with_its_newline_too() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            short_line: 100,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.send(&line_of("ping", 2, "", 101));
    assert_eq!(c.code(), "too_large");
}

#[test]
fn a_long_line_of_a_method_that_may_send_one_goes_through() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let commit = e.trunk();
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    let paths: Vec<String> = (0..SHORT_LINE / 4).map(|i| format!("{i}")).collect();
    let params = json!({"commit": commit, "paths": paths}).to_string();
    let line = format!("{{\"id\":4,\"method\":\"tree\",{auth}\"params\":{params}}}\n");
    assert!(line.len() > SHORT_LINE);
    c.send(line.as_bytes());
    let r = c.answer();
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(r.id, 4);
}

#[test]
fn a_long_line_needs_its_method_and_a_live_token_first() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    let long = SHORT_LINE * 2;
    c.send(&line_of("tree", 2, "", long));
    assert_eq!(c.code(), "too_large", "no token before the params");
    c.send(&line_of(
        "tree",
        3,
        r#""repo":"demo","token":"lonca_h_no","#,
        long,
    ));
    assert_eq!(c.code(), "unauthenticated");
    c.send(&line_of("no.such", 4, &auth, long));
    assert_eq!(c.code(), "too_large");
    // A token of the wrong kind for the method.
    c.send(&line_of("change.propose", 5, &auth, long));
    assert_eq!(c.code(), "forbidden");
    let mut first = br#"{"params":{"p":""#.to_vec();
    first.resize(long, b'x');
    first.extend_from_slice(b"\"},\"id\":6,\"method\":\"tree\"}\n");
    c.send(&first);
    assert_eq!(c.code(), "too_large", "the params came first");
}

/// Asked of the method's own credential: a line that passed would be
/// `too_large` here.
#[test]
fn a_long_line_is_held_to_its_own_method() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let limits = Limits {
        short_line: 512,
        long_line: 1024,
        ..Limits::default()
    };
    let sock = served(&e, limits);
    let mut c = Raw::open(&sock);
    c.send(&line_of("change.propose", 2, &auth, 2048));
    assert_eq!(c.code(), "forbidden");
}

#[test]
fn a_long_line_ends_at_its_limit() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(
        &e,
        Limits {
            short_line: 1024,
            long_line: 4096,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.send(&line_of("tree", 2, &auth, 4096));
    assert_eq!(c.code(), "invalid", "exactly the limit reaches the method");
    c.send(&line_of("tree", 3, &auth, 4097));
    assert_eq!(c.code(), "too_large");
}

#[test]
fn long_lines_at_once_can_not_hold_more_than_the_budget() {
    let mut e = Env::new();
    e.init(None);
    let auth = human_auth(&mut e);
    let sock = served(
        &e,
        Limits {
            short_line: 1024,
            buffered: 2048,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.send(&line_of("tree", 2, &auth, 4096));
    assert_eq!(c.code(), "busy");
    assert_eq!(c.refused()["busy"], 1);
    c.send(&line_of("tree", 3, &auth, 2000));
    assert_eq!(c.code(), "invalid", "the budget was given back");
}

#[test]
fn a_line_refused_for_its_method_costs_the_budget_nothing() {
    let e = Env::new();
    let sock = served(
        &e,
        Limits {
            short_line: 1024,
            buffered: 512,
            ..Limits::default()
        },
    );
    let mut c = Raw::open(&sock);
    c.send(&line_of("ping", 2, "", 2048));
    assert_eq!(c.code(), "too_large");
    assert_eq!(c.refused()["busy"], 0);
}

#[test]
fn a_blank_line_is_no_request() {
    let e = Env::new();
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    c.send(b"\n  \n{\"id\":8,\"method\":\"ping\"}\n");
    assert_eq!(c.answer().id, 8);
}

#[test]
fn a_last_line_with_no_newline_is_still_a_line() {
    let e = Env::new();
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    c.send(b"{\"id\":8,\"method\":\"ping\"}");
    c.0.get_ref().shutdown(Shutdown::Write).unwrap();
    assert_eq!(c.answer().id, 8);
    assert!(c.closed());
}

#[test]
fn a_last_line_too_long_is_refused_at_the_end_of_the_stream() {
    let e = Env::new();
    let sock = served(&e, Limits::default());
    let mut c = Raw::open(&sock);
    let mut long = line_of("ping", 8, "", SHORT_LINE * 2);
    long.pop();
    c.send(&long);
    c.0.get_ref().shutdown(Shutdown::Write).unwrap();
    assert_eq!(c.code(), "too_large");
    assert!(c.closed());
}

#[test]
fn every_long_method_exists_and_takes_a_token() {
    use lonca_daemon::service::{Cred, LONG_LINES, METHODS};
    for m in LONG_LINES {
        let (_, cred) = METHODS.iter().find(|(name, _)| name == m).unwrap();
        assert!(
            !matches!(cred, Cred::Public | Cred::Login | Cred::Bootstrap),
            "{m}"
        );
    }
}

// ---------------------------------------------------------------- session rate

fn with_rate(e: &mut Env, rate: u32) {
    let policy = lonca_policy::config::DEFAULT_POLICY;
    let config = format!("[sessions]\nops_per_minute = {rate}\n");
    let p = json!({"config": config, "policy": policy});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
}

fn next_seq(e: &mut Env) -> u64 {
    let s = e.ok("status", Some("demo"), None, json!({}));
    s["next_seq"].as_u64().unwrap()
}

/// A refused request left no trace: the log audits as it would without it.
fn assert_audits(e: &Env) {
    let audit = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(audit.ok(), "{:#?}", audit.findings);
}

fn beat(e: &mut Env, token: &str) -> Result<Value, (String, String)> {
    e.call("session.heartbeat", None, Some(token), json!({}))
}

#[test]
fn a_session_over_its_rate_is_refused_and_the_log_does_not_grow() {
    let mut e = Env::new();
    e.init(None);
    with_rate(&mut e, 3);
    let t = e.session("s1", &["src/**"]);
    for _ in 0..3 {
        beat(&mut e, &t).unwrap();
    }
    let seq = next_seq(&mut e);
    let (code, msg) = beat(&mut e, &t).unwrap_err();
    assert_eq!(code, "rate_limited");
    assert!(msg.contains("ms"), "{msg}");
    assert_eq!(next_seq(&mut e), seq);
    let ping = e.ok("ping", None, None, json!({}));
    assert_eq!(ping["refused"]["rate_limited"], 1);
    e.advance(20_000);
    beat(&mut e, &t).unwrap();
    assert_eq!(next_seq(&mut e), seq + 1);
    assert_audits(&e);
}

#[test]
fn what_writes_nothing_and_the_end_of_a_session_are_not_refused() {
    let mut e = Env::new();
    e.init(None);
    with_rate(&mut e, 1);
    let t = e.session("s1", &["src/**"]);
    beat(&mut e, &t).unwrap();
    assert_eq!(beat(&mut e, &t).unwrap_err().0, "rate_limited");
    e.ok("events", None, Some(&t), json!({"from": 0}));
    e.ok("inbox", None, Some(&t), json!({}));
    e.ok("harness.setup", None, Some(&t), json!({"harness": "x"}));
    let base = e.trunk();
    let p = json!({"base": base, "files": []});
    let (code, _) = e.call("facts.preview", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid", "it reached the method");
    e.ok("session.end", None, Some(&t), json!({}));
    assert_audits(&e);
}

#[test]
fn a_session_and_those_made_from_it_share_their_rate() {
    let mut e = Env::new();
    e.init(None);
    with_rate(&mut e, 2);
    let parent = e.session("s1", &["src/**"]);
    let scope = json!({"paths": ["src/**"], "ops": ["lease.acquire"]});
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&parent),
        json!({"agent": "kid", "scope": scope, "expires_ms": e.now() + 60_000}),
    );
    let child = child["token"].as_str().unwrap().to_string();
    beat(&mut e, &child).unwrap();
    assert_eq!(beat(&mut e, &child).unwrap_err().0, "rate_limited");
    assert_eq!(beat(&mut e, &parent).unwrap_err().0, "rate_limited");
    assert_audits(&e);
}

#[test]
fn another_session_keeps_its_own_rate() {
    let mut e = Env::new();
    e.init(None);
    with_rate(&mut e, 1);
    let a = e.session("s1", &["src/**"]);
    let b = e.session("s2", &["src/**"]);
    beat(&mut e, &a).unwrap();
    assert_eq!(beat(&mut e, &a).unwrap_err().0, "rate_limited");
    beat(&mut e, &b).unwrap();
    assert_audits(&e);
}

// ---------------------------------------------------------------- log, queue

#[test]
fn log_answers_from_where_it_is_asked_and_as_many_as_asked() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    for _ in 0..4 {
        beat(&mut e, &t).unwrap();
    }
    let seqs = |v: Value| -> Vec<u64> {
        let all = v.as_array().unwrap();
        all.iter()
            .map(|o| o["entry"]["seq"].as_u64().unwrap())
            .collect()
    };
    let p = json!({"from": 1, "limit": 2});
    assert_eq!(seqs(e.ok("log", Some("demo"), None, p)), [1, 2]);
    let n = next_seq(&mut e);
    let p = json!({"from": n - 1, "limit": 5});
    assert_eq!(seqs(e.ok("log", Some("demo"), None, p)), [n - 1]);
    let p = json!({"from": n});
    assert_eq!(e.ok("log", Some("demo"), None, p), json!([]));
}

#[test]
fn queue_run_merges_nothing_on_the_callers_thread() {
    let mut e = Env::new();
    e.init(None);
    let r = e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let woken = e.ok("queue.run", None, None, json!({}));
    assert_eq!(woken, json!({"integrated": 0, "woken": true}));
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["queue"].as_array().unwrap().len(), 1, "{s}");
    assert_eq!(e.svc.process_all(), 1);
}
