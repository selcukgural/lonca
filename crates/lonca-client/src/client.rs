//! Client for the daemon socket.

use std::io::BufReader;
use std::io::ErrorKind::{BrokenPipe, ConnectionReset, TimedOut, UnexpectedEof, WouldBlock};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::protocol::{ErrorBody, MAX_LINE, Response, read_line_limited, write_line};
use crate::trust::Trust;

pub struct Client {
    socket: PathBuf,
    trust: Trust,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next: u64,
    timeout: Option<Duration>,
    /// The last exchange did not finish: what is still on the connection
    /// could be the answer to it, so the next call opens a new one.
    broken: bool,
    pub token: Option<String>,
    pub repo: Option<String>,
}

/// An error code of the daemon (`docs/protocol.md`, "Error codes"), or of
/// this client: `io` (the connection failed) and `timed_out` (no answer
/// within [`Client::set_timeout`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    Invalid,
    Unauthenticated,
    Forbidden,
    NotInSandbox,
    SessionInactive,
    UnknownMethod,
    NotFound,
    TooLarge,
    RateLimited,
    /// The stores' disk is below what it keeps free: the request's files
    /// were not written. Not transient; a human frees space.
    DiskSpace,
    Busy,
    Verifying,
    Closed,
    /// The daemon's: the request line took too long to arrive.
    Timeout,
    Conflict,
    Denied,
    ForeignKey,
    UpToDate,
    NotFastForward,
    Git,
    Integrity,
    Unsupported,
    Internal,
    /// The client's: the connection failed, or the answer was not one.
    Io,
    /// The client's: no answer within the timeout. The request may have
    /// run; the connection is dropped and the next call opens another.
    TimedOut,
    /// A code this version does not know.
    Other,
}

impl ErrorKind {
    pub fn of(code: &str) -> Self {
        use ErrorKind::*;
        match code {
            "invalid" => Invalid,
            "unauthenticated" => Unauthenticated,
            "forbidden" => Forbidden,
            "not_in_sandbox" => NotInSandbox,
            "session_inactive" => SessionInactive,
            "unknown_method" => UnknownMethod,
            "not_found" => NotFound,
            "too_large" => TooLarge,
            "rate_limited" => RateLimited,
            "disk_space" => DiskSpace,
            "busy" => Busy,
            "verifying" => Verifying,
            "closed" => Closed,
            "timeout" => Timeout,
            "conflict" => Conflict,
            "denied" => Denied,
            "foreign_key" => ForeignKey,
            "up_to_date" => UpToDate,
            "not_fast_forward" => NotFastForward,
            "git" => Git,
            "integrity" => Integrity,
            "unsupported" => Unsupported,
            "internal" => Internal,
            CODE_IO => Io,
            CODE_TIMED_OUT => TimedOut,
            _ => Other,
        }
    }

    /// Nothing of the request ran, and the same request may be sent again:
    /// `rate_limited` (after the wait its message names), `busy` and
    /// `closed` (on a new connection). Everything else is an answer.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            ErrorKind::RateLimited | ErrorKind::Busy | ErrorKind::Closed
        )
    }
}

const CODE_IO: &str = "io";
const CODE_TIMED_OUT: &str = "timed_out";

#[derive(Debug)]
pub struct CallError(pub ErrorBody);

impl CallError {
    pub fn code(&self) -> &str {
        &self.0.code
    }

    pub fn kind(&self) -> ErrorKind {
        ErrorKind::of(&self.0.code)
    }

    /// See [`ErrorKind::is_transient`].
    pub fn is_transient(&self) -> bool {
        self.kind().is_transient()
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0.code, self.0.message)
    }
}

impl std::error::Error for CallError {}

/// How a request and its answer did not go through.
enum Exchange {
    Write(std::io::Error),
    Read(std::io::Error),
    /// An answer with the id of another request.
    Stray(u64),
}

impl From<Exchange> for CallError {
    fn from(e: Exchange) -> Self {
        match e {
            Exchange::Write(e) | Exchange::Read(e) if matches!(e.kind(), WouldBlock | TimedOut) => {
                error(CODE_TIMED_OUT, "no answer within the client's timeout")
            }
            Exchange::Write(e) | Exchange::Read(e) if e.kind() == UnexpectedEof => {
                gone("daemon closed the connection")
            }
            Exchange::Write(e) | Exchange::Read(e) => io(e),
            Exchange::Stray(id) => gone(&format!("an answer to request {id}, not this one")),
        }
    }
}

fn error(code: &str, message: &str) -> CallError {
    CallError(ErrorBody {
        code: code.into(),
        message: message.into(),
    })
}

fn gone(message: &str) -> CallError {
    error(CODE_IO, message)
}

fn io(e: std::io::Error) -> CallError {
    gone(&e.to_string())
}

/// The daemon had closed the connection before the request got there.
fn not_sent(e: &Exchange) -> bool {
    matches!(e, Exchange::Write(e) if matches!(e.kind(), BrokenPipe | ConnectionReset))
}

/// The daemon's last line on a connection it closed: id 0, which no request
/// of this client has.
fn not_read(r: &Response) -> bool {
    r.id == 0 && r.error.as_ref().is_some_and(|e| e.code == "closed")
}

/// A [`crate::protocol::Request`] as it is written: the same fields in the
/// same order, with the parameters where the caller has them.
#[derive(Serialize)]
struct Sent<'a, P: Serialize + ?Sized> {
    id: u64,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    params: &'a P,
}

impl Client {
    /// Connects to the daemon this machine trusts. There is no way to get
    /// a client without the check: a token goes nowhere unverified.
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        Self::connect_to(path, &Trust::load()?)
    }

    pub fn connect_to(path: &Path, trust: &Trust) -> std::io::Result<Self> {
        trust.check_socket(path)?;
        let s = UnixStream::connect(path)?;
        trust.check_peer(&s)?;
        Ok(Self {
            socket: path.to_path_buf(),
            trust: *trust,
            reader: BufReader::new(s.try_clone()?),
            writer: s,
            next: 1,
            timeout: None,
            broken: false,
            token: None,
            repo: None,
        })
    }

    /// How long a request may take to be sent and answered; `None` (the
    /// default) waits as long as the daemon does. Mind `log`'s `wait_ms`.
    /// Past it the call fails with `timed_out` and the connection is
    /// dropped: the request may have run.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> std::io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a timeout of zero",
            ));
        }
        self.timeout = timeout;
        self.writer.set_read_timeout(timeout)?;
        self.writer.set_write_timeout(timeout)
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        self.call_with(method, &params)
    }

    /// [`Client::call`] with parameters that are written to the line from
    /// where they are: a change's files are not copied into a `Value`
    /// first. The line is the one `call` writes for the same JSON.
    pub fn call_with<P: Serialize + ?Sized>(
        &mut self,
        method: &str,
        params: &P,
    ) -> Result<Value, CallError> {
        if self.broken {
            self.reconnect()?;
        }
        let id = self.next;
        self.next += 1;
        let repo = self.repo.clone();
        let token = self.token.clone();
        let req = Sent {
            id,
            method,
            repo: repo.as_deref(),
            token: token.as_deref(),
            params,
        };
        let resp = match self.exchange(&req) {
            Err(e) if not_sent(&e) => self.again(&req),
            Ok(r) if not_read(&r) => self.again(&req),
            done => done.map_err(CallError::from),
        };
        let resp = resp.inspect_err(|_| self.broken = true)?;
        if resp.ok {
            Ok(resp.result)
        } else {
            Err(CallError(resp.error.unwrap_or(ErrorBody {
                code: "unknown".into(),
                message: String::new(),
            })))
        }
    }

    fn reconnect(&mut self) -> Result<(), CallError> {
        let mut fresh = Self::connect_to(&self.socket, &self.trust).map_err(io)?;
        fresh.set_timeout(self.timeout).map_err(io)?;
        self.reader = fresh.reader;
        self.writer = fresh.writer;
        self.broken = false;
        Ok(())
    }

    /// The daemon closed this connection for being quiet and never saw the
    /// request, so it is safe to send on a new one, once.
    fn again<P: Serialize + ?Sized>(&mut self, req: &Sent<P>) -> Result<Response, CallError> {
        self.reconnect()?;
        Ok(self.exchange(req)?)
    }

    fn exchange<P: Serialize + ?Sized>(&mut self, req: &Sent<P>) -> Result<Response, Exchange> {
        write_line(&mut self.writer, req).map_err(Exchange::Write)?;
        let line = read_line_limited(&mut self.reader, MAX_LINE)
            .map_err(Exchange::Read)?
            .ok_or_else(|| Exchange::Read(UnexpectedEof.into()))?;
        let resp: Response = serde_json::from_str(&line).map_err(|e| Exchange::Read(e.into()))?;
        // Id 0 is the daemon's word on the connection, not on a request.
        if resp.id != req.id && resp.id != 0 {
            return Err(Exchange::Stray(resp.id));
        }
        Ok(resp)
    }

    pub fn call_as<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, CallError> {
        let v = self.call(method, params)?;
        serde_json::from_value(v).map_err(|e| gone(&format!("bad result: {e}")))
    }

    /// `events.watch` with the human session this client carries: what
    /// happened to its agents' sessions, held up to `watch.wait_ms` while
    /// nothing did. Go on with `watch.after(&answer)`. A client timeout
    /// ([`Client::set_timeout`]) must be longer than the wait.
    pub fn watch(
        &mut self,
        watch: &crate::protocol::Watch,
    ) -> Result<crate::protocol::Watched, CallError> {
        let params = serde_json::to_value(watch).map_err(|e| gone(&format!("bad watch: {e}")))?;
        self.call_as("events.watch", params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Request, write_line};
    use std::io::BufRead;
    use std::os::unix::net::UnixListener;

    /// What `call_with` writes is the line of a [`Request`], byte for byte,
    /// with and without a repository and a token.
    #[test]
    fn a_borrowed_request_is_written_as_an_owned_one() {
        let params =
            serde_json::json!({"files": [{"path": "a", "content_b64": "eA=="}], "base": "b"});
        for (repo, token) in [
            (None, None),
            (Some("demo"), None),
            (Some("demo"), Some("t")),
        ] {
            let owned = Request {
                id: 7,
                method: "change.propose".into(),
                repo: repo.map(String::from),
                token: token.map(String::from),
                params: params.clone(),
            };
            let sent = Sent {
                id: 7,
                method: "change.propose",
                repo,
                token,
                params: &params,
            };
            let (mut a, mut b) = (Vec::new(), Vec::new());
            write_line(&mut a, &owned).unwrap();
            write_line(&mut b, &sent).unwrap();
            assert_eq!(a, b);
        }
    }

    /// A daemon of one connection at a time: `answer` gets each request
    /// line and says what to send back (nothing: stay quiet).
    fn fake(
        answer: impl Fn(usize, &Request) -> Option<Value> + Send + Sync + 'static,
    ) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::Builder::new().prefix("lc").tempdir().unwrap();
        let sock = dir.path().join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        let answer = std::sync::Arc::new(answer);
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { return };
                let (answer, count) = (answer.clone(), count.clone());
                std::thread::spawn(move || {
                    let mut reader = std::io::BufReader::new(conn.try_clone().unwrap());
                    let mut w = conn;
                    let mut line = String::new();
                    while reader.read_line(&mut line).unwrap_or(0) > 0 {
                        let req: Request = serde_json::from_str(&line).unwrap();
                        line.clear();
                        let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        if let Some(v) = answer(n, &req) {
                            let _ = write_line(&mut w, &v);
                        }
                    }
                });
            }
        });
        (dir, sock)
    }

    fn client(sock: &Path) -> Client {
        Client::connect_to(sock, &Trust::cooperative()).unwrap()
    }

    #[test]
    fn every_code_of_the_table_has_its_kind() {
        let codes = [
            ("invalid", ErrorKind::Invalid),
            ("unauthenticated", ErrorKind::Unauthenticated),
            ("forbidden", ErrorKind::Forbidden),
            ("not_in_sandbox", ErrorKind::NotInSandbox),
            ("session_inactive", ErrorKind::SessionInactive),
            ("unknown_method", ErrorKind::UnknownMethod),
            ("not_found", ErrorKind::NotFound),
            ("too_large", ErrorKind::TooLarge),
            ("rate_limited", ErrorKind::RateLimited),
            ("disk_space", ErrorKind::DiskSpace),
            ("busy", ErrorKind::Busy),
            ("verifying", ErrorKind::Verifying),
            ("closed", ErrorKind::Closed),
            ("timeout", ErrorKind::Timeout),
            ("conflict", ErrorKind::Conflict),
            ("denied", ErrorKind::Denied),
            ("foreign_key", ErrorKind::ForeignKey),
            ("up_to_date", ErrorKind::UpToDate),
            ("not_fast_forward", ErrorKind::NotFastForward),
            ("git", ErrorKind::Git),
            ("integrity", ErrorKind::Integrity),
            ("unsupported", ErrorKind::Unsupported),
            ("internal", ErrorKind::Internal),
            ("io", ErrorKind::Io),
            ("timed_out", ErrorKind::TimedOut),
            ("something_new", ErrorKind::Other),
        ];
        for (code, kind) in codes {
            assert_eq!(ErrorKind::of(code), kind, "{code}");
            let transient = matches!(code, "rate_limited" | "busy" | "closed");
            assert_eq!(kind.is_transient(), transient, "{code}");
            let e = error(code, "m");
            assert_eq!(
                (e.code(), e.kind(), e.is_transient()),
                (code, kind, transient)
            );
            assert_eq!(e.to_string(), format!("{code}: m"));
        }
    }

    #[test]
    fn a_call_gets_its_result_or_the_daemons_error() {
        let (_d, sock) = fake(|_, req| {
            Some(match req.method.as_str() {
                "ping" => serde_json::json!({"id": req.id, "ok": true, "result": {"protocol": 1}}),
                _ => serde_json::json!({"id": req.id, "ok": false,
                    "error": {"code": "rate_limited", "message": "try again in 3 s"}}),
            })
        });
        let mut c = client(&sock);
        c.token = Some("lonca_t".into());
        c.repo = Some("demo".into());
        let v = c.call("ping", serde_json::json!({})).unwrap();
        assert_eq!(v["protocol"], crate::PROTOCOL);
        #[derive(serde::Deserialize)]
        struct Ping {
            protocol: u32,
        }
        let p: Ping = c.call_as("ping", serde_json::json!({})).unwrap();
        assert_eq!(p.protocol, 1);
        let bad: Result<Vec<u8>, _> = c.call_as("ping", serde_json::json!({}));
        assert_eq!(bad.unwrap_err().kind(), ErrorKind::Io);
        let e = c.call("status", serde_json::json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::RateLimited);
        // Each request has an id of its own, counting up.
        let (_d, sock) = fake(|_, req| {
            Some(serde_json::json!({"id": req.id, "ok": true,
                "result": [req.id, req.token, req.repo]}))
        });
        let mut c = client(&sock);
        c.token = Some("lonca_t".into());
        let first = c.call("ping", serde_json::json!({})).unwrap();
        assert_eq!(first, serde_json::json!([1, "lonca_t", null]));
        c.repo = Some("demo".into());
        let second = c.call("ping", serde_json::json!({})).unwrap();
        assert_eq!(second, serde_json::json!([2, "lonca_t", "demo"]));
        assert!(e.is_transient());
        assert!(e.to_string().contains("try again"), "{e}");
    }

    /// An error with no body is still an error.
    #[test]
    fn an_error_without_a_body_is_unknown() {
        let (_d, sock) = fake(|_, req| Some(serde_json::json!({"id": req.id, "ok": false})));
        let e = client(&sock)
            .call("ping", serde_json::json!({}))
            .unwrap_err();
        assert_eq!((e.code(), e.kind()), ("unknown", ErrorKind::Other));
    }

    /// The request and the answer carry the same id; another id is not an
    /// answer, and the connection is not used again.
    #[test]
    fn an_answer_to_another_request_is_refused() {
        let (_d, sock) = fake(|n, req| {
            let id = if n == 1 { req.id + 7 } else { req.id };
            Some(serde_json::json!({"id": id, "ok": true, "result": n}))
        });
        let mut c = client(&sock);
        let e = c.call("ping", serde_json::json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert!(e.to_string().contains("request 8"), "{e}");
        // A new connection, and the next answer is its own.
        assert_eq!(c.call("ping", serde_json::json!({})).unwrap(), 2);
    }

    /// No answer in time: `timed_out`, and the late answer is never taken
    /// for the next request's.
    #[test]
    fn a_timeout_drops_the_connection() {
        let (_d, sock) = fake(|n, req| match n {
            1 => {
                std::thread::sleep(Duration::from_millis(400));
                Some(serde_json::json!({"id": req.id, "ok": true, "result": "late"}))
            }
            _ => Some(serde_json::json!({"id": req.id, "ok": true, "result": "fresh"})),
        });
        let mut c = client(&sock);
        assert!(c.set_timeout(Some(Duration::ZERO)).is_err());
        assert_eq!(c.timeout(), None);
        c.set_timeout(Some(Duration::from_millis(100))).unwrap();
        assert_eq!(c.timeout(), Some(Duration::from_millis(100)));
        let e = c.call("ping", serde_json::json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::TimedOut, "{e}");
        assert!(!e.is_transient(), "it may have run");
        assert_eq!(c.call("ping", serde_json::json!({})).unwrap(), "fresh");
        assert_eq!(c.timeout(), Some(Duration::from_millis(100)), "kept");
    }

    /// The daemon's farewell on a quiet connection: the request was never
    /// read, so it goes again on a new connection, once.
    #[test]
    fn a_closed_connection_is_sent_again_once() {
        let (_d, sock) = fake(|n, req| {
            Some(match n {
                1 | 3 | 4 => serde_json::json!({"id": 0, "ok": false,
                    "error": {"code": "closed", "message": "quiet"}}),
                _ => serde_json::json!({"id": req.id, "ok": true, "result": n}),
            })
        });
        let mut c = client(&sock);
        assert_eq!(c.call("ping", serde_json::json!({})).unwrap(), 2);
        let e = c.call("ping", serde_json::json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Closed, "not twice");
        assert!(e.is_transient());
    }

    #[test]
    fn a_closed_socket_is_an_io_error() {
        let (_d, sock) = fake(|_, _| None);
        let mut c = client(&sock);
        c.writer.shutdown(std::net::Shutdown::Read).unwrap();
        let e = c.call("ping", serde_json::json!({})).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io, "{e}");
    }
}
