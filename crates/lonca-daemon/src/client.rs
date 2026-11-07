//! Client for the daemon socket.

use std::io::BufReader;
use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::protocol::{ErrorBody, MAX_LINE, Request, Response, read_line_limited, write_line};
use crate::trust::Trust;

pub struct Client {
    socket: PathBuf,
    trust: Trust,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next: u64,
    pub token: Option<String>,
    pub repo: Option<String>,
}

#[derive(Debug)]
pub struct CallError(pub ErrorBody);

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
}

impl From<Exchange> for CallError {
    fn from(e: Exchange) -> Self {
        match e {
            Exchange::Write(e) | Exchange::Read(e) if e.kind() == UnexpectedEof => {
                gone("daemon closed the connection")
            }
            Exchange::Write(e) | Exchange::Read(e) => io(e),
        }
    }
}

fn gone(message: &str) -> CallError {
    CallError(ErrorBody {
        code: "io".into(),
        message: message.into(),
    })
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
            token: None,
            repo: None,
        })
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        let id = self.next;
        self.next += 1;
        let req = Request {
            id,
            method: method.into(),
            repo: self.repo.clone(),
            token: self.token.clone(),
            params,
        };
        let resp = match self.exchange(&req) {
            Err(e) if not_sent(&e) => self.again(&req)?,
            Ok(r) if not_read(&r) => self.again(&req)?,
            done => done?,
        };
        if resp.ok {
            Ok(resp.result)
        } else {
            Err(CallError(resp.error.unwrap_or(ErrorBody {
                code: "unknown".into(),
                message: String::new(),
            })))
        }
    }

    /// The daemon closed this connection for being quiet and never saw the
    /// request, so it is safe to send on a new one, once.
    fn again(&mut self, req: &Request) -> Result<Response, CallError> {
        let fresh = Self::connect_to(&self.socket, &self.trust).map_err(io)?;
        self.reader = fresh.reader;
        self.writer = fresh.writer;
        Ok(self.exchange(req)?)
    }

    fn exchange(&mut self, req: &Request) -> Result<Response, Exchange> {
        write_line(&mut self.writer, req).map_err(Exchange::Write)?;
        let line = read_line_limited(&mut self.reader, MAX_LINE)
            .map_err(Exchange::Read)?
            .ok_or_else(|| Exchange::Read(std::io::ErrorKind::UnexpectedEof.into()))?;
        serde_json::from_str(&line).map_err(|e| Exchange::Read(e.into()))
    }

    pub fn call_as<T: DeserializeOwned>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, CallError> {
        let v = self.call(method, params)?;
        serde_json::from_value(v).map_err(|e| {
            CallError(ErrorBody {
                code: "io".into(),
                message: format!("bad result: {e}"),
            })
        })
    }
}
