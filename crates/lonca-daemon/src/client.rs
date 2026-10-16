//! Client for the daemon socket.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::protocol::{ErrorBody, MAX_LINE, Request, Response, read_line_limited, write_line};

pub struct Client {
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

impl Client {
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        let s = UnixStream::connect(path)?;
        Ok(Self { reader: BufReader::new(s.try_clone()?), writer: s, next: 1, token: None, repo: None })
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        let id = self.next;
        self.next += 1;
        let req = Request { id, method: method.into(), repo: self.repo.clone(), token: self.token.clone(), params };
        let io = |e: std::io::Error| CallError(ErrorBody { code: "io".into(), message: e.to_string() });
        write_line(&mut self.writer, &req).map_err(io)?;
        let line = read_line_limited(&mut self.reader, MAX_LINE)
            .map_err(io)?
            .ok_or_else(|| CallError(ErrorBody { code: "io".into(), message: "daemon closed the connection".into() }))?;
        let resp: Response = serde_json::from_str(&line)
            .map_err(|e| CallError(ErrorBody { code: "io".into(), message: format!("bad response: {e}") }))?;
        if resp.ok { Ok(resp.result) } else { Err(CallError(resp.error.unwrap_or(ErrorBody { code: "unknown".into(), message: String::new() }))) }
    }

    pub fn call_as<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T, CallError> {
        let v = self.call(method, params)?;
        serde_json::from_value(v).map_err(|e| CallError(ErrorBody { code: "io".into(), message: format!("bad result: {e}") }))
    }
}
