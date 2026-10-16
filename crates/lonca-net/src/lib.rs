//! A small network proxy for sandboxed commands, shared by Lonca and Kule.
//!
//! A sandbox lets commands reach only this proxy, on loopback. Every
//! connection (`CONNECT host:port` or an absolute `http://` request) is put to
//! a [`Gate`], which decides whether it goes through. Loopback, private and
//! link-local destinations are refused unless the gate allows them, and the
//! proxy connects to the address it checked, so DNS cannot swap in a private
//! address after the check. The proxy never sees inside TLS.
//!
//! It has no dependencies and knows nothing about who uses it: the gate
//! holds all the policy.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 * 1024;

/// One connection a client asked for.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Lowercased host name or IP literal, as the client wrote it.
    pub host: &'a str,
    pub port: u16,
    /// The client's end of the connection to the proxy.
    pub peer: SocketAddr,
    /// The proxy's end of it.
    pub local: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub allow: bool,
    /// Whether loopback and private addresses may be reached.
    pub allow_private: bool,
    /// Shown to the client when the connection is refused.
    pub reason: String,
}

impl Verdict {
    pub fn allow() -> Verdict {
        Verdict {
            allow: true,
            allow_private: false,
            reason: String::new(),
        }
    }

    pub fn deny(reason: impl Into<String>) -> Verdict {
        Verdict {
            allow: false,
            allow_private: false,
            reason: reason.into(),
        }
    }
}

/// How a connection ended up, after the gate's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The gate refused it.
    Refused,
    /// The host did not resolve.
    Unresolved,
    /// Every address the host resolved to is private or loopback.
    Private,
    /// The upstream did not accept the connection.
    Unreachable,
    /// Bytes flowed both ways until one side closed.
    Tunneled,
}

pub trait Gate: Send + Sync + 'static {
    /// Decides whether `request` may go through.
    fn decide(&self, request: &Request<'_>) -> Verdict;

    /// Told how every request that reached [`Gate::decide`] ended.
    fn finished(&self, _request: &Request<'_>, _outcome: Outcome) {}
}

/// Binds the proxy. Only loopback addresses are accepted: the proxy is for
/// processes on this machine.
pub fn bind(addr: &str) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(addr)?;
    if !l.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the proxy only listens on loopback",
        ));
    }
    Ok(l)
}

/// Serves connections until the listener fails, one thread each.
pub fn serve<G: Gate>(listener: TcpListener, gate: Arc<G>) {
    accept(listener, gate, &Arc::new(Shared::default()));
}

/// A proxy serving on its own thread until [`Server::stop`], or until it is
/// dropped.
pub struct Server {
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct Shared {
    stopping: AtomicBool,
    /// Both sides of every connection being handled, by number, so stopping
    /// can cut tunnels that would otherwise stay open.
    open: Mutex<HashMap<u64, Vec<TcpStream>>>,
    next: AtomicU64,
}

impl Shared {
    /// Adds `stream` to connection `id`; cuts it at once when stopping has
    /// begun, since nothing will cut it later.
    fn track(&self, id: u64, stream: &TcpStream) {
        let mut open = self.open.lock().unwrap();
        if self.stopping.load(Ordering::SeqCst) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        } else if let Ok(clone) = stream.try_clone() {
            open.entry(id).or_default().push(clone);
        }
    }
}

/// Starts serving `listener` on a new thread.
pub fn spawn<G: Gate>(listener: TcpListener, gate: Arc<G>) -> std::io::Result<Server> {
    let addr = listener.local_addr()?;
    let shared = Arc::new(Shared::default());
    let served = Arc::clone(&shared);
    let thread = std::thread::spawn(move || accept(listener, gate, &served));
    Ok(Server {
        addr,
        shared,
        thread: Some(thread),
    })
}

impl Server {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting, closes the listener and cuts every open connection;
    /// returns once each of them has ended and the gate has heard how
    /// ([`Gate::finished`]), or after a few seconds at most.
    pub fn stop(mut self) {
        self.shut();
    }

    fn shut(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        {
            // Set under the lock: a stream tracked from here on sees the flag
            // and is cut at once, any other is cut below.
            let _open = self.shared.open.lock().unwrap();
            self.shared.stopping.store(true, Ordering::SeqCst);
        }
        // Wakes the accept loop, which sees the flag and returns.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        let _ = thread.join();
        for stream in self.shared.open.lock().unwrap().values().flatten() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        // Handlers leave the map once the gate has heard how they ended. One
        // still connecting upstream (up to its 10 s timeout) is not waited for.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.shared.open.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shut();
    }
}

fn accept<G: Gate>(listener: TcpListener, gate: Arc<G>, shared: &Arc<Shared>) {
    for conn in listener.incoming() {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = conn else { continue };
        let id = shared.next.fetch_add(1, Ordering::Relaxed);
        shared.track(id, &stream);
        let (gate, shared) = (gate.clone(), Arc::clone(shared));
        std::thread::spawn(move || {
            // Stopping may have come between tracking and now.
            if !shared.stopping.load(Ordering::SeqCst) {
                let _ = handle(stream, &*gate, &|upstream| shared.track(id, upstream));
            }
            shared.open.lock().unwrap().remove(&id);
        });
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64 // 100.64.0.0/10
                || v.octets()[0] == 0
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let s = v.segments()[0];
            v.is_loopback()
                || v.is_unspecified()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80
        }
    }
}

/// Splits `host:port` (with `[v6]` brackets) and checks it.
fn parse_authority(a: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .map(|p| p.parse().ok())
            .unwrap_or(Some(default_port))?;
        (h.to_string(), port)
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (a.to_string(), default_port),
        }
    };
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    ok.then_some((host.to_ascii_lowercase(), port))
}

/// Working directory of the process on the other end of `peer`, if the
/// operating system tells us (same user only).
pub fn peer_cwd(peer: SocketAddr, local: SocketAddr) -> Option<PathBuf> {
    let me = std::process::id().to_string();
    let out = Command::new("lsof")
        .args([
            "-nP",
            &format!("-iTCP@{}:{}", peer.ip(), peer.port()),
            "-sTCP:ESTABLISHED",
            "-Fpn",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // Records: p<pid> then n<local>-><remote>. The client is the process
    // whose local end is `peer` and whose remote end is our listener.
    let want = format!(
        "{}:{}->{}:{}",
        peer.ip(),
        peer.port(),
        local.ip(),
        local.port()
    );
    let mut pid = None;
    let mut cur = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            cur = Some(p.to_string());
        } else if let Some(n) = line.strip_prefix('n')
            && n == want
            && cur.as_deref() != Some(me.as_str())
        {
            pid = cur.clone();
        }
    }
    let pid = pid?;
    let out = Command::new("lsof")
        .args(["-a", "-p", &pid, "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n').map(PathBuf::from))
}

fn respond(mut s: &TcpStream, code: u16, reason: &str) {
    let body = format!("proxy: {reason}\n");
    let _ = write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Serves one client; `track` is shown the upstream connection, if one is
/// made, so it can be cut from outside.
fn handle(client: TcpStream, gate: &dyn Gate, track: &dyn Fn(&TcpStream)) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let peer = client.peer_addr()?;
    let local = client.local_addr()?;
    let mut reader = BufReader::new(client.try_clone()?);
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take((MAX_HEAD - head.len()) as u64)
            .read_until(b'\n', &mut line)?;
        if n == 0 || head.len() + n >= MAX_HEAD {
            respond(&client, 400, "bad request");
            return Ok(());
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let head_text = String::from_utf8_lossy(&head).into_owned();
    let first = head_text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let (authority, rest_of_request) = if method.eq_ignore_ascii_case("CONNECT") {
        (parse_authority(target, 443), None)
    } else if let Some(url) = target.strip_prefix("http://") {
        let (auth, path) = url.split_at(url.find('/').unwrap_or(url.len()));
        let path = if path.is_empty() { "/" } else { path };
        let rewritten = head_text.replacen(target, path, 1);
        (parse_authority(auth, 80), Some(rewritten))
    } else {
        respond(&client, 400, "only CONNECT and absolute http:// requests");
        return Ok(());
    };
    let Some((host, port)) = authority else {
        respond(&client, 400, "bad target");
        return Ok(());
    };
    let request = Request {
        host: &host,
        port,
        peer,
        local,
    };
    let verdict = gate.decide(&request);
    if !verdict.allow {
        respond(&client, 403, &verdict.reason);
        gate.finished(&request, Outcome::Refused);
        return Ok(());
    }
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => {
            respond(&client, 502, "cannot resolve host");
            gate.finished(&request, Outcome::Unresolved);
            return Ok(());
        }
    };
    let Some(addr) = addrs
        .into_iter()
        .find(|a| verdict.allow_private || !is_private(a.ip()))
    else {
        respond(
            &client,
            403,
            "private and loopback addresses are not reachable",
        );
        gate.finished(&request, Outcome::Private);
        return Ok(());
    };
    let upstream = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(u) => u,
        Err(_) => {
            respond(&client, 502, "cannot connect");
            gate.finished(&request, Outcome::Unreachable);
            return Ok(());
        }
    };
    track(&upstream);
    client.set_read_timeout(None)?;
    let mut up_w = upstream.try_clone()?;
    match rest_of_request {
        None => {
            let mut c = &client;
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        }
        Some(h) => up_w.write_all(h.as_bytes())?,
    }
    // Bytes already buffered after the head belong to the tunnel.
    let buffered = reader.buffer().to_vec();
    if !buffered.is_empty() {
        up_w.write_all(&buffered)?;
    }
    let mut up_r = upstream;
    let mut client_w = client.try_clone()?;
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut up_r, &mut client_w);
        let _ = client_w.shutdown(std::net::Shutdown::Write);
    });
    let mut client_r = client;
    let _ = std::io::copy(&mut client_r, &mut up_w);
    let _ = up_w.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    gate.finished(&request, Outcome::Tunneled);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.4",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700::1111"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn authorities() {
        assert_eq!(
            parse_authority("Example.com:443", 1),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            parse_authority("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(parse_authority("[::1]:8080", 1), Some(("::1".into(), 8080)));
        assert_eq!(parse_authority("a b:1", 1), None);
        assert_eq!(parse_authority("x:notaport", 1), None);
    }
}
