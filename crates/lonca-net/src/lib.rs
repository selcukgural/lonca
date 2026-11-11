#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub mod hello;

use hello::Hello;

const MAX_HEAD: usize = 16 * 1024;

/// Connections served at once, by every client together. One past it is
/// answered 503 and closed: each takes a thread and two descriptors.
pub const MAX_CONNECTIONS: usize = 256;

/// How much of a tunnel is copied between two reports to
/// [`Gate::carried`].
const CHUNK: usize = 16 * 1024;

/// How long the proxy waits on a client. Without them a client that says
/// nothing keeps one of the [`MAX_CONNECTIONS`] places for as long as it
/// likes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// For the whole request head, from the first read of it: answered 408
    /// past it, before the gate is asked anything.
    pub head: Duration,
    /// For a tunnel through which nothing moves, either way: it is cut
    /// ([`Outcome::Idle`]) once it has been silent this long, and a quarter
    /// longer at most.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            head: Duration::from_secs(10),
            idle: Duration::from_secs(600),
        }
    }
}

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
    /// The gate stopped it midway ([`Gate::carried`]).
    Cut,
    /// Nothing moved through it for [`Limits::idle`].
    Idle,
    /// Its TLS client asked for another server name than the host the
    /// tunnel was let through for, or in a way that can not be read: cut
    /// before a byte of the client's reached the host.
    Misnamed,
    /// Bytes flowed both ways until one side closed.
    Tunneled,
}

pub trait Gate: Send + Sync + 'static {
    /// Decides whether `request` may go through.
    fn decide(&self, request: &Request<'_>) -> Verdict;

    /// Told how every request that reached [`Gate::decide`] ended.
    fn finished(&self, _request: &Request<'_>, _outcome: Outcome) {}

    /// Told of a tunnel that ends [`Outcome::Misnamed`], before
    /// [`Gate::finished`] is: `asked` is the server name its TLS client
    /// asked for, lowercased and as long as the client made it, or `None`
    /// for a hello that could not be read to its end.
    fn misnamed(&self, _request: &Request<'_>, _asked: Option<&str>) {}

    /// Told of every `bytes` relayed for `request`, either way, before they
    /// are passed on. `false` cuts the connection: a budget is spent.
    fn carried(&self, _request: &Request<'_>, _bytes: u64) -> bool {
        true
    }

    /// Offered every `CONNECT` tunnel the gate let through, before a byte
    /// of it is relayed. A gate that serves the tunnel itself (to look
    /// inside TLS for a host it holds the keys of, say) returns `None` once
    /// it is done; returning the tunnel has the proxy relay its bytes as
    /// they are.
    fn relay(&self, _request: &Request<'_>, tunnel: Tunnel) -> Option<Tunnel> {
        Some(tunnel)
    }

    /// Offered every plain (absolute `http://`) request the gate let
    /// through, before a byte of it reaches the host: its `head` with the
    /// target cut to the path, and the connection to the host, whose
    /// `early` is what the client sent after the head. A gate that serves
    /// it itself (to read each request on the connection, say) returns
    /// `None` once it is done; handing them back has the proxy send the
    /// head on and relay the rest as it is.
    fn relay_plain(
        &self,
        _request: &Request<'_>,
        head: String,
        tunnel: Tunnel,
    ) -> Option<(String, Tunnel)> {
        Some((head, tunnel))
    }
}

/// A connection the gate let through: for a `CONNECT` tunnel, the client
/// has been told it is established; nothing has been relayed yet.
pub struct Tunnel {
    pub client: TcpStream,
    pub upstream: TcpStream,
    /// What the client sent after its request, which the proxy has already
    /// read: the start of the tunnel's bytes.
    pub early: Vec<u8>,
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
    serve_with(listener, gate, Limits::default());
}

/// [`serve`] with other limits than the usual.
pub fn serve_with<G: Gate>(listener: TcpListener, gate: Arc<G>, limits: Limits) {
    accept(listener, gate, &Arc::new(Shared::default()), limits);
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
    spawn_with(listener, gate, Limits::default())
}

/// [`spawn`] with other limits than the usual.
pub fn spawn_with<G: Gate>(
    listener: TcpListener,
    gate: Arc<G>,
    limits: Limits,
) -> std::io::Result<Server> {
    let addr = listener.local_addr()?;
    let shared = Arc::new(Shared::default());
    let served = Arc::clone(&shared);
    let thread = std::thread::spawn(move || accept(listener, gate, &served, limits));
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

fn accept<G: Gate>(listener: TcpListener, gate: Arc<G>, shared: &Arc<Shared>, limits: Limits) {
    for conn in listener.incoming() {
        if shared.stopping.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = conn else { continue };
        if shared.open.lock().unwrap().len() >= MAX_CONNECTIONS {
            respond(&stream, 503, "too many connections through the proxy");
            continue;
        }
        let id = shared.next.fetch_add(1, Ordering::Relaxed);
        shared.track(id, &stream);
        let (gate, shared) = (gate.clone(), Arc::clone(shared));
        std::thread::spawn(move || {
            // Stopping may have come between tracking and now.
            if !shared.stopping.load(Ordering::SeqCst) {
                let track = |upstream: &TcpStream| shared.track(id, upstream);
                let _ = handle(stream, &*gate, &track, limits);
            }
            shared.open.lock().unwrap().remove(&id);
        });
    }
}

/// Whether `ip` is anything but the public internet: this computer, its
/// network, a link, a documentation or benchmarking range, multicast or
/// reserved, or any of those inside an IPv6 address (mapped, NAT64, or the
/// old IPv4-compatible form).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => private_v4(v),
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return private_v4(v4);
            }
            let s = v.segments();
            // NAT64 (64:ff9b::/96) carries an IPv4 address at its end.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return private_v4(std::net::Ipv4Addr::new(a, b, c, d));
            }
            v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || (s[0] & 0xffc0) == 0xfec0 // site local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || s[..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible, deprecated
        }
    }
}

/// Cloud metadata endpoints, which hand out a machine's credentials. Never
/// reachable, whatever a gate allows: `allow_private` opens a network, not
/// these.
pub fn is_metadata(ip: IpAddr) -> bool {
    let v4 = |v: std::net::Ipv4Addr| {
        matches!(
            v.octets(),
            [169, 254, 169, 254] | [169, 254, 170, 2] | [169, 254, 170, 23] | [100, 100, 100, 200]
        )
    };
    match ip {
        IpAddr::V4(v) => v4(v),
        IpAddr::V6(v) => {
            v.to_ipv4_mapped().is_some_and(v4)
                || v.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

fn private_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // shared address space
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || a >= 240 // reserved
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

/// The head of a plain request for `host:port`, as it goes to the host:
/// `target` cut to `path`, and the connection said to end with this one
/// request. `None` if the head names another host than its target, names
/// one twice, or has a folded line (which servers read differently).
///
/// What follows a request on its connection is relayed unread, so a second
/// request could name any host the address serves; a server that is told
/// `Connection: close` reads none.
fn one_request(head: &str, target: &str, path: &str, host: &str, port: u16) -> Option<String> {
    let (first, headers) = head.split_once('\n')?;
    let mut out = first.replacen(target, path, 1);
    out.push('\n');
    let mut hosts = 0;
    for line in headers.split_inclusive('\n') {
        if line.starts_with([' ', '\t']) {
            return None;
        }
        if line.trim().is_empty() {
            // The line that ends the head.
            out.push_str("Connection: close\r\n");
            out.push_str(line);
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let is = |n: &str| name.trim().eq_ignore_ascii_case(n);
        if is("host") {
            hosts += 1;
            let named = parse_authority(value.trim(), 80)?;
            if hosts > 1 || !hello::names(&named.0, host) || named.1 != port {
                return None;
            }
        }
        if is("connection") || is("proxy-connection") || is("keep-alive") {
            continue;
        }
        out.push_str(line);
    }
    Some(out)
}

/// The process on the other end of `peer`, if the operating system tells
/// us (same user only): the one whose end of a connection to `local`, our
/// listener, is `peer`.
pub fn peer_pid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let out = Command::new("lsof")
        .args([
            "-nP",
            &format!("-iTCP@{}:{}", peer.ip(), peer.port()),
            "-sTCP:ESTABLISHED",
            "-Fpn",
        ])
        .output()
        .ok()?;
    pid_of(
        &String::from_utf8_lossy(&out.stdout),
        peer,
        local,
        std::process::id(),
    )
}

/// Reads `lsof -Fpn`: records of `p<pid>` then `n<local>-><remote>`. The
/// client is the process whose local end is `peer` and whose remote end is
/// `local`; `me` holds the other end of the same connection.
fn pid_of(text: &str, peer: SocketAddr, local: SocketAddr, me: u32) -> Option<u32> {
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
            cur = p.parse::<u32>().ok();
        } else if line.strip_prefix('n') == Some(want.as_str()) && cur != Some(me) {
            pid = cur.or(pid);
        }
    }
    pid
}

/// The first of `addrs` that takes a connection, tried in order within one
/// budget, as a client does: a name whose first address has no listener
/// (`localhost` as `::1` on Linux, with the server on `127.0.0.1` only) is
/// still reached on the next. Only addresses the rules allow are passed in.
fn connect_any(addrs: &[SocketAddr], within: Duration) -> Option<TcpStream> {
    let deadline = Instant::now() + within;
    addrs.iter().find_map(|a| {
        TcpStream::connect_timeout(a, deadline.saturating_duration_since(Instant::now())).ok()
    })
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
fn handle(
    client: TcpStream,
    gate: &dyn Gate,
    track: &dyn Fn(&TcpStream),
    limits: Limits,
) -> std::io::Result<()> {
    let peer = client.peer_addr()?;
    let local = client.local_addr()?;
    let mut reader = BufReader::new(Until {
        stream: &client,
        until: Instant::now() + limits.head,
    });
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_HEAD - head.len()) as u64)
            .read_until(b'\n', &mut line);
        let n = match read {
            Err(e) if timed_out(&e) => {
                respond(&client, 408, "the request head took too long");
                return Ok(());
            }
            other => other?,
        };
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
        let authority = parse_authority(auth, 80);
        let rewritten = authority
            .as_ref()
            .and_then(|(host, port)| one_request(&head_text, target, path, host, *port));
        if authority.is_some() && rewritten.is_none() {
            respond(
                &client,
                400,
                "the Host header names another host than the request",
            );
            return Ok(());
        }
        (authority, rewritten)
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
    if !addrs.is_empty() && addrs.iter().all(|a| is_metadata(a.ip())) {
        respond(&client, 403, "cloud metadata addresses are never reachable");
        gate.finished(&request, Outcome::Private);
        return Ok(());
    }
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| !is_metadata(a.ip()))
        .filter(|a| verdict.allow_private || !is_private(a.ip()))
        .collect();
    if allowed.is_empty() {
        respond(
            &client,
            403,
            "private and loopback addresses are not reachable",
        );
        gate.finished(&request, Outcome::Private);
        return Ok(());
    }
    let Some(upstream) = connect_any(&allowed, Duration::from_secs(10)) else {
        respond(&client, 502, "cannot connect");
        gate.finished(&request, Outcome::Unreachable);
        return Ok(());
    };
    track(&upstream);
    client.set_read_timeout(None)?;
    // Bytes already buffered after the head belong to the tunnel.
    let buffered = reader.buffer().to_vec();
    drop(reader);
    // A tunnel to a name is held to it; one to an address is for whatever
    // that address serves, and a plain request has said its host already.
    let named = (rest_of_request.is_none() && host.parse::<IpAddr>().is_err()).then_some(&*host);
    let (client, upstream, buffered) = match rest_of_request {
        None => {
            let mut c = &client;
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            let tunnel = Tunnel {
                client,
                upstream,
                early: buffered,
            };
            match gate.relay(&request, tunnel) {
                Some(t) => (t.client, t.upstream, t.early),
                None => {
                    gate.finished(&request, Outcome::Tunneled);
                    return Ok(());
                }
            }
        }
        Some(h) => {
            let tunnel = Tunnel {
                client,
                upstream,
                early: buffered,
            };
            match gate.relay_plain(&request, h, tunnel) {
                Some((h, t)) => {
                    (&t.upstream).write_all(h.as_bytes())?;
                    (t.client, t.upstream, t.early)
                }
                None => {
                    gate.finished(&request, Outcome::Tunneled);
                    return Ok(());
                }
            }
        }
    };
    let up_w = upstream.try_clone()?;
    // A read wakes often enough to see the silence of both ways together;
    // a side that takes nothing for as long is as silent.
    let wake = (limits.idle / 4).max(Duration::from_millis(1));
    for s in [&client, &upstream] {
        s.set_read_timeout(Some(wake))?;
        s.set_write_timeout(Some(limits.idle.max(wake)))?;
    }
    let way = Way {
        gate,
        request: &request,
        idle: limits.idle,
        moved: Mutex::new(Instant::now()),
        named,
    };
    // The worst of what the two directions ended with.
    let end = Mutex::new(Outcome::Tunneled);
    let ended = |how: Outcome, a: &TcpStream, b: &TcpStream| {
        if how != Outcome::Tunneled {
            let mut end = end.lock().unwrap();
            if !matches!(*end, Outcome::Cut | Outcome::Misnamed) {
                *end = how;
            }
            let _ = a.shutdown(std::net::Shutdown::Both);
            let _ = b.shutdown(std::net::Shutdown::Both);
        }
        let _ = b.shutdown(std::net::Shutdown::Write);
    };
    let (up_r, client_w) = (upstream.try_clone()?, client.try_clone()?);
    std::thread::scope(|scope| {
        scope.spawn(|| ended(way.carry(&up_r, &client_w), &up_r, &client_w));
        ended(way.client_side(&client, &up_w, buffered), &client, &up_w);
    });
    let how = *end.lock().unwrap();
    gate.finished(&request, how);
    Ok(())
}

/// Reads of `stream` that end, all of them together, by `until`: a limit on
/// each read alone is none for a client that sends a byte now and then.
struct Until<'a> {
    stream: &'a TcpStream,
    until: Instant,
}

impl Read for Until<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// Whether a read ended because its time was up (which of the two kinds
/// depends on the system).
fn timed_out(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(e.kind(), TimedOut | WouldBlock)
}

/// The two directions of one tunnel.
struct Way<'a> {
    gate: &'a dyn Gate,
    request: &'a Request<'a>,
    idle: Duration,
    /// When a byte last moved, either way.
    moved: Mutex<Instant>,
    /// The host a TLS client in the tunnel has to ask for, if it is held to
    /// one.
    named: Option<&'a str>,
}

impl Way<'_> {
    /// Copies `from` to `to` until the end, telling the gate of every chunk
    /// first: [`Outcome::Cut`] when the gate stopped it, [`Outcome::Idle`]
    /// when nothing moved either way for too long.
    fn carry(&self, from: &TcpStream, mut to: &TcpStream) -> Outcome {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match self.read(from, &mut buf) {
                Ok(n) => n,
                Err(end) => return end,
            };
            if !self.gate.carried(self.request, n as u64) {
                return Outcome::Cut;
            }
            if to.write_all(&buf[..n]).is_err() {
                return Outcome::Tunneled;
            }
        }
    }

    /// The client's direction: what it sends first, `early` being the start
    /// of it, is held back until it is seen not to be TLS, or to be a TLS
    /// client's first message for the host the tunnel is held to. For
    /// another name, or one that can not be read, nothing of it is passed
    /// on ([`Outcome::Misnamed`]). The other direction does not wait: a
    /// server that speaks first is heard meanwhile.
    fn client_side(&self, from: &TcpStream, mut to: &TcpStream, early: Vec<u8>) -> Outcome {
        let mut first = early;
        if let Some(host) = self.named {
            let mut buf = vec![0u8; CHUNK];
            loop {
                match hello::read(&first) {
                    Hello::More if first.len() < hello::MAX_HELLO + CHUNK => {}
                    Hello::Other | Hello::Named(None) => break,
                    Hello::Named(Some(name)) if hello::names(&name, host) => break,
                    Hello::Named(Some(name)) => {
                        self.gate.misnamed(self.request, Some(&name));
                        return Outcome::Misnamed;
                    }
                    Hello::More | Hello::Unreadable => {
                        self.gate.misnamed(self.request, None);
                        return Outcome::Misnamed;
                    }
                }
                match self.read(from, &mut buf) {
                    Ok(n) => first.extend_from_slice(&buf[..n]),
                    Err(end) => return end,
                }
            }
        }
        if !first.is_empty() {
            if !self.gate.carried(self.request, first.len() as u64) {
                return Outcome::Cut;
            }
            if to.write_all(&first).is_err() {
                return Outcome::Tunneled;
            }
        }
        self.carry(from, to)
    }

    /// One read of a direction: how the direction ended, if it did.
    fn read(&self, mut from: &TcpStream, buf: &mut [u8]) -> Result<usize, Outcome> {
        loop {
            match from.read(buf) {
                Err(e) if timed_out(&e) => {
                    if self.moved.lock().unwrap().elapsed() >= self.idle {
                        return Err(Outcome::Idle);
                    }
                }
                Ok(0) | Err(_) => return Err(Outcome::Tunneled),
                Ok(n) => {
                    *self.moved.lock().unwrap() = Instant::now();
                    return Ok(n);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_goes_to_the_first_address_that_takes_it() {
        // A port nobody listens on: bound, then given back.
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let open = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = open.local_addr().unwrap();
        let budget = Duration::from_secs(5);
        let s = connect_any(&[closed, at], budget).expect("the second address");
        assert_eq!(s.peer_addr().unwrap(), at);
        assert!(connect_any(&[closed], budget).is_none());
        assert!(connect_any(&[], budget).is_none());
        assert!(
            connect_any(&[at], Duration::ZERO).is_none(),
            "no budget, no attempt"
        );
    }

    #[test]
    fn the_client_is_the_other_end_of_our_connection() {
        let peer: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        // lsof names both ends: the client's record and our own.
        let text = "p41\nn127.0.0.1:8080->127.0.0.1:50001\n\
                    p77\nn127.0.0.1:50001->127.0.0.1:8080\nn127.0.0.1:50002->127.0.0.1:8080\n\
                    p90\nn127.0.0.1:50003->127.0.0.1:8080\n";
        assert_eq!(pid_of(text, peer, local, 41), Some(77));
        // A connection of our own to ourselves is nobody's.
        assert_eq!(pid_of(text, peer, local, 77), None);
        let other: SocketAddr = "127.0.0.1:50009".parse().unwrap();
        assert_eq!(pid_of(text, other, local, 41), None);
        assert_eq!(
            pid_of("pzz\nn127.0.0.1:50001->127.0.0.1:8080\n", peer, local, 41),
            None
        );
        assert_eq!(pid_of("", peer, local, 41), None);
    }

    #[test]
    fn metadata_addresses() {
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_metadata(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["169.254.169.253", "10.0.0.1", "fd00:ec2::253", "8.8.8.8"] {
            assert!(!is_metadata(ip.parse().unwrap()), "{ip}");
        }
    }

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
            "192.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
            "::127.0.0.1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "1.1.1.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
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
