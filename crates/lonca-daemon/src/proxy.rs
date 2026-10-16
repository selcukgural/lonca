//! The Lonca network proxy (observation level H2).
//!
//! The harness sandbox routes every outbound connection of sandboxed shell
//! commands here (Claude Code: `sandbox.network.httpProxyPort`). Each
//! connection is logged as an observation of the session it belongs to,
//! which taints that session; repository policy may refuse it instead.
//! Loopback, private and link-local destinations are refused unless policy
//! allows them, and the proxy connects to the address it checked, so DNS can
//! not be used to swap in a private address after the check.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::service::Service;

const MAX_HEAD: usize = 16 * 1024;

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

pub fn serve(listener: TcpListener, svc: Arc<Service>) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let svc = svc.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &svc);
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
            && n == want && cur.as_deref() != Some(me.as_str()) {
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
    let body = format!("lonca proxy: {reason}\n");
    let _ = write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn handle(client: TcpStream, svc: &Service) -> std::io::Result<()> {
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
    let verdict = svc.proxy_connect(peer_cwd(peer, local).as_deref(), &host);
    if !verdict.allow {
        respond(&client, 403, &verdict.reason);
        return Ok(());
    }
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => {
            respond(&client, 502, "cannot resolve host");
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
        return Ok(());
    };
    let upstream = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(u) => u,
        Err(_) => {
            respond(&client, 502, "cannot connect");
            return Ok(());
        }
    };
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
