//! The proxy against a real upstream: the gate decides, and hears how each
//! connection ended.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use lonca_net::{Gate, Outcome, Request, Verdict};

/// Lets through only `allowed`, reaching private addresses (the upstream is
/// on loopback), and records every outcome.
struct Recorder {
    allowed: String,
    outcomes: Mutex<Vec<(String, Outcome)>>,
}

impl Gate for Recorder {
    fn decide(&self, request: &Request<'_>) -> Verdict {
        if request.host == self.allowed {
            Verdict {
                allow: true,
                allow_private: true,
                reason: String::new(),
            }
        } else {
            Verdict::deny("not on the list")
        }
    }

    fn finished(&self, request: &Request<'_>, outcome: Outcome) {
        self.outcomes
            .lock()
            .unwrap()
            .push((request.host.to_owned(), outcome));
    }
}

fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let _ = s.write_all(b"hello from upstream\n");
        }
    });
    port
}

fn connect(proxy: u16, target: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut r = BufReader::new(s);
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    let mut rest = String::new();
    let _ = r.read_to_string(&mut rest);
    (status.trim().to_owned(), rest)
}

fn wait_for(gate: &Recorder, n: usize) -> Vec<(String, Outcome)> {
    for _ in 0..200 {
        let seen = gate.outcomes.lock().unwrap().clone();
        if seen.len() >= n {
            return seen;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the gate heard {:?}", gate.outcomes.lock().unwrap());
}

#[test]
fn the_gate_decides_and_hears_how_it_ended() {
    let gate = Arc::new(Recorder {
        allowed: "127.0.0.1".into(),
        outcomes: Mutex::new(Vec::new()),
    });
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap().port();
    let served = gate.clone();
    std::thread::spawn(move || lonca_net::serve(listener, served));
    let up = upstream();

    let (status, body) = connect(proxy, &format!("127.0.0.1:{up}"));
    assert!(status.contains("200"), "{status}");
    assert!(body.contains("hello from upstream"), "{body}");

    let (status, _) = connect(proxy, "elsewhere.example:443");
    assert!(status.contains("403"), "{status}");

    let mut seen = wait_for(&gate, 2);
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        seen,
        [
            ("127.0.0.1".to_owned(), Outcome::Tunneled),
            ("elsewhere.example".to_owned(), Outcome::Refused),
        ]
    );
}

#[test]
fn only_loopback_can_be_bound() {
    assert!(lonca_net::bind("0.0.0.0:0").is_err());
}

/// An upstream that keeps every connection open and silent.
fn silent_upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            held.push(s.unwrap());
        }
    });
    port
}

fn spawn_proxy() -> (lonca_net::Server, Arc<Recorder>) {
    let gate = Arc::new(Recorder {
        allowed: "127.0.0.1".into(),
        outcomes: Mutex::new(Vec::new()),
    });
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let server = lonca_net::spawn(listener, gate.clone()).unwrap();
    (server, gate)
}

#[test]
fn stopping_cuts_open_tunnels_and_closes_the_port() {
    let (server, gate) = spawn_proxy();
    let addr = server.local_addr();
    let up = silent_upstream();

    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    assert!(status.contains("200"), "{status}");

    server.stop();
    // Once stop returns, the gate has heard how the cut tunnel ended.
    assert_eq!(
        *gate.outcomes.lock().unwrap(),
        [("127.0.0.1".to_owned(), Outcome::Tunneled)]
    );
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut rest = Vec::new();
    // The tunnel ends instead of waiting on the silent upstream.
    assert!(r.read_to_end(&mut rest).is_ok());
    assert!(TcpStream::connect(addr).is_err());
}

#[test]
fn dropping_the_server_stops_it() {
    let (server, _) = spawn_proxy();
    let addr = server.local_addr();
    assert!(TcpStream::connect(addr).is_ok());
    drop(server);
    assert!(TcpStream::connect(addr).is_err());
}

/// Serves the tunnels it is offered itself, writing its own greeting
/// instead of relaying the upstream's.
struct Taker;

impl Gate for Taker {
    fn decide(&self, _request: &Request<'_>) -> Verdict {
        Verdict {
            allow: true,
            allow_private: true,
            reason: String::new(),
        }
    }

    fn relay(&self, request: &Request<'_>, tunnel: lonca_net::Tunnel) -> Option<lonca_net::Tunnel> {
        if !request.port.is_multiple_of(2) {
            return Some(tunnel);
        }
        let mut client = tunnel.client;
        let _ = writeln!(
            client,
            "taken over, early {:?}",
            String::from_utf8_lossy(&tunnel.early)
        );
        None
    }
}

#[test]
fn a_gate_can_serve_a_tunnel_itself() {
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap().port();
    std::thread::spawn(move || lonca_net::serve(listener, Arc::new(Taker)));
    // An even port is taken over, an odd one relayed; find one of each.
    let (mut even, mut odd) = (None, None);
    while even.is_none() || odd.is_none() {
        let up = upstream();
        if up.is_multiple_of(2) {
            even.get_or_insert(up);
        } else {
            odd.get_or_insert(up);
        }
    }

    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    let target = format!("127.0.0.1:{}", even.unwrap());
    // The tunnel's first bytes come with the request.
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\nhi").unwrap();
    let mut all = String::new();
    let _ = BufReader::new(s).read_to_string(&mut all);
    assert!(all.starts_with("HTTP/1.1 200"), "{all}");
    assert!(all.ends_with("taken over, early \"hi\"\n"), "{all}");

    let (status, body) = connect(proxy, &format!("127.0.0.1:{}", odd.unwrap()));
    assert!(status.contains("200"), "{status}");
    assert!(body.contains("hello from upstream"), "{body}");
}
