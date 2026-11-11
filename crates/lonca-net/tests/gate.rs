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

/// Serves the plain requests it is offered itself on an even port, saying
/// what it was handed; on an odd one hands them back to go on as they are.
struct PlainTaker;

impl Gate for PlainTaker {
    fn decide(&self, _request: &Request<'_>) -> Verdict {
        Verdict {
            allow: true,
            allow_private: true,
            reason: String::new(),
        }
    }

    fn relay_plain(
        &self,
        request: &Request<'_>,
        head: String,
        tunnel: lonca_net::Tunnel,
    ) -> Option<(String, lonca_net::Tunnel)> {
        if !request.port.is_multiple_of(2) {
            return Some((head, tunnel));
        }
        let mut client = tunnel.client;
        let _ = writeln!(
            client,
            "taken over: {:?}, early {:?}",
            head.lines().next().unwrap_or_default(),
            String::from_utf8_lossy(&tunnel.early)
        );
        None
    }
}

/// An upstream that answers each connection with the first line it got.
fn echo_upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut line = String::new();
            let _ = BufReader::new(s.try_clone().unwrap()).read_line(&mut line);
            let _ = write!(s, "upstream got {line}");
        }
    });
    port
}

#[test]
fn a_gate_can_serve_a_plain_request_itself() {
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap().port();
    std::thread::spawn(move || lonca_net::serve(listener, Arc::new(PlainTaker)));
    let (mut even, mut odd) = (None, None);
    while even.is_none() || odd.is_none() {
        let up = echo_upstream();
        if up.is_multiple_of(2) {
            even.get_or_insert(up);
        } else {
            odd.get_or_insert(up);
        }
    }
    let ask = |port: u16, extra: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
        // One write: `early` is what arrived with the head, so the head and
        // what follows it must leave in the same segment, not one
        // `write_fmt` piece at a time.
        let request = format!(
            "GET http://127.0.0.1:{port}/a?b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n{extra}"
        );
        s.write_all(request.as_bytes()).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        let mut all = String::new();
        let _ = BufReader::new(s).read_to_string(&mut all);
        all
    };
    // Handed the head with its path alone, and what came after it.
    let taken = ask(even.unwrap(), "next");
    assert_eq!(
        taken, "taken over: \"GET /a?b HTTP/1.1\", early \"next\"\n",
        "{taken}"
    );
    let passed = ask(odd.unwrap(), "");
    assert_eq!(passed, "upstream got GET /a?b HTTP/1.1\r\n", "{passed}");
}

fn spawn_with(limits: lonca_net::Limits) -> (lonca_net::Server, Arc<Recorder>) {
    let gate = Arc::new(Recorder {
        allowed: "127.0.0.1".into(),
        outcomes: Mutex::new(Vec::new()),
    });
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let server = lonca_net::spawn_with(listener, gate.clone(), limits).unwrap();
    (server, gate)
}

fn ms(n: u64) -> std::time::Duration {
    std::time::Duration::from_millis(n)
}

#[test]
fn a_head_that_comes_a_byte_at_a_time_is_given_up() {
    let (server, gate) = spawn_with(lonca_net::Limits {
        head: ms(400),
        idle: ms(60_000),
    });
    let mut s = TcpStream::connect(server.local_addr()).unwrap();
    let begun = std::time::Instant::now();
    // Each byte comes well inside the limit; the head as a whole does not.
    let feeder = s.try_clone().unwrap();
    std::thread::spawn(move || {
        for b in b"CONNECT 127.0.0.1:1 HTTP/1.1".iter().cycle().take(100) {
            if (&feeder).write_all(&[*b]).is_err() {
                return;
            }
            std::thread::sleep(ms(100));
        }
    });
    s.set_read_timeout(Some(ms(5000))).unwrap();
    let mut answer = String::new();
    let _ = s.read_to_string(&mut answer);
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    assert!(begun.elapsed() < ms(3000), "{:?}", begun.elapsed());
    // The gate was never asked.
    assert!(gate.outcomes.lock().unwrap().is_empty());
}

#[test]
fn a_tunnel_that_carries_nothing_is_cut() {
    let (server, gate) = spawn_with(lonca_net::Limits {
        head: ms(5000),
        idle: ms(300),
    });
    let up = silent_upstream();
    let mut s = TcpStream::connect(server.local_addr()).unwrap();
    write!(s, "CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    assert!(status.contains("200"), "{status}");
    assert_eq!(
        wait_for(&gate, 1),
        [("127.0.0.1".to_owned(), Outcome::Idle)]
    );
    s.set_read_timeout(Some(ms(5000))).unwrap();
    let mut rest = Vec::new();
    assert!(
        r.read_to_end(&mut rest).is_ok(),
        "the client's end is closed"
    );
}

#[test]
fn a_tunnel_that_carries_one_way_only_stays() {
    let (server, gate) = spawn_with(lonca_net::Limits {
        head: ms(5000),
        idle: ms(400),
    });
    // An upstream that takes what comes and never says a word.
    let up = silent_upstream();
    let mut s = TcpStream::connect(server.local_addr()).unwrap();
    write!(s, "CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    assert!(status.contains("200"), "{status}");
    // Three limits long, a byte every quarter of one: the silent way back
    // does not end it.
    for _ in 0..12 {
        s.write_all(b"x").unwrap();
        std::thread::sleep(ms(100));
        assert!(gate.outcomes.lock().unwrap().is_empty());
    }
    // The client leaves; the upstream never answers nor closes, and the
    // half that is left does not wait for it for ever.
    drop((s, r));
    assert_eq!(
        wait_for(&gate, 1),
        [("127.0.0.1".to_owned(), Outcome::Idle)]
    );
}

/// An upstream that sends back what it is sent, to the end.
fn mirror_upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut all = Vec::new();
            let _ = s.read_to_end(&mut all);
            let _ = s.write_all(&all);
        }
    });
    port
}

/// A proxy that lets `localhost` through: a name, as tunnels to names are
/// the ones held to it.
fn spawn_named() -> (lonca_net::Server, Arc<Recorder>) {
    let gate = Arc::new(Recorder {
        allowed: "localhost".into(),
        outcomes: Mutex::new(Vec::new()),
    });
    let listener = lonca_net::bind("127.0.0.1:0").unwrap();
    let server = lonca_net::spawn(listener, gate.clone()).unwrap();
    (server, gate)
}

/// Opens a tunnel to `target`, sends `parts` through it one by one, and
/// reads what comes back after the proxy's answer.
fn through(server: &lonca_net::Server, target: &str, parts: &[&[u8]]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(server.local_addr()).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    r.read_line(&mut String::new()).unwrap();
    for part in parts {
        // A tunnel that is cut takes no more.
        let _ = s.write_all(part);
        std::thread::sleep(ms(30));
    }
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut back = Vec::new();
    let _ = r.read_to_end(&mut back);
    (status, back)
}

#[test]
fn a_tunnel_is_held_to_the_name_it_was_let_through_for() {
    let (server, gate) = spawn_named();
    let target = format!("localhost:{}", mirror_upstream());
    let hello = |name| lonca_net::hello::sample(name, 16384);

    // The host's own name, however it is written and however it comes.
    for name in ["localhost", "LocalHost", "localhost."] {
        let sent = hello(Some(name));
        let (status, back) = through(&server, &target, &[&sent, b"and more"]);
        assert!(status.contains("200"), "{status}");
        assert_eq!(back, [&sent[..], b"and more"].concat(), "{name}");
    }
    let sent = hello(Some("localhost"));
    let (a, b) = sent.split_at(20);
    assert_eq!(through(&server, &target, &[a, b]).1, sent, "in two pieces");
    let small = lonca_net::hello::sample(Some("localhost"), 9);
    assert_eq!(through(&server, &target, &[&small]).1, small, "in records");
    // No name at all picks nothing, and what is not TLS has none.
    let sent = hello(None);
    assert_eq!(through(&server, &target, &[&sent]).1, sent);
    let ssh = b"SSH-2.0-OpenSSH_9.9\r\n";
    assert_eq!(through(&server, &target, &[ssh]).1, ssh);
    assert_eq!(through(&server, &target, &[]).1, b"");
    let seen = wait_for(&gate, 8);
    assert!(
        seen.iter().all(|(_, o)| *o == Outcome::Tunneled),
        "{seen:?}"
    );

    // Another name the same address may serve: nothing of it gets there.
    for sent in [
        hello(Some("elsewhere.example")),
        hello(Some("localhost.elsewhere.example")),
        // A hello that something else is put in the middle of.
        [&small[..13], &[23, 3, 3, 0, 1, 0], &small[13..]].concat(),
    ] {
        let before = gate.outcomes.lock().unwrap().len();
        let (status, back) = through(&server, &target, &[&sent, b"and more"]);
        assert!(status.contains("200"), "{status}");
        assert_eq!(back, b"", "nothing came back, as nothing got there");
        let seen = wait_for(&gate, before + 1);
        assert_eq!(seen[before], ("localhost".to_owned(), Outcome::Misnamed));
    }
    // A hello that never ends is held back for as long as it does not.
    let (_, back) = through(&server, &target, &[&hello(Some("localhost"))[..40]]);
    assert_eq!(back, b"");
}

#[test]
fn a_server_that_speaks_first_is_heard_before_the_client_says_anything() {
    let (server, _gate) = spawn_named();
    let target = format!("localhost:{}", upstream());
    let (status, back) = through(&server, &target, &[]);
    assert!(status.contains("200"), "{status}");
    assert_eq!(back, b"hello from upstream\n");
}

#[test]
fn a_tunnel_to_an_address_is_for_whatever_the_address_serves() {
    let (server, gate) = spawn_proxy();
    let target = format!("127.0.0.1:{}", mirror_upstream());
    let sent = lonca_net::hello::sample(Some("elsewhere.example"), 16384);
    assert_eq!(through(&server, &target, &[&sent]).1, sent);
    assert_eq!(
        wait_for(&gate, 1),
        [("127.0.0.1".to_owned(), Outcome::Tunneled)]
    );
}

/// An upstream that answers each connection with the whole head it got.
fn head_upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            while r.read_line(&mut head).is_ok_and(|n| n > 2) {}
            let _ = s.write_all(head.as_bytes());
        }
    });
    port
}

#[test]
fn a_plain_request_is_for_its_own_host_and_is_the_only_one() {
    let (server, gate) = spawn_named();
    let up = head_upstream();
    let ask = |headers: &str| {
        let mut s = TcpStream::connect(server.local_addr()).unwrap();
        let request = format!("GET http://localhost:{up}/a HTTP/1.1\r\n{headers}\r\n");
        s.write_all(request.as_bytes()).unwrap();
        let mut all = String::new();
        let _ = BufReader::new(s).read_to_string(&mut all);
        all
    };
    // The host is told that no request follows this one: the next on the
    // connection would be relayed unread, whatever host it named.
    let got = ask(&format!(
        "Host: LOCALHOST:{up}\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n"
    ));
    assert_eq!(
        got,
        format!(
            "GET /a HTTP/1.1\r\nHost: LOCALHOST:{up}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
    );
    assert_eq!(ask(""), "GET /a HTTP/1.1\r\nConnection: close\r\n\r\n");

    let before = wait_for(&gate, 2).len();
    for headers in [
        "Host: elsewhere.example\r\n".to_owned(),
        // The right name on another port is another server.
        "Host: localhost\r\n".to_owned(),
        format!("Host: localhost:{up}\r\nhost: elsewhere.example\r\n"),
        format!("Host: localhost:{up}\r\n elsewhere.example\r\n"),
        format!("Host: localhost:{up}\r\nnot a header\r\n"),
    ] {
        let got = ask(&headers);
        assert!(got.starts_with("HTTP/1.1 400"), "{headers:?}: {got}");
        assert!(got.contains("Host header"), "{got}");
    }
    // Refused before the gate was asked: nothing was let through.
    assert_eq!(gate.outcomes.lock().unwrap().len(), before);
}
