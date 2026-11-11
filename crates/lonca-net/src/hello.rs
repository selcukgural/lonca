//! The name a TLS client asks for, read from the first bytes it sends.
//!
//! A tunnel is let through for one host, and reaches an address of it. That
//! address may serve other names too, and which one answers is the client's
//! word: the server name in its first message, sent in the clear. Read here
//! so that the proxy can hold it to the host that was asked for.

/// More than any client's first message: one past it is not read.
pub const MAX_HELLO: usize = 64 * 1024;

/// What the first bytes of a tunnel say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// Not enough of it yet.
    More,
    /// Not the start of TLS.
    Other,
    /// A TLS client's first message, and the server name in it, lowercased.
    Named(Option<String>),
    /// The start of one that can not be read to its end.
    Unreadable,
}

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_NAME: u16 = 0;
const HOST_NAME: u8 = 0;
/// A record's body is 2^14 bytes at most; some room for what is not.
const MAX_RECORD: usize = (1 << 14) + 256;

/// Reads the start of a tunnel, `bytes` being all of it so far.
pub fn read(bytes: &[u8]) -> Hello {
    // The message, put together from the records it came in.
    let mut message: Vec<u8> = Vec::new();
    let mut rest = bytes;
    loop {
        // A record: its type, a version (3, x), the length of its body.
        match rest {
            [] if message.is_empty() => return Hello::More,
            [t, ..] if *t != HANDSHAKE => return other_or(&message),
            [_, v, ..] if *v != 3 => return other_or(&message),
            _ => {}
        }
        let Some((head, body)) = rest.split_at_checked(5) else {
            return Hello::More;
        };
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        if len == 0 || len > MAX_RECORD {
            return other_or(&message);
        }
        if message.is_empty() && body.first().is_some_and(|t| *t != CLIENT_HELLO) {
            return Hello::Other;
        }
        let Some((body, after)) = body.split_at_checked(len) else {
            return Hello::More;
        };
        message.extend_from_slice(body);
        rest = after;
        // The message: its type, three bytes of length, the hello.
        let Some((head, hello)) = message.split_at_checked(4) else {
            continue;
        };
        let want =
            (usize::from(head[1]) << 16) | (usize::from(head[2]) << 8) | usize::from(head[3]);
        if want + 4 > MAX_HELLO {
            return Hello::Unreadable;
        }
        if let Some(hello) = hello.get(..want) {
            return match server_name(hello) {
                Some(name) => Hello::Named(name),
                None => Hello::Unreadable,
            };
        }
        if rest.is_empty() {
            return Hello::More;
        }
    }
}

/// What a record that does not go on a begun message means: nothing before
/// a message, a broken one after.
fn other_or(message: &[u8]) -> Hello {
    if message.is_empty() {
        Hello::Other
    } else {
        Hello::Unreadable
    }
}

/// Bytes read from the front, `None` past the end.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        Some(usize::from(self.take(1)?[0]))
    }

    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// The server name of a hello: `Some(None)` if it has none, `None` if the
/// hello is not well formed or names a server twice.
fn server_name(hello: &[u8]) -> Option<Option<String>> {
    let mut c = Cursor(hello);
    c.take(2 + 32)?; // version, random
    let n = c.u8()?;
    c.take(n)?; // session id
    let n = c.u16()?;
    c.take(n)?; // cipher suites
    let n = c.u8()?;
    c.take(n)?; // compression methods
    if c.done() {
        return Some(None); // no extensions at all
    }
    let n = c.u16()?;
    let mut exts = Cursor(c.take(n)?);
    if !c.done() {
        return None;
    }
    let mut found = None;
    while !exts.done() {
        let kind = exts.u16()?;
        let n = exts.u16()?;
        let body = exts.take(n)?;
        if kind != usize::from(SERVER_NAME) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(host_name(body)?);
    }
    Some(found)
}

/// The one host name of a server name extension.
fn host_name(body: &[u8]) -> Option<String> {
    let mut c = Cursor(body);
    let n = c.u16()?;
    let mut list = Cursor(c.take(n)?);
    if !c.done() {
        return None;
    }
    let mut found = None;
    while !list.done() {
        let kind = list.u8()?;
        let n = list.u16()?;
        let name = list.take(n)?;
        if kind != usize::from(HOST_NAME) || found.is_some() {
            return None;
        }
        let name = std::str::from_utf8(name).ok()?;
        if name.is_empty() || !name.is_ascii() {
            return None;
        }
        found = Some(name.to_ascii_lowercase());
    }
    found
}

/// Whether `name`, a hello's server name, is `host`, the one a tunnel was
/// asked for (both lowercased; a last dot says nothing).
pub fn names(name: &str, host: &str) -> bool {
    let bare = |s: &str| s.strip_suffix('.').unwrap_or(s).to_owned();
    bare(name) == bare(host)
}

/// A hello for `name`, in records of `record` bytes at most: what a client
/// would send, for the tests of this crate and of those that use it.
#[doc(hidden)]
pub fn sample(name: Option<&str>, record: usize) -> Vec<u8> {
    let mut exts = Vec::new();
    // An extension before the name (supported versions), and one after.
    exts.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
    if let Some(name) = name {
        let n = name.len() as u16;
        exts.extend_from_slice(&SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(n + 5).to_be_bytes());
        exts.extend_from_slice(&(n + 3).to_be_bytes());
        exts.push(HOST_NAME);
        exts.extend_from_slice(&n.to_be_bytes());
        exts.extend_from_slice(name.as_bytes());
    }
    exts.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[7; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0, 2, 0x13, 0x01]);
    hello.extend_from_slice(&[1, 0]);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);
    let mut message = vec![CLIENT_HELLO];
    message.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&hello);
    let mut out = Vec::new();
    for part in message.chunks(record.max(1)) {
        out.extend_from_slice(&[HANDSHAKE, 3, 1]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(s: &str) -> Hello {
        Hello::Named(Some(s.to_owned()))
    }

    #[test]
    fn the_name_is_read_whole_or_in_pieces() {
        for record in [1, 2, 3, 4, 5, 7, 64, 16384] {
            let bytes = sample(Some("Crates.IO"), record);
            assert_eq!(read(&bytes), named("crates.io"), "records of {record}");
            // What follows the hello is not looked at.
            let mut more = bytes.clone();
            more.extend_from_slice(&[23, 3, 3, 0, 1, 0]);
            assert_eq!(read(&more), named("crates.io"));
        }
        assert_eq!(read(&sample(None, 16384)), Hello::Named(None));
    }

    #[test]
    fn every_cut_of_a_hello_waits_for_more() {
        for record in [3, 16384] {
            let bytes = sample(Some("crates.io"), record);
            for end in 0..bytes.len() {
                assert_eq!(read(&bytes[..end]), Hello::More, "{end} of {record}");
            }
        }
    }

    #[test]
    fn what_is_not_tls_is_seen_at_its_first_bytes() {
        assert_eq!(read(b"S"), Hello::Other);
        assert_eq!(read(b"SSH-2.0-OpenSSH_9.9\r\n"), Hello::Other);
        assert_eq!(read(b"GET / HTTP/1.1\r\n\r\n"), Hello::Other);
        assert_eq!(read(&[22]), Hello::More);
        assert_eq!(read(&[22, 2]), Hello::Other, "no TLS has this version");
        assert_eq!(read(&[22, 3, 1, 0, 0]), Hello::Other, "an empty record");
        assert_eq!(read(&[22, 3, 1, 0xff, 0xff]), Hello::Other, "too long");
        // A handshake record that is not a client's first message.
        assert_eq!(read(&[22, 3, 3, 0, 4, 2, 0, 0, 0]), Hello::Other);
        assert_eq!(read(&[]), Hello::More);
    }

    #[test]
    fn a_hello_that_can_not_be_read_is_not_passed_as_nameless() {
        let good = sample(Some("crates.io"), 16384);
        // The name twice.
        let at = good.windows(9).position(|w| w == b"crates.io").unwrap();
        let ext = good[at - 9..at + 9].to_vec();
        let mut twice = good.clone();
        twice.splice(at + 9..at + 9, ext.iter().copied());
        let grow = |b: &mut Vec<u8>, at: usize, by: usize| {
            let n = u16::from_be_bytes([b[at], b[at + 1]]) + by as u16;
            b[at..at + 2].copy_from_slice(&n.to_be_bytes());
        };
        grow(&mut twice, 3, ext.len());
        grow(&mut twice, 7, ext.len());
        let exts = 5 + 4 + 2 + 32 + 1 + 4 + 2;
        grow(&mut twice, exts, ext.len());
        assert_eq!(read(&twice), Hello::Unreadable);
        // A message said to be longer than any.
        assert_eq!(
            read(&[22, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff]),
            Hello::Unreadable
        );
        // Another kind of record in the middle of the message.
        let mut split = sample(Some("crates.io"), 8);
        split.splice(13..13, [23, 3, 3, 0, 1, 0]);
        assert_eq!(read(&split), Hello::Unreadable);
        // A name that is not a host name.
        let mut odd = good.clone();
        odd[at] = 0xc3;
        assert_eq!(read(&odd), Hello::Unreadable);
    }

    #[test]
    fn no_change_of_a_byte_panics_or_names_another_host() {
        let good = sample(Some("crates.io"), 16384);
        let at = good.windows(9).position(|w| w == b"crates.io").unwrap();
        for i in 0..good.len() {
            for v in [
                0,
                1,
                2,
                22,
                0x7f,
                0xff,
                good[i] ^ 1,
                good[i].wrapping_add(1),
            ] {
                let mut b = good.clone();
                b[i] = v;
                let got = read(&b);
                if (at..at + 9).contains(&i) || got == named("crates.io") {
                    continue;
                }
                assert!(
                    !matches!(got, Hello::Named(Some(_))),
                    "byte {i} = {v}: {got:?}"
                );
            }
        }
    }

    #[test]
    fn a_last_dot_says_nothing() {
        assert!(names("crates.io", "crates.io"));
        assert!(names("crates.io.", "crates.io"));
        assert!(names("crates.io", "crates.io."));
        assert!(!names("static.crates.io", "crates.io"));
        assert!(!names("crates.io.evil.example", "crates.io"));
        assert!(!names("", "crates.io"));
    }
}
