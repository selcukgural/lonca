//! What keeps one client from tying the daemon up. All of it sits in front
//! of the single writer and none of it reaches `decide()`: a request refused
//! here was never logged, so a replay does not see it.

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};

use crate::protocol::MAX_LINE;

/// A request line of any method up to here; past it, see [`Head`].
pub const SHORT_LINE: usize = 64 * 1024;
/// File descriptors the daemon asks the system for.
const WANTED_FILES: u64 = 4096;

#[derive(Clone, Debug)]
pub struct Limits {
    /// Connections at once, every uid together.
    pub connections: usize,
    /// Connections at once of one uid.
    pub per_uid: usize,
    /// How long a connection may send nothing.
    pub idle: Duration,
    /// How long a line may take, from its first byte to its newline.
    pub line: Duration,
    /// How long a response may take to be read.
    pub write: Duration,
    /// A line past this must be of a method that may send more.
    pub short_line: usize,
    pub long_line: usize,
    /// Bytes of long lines held in memory at once, every connection together.
    pub buffered: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: 1024,
            per_uid: 512,
            idle: Duration::from_secs(15 * 60),
            line: Duration::from_secs(60),
            write: Duration::from_secs(60),
            short_line: SHORT_LINE,
            long_line: MAX_LINE,
            buffered: 2 * MAX_LINE,
        }
    }
}

impl Limits {
    /// What a daemon with `files` descriptors ([`open_files`]) runs with: half
    /// of them for connections, the rest for repositories and children.
    pub fn for_files(files: u64) -> Self {
        let d = Self::default();
        let connections = d.connections.min(files as usize / 2);
        Self {
            connections,
            per_uid: d.per_uid.min(connections),
            ..d
        }
    }
}

/// Asks for [`WANTED_FILES`] descriptors, as far as the hard limit goes
/// (a launchd daemon starts with 256), and says what it has.
pub fn open_files() -> u64 {
    crate::sys::raise_open_files(WANTED_FILES)
}

/// How often each limit said no. The daemon's own count: nothing refused
/// here is in a log. `ping` shows it.
#[derive(Debug, Default)]
pub struct Counters {
    /// Connections refused, or long lines with no room left.
    pub busy: AtomicU64,
    /// Quiet connections closed to let a new one in.
    pub evicted: AtomicU64,
    /// Connections closed after sending nothing for too long.
    pub idle: AtomicU64,
    /// Connections closed in the middle of a line or a response.
    pub slow: AtomicU64,
    pub too_large: AtomicU64,
    pub rate_limited: AtomicU64,
}

impl Counters {
    pub fn add(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_json(&self) -> Value {
        let n = |c: &AtomicU64| c.load(Ordering::Relaxed);
        json!({
            "busy": n(&self.busy),
            "evicted": n(&self.evicted),
            "idle": n(&self.idle),
            "slow": n(&self.slow),
            "too_large": n(&self.too_large),
            "rate_limited": n(&self.rate_limited),
        })
    }
}

/// A connection the server holds.
struct Conn {
    uid: u32,
    stream: Arc<UnixStream>,
    /// A request is being answered: the only state that can not be cut.
    working: bool,
    quiet_since: Instant,
}

/// The connections alive, and the bytes of long lines they hold.
pub struct Registry {
    pub limits: Limits,
    conns: Mutex<BTreeMap<u64, Conn>>,
    next: AtomicU64,
    buffered: AtomicUsize,
}

impl Registry {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            conns: Mutex::default(),
            next: AtomicU64::new(0),
            buffered: AtomicUsize::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Conn>> {
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A place for a new connection. When there is none the connection that
    /// has been quiet longest gives up its own, so connections that do
    /// nothing can not keep a client out; `None` when all of them are at
    /// work. The second value says whether one was evicted.
    pub fn admit(self: &Arc<Self>, uid: u32, stream: Arc<UnixStream>) -> Option<(Slot, bool)> {
        let mut conns = self.lock();
        let of_uid = conns.values().filter(|c| c.uid == uid).count();
        let crowded = of_uid >= self.limits.per_uid;
        let full = crowded || conns.len() >= self.limits.connections;
        if full {
            let quiet = conns.iter().filter(|(_, c)| !c.working);
            let fair = quiet.filter(|(_, c)| !crowded || c.uid == uid);
            let (&id, _) = fair.min_by_key(|(_, c)| c.quiet_since)?;
            let gone = conns.remove(&id)?;
            // Its thread wakes to end of stream and says why it is closing.
            let _ = gone.stream.shutdown(std::net::Shutdown::Read);
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let conn = Conn {
            uid,
            stream,
            working: false,
            quiet_since: Instant::now(),
        };
        conns.insert(id, conn);
        let slot = Slot {
            registry: self.clone(),
            id,
        };
        Some((slot, full))
    }
}

/// A connection's place in the [`Registry`], given up when it is dropped.
pub struct Slot {
    registry: Arc<Registry>,
    id: u64,
}

impl Slot {
    pub fn limits(&self) -> &Limits {
        &self.registry.limits
    }

    /// The uid of the connection's peer (`u32::MAX` when the socket did not
    /// tell), for the security log.
    pub fn uid(&self) -> Option<u32> {
        self.registry.lock().get(&self.id).map(|c| c.uid)
    }

    /// Says a request is being answered. False if the connection was evicted
    /// first: the request must not run, whoever sent it is told to send it
    /// again.
    pub fn begin(&self) -> bool {
        let mut conns = self.registry.lock();
        let conn = conns.get_mut(&self.id);
        conn.map(|c| c.working = true).is_some()
    }

    /// The request was answered.
    pub fn end(&self) {
        if let Some(c) = self.registry.lock().get_mut(&self.id) {
            c.working = false;
            c.quiet_since = Instant::now();
        }
    }

    pub fn evicted(&self) -> bool {
        !self.registry.lock().contains_key(&self.id)
    }

    pub fn hold(&self) -> Held<'_> {
        Held {
            registry: &self.registry,
            bytes: 0,
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.id);
    }
}

/// The bytes of one long line, counted against [`Limits::buffered`] until
/// the request is done with.
pub struct Held<'a> {
    registry: &'a Registry,
    bytes: usize,
}

impl Held<'_> {
    /// Grows what is held to `total` bytes, if there is room.
    pub fn grow(&mut self, total: usize) -> bool {
        let more = total.saturating_sub(self.bytes);
        let was = self.registry.buffered.fetch_add(more, Ordering::Relaxed);
        if was + more > self.registry.limits.buffered {
            self.registry.buffered.fetch_sub(more, Ordering::Relaxed);
            return false;
        }
        self.bytes += more;
        true
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let bytes = self.bytes;
        self.registry.buffered.fetch_sub(bytes, Ordering::Relaxed);
    }
}

/// What the first [`SHORT_LINE`] bytes of a line say about it. A line that
/// goes on past them must have named its method and token by then, so a
/// long line is only held for a method that may send one and a caller the
/// daemon knows.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Head {
    pub id: u64,
    pub method: Option<String>,
    pub repo: Option<String>,
    pub token: Option<String>,
}

impl<'de> Visitor<'de> for &mut Head {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a request")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => self.id = map.next_value()?,
                "method" => self.method = map.next_value()?,
                "repo" => self.repo = map.next_value()?,
                "token" => self.token = map.next_value()?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// Reads as far as the bytes go: the line is cut off, so the parse ends in
/// an error and what came before it stands.
pub fn head_of(bytes: &[u8]) -> Head {
    let mut head = Head::default();
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let _ = (&mut de).deserialize_map(&mut head);
    head
}

/// One operation, in the units of a [`Bucket`]: the level grows by the rate
/// in operations a minute every millisecond.
const OP: u64 = 60_000;

/// A token bucket holding a minute's worth of operations.
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    level: u64,
    at_ms: i64,
}

impl Bucket {
    pub fn full(per_minute: u64, now_ms: i64) -> Self {
        Self {
            level: per_minute * OP,
            at_ms: now_ms,
        }
    }

    /// Takes one operation; `Err` is how many milliseconds until there is one.
    pub fn take(&mut self, per_minute: u64, now_ms: i64) -> Result<(), u64> {
        let passed = now_ms.saturating_sub(self.at_ms).max(0) as u64;
        let grown = self.level.saturating_add(passed.saturating_mul(per_minute));
        self.level = grown.min(per_minute * OP);
        self.at_ms = now_ms;
        match self.level.checked_sub(OP) {
            Some(left) => {
                self.level = left;
                Ok(())
            }
            None => Err((OP - self.level).div_ceil(per_minute)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream() -> Arc<UnixStream> {
        Arc::new(UnixStream::pair().unwrap().0)
    }

    fn limits(connections: usize, per_uid: usize) -> Limits {
        Limits {
            connections,
            per_uid,
            ..Limits::default()
        }
    }

    #[test]
    fn file_descriptors_decide_the_connections() {
        let few = Limits::for_files(256);
        assert_eq!((few.connections, few.per_uid), (128, 128));
        let some = Limits::for_files(1600);
        assert_eq!((some.connections, some.per_uid), (800, 512));
        let many = Limits::for_files(1 << 20);
        assert_eq!((many.connections, many.per_uid), (1024, 512));
    }

    #[test]
    fn the_daemon_asks_for_descriptors() {
        let files = open_files();
        assert!(files >= 256, "{files}");
    }

    #[test]
    fn the_quietest_connection_makes_room() {
        let r = Registry::new(limits(2, 2));
        let a = stream();
        let (first, cut) = r.admit(1, a.clone()).unwrap();
        assert!(!cut);
        let (second, cut) = r.admit(1, stream()).unwrap();
        assert!(!cut);
        std::thread::sleep(Duration::from_millis(2));
        first.begin();
        first.end(); // the first has been quiet for less time now
        let (_third, cut) = r.admit(1, stream()).unwrap();
        assert!(cut);
        assert!(!first.evicted());
        assert!(second.evicted());
        assert!(!second.begin(), "evicted: its request must not run");
    }

    #[test]
    fn a_connection_at_work_is_never_cut() {
        let r = Registry::new(limits(1, 1));
        let (slot, _) = r.admit(1, stream()).unwrap();
        assert!(slot.begin());
        assert!(r.admit(1, stream()).is_none());
        slot.end();
        assert!(r.admit(1, stream()).is_some());
    }

    #[test]
    fn a_uid_at_its_cap_gives_up_its_own() {
        let r = Registry::new(limits(8, 1));
        let (other, _) = r.admit(2, stream()).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let (mine, cut) = r.admit(1, stream()).unwrap();
        assert!(!cut);
        std::thread::sleep(Duration::from_millis(2));
        let (_next, cut) = r.admit(1, stream()).unwrap();
        assert!(cut);
        assert!(mine.evicted());
        assert!(!other.evicted(), "older, but another uid's");
    }

    #[test]
    fn a_full_daemon_takes_the_quietest_of_any_uid() {
        let r = Registry::new(limits(1, 8));
        let (other, _) = r.admit(2, stream()).unwrap();
        let (_mine, cut) = r.admit(1, stream()).unwrap();
        assert!(cut);
        assert!(other.evicted());
    }

    #[test]
    fn eviction_ends_the_reads_of_the_connection() {
        use std::io::Read;
        let (a, _keep) = UnixStream::pair().unwrap();
        let a = Arc::new(a);
        let r = Registry::new(limits(1, 1));
        let (_slot, _) = r.admit(1, a.clone()).unwrap();
        let _next = r.admit(1, stream()).unwrap();
        assert_eq!((&*a).read(&mut [0; 8]).unwrap(), 0);
    }

    #[test]
    fn a_slot_gives_its_place_back() {
        let r = Registry::new(limits(1, 1));
        let (slot, _) = r.admit(1, stream()).unwrap();
        slot.begin();
        drop(slot);
        let (_slot, cut) = r.admit(1, stream()).unwrap();
        assert!(!cut);
    }

    #[test]
    fn long_lines_share_a_budget() {
        let r = Registry::new(Limits {
            buffered: 100,
            ..Limits::default()
        });
        let (slot, _) = r.admit(1, stream()).unwrap();
        let mut a = slot.hold();
        assert!(a.grow(60));
        assert!(a.grow(100), "its own bytes are not counted twice");
        let mut b = slot.hold();
        assert!(!b.grow(1));
        drop(a);
        assert!(b.grow(100), "a line done with gives its room back");
        assert!(!b.grow(101));
        assert!(b.grow(100));
    }

    #[test]
    fn a_head_reads_what_comes_before_the_cut() {
        let line = br#"{"id":7,"method":"tree","repo":"r","token":"t","params":{"paths":["a","#;
        let want = Head {
            id: 7,
            method: Some("tree".into()),
            repo: Some("r".into()),
            token: Some("t".into()),
        };
        assert_eq!(head_of(line), want);
        // Sorted keys, as a generic JSON map writes them: no token yet.
        let sorted = br#"{"id":1,"method":"blobs","params":{"paths":["a","#;
        let head = head_of(sorted);
        assert_eq!(head.method.as_deref(), Some("blobs"));
        assert_eq!(head.token, None);
        assert_eq!(head_of(b"nonsense"), Head::default());
        assert_eq!(head_of(br#"{"params":{"x":"#), Head::default());
    }

    #[test]
    fn what_a_head_expects_is_a_request() {
        let mut head = Head::default();
        let mut de = serde_json::Deserializer::from_slice(b"1");
        let e = (&mut de).deserialize_map(&mut head).unwrap_err();
        assert!(e.to_string().contains("expected a request"), "{e}");
    }

    #[test]
    fn a_bucket_lets_a_minute_through_and_then_the_rate() {
        let mut b = Bucket::full(60, 0);
        for _ in 0..60 {
            assert_eq!(b.take(60, 0), Ok(()));
        }
        assert_eq!(b.take(60, 0), Err(1000));
        assert_eq!(b.take(60, 400), Err(600));
        assert_eq!(b.take(60, 1000), Ok(()));
        assert_eq!(b.take(60, 1000), Err(1000));
    }

    #[test]
    fn a_bucket_holds_no_more_than_a_minute() {
        let mut b = Bucket::full(2, 0);
        assert_eq!(b.take(2, 10_000_000), Ok(()));
        assert_eq!(b.take(2, 10_000_000), Ok(()));
        assert!(b.take(2, 10_000_000).is_err());
    }

    #[test]
    fn a_clock_that_goes_back_adds_nothing() {
        let mut b = Bucket::full(1, 1_000_000);
        assert_eq!(b.take(1, 1_000_000), Ok(()));
        assert_eq!(b.take(1, 0), Err(60_000));
    }

    #[test]
    fn a_lower_rate_cuts_what_was_saved() {
        let mut b = Bucket::full(600, 0);
        assert_eq!(b.take(1, 0), Ok(()));
        assert_eq!(b.take(1, 0), Err(60_000));
    }

    #[test]
    fn counters_show_each_refusal() {
        let c = Counters::default();
        Counters::add(&c.busy);
        Counters::add(&c.too_large);
        Counters::add(&c.too_large);
        let shown = c.to_json();
        assert_eq!(shown["busy"], 1);
        assert_eq!(shown["too_large"], 2);
        assert_eq!(shown["rate_limited"], 0);
    }
}
