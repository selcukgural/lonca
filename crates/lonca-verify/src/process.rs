//! One command from start to end. Nothing of it outlives it: it starts as a
//! session, its group is killed whichever way the command ends, and reading
//! its output stops soon after, whoever still holds the pipe. A command that
//! was never heard of again would stand in the queue for good.

// Process control is libc calls; each unsafe block says why it is sound.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use lonca_policy::config::Verification;

use crate::sweep;

/// How much of a command's output is kept: its end says why it failed.
pub const OUTPUT_TAIL: usize = 64 * 1024;

/// How long output is still read for once the group is killed. What is not
/// in it can only be something that left the group and holds the pipes.
const GRACE: Duration = Duration::from_secs(1);

/// How long one look at the pipe waits, and so how late an exit is seen.
const POLL_MS: libc::c_int = 20;

/// Sees that the leader ended and leaves it unreaped: a group's id can not
/// be taken by anyone else while its leader is a zombie.
const SEE_EXIT: libc::c_int = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;

/// What the account keeps of its processes whatever a command forks. The
/// limit counts every process of the account, the daemon's and those of the
/// person at the machine, so this is what they can still start.
pub const KEEP_PROCESSES: u64 = 256;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

/// How a command ended.
pub struct Ended {
    /// `None` when it was stopped, or when its end was not seen: out of time.
    pub status: Option<ExitStatus>,
    /// Stopped because the disk came down to what it must keep free.
    pub out_of_room: bool,
    /// The end of its output, stdout and stderr as they were written.
    pub output: Vec<u8>,
    /// For the evidence, when something of it would not end.
    pub left: Option<(String, String)>,
}

/// A command under way.
pub struct Running {
    child: Child,
    output: File,
}

/// The disk a command writes to, and what it must leave free there.
pub struct Room<'a> {
    pub dir: &'a Path,
    pub keep: u64,
}

impl Room<'_> {
    /// Whether the disk is down to what it must keep. One that can not be
    /// asked counts as full: a command does not write on unseen.
    pub fn is_short(&self) -> bool {
        short_of(free_bytes(self.dir), self.keep)
    }
}

fn short_of(free: Option<u64>, keep: u64) -> bool {
    free.is_none_or(|free| free < keep)
}

/// The bytes on the disk of `dir` that a process without privileges may
/// still write.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    // macOS: `statvfs` has 32-bit counts there, `statfs` does not.
    #[cfg(target_os = "macos")]
    {
        // SAFETY: an all-zero `statfs` is valid, and the path outlives the
        // call.
        let mut s: libc::statfs = unsafe { std::mem::zeroed() };
        let got = unsafe { libc::statfs(path.as_ptr(), &mut s) };
        (got == 0).then(|| s.f_bavail.saturating_mul(u64::from(s.f_bsize)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: as above.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        let got = unsafe { libc::statvfs(path.as_ptr(), &mut s) };
        (got == 0).then(|| (s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
    }
}

/// Removes `dir` and all in it, whatever a command did to keep it there: a
/// directory it closed (`chmod 0`) and, on macOS, what it made unchangeable
/// (`chflags uchg`). A directory that will not go keeps its disk space from
/// every later run. Links are not followed, and the walk keeps its own list:
/// a command can nest directories deeper than any stack.
pub fn remove_tree(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut todo = vec![dir.to_path_buf()];
    while let Some(path) = todo.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        unflag(&path);
        if meta.is_dir() {
            // The path is a directory, not a link, so this changes only it.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
            let entries = std::fs::read_dir(&path).into_iter().flatten();
            todo.extend(entries.flatten().map(|e| e.path()));
        }
    }
    std::fs::remove_dir_all(dir)
}

/// macOS: clears the flags an owner may set, `uchg` and `uappnd` among them;
/// a link's own, not what it points at.
#[cfg(target_os = "macos")]
fn unflag(path: &Path) {
    let Ok(name) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: the path outlives the call.
    unsafe { libc::lchflags(name.as_ptr(), 0) };
}

/// Linux: a flag that keeps a file takes a privilege to set.
#[cfg(not(target_os = "macos"))]
fn unflag(_: &Path) {}

/// Starts `command` as a session of its own, under the limits of `cfg`. A
/// session, not only a group: the leader of a group can move to another one
/// of its session and leave nothing for a kill to reach, and the leader of a
/// session can not move. Stdout and stderr share a pipe, the one way to have
/// them in the order they were written.
pub fn start(mut command: Command, cfg: &Verification) -> io::Result<Running> {
    let limits: Vec<(Resource, libc::rlimit)> = wanted(cfg)
        .into_iter()
        .map(|(resource, value)| {
            let now = in_force(resource);
            let value = match resource == libc::RLIMIT_NPROC {
                true => processes(value, now.rlim_cur, per_account()),
                false => value,
            };
            (resource, held_to(value, now))
        })
        .collect();
    let (output, input) = io::pipe()?;
    command
        .stdin(Stdio::null())
        .stdout(input.try_clone()?)
        .stderr(input);
    // SAFETY: between fork and exec this only makes system calls: `limits`
    // is read and not allocated, and a failure is an errno. `setsid` fails
    // only for the leader of a group, which a forked child is not. A limit
    // that can not be set fails the spawn: the command does not run without.
    unsafe {
        command.pre_exec(move || {
            libc::setsid();
            first_to_go()?;
            for (resource, limit) in &limits {
                if libc::setrlimit(*resource, limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    Ok(Running {
        child,
        output: reader(output),
    })
}

/// The limits `cfg` sets: 0 sets none.
fn wanted(cfg: &Verification) -> Vec<(Resource, u64)> {
    let mut all = vec![
        (libc::RLIMIT_CPU, cfg.limit_cpu_seconds),
        (libc::RLIMIT_FSIZE, cfg.limit_file_bytes),
        (libc::RLIMIT_NOFILE, cfg.limit_open_files),
        (libc::RLIMIT_NPROC, cfg.limit_processes),
    ];
    // macOS refuses it below what a process maps at its start, so every
    // spawn would fail.
    if cfg!(target_os = "linux") {
        all.push((libc::RLIMIT_AS, cfg.limit_address_bytes));
    }
    all.retain(|&(_, value)| value != 0);
    all
}

/// `wanted` processes for the account, and never so many that it is left
/// with fewer than [`KEEP_PROCESSES`] of the most it may have: its limit in
/// force, and the system's for one account where there is one.
fn processes(wanted: u64, in_force: u64, per_account: Option<u64>) -> u64 {
    let most = per_account.map_or(in_force, |system| system.min(in_force));
    wanted.min(most.saturating_sub(KEEP_PROCESSES))
}

/// macOS holds an account to `kern.maxprocperuid` whatever its limit says.
#[cfg(target_os = "macos")]
fn per_account() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: `value` is live and `size` is its size; nothing is set.
    let got = unsafe {
        libc::sysctlbyname(
            c"kern.maxprocperuid".as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (got == 0 && value > 0).then_some(value as u64)
}

/// Linux has no limit for one account but `RLIMIT_NPROC`.
#[cfg(not(target_os = "macos"))]
fn per_account() -> Option<u64> {
    None
}

/// Linux: when memory runs out, the kernel ends the command's processes
/// before anything else, the daemon among them. Nothing else bounds the
/// memory of a command as a whole, nor what it keeps in a memory file
/// system. Any process may raise its own; only lowering it takes a
/// privilege. Between fork and exec: system calls only.
#[cfg(target_os = "linux")]
fn first_to_go() -> io::Result<()> {
    let flags = libc::O_WRONLY | libc::O_CLOEXEC;
    // SAFETY: the path is a C string literal, and `fd` is closed below.
    let fd = unsafe { libc::open(c"/proc/self/oom_score_adj".as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let most = b"1000";
    // SAFETY: `most` is live and its length goes with it.
    let wrote = unsafe { libc::write(fd, most.as_ptr().cast(), most.len()) };
    let error = io::Error::last_os_error();
    // SAFETY: `fd` was opened above and is not used after.
    unsafe { libc::close(fd) };
    match wrote == most.len() as isize {
        true => Ok(()),
        false => Err(error),
    }
}

/// macOS has no such order to set.
#[cfg(not(target_os = "linux"))]
fn first_to_go() -> io::Result<()> {
    Ok(())
}

fn in_force(resource: Resource) -> libc::rlimit {
    let mut now = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `now` is live. If it fails the values stay as they are, and
    // setting a limit past the hard one fails the spawn.
    unsafe { libc::getrlimit(resource, &mut now) };
    now
}

/// `wanted`, never above what is in force: raising a hard limit is refused,
/// and a limit the daemon was started under is someone's choice.
fn held_to(wanted: u64, now: libc::rlimit) -> libc::rlimit {
    libc::rlimit {
        rlim_cur: wanted.min(now.rlim_cur),
        rlim_max: wanted.min(now.rlim_max),
    }
}

/// Follows a command to its end, to `timeout`, or to the disk coming down
/// to what `room` keeps, and ends all of it. `mark` names its sandbox, where
/// something can have left the group.
pub fn watch(
    running: Running,
    timeout: Duration,
    room: Option<&Room>,
    mark: Option<&str>,
) -> Ended {
    let started = Instant::now();
    let Running { mut child, output } = running;
    let pid = child.id();
    let mut pipe = Some(output);
    let mut tail = Tail::default();
    let mut stopped = false;
    let mut out_of_room = false;
    let mut left = None;
    let mut killed_at = None;
    loop {
        pump(&mut pipe, &mut tail);
        match killed_at {
            None => {
                let exited = has_exited(pid);
                out_of_room = !exited && room.is_some_and(Room::is_short);
                stopped = !exited && (out_of_room || past(started.elapsed(), timeout));
                if exited || stopped {
                    kill_group(pid);
                    left = mark.and_then(sweep::what_would_not_end);
                    killed_at = Some(Instant::now());
                }
            }
            Some(at) => {
                // Again: a kill can miss what is being forked as it runs.
                kill_group(pid);
                if past(at.elapsed(), GRACE) || pipe.is_none() {
                    break;
                }
            }
        }
    }
    Ended {
        status: reaped(&mut child).filter(|_| !stopped),
        out_of_room,
        output: tail.into_bytes(),
        left,
    }
}

/// The status of a killed leader, in the time that takes: a process can be
/// kept from ending, and this must not wait with it. One that is not seen to
/// end has no status, which is what running out of time is.
fn reaped(child: &mut Child) -> Option<ExitStatus> {
    let started = Instant::now();
    while !past(started.elapsed(), GRACE) {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(POLL_MS as u64));
    }
    None
}

fn past(elapsed: Duration, limit: Duration) -> bool {
    elapsed > limit
}

fn reader(pipe: impl Into<OwnedFd>) -> File {
    let fd = pipe.into();
    // SAFETY: `fd` is open and owned here, and this takes no pointers.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
    File::from(fd)
}

/// Waits for output, up to [`POLL_MS`], and takes what there is.
fn pump(pipe: &mut Option<File>, tail: &mut Tail) {
    let mut open: Vec<libc::pollfd> = pipe
        .iter()
        .map(|file| libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: `open` is live and its length goes with it. With the pipe
    // closed this only waits.
    unsafe { libc::poll(open.as_mut_ptr(), open.len() as libc::nfds_t, POLL_MS) };
    read_some(pipe, tail);
}

/// One read, so that output can not keep the clock waiting.
fn read_some(pipe: &mut Option<File>, tail: &mut Tail) {
    let Some(file) = pipe else {
        return;
    };
    let mut buffer = [0; OUTPUT_TAIL];
    let closed = match file.read(&mut buffer) {
        Ok(0) => true,
        Ok(read) => {
            tail.push(&buffer[..read]);
            false
        }
        Err(e) => ends_a_pipe(e.kind()),
    };
    if closed {
        *pipe = None;
    }
}

fn ends_a_pipe(kind: ErrorKind) -> bool {
    !matches!(kind, ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

/// Whether the group's leader has ended. An error counts: a child that can
/// not be asked after must not hold the run until its timeout.
fn has_exited(pid: u32) -> bool {
    // SAFETY: an all-zero `siginfo_t` is valid, and stays so if nothing ended.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is live.
    let asked = unsafe { libc::waitid(libc::P_PID, pid, &mut info, SEE_EXIT) };
    asked != 0 || info.si_signo != 0
}

fn kill_group(pid: u32) {
    // SAFETY: `kill` takes no pointers. The group's leader is not reaped
    // before the last of these, so its id is still the group's.
    unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
}

/// The end of the output, however much of it there is.
#[derive(Default)]
struct Tail(VecDeque<u8>);

impl Tail {
    fn push(&mut self, bytes: &[u8]) {
        self.0.extend(bytes);
        let over = self.0.len().saturating_sub(OUTPUT_TAIL);
        self.0.drain(..over);
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Verification {
        Verification {
            limit_cpu_seconds: 1,
            limit_address_bytes: 2,
            limit_processes: 3,
            limit_file_bytes: 4,
            limit_open_files: 5,
            ..Default::default()
        }
    }

    #[test]
    fn each_limit_sets_its_own_resource() {
        let mut expected = vec![
            (libc::RLIMIT_CPU, 1),
            (libc::RLIMIT_FSIZE, 4),
            (libc::RLIMIT_NOFILE, 5),
            (libc::RLIMIT_NPROC, 3),
        ];
        if cfg!(target_os = "linux") {
            expected.push((libc::RLIMIT_AS, 2));
        }
        assert_eq!(wanted(&cfg()), expected);
    }

    #[test]
    fn the_account_keeps_room_to_start_processes() {
        let keep = KEEP_PROCESSES;
        // Below what the account may have, the policy's figure stands.
        assert_eq!(processes(100, 10_000, None), 100);
        assert_eq!(processes(10_000 - keep, 10_000, None), 10_000 - keep);
        // At or past it, the account keeps its share.
        assert_eq!(processes(10_000 - keep + 1, 10_000, None), 10_000 - keep);
        assert_eq!(processes(16_384, 10_000, None), 10_000 - keep);
        // The system's limit for one account counts when it is the lower.
        assert_eq!(processes(16_384, 10_000, Some(8_000)), 8_000 - keep);
        assert_eq!(processes(16_384, 8_000, Some(10_000)), 8_000 - keep);
        // No limit in force: only the policy's.
        assert_eq!(processes(16_384, libc::RLIM_INFINITY, None), 16_384);
        // An account with less than its share starts nothing.
        assert_eq!(processes(16_384, keep - 1, None), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_says_what_one_account_may_have() {
        assert!(per_account().is_some_and(|n| n > KEEP_PROCESSES));
    }

    #[test]
    fn a_tree_goes_whatever_was_done_to_keep_it() {
        use std::os::unix::fs::PermissionsExt;
        let here = tempfile::tempdir().unwrap();
        let outside = here.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("kept"), "").unwrap();
        let dir = here.path().join("run");
        let mut deep = dir.clone();
        for _ in 0..50 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("f"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
        let closed = dir.join("closed");
        std::fs::create_dir(&closed).unwrap();
        std::fs::write(closed.join("f"), "x").unwrap();
        #[cfg(target_os = "macos")]
        {
            let fixed = dir.join("fixed");
            std::fs::write(&fixed, "x").unwrap();
            let name = CString::new(fixed.as_os_str().as_bytes()).unwrap();
            // SAFETY: the path outlives the call.
            assert_eq!(
                unsafe { libc::chflags(name.as_ptr(), libc::UF_IMMUTABLE) },
                0
            );
            assert!(std::fs::remove_file(&fixed).is_err(), "it is not kept");
        }
        let mode = |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m));
        mode(&closed, 0o000).unwrap();
        mode(&deep, 0o000).unwrap();
        assert!(std::fs::remove_dir_all(&dir).is_err(), "nothing kept it");
        remove_tree(&dir).unwrap();
        assert!(!dir.exists());
        // What a link pointed at stays as it was.
        assert!(outside.join("kept").exists());
        let outside_mode = std::fs::metadata(&outside).unwrap().permissions().mode();
        assert_ne!(outside_mode & 0o777, 0o700);
    }

    #[test]
    fn a_disk_is_short_once_it_has_less_than_it_keeps() {
        assert!(!short_of(Some(11), 10));
        assert!(!short_of(Some(10), 10));
        assert!(short_of(Some(9), 10));
        assert!(!short_of(Some(0), 0));
        assert!(short_of(None, 0), "what can not be asked is full");
        let here = tempfile::tempdir().unwrap();
        assert!(free_bytes(here.path()).is_some_and(|n| n > 0));
        assert_eq!(free_bytes(&here.path().join("no-such-dir")), None);
        let room = |keep| Room {
            dir: here.path(),
            keep,
        };
        assert!(!room(0).is_short());
        assert!(room(u64::MAX).is_short());
    }

    #[test]
    fn zero_sets_no_limit() {
        let off = Verification {
            limit_address_bytes: 0,
            limit_processes: 0,
            ..cfg()
        };
        let expected = vec![
            (libc::RLIMIT_CPU, 1),
            (libc::RLIMIT_FSIZE, 4),
            (libc::RLIMIT_NOFILE, 5),
        ];
        assert_eq!(wanted(&off), expected);
    }

    #[test]
    fn a_limit_in_force_is_never_raised() {
        let got = |wanted, rlim_cur, rlim_max| {
            let now = libc::rlimit { rlim_cur, rlim_max };
            let held = held_to(wanted, now);
            (held.rlim_cur, held.rlim_max)
        };
        assert_eq!(got(5, 10, 20), (5, 5));
        assert_eq!(got(15, 10, 20), (10, 15));
        assert_eq!(got(25, 10, 20), (10, 20));
    }

    #[test]
    fn a_limit_is_past_only_once_it_is_over() {
        let limit = Duration::from_secs(1);
        assert!(!past(limit - Duration::from_nanos(1), limit));
        assert!(!past(limit, limit));
        assert!(past(limit + Duration::from_nanos(1), limit));
    }

    #[test]
    fn only_a_pipe_with_nothing_yet_stays_open() {
        assert!(!ends_a_pipe(ErrorKind::WouldBlock));
        assert!(!ends_a_pipe(ErrorKind::Interrupted));
        assert!(ends_a_pipe(ErrorKind::BrokenPipe));
    }

    #[test]
    fn the_tail_keeps_the_end_and_no_more() {
        let mut tail = Tail::default();
        tail.push(&[1; OUTPUT_TAIL]);
        tail.push(&[2, 3]);
        let bytes = tail.into_bytes();
        assert_eq!(bytes.len(), OUTPUT_TAIL);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[OUTPUT_TAIL - 2..], [2, 3]);
    }

    #[test]
    fn what_fits_is_kept_whole() {
        let mut tail = Tail::default();
        tail.push(b"ab");
        tail.push(b"c");
        assert_eq!(tail.into_bytes(), b"abc");
    }
}
