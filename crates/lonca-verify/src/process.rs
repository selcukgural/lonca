//! One command from start to end. Nothing of it outlives it: it starts as a
//! session, its group is killed whichever way the command ends, and reading
//! its output stops soon after, whoever still holds the pipe. A command that
//! was never heard of again would stand in the queue for good.

// Process control is libc calls; each unsafe block says why it is sound.
#![allow(unsafe_code)]

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
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

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

/// How a command ended.
pub struct Ended {
    /// `None` when it ran out of time.
    pub status: Option<ExitStatus>,
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

/// Starts `command` as a session of its own, under the limits of `cfg`. A
/// session, not only a group: the leader of a group can move to another one
/// of its session and leave nothing for a kill to reach, and the leader of a
/// session can not move. Stdout and stderr share a pipe, the one way to have
/// them in the order they were written.
pub fn start(mut command: Command, cfg: &Verification) -> io::Result<Running> {
    let limits: Vec<(Resource, libc::rlimit)> = wanted(cfg)
        .into_iter()
        .map(|(resource, value)| (resource, held_to(value, in_force(resource))))
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
    ];
    // On macOS one counts every process of the account, and the other is
    // refused below what a process maps at its start, so every spawn fails.
    if cfg!(target_os = "linux") {
        all.push((libc::RLIMIT_NPROC, cfg.limit_processes));
        all.push((libc::RLIMIT_AS, cfg.limit_address_bytes));
    }
    all.retain(|&(_, value)| value != 0);
    all
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

/// Follows a command to its end, or to `timeout`, and ends all of it. `mark`
/// names its sandbox, where something can have left the group.
pub fn watch(running: Running, timeout: Duration, mark: Option<&str>) -> Ended {
    let started = Instant::now();
    let Running { mut child, output } = running;
    let pid = child.id();
    let mut pipe = Some(output);
    let mut tail = Tail::default();
    let mut timed_out = false;
    let mut left = None;
    let mut killed_at = None;
    loop {
        pump(&mut pipe, &mut tail);
        match killed_at {
            None => {
                let exited = has_exited(pid);
                timed_out = !exited && past(started.elapsed(), timeout);
                if exited || timed_out {
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
        status: reaped(&mut child).filter(|_| !timed_out),
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
        ];
        if cfg!(target_os = "linux") {
            expected.push((libc::RLIMIT_NPROC, 3));
            expected.push((libc::RLIMIT_AS, 2));
        }
        assert_eq!(wanted(&cfg()), expected);
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
