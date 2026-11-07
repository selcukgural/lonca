//! What a command leaves running in its sandbox, on macOS. On Linux the
//! sandbox's pid namespace goes with the command and takes everything in it;
//! Seatbelt has nothing like that, and a process that forked twice and left
//! its session is out of reach of any signal to a group.
//!
//! So a sandbox is told by its profile: it allows a Mach name that only this
//! run uses, and the operating system answers for any process whether its
//! profile allows that name. A process can not shed the mark: a sandbox stays
//! over `exec`, and nothing in one can start another.
//!
//! Apart from `run.rs` because mutation testing runs on Linux, where none of
//! this is compiled: `.cargo/mutants.toml` leaves this file out, and the
//! end-to-end tests of `lonca run` hold it on macOS.

/// Ends every process in the sandbox marked `mark`, and what they start
/// meanwhile. Returns how many would not end.
#[cfg(target_os = "macos")]
pub fn end_what_is_left(mark: &str) -> usize {
    use std::ffi::CString;
    use std::time::Duration;
    let (Ok(name), Ok(other)) = (CString::new(mark), CString::new(format!("{mark}.other"))) else {
        return 0;
    };
    let mut left = 0;
    for _ in 0..ROUNDS {
        let found: Vec<libc::pid_t> = all_pids()
            .into_iter()
            .filter(|&pid| in_sandbox_of(pid, &name, &other))
            .collect();
        left = found.len();
        if left == 0 {
            break;
        }
        for pid in found {
            // SAFETY: `kill` takes no pointers.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    left
}

/// Each round ends what it saw, which takes care of what those started. A
/// chain that forks and exits outruns any number of rounds, so this ends:
/// the caller says what was left.
#[cfg(target_os = "macos")]
const ROUNDS: usize = 200;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, kind: i32, ...) -> i32;
}

/// `SANDBOX_FILTER_GLOBAL_NAME`, and `SANDBOX_CHECK_NO_REPORT`: a question,
/// not a violation for the system log.
#[cfg(target_os = "macos")]
const BY_NAME: i32 = 2 | 0x4000_0000;

/// Whether `pid` lives in the sandbox that allows `mark`. `other` is asked
/// too: an application whose sandbox allows every Mach name would pass for
/// this one, and this ends what it finds. A zombie has no path.
#[cfg(target_os = "macos")]
fn in_sandbox_of(pid: libc::pid_t, mark: &std::ffi::CStr, other: &std::ffi::CStr) -> bool {
    let lookup = c"mach-lookup".as_ptr();
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the strings outlive the calls and `path` is live, its size
    // passed with it; a null operation asks whether `pid` is sandboxed at all.
    unsafe {
        sandbox_check(pid, std::ptr::null(), 0) == 1
            && sandbox_check(pid, lookup, BY_NAME, mark.as_ptr()) == 0
            && sandbox_check(pid, lookup, BY_NAME, other.as_ptr()) == 1
            && libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) > 0
    }
}

#[cfg(target_os = "macos")]
fn all_pids() -> Vec<libc::pid_t> {
    let size = std::mem::size_of::<libc::pid_t>();
    // SAFETY: a null buffer asks only for the number.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let mut pids = vec![0; count.max(0) as usize + 256];
    let bytes = (pids.len() * size) as libc::c_int;
    // SAFETY: `pids` is live and `bytes` is its size.
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(got.max(0) as usize);
    pids
}

/// On Linux nothing is left: see above.
#[cfg(not(target_os = "macos"))]
pub fn end_what_is_left(_: &str) -> usize {
    0
}
