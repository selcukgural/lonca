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
//! `lonca run` and the verifier both end with this. It is a file of its own
//! because mutation testing runs on Linux, where none of this is compiled:
//! `.cargo/mutants.toml` leaves this file out, and the end-to-end tests of
//! `lonca run` and the verifier's own hold it on macOS.

// Process control is libc calls; each unsafe block says why it is sound.
#![allow(unsafe_code)]

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
/// this one, and this ends what it finds. A zombie needs no ending: it stays
/// until its parent looks.
#[cfg(target_os = "macos")]
fn in_sandbox_of(pid: libc::pid_t, mark: &std::ffi::CStr, other: &std::ffi::CStr) -> bool {
    let lookup = c"mach-lookup".as_ptr();
    // SAFETY: the strings outlive the calls; a null operation asks whether
    // `pid` is sandboxed at all.
    let marked = unsafe {
        sandbox_check(pid, std::ptr::null(), 0) == 1
            && sandbox_check(pid, lookup, BY_NAME, mark.as_ptr()) == 0
            && sandbox_check(pid, lookup, BY_NAME, other.as_ptr()) == 1
    };
    marked && !is_zombie(pid)
}

/// Asked of the process itself: a path says nothing, since a live process
/// whose program was deleted has none either. What can not be asked is not
/// taken for a zombie.
#[cfg(target_os = "macos")]
fn is_zombie(pid: libc::pid_t) -> bool {
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: an all-zero `proc_bsdinfo` is valid, it is live, and its size
    // goes with it.
    let (got, info) = unsafe {
        let mut info: libc::proc_bsdinfo = std::mem::zeroed();
        let buffer = (&raw mut info).cast();
        let got = libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, buffer, size);
        (got, info)
    };
    got == size && info.pbi_status == libc::SZOMB
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

/// Ends what is left in the sandbox marked `mark`, and says for the evidence
/// what would not end.
pub fn what_would_not_end(mark: &str) -> Option<(String, String)> {
    let left = end_what_is_left(mark);
    (left > 0).then(|| ("left_running".into(), left.to_string()))
}
