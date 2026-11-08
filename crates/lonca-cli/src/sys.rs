//! Every call into libc the command line makes. Unsafe code is refused in
//! the rest of the workspace (`[workspace.lints]`); each block here says why
//! it is sound.

#![allow(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Makes `command` start a session of its own and close every descriptor
/// past standard error before it runs.
pub fn new_session_closing_from(command: &mut Command, close_from: libc::c_int) {
    // SAFETY: between fork and exec, this calls only async-signal-safe
    // functions and touches no memory shared with the parent.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let top = libc::sysconf(libc::_SC_OPEN_MAX).clamp(256, 65536) as libc::c_int;
            for fd in close_from..top {
                libc::close(fd);
            }
            Ok(())
        });
    }
}

/// Sends `signal` to every process of the group `group`.
pub fn kill_group(group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` takes no pointers.
    unsafe { libc::kill(-group, signal) };
}

/// Whether a process `pid` exists (signal 0 only asks).
#[cfg(test)]
pub fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: `kill` takes no pointers; signal 0 sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The session id of `pid` (0: this process).
#[cfg(test)]
pub fn session_of(pid: libc::pid_t) -> libc::pid_t {
    // SAFETY: `getsid` takes a pid and no pointers.
    unsafe { libc::getsid(pid) }
}

/// Calls `handler` for each of `signals`. The handler must be
/// async-signal-safe: storing to an atomic is.
pub fn on_signals(signals: &[libc::c_int], handler: extern "C" fn(libc::c_int)) {
    for &s in signals {
        // SAFETY: `handler` is a plain function that lives for the program.
        unsafe { libc::signal(s, handler as *const () as libc::sighandler_t) };
    }
}
