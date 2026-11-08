//! The calls into libc a client needs: who it is, and who is on the other
//! end of a socket. Unsafe code is refused in the rest of the workspace
//! (`[workspace.lints]`); each block here says why it is sound.

#![allow(unsafe_code)]

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// The real uid of this process.
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and can not fail.
    unsafe { libc::getuid() }
}

/// The credentials of the process on the other end of `s` (Linux).
#[cfg(target_os = "linux")]
pub fn peer_cred(s: &UnixStream) -> Option<libc::ucred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is a socket that lives as long as `s`; `cred`
    // and `len` are live, and `len` holds the size of `cred`.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    (rc == 0).then_some(cred)
}

/// The uid of the process on the other end of a Unix socket.
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        peer_cred(s).map(|c| c.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: the descriptor is a socket that lives as long as `s`; the
        // out pointers point to live stack variables.
        let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_of_a_pair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a), Some(current_uid()));
    }
}
