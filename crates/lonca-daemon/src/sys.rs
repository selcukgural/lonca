//! Every call into libc the daemon makes, apart from `peer_other.rs`
//! (macOS sandbox questions) and the client's own (`lonca_client::sys`,
//! re-exported here). Unsafe code is refused in the rest of the workspace
//! (`[workspace.lints]`); each block here says why it is sound.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
pub use lonca_client::sys::peer_cred;
pub use lonca_client::sys::{current_uid, peer_uid};

/// Raises the soft limit on open descriptors to `wanted`, as far as the
/// hard limit goes, and returns the soft limit in force afterwards.
pub fn raise_open_files(wanted: u64) -> u64 {
    let mut l = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: every call reads or writes the one live struct above.
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut l);
        l.rlim_cur = l.rlim_cur.max(wanted.min(l.rlim_max));
        libc::setrlimit(libc::RLIMIT_NOFILE, &l);
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut l);
    }
    l.rlim_cur
}

/// Sends `signal` to every process of the group `group`.
pub fn kill_group(group: libc::pid_t, signal: libc::c_int) {
    // SAFETY: `kill` takes no pointers.
    unsafe { libc::kill(-group, signal) };
}

/// The gid of the group called `name`, looked up with the re-entrant
/// `getgrnam_r`: the static buffer of `getgrnam` is shared by every thread.
pub fn group_named(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut size = 1024usize;
    // A group with many members needs a larger buffer: grow it, to a bound.
    while size <= 1 << 20 {
        let mut buf = vec![0 as libc::c_char; size];
        // SAFETY: an all-zero `group` is valid (null pointers, zero gid);
        // getgrnam_r writes only into it and into `buf`, whose length it is
        // told, and sets `found` to null or to `&mut group`.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::group = std::ptr::null_mut();
        // SAFETY: as above; `c` is NUL-terminated and outlives the call.
        let rc = unsafe {
            libc::getgrnam_r(
                c.as_ptr(),
                &mut group,
                buf.as_mut_ptr(),
                buf.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE {
            size *= 4;
            continue;
        }
        return (rc == 0 && !found.is_null()).then_some(group.gr_gid);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_peer_of_a_pair_is_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a), Some(current_uid()));
    }

    #[test]
    fn groups_resolve_by_name() {
        assert!(group_named("wheel").is_some() || group_named("root").is_some());
        assert_eq!(group_named("no-such-group-lonca"), None);
        assert_eq!(group_named("bad\0name"), None);
    }

    #[test]
    fn the_descriptor_limit_never_falls() {
        let before = raise_open_files(0);
        assert!(before > 0);
        assert!(raise_open_files(before + 1) >= before);
    }
}
