//! Where a path really is: what a hook program answers when the daemon
//! asks (`"phase": "resolve"` of `hook.input`). The daemon places a tool's
//! path inside or outside the workspace, and it often can not see the
//! workspace itself; whoever calls it for the harness can.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// More links than this on the way is a loop (the kernel's own limit is
/// 32 on macOS and 40 on Linux).
const MAX_LINKS: usize = 40;

fn names(p: &Path) -> impl DoubleEndedIterator<Item = OsString> + '_ {
    p.components().filter_map(|c| match c {
        Component::Normal(n) => Some(n.to_os_string()),
        Component::ParentDir => Some("..".into()),
        _ => None,
    })
}

/// The absolute path `p` with every symbolic link on the way resolved, as
/// the kernel would walk it: `..` after a link leaves the link's target,
/// not its name. What does not exist yet is kept as named, and a link
/// whose target is missing is followed all the same: a write through it
/// lands there. `None` for a relative path, a loop, or a directory that
/// can not be looked into: a path nobody can place.
pub fn real_path(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut todo: Vec<OsString> = names(p).rev().collect();
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(name) = todo.pop() {
        if name == ".." {
            at.pop();
            continue;
        }
        let next = at.join(&name);
        match std::fs::read_link(&next) {
            Ok(target) => {
                links += 1;
                if links > MAX_LINKS {
                    return None;
                }
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                todo.extend(names(&target).rev());
            }
            // Not a link, not there, or below a plain file: as named.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::InvalidInput | ErrorKind::NotFound | ErrorKind::NotADirectory
                ) =>
            {
                at = next;
            }
            Err(_) => return None,
        }
    }
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A directory of its own, with its links resolved (`/tmp` is one on
    /// macOS).
    fn dir() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        (d, real)
    }

    #[test]
    fn a_path_with_no_link_is_itself_there_or_not() {
        let (_d, root) = dir();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "").unwrap();
        assert_eq!(
            real_path(&root.join("src/lib.rs")),
            Some(root.join("src/lib.rs"))
        );
        assert_eq!(
            real_path(&root.join("src/new/a.rs")),
            Some(root.join("src/new/a.rs"))
        );
        assert_eq!(
            real_path(&root.join("src/./x/../lib.rs")),
            Some(root.join("src/lib.rs"))
        );
        // Below a plain file nothing can be: placed as named.
        assert_eq!(
            real_path(&root.join("src/lib.rs/x")),
            Some(root.join("src/lib.rs/x"))
        );
        assert_eq!(real_path(Path::new("/")), Some(PathBuf::from("/")));
        assert_eq!(real_path(Path::new("/../..")), Some(PathBuf::from("/")));
        assert_eq!(real_path(Path::new("src/lib.rs")), None);
        assert_eq!(real_path(Path::new("")), None);
    }

    #[test]
    fn a_link_is_followed_wherever_it_stands() {
        let (_d, root) = dir();
        let (ws, out) = (root.join("ws"), root.join("out"));
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::create_dir_all(out.join("deep")).unwrap();
        symlink(&out, ws.join("h")).unwrap();
        symlink("../out/deep", ws.join("rel")).unwrap();
        symlink("src", ws.join("inside")).unwrap();
        symlink("h", ws.join("twice")).unwrap();

        assert_eq!(real_path(&ws.join("h/.zshrc")), Some(out.join(".zshrc")));
        assert_eq!(real_path(&ws.join("h")), Some(out.clone()));
        assert_eq!(real_path(&ws.join("rel/x")), Some(out.join("deep/x")));
        assert_eq!(
            real_path(&ws.join("inside/a.rs")),
            Some(ws.join("src/a.rs"))
        );
        assert_eq!(real_path(&ws.join("twice/x")), Some(out.join("x")));
        // `..` leaves where the link leads, not where it is named.
        assert_eq!(real_path(&ws.join("rel/../x")), Some(out.join("x")));
        assert_eq!(real_path(&ws.join("inside/../h/x")), Some(out.join("x")));
    }

    #[test]
    fn a_link_to_nothing_is_followed_and_a_loop_is_nowhere() {
        let (_d, root) = dir();
        // A write through it makes the file where it points.
        symlink(root.join("gone/file"), root.join("dangling")).unwrap();
        assert_eq!(
            real_path(&root.join("dangling")),
            Some(root.join("gone/file"))
        );
        assert_eq!(
            real_path(&root.join("dangling/x")),
            Some(root.join("gone/file/x"))
        );

        symlink("b", root.join("a")).unwrap();
        symlink("a", root.join("b")).unwrap();
        assert_eq!(real_path(&root.join("a")), None);
        assert_eq!(real_path(&root.join("a/x")), None);

        // Forty links in a row are a path; one more is a loop.
        std::fs::write(root.join("l0"), "").unwrap();
        for i in 1..=MAX_LINKS + 1 {
            symlink(format!("l{}", i - 1), root.join(format!("l{i}"))).unwrap();
        }
        assert_eq!(
            real_path(&root.join(format!("l{MAX_LINKS}"))),
            Some(root.join("l0"))
        );
        assert_eq!(real_path(&root.join(format!("l{}", MAX_LINKS + 1))), None);
    }

    #[test]
    fn a_directory_nobody_may_look_into_places_nothing() {
        if crate::sys::current_uid() == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let (_d, root) = dir();
        let shut = root.join("shut");
        std::fs::create_dir(&shut).unwrap();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(real_path(&shut.join("x")), None);
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
