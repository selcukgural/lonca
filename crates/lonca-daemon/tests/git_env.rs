//! The daemon's git child (issue #57): a remote that never answers ends
//! after the timeout without holding up other requests, and local-path
//! remotes stay out of the daemon home. `git_config.rs` has the test of the
//! environment.

mod common;
use common::*;

use std::time::{Duration, Instant};

use lonca_daemon::protocol::Request;

fn upstream(root: &Path, name: &str, text: &str) -> PathBuf {
    let up = root.join(name);
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "-q", "-b", "main"]);
    git(&up, &["config", "user.email", "t@t"]);
    git(&up, &["config", "user.name", "t"]);
    std::fs::write(up.join("README.md"), text).unwrap();
    git(&up, &["add", "."]);
    git(&up, &["commit", "-q", "-m", text]);
    up
}

/// Accepts connections and never says a word.
fn silent_server() -> (u16, std::thread::JoinHandle<()>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let t = std::thread::spawn(move || {
        let mut held = Vec::new();
        for c in l.incoming().take(4).flatten() {
            held.push(c);
        }
        std::thread::sleep(Duration::from_secs(30));
    });
    (port, t)
}

fn request(token: &str, method: &str, params: Value) -> Request {
    Request {
        id: 1,
        method: method.into(),
        repo: Some("demo".into()),
        token: Some(token.into()),
        params,
    }
}

/// A fetch and a push to a remote that never answers end after the time
/// limit, and the daemon answers other requests in the meantime: the push
/// runs outside the service lock.
#[test]
fn a_silent_remote_times_out_and_holds_nobody_up() {
    let mut e = Env::new();
    e.settings.git_timeout = Duration::from_secs(2);
    e.reopen();
    e.init(None);
    let token = e.login().unwrap();
    let (port, _server) = silent_server();
    let remote = format!("https://127.0.0.1:{port}/repo.git");

    let svc = e.svc.clone();
    let (t, r) = (token.clone(), remote.clone());
    let started = Instant::now();
    let fetch = std::thread::spawn(move || {
        svc.handle(request(&t, "human.prepare_import", json!({"remote": r})))
    });
    let prep = e.ok(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": remote}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let body = e.sign(&op);
    let svc = e.svc.clone();
    let t = token.clone();
    let push = std::thread::spawn(move || svc.handle(request(&t, "human.submit", body)));

    // While both hang, status is answered at once, again and again.
    std::thread::sleep(Duration::from_millis(300));
    for _ in 0..5 {
        let asked = Instant::now();
        e.ok("status", Some("demo"), None, json!({}));
        assert!(
            asked.elapsed() < Duration::from_millis(500),
            "status waited"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    for (what, handle) in [("fetch", fetch), ("push", push)] {
        let r = handle.join().unwrap();
        let err = r.error.unwrap_or_else(|| panic!("{what} succeeded"));
        assert_eq!(err.code, "git", "{what}: {}", err.message);
        assert!(
            err.message.contains("did not finish"),
            "{what}: {}",
            err.message
        );
    }
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(15),
        "{took:?}"
    );
}

/// A local path may not name anything in the daemon home but its backups,
/// and with `local_roots` it must lie under one of them.
#[test]
fn local_remotes_stay_out_of_the_daemon_home() {
    let mut e = Env::new();
    e.init(None);
    let try_import = |e: &mut Env, remote: &Path| {
        e.call(
            "human.prepare_import",
            Some("demo"),
            None,
            json!({"remote": remote}),
        )
    };
    let store = e.root.join("home/repos/demo.git");
    let r = try_import(&mut e, &store);
    let (code, message) = r.unwrap_err();
    assert_eq!(code, "forbidden");
    assert!(message.contains("inside the daemon home"), "{message}");
    let home = e.root.join("home");
    let r = try_import(&mut e, &home);
    assert_eq!(r.unwrap_err().0, "forbidden");
    // Through a link it is the same place.
    let link = e.root.join("link.git");
    std::os::unix::fs::symlink(&store, &link).unwrap();
    assert_eq!(try_import(&mut e, &link).unwrap_err().0, "forbidden");
    let nowhere = e.root.join("nowhere");
    let (code, message) = try_import(&mut e, &nowhere).unwrap_err();
    assert_eq!(code, "forbidden");
    assert!(message.contains("does not exist"), "{message}");

    // Past the check, git fetches: an unrelated history is refused later.
    let passed = |r: Result<Value, (String, String)>| {
        r.err().is_none_or(|(code, _)| code == "not_fast_forward")
    };
    let up = upstream(&e.root, "up", "one\n");
    let r = try_import(&mut e, &up);
    assert!(passed(r.clone()), "{r:?}");

    e.settings.local_roots = Some(vec![e.root.join("allowed")]);
    e.reopen();
    let r = try_import(&mut e, &up);
    let (code, message) = r.unwrap_err();
    assert_eq!(code, "forbidden");
    assert!(message.contains("--local-root"), "{message}");
    let inside = upstream(&e.root.join("allowed"), "up", "two\n");
    let r = try_import(&mut e, &inside);
    assert!(passed(r.clone()), "{r:?}");
}

/// A hardened install's import directory: a bundle directly in it is
/// fetched from the daemon's own copy, which goes afterwards. A link, a
/// repository directory, a file further down, a link from outside and a
/// push there are refused.
#[test]
fn the_import_directory_gives_git_only_a_copy_of_a_bundle() {
    let mut e = Env::new();
    let dir = e.root.join("import");
    std::fs::create_dir_all(&dir).unwrap();
    e.settings.local_roots = Some(vec![]);
    e.settings.import_dir = Some(dir.clone());
    e.reopen();
    let up = upstream(&e.root, "up", "one\n");
    let bundle = dir.join("up.bundle");
    git(
        &up,
        &["bundle", "create", "-q", bundle.to_str().unwrap(), "main"],
    );
    let head = String::from_utf8(
        std::process::Command::new("git")
            .args(["-C", up.to_str().unwrap(), "rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    e.init(Some(bundle.to_str().unwrap()));
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["trunk"], json!(head.trim()), "{st}");
    let imports = e.root.join("home/imports");
    assert_eq!(std::fs::read_dir(&imports).unwrap().count(), 0, "copy gone");
    // A copy a killed daemon left is gone at the next start.
    std::fs::write(imports.join("import-x.bundle"), "left").unwrap();
    e.reopen();
    assert!(!imports.exists());

    let try_import = |e: &mut Env, remote: &Path| {
        e.call(
            "human.prepare_import",
            Some("demo"),
            None,
            json!({"remote": remote}),
        )
        .unwrap_err()
    };
    let refused = |(code, message): (String, String), why: &str| {
        assert_eq!(code, "forbidden", "{message}");
        assert!(message.contains(why), "{message}");
    };
    // Past the check git reads the copy: the same commit is up to date.
    let (code, _) = try_import(&mut e, &bundle);
    assert_eq!(code, "up_to_date");

    std::os::unix::fs::symlink(&bundle, dir.join("link.bundle")).unwrap();
    refused(try_import(&mut e, &dir.join("link.bundle")), "a link");
    let repo = dir.join("repo.git");
    git(&e.root, &["init", "-q", "--bare", repo.to_str().unwrap()]);
    refused(try_import(&mut e, &repo), "not a regular file");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::copy(&bundle, dir.join("sub/up.bundle")).unwrap();
    refused(
        try_import(&mut e, &dir.join("sub/up.bundle")),
        "directly in",
    );
    refused(try_import(&mut e, &dir), "directly in");
    let text = dir.join("notes.txt");
    std::fs::write(&text, "hello\n").unwrap();
    refused(try_import(&mut e, &text), "not a git bundle");
    let outside = e.root.join("outside.bundle");
    std::os::unix::fs::symlink(&bundle, &outside).unwrap();
    refused(try_import(&mut e, &outside), "only read");
    let r = e.call(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": dir.join("out.git")}),
    );
    let pushed_into = std::fs::create_dir(dir.join("out.git"));
    assert!(pushed_into.is_ok());
    let r2 = e.call(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": dir.join("out.git")}),
    );
    assert_eq!(r.unwrap_err().0, "forbidden", "a missing path");
    refused(r2.unwrap_err(), "only read");
    assert!(!imports.exists() || std::fs::read_dir(&imports).unwrap().count() == 0);
}

/// Without an import directory nothing changes: a bundle is a local path
/// like any other.
#[test]
fn without_an_import_directory_a_bundle_is_a_local_path() {
    let mut e = Env::new();
    let up = upstream(&e.root, "up", "one\n");
    let bundle = e.root.join("up.bundle");
    git(
        &up,
        &["bundle", "create", "-q", bundle.to_str().unwrap(), "main"],
    );
    e.init(Some(bundle.to_str().unwrap()));
    assert!(!e.root.join("home/imports").exists());
}
