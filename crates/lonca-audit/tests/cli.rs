//! The `lonca-audit` binary: output and exit status (0 clean, 1 findings,
//! 2 usage or I/O errors), on the golden v4 log.

use std::path::Path;
use std::process::{Command, Output};

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", text(&out.stderr));
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn audit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lonca-audit"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn verify_prints_the_daemon_key_switches_and_reports_findings_in_its_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("r.git");
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../lonca-daemon/tests/fixtures/oplog-v4.bundle");
    git(
        dir.path(),
        &["init", "-q", "--bare", repo.to_str().unwrap()],
    );
    git(
        &repo,
        &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
    );
    let repo = repo.to_str().unwrap();

    let ok = audit(&["verify", repo]);
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stderr));
    let out = text(&ok.stdout);
    assert!(
        out.contains("daemon key") && out.contains("daemon.rotate"),
        "{out}"
    );
    assert!(
        out.contains("daemon.recover") && out.contains("by human:ayse"),
        "{out}"
    );
    assert!(out.trim_end().ends_with("ok"), "{out}");

    // Trunk moved outside the log: a finding.
    let policy = Command::new("git")
        .args(["-C", repo, "rev-parse", "refs/lonca/policy"])
        .output()
        .unwrap();
    let policy = text(&policy.stdout);
    git(
        Path::new(repo),
        &["update-ref", "refs/heads/main", policy.trim()],
    );
    let bad = audit(&["verify", repo]);
    assert_eq!(bad.status.code(), Some(1), "{}", text(&bad.stdout));
    assert!(text(&bad.stdout).contains("FAILED"));

    let missing = audit(&["verify", dir.path().join("nope").to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(audit(&[]).status.code(), Some(2));
}

/// A store the auditor may not read (a hardened daemon's) is named as such,
/// not as "not a git repository", with the way that works there.
#[cfg(unix)]
#[test]
fn a_store_it_can_not_read_is_named_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let repo = home.join("r.git");
    std::fs::create_dir(&home).unwrap();
    git(
        dir.path(),
        &["init", "-q", "--bare", repo.to_str().unwrap()],
    );
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&repo).is_ok();
    let out = audit(&["verify", repo.to_str().unwrap()]);
    let compared = audit(&["compare", repo.to_str().unwrap(), repo.to_str().unwrap()]);
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    if readable {
        return; // root reads anything: nothing to see here
    }
    for out in [out, compared] {
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains("permission denied"), "{err}");
        assert!(err.contains("lonca backup"), "{err}");
    }
    // A path that is not there is still what Git says.
    let out = audit(&["verify", dir.path().join("none").to_str().unwrap()]);
    assert!(!text(&out.stderr).contains("permission denied"));
}

#[test]
fn version_is_the_workspace_version_and_anything_else_is_usage() {
    for flag in ["--version", "-V"] {
        let out = audit(&[flag]);
        assert!(out.status.success(), "{}", text(&out.stderr));
        assert_eq!(
            text(&out.stdout),
            format!("lonca-audit {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
    for args in [&["--version", "x"][..], &[][..], &["--versions"][..]] {
        let out = audit(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("lonca-audit --version"));
    }
}

/// What a log proves of itself is that it is whole and signed by its own
/// daemon key. That it is the expected log (`--genesis`), and no older
/// state of it (`--extends`), is said from outside it.
#[test]
fn verify_holds_a_log_to_the_genesis_and_the_head_it_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let load = |name: &str, fixture: &str| {
        let repo = dir.path().join(name);
        let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../lonca-daemon/tests/fixtures")
            .join(fixture);
        git(
            dir.path(),
            &["init", "-q", "--bare", repo.to_str().unwrap()],
        );
        git(
            &repo,
            &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
        );
        repo.to_str().unwrap().to_string()
    };
    let (mine, other) = (
        load("a.git", "oplog-v4.bundle"),
        load("b.git", "oplog-v5.bundle"),
    );
    let line = |out: &str, name: &str| {
        let l = out.lines().find(|l| l.starts_with(name)).unwrap();
        l.split_whitespace().last().unwrap().to_string()
    };
    let out = text(&audit(&["verify", &mine]).stdout);
    let (genesis, head) = (line(&out, "genesis:"), line(&out, "head:"));
    assert_eq!(genesis.len(), 64, "{out}");
    assert_ne!(genesis, head);

    let ok = audit(&["verify", &mine, "--genesis", &genesis, "--extends", &head]);
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stdout));
    // An entry in the middle is one the log has too.
    let ok = audit(&["verify", &mine, "--extends", &genesis]);
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stdout));

    // Another log, whole and signed by its own key, in the place of mine.
    let alone = audit(&["verify", &other]);
    assert_eq!(alone.status.code(), Some(0), "{}", text(&alone.stdout));
    for anchor in [["--genesis", &genesis], ["--extends", &head]] {
        let bad = audit(&["verify", &other, anchor[0], anchor[1]]);
        let out = text(&bad.stdout);
        assert_eq!(bad.status.code(), Some(1), "{out}");
        assert!(out.contains("FINDING") && out.contains("anchor"), "{out}");
        assert!(out.trim_end().ends_with("FAILED"), "{out}");
    }

    // Mine, taken back by one entry: its own genesis, but not its head.
    git(
        Path::new(&mine),
        &["update-ref", "refs/lonca/oplog", "refs/lonca/oplog~1"],
    );
    let back = audit(&["verify", &mine, "--no-refs", "--genesis", &genesis]);
    assert_eq!(back.status.code(), Some(0), "{}", text(&back.stdout));
    let back = audit(&["verify", &mine, "--no-refs", "--extends", &head]);
    let out = text(&back.stdout);
    assert_eq!(back.status.code(), Some(1), "{out}");
    assert!(out.contains("taken back"), "{out}");

    // A hash is whole.
    for bad in [&genesis[..12], "", &genesis.to_uppercase()] {
        assert_eq!(
            audit(&["verify", &mine, "--genesis", bad]).status.code(),
            Some(2)
        );
    }
    assert_eq!(
        audit(&["verify", &mine, "--extends"]).status.code(),
        Some(2)
    );
}
