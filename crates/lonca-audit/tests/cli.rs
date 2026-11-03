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
