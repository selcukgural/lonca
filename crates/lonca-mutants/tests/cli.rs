//! The program itself: what it prints and how it exits.

use std::fs;
use std::process::Command;

fn program() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lonca-mutants"))
}

#[test]
fn a_wrong_call_fails_and_says_how() {
    let out = program().arg("what").output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.starts_with("lonca-mutants: usage:"), "{err}");
}

#[test]
fn skip_prints_the_names_for_the_next_run() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };
    write("Cargo.lock", "lock");
    write("crates/a/src/lib.rs", "fn f() -> bool {\n    true\n}\n");
    let name = "crates/a/src/lib.rs:2:5: replace f -> bool with false";
    let span = r#"{"start": {"line": 1, "column": 1}, "end": {"line": 3, "column": 2}}"#;
    write(
        "mutants.json",
        &format!(
            r#"[{{"name": "{name}", "file": "crates/a/src/lib.rs", "function": {{"span": {span}}}, "span": {span}}}]"#
        ),
    );
    write("done.txt", name);
    let run = |args: &[&str]| {
        let out = program()
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        run(&["record", "mutants.json", "done.txt", "state.json"]),
        ""
    );
    assert_eq!(
        run(&["skip", "mutants.json", "state.json"]),
        format!("{name}\n")
    );
}
