//! `lonca-audit`: independent verification of a Lonca repository.
//!
//! ```text
//! lonca-audit verify <git-dir> [--shallow] [--no-refs] [--json] [--freeze-flag <file>]
//! lonca-audit compare <local-git-dir> <published-git-dir>
//! lonca-audit --version
//! ```
//!
//! Exit status: 0 when clean, 1 when findings exist, 2 on usage or I/O errors.
//! `--freeze-flag` writes a flag file on findings; the daemon freezes the
//! repository when it sees it. That file is the auditor's only write.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use lonca_audit::{EnvChange, Options, audit, compare};
use lonca_core::Store;
use lonca_core::oplog::OpLog;
use lonca_core::terminal::printable;

/// `println!` for a terminal: a finding quotes paths, names and reasons
/// from the log, which agents wrote, and nothing of it is obeyed there
/// (`lonca_core::terminal`). JSON has no raw control character to begin
/// with.
macro_rules! say {
    ($($arg:tt)*) => {
        println!("{}", printable(&format!($($arg)*)))
    };
}

/// `eprintln!`, the same way.
macro_rules! complain {
    ($($arg:tt)*) => {
        eprintln!("{}", printable(&format!($($arg)*)))
    };
}

/// A check that ran in another environment, as `verify` prints it.
fn env_line(c: &EnvChange) -> String {
    format!(
        "env       {:>6} {:<9} changed since {}",
        c.seq, c.check, c.since
    )
}

fn usage() -> ExitCode {
    complain!(
        "usage:\n  lonca-audit verify <git-dir> [--shallow] [--no-refs] [--all-refs] [--json] [--freeze-flag <file>]\n  lonca-audit compare <local-git-dir> <published-git-dir>\n  lonca-audit --version"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify") => verify(&args[1..]),
        Some("compare") => compare_cmd(&args[1..]),
        // The same answer as `lonca --version`, so a script can check that
        // the auditor it runs is the release it installed.
        Some("--version" | "-V") if args.len() == 1 => {
            say!("lonca-audit {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn verify(args: &[String]) -> ExitCode {
    let mut dir = None;
    let mut opts = Options::default();
    let mut json = false;
    let mut freeze_flag: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--shallow" => opts.deep = false,
            "--no-refs" => opts.check_refs = false,
            "--all-refs" => opts.all_refs = true,
            "--json" => json = true,
            "--freeze-flag" => match it.next() {
                Some(p) => freeze_flag = Some(PathBuf::from(p)),
                None => return usage(),
            },
            p if dir.is_none() && !p.starts_with('-') => dir = Some(PathBuf::from(p)),
            _ => return usage(),
        }
    }
    let Some(dir) = dir else { return usage() };
    let store = match Store::open(&dir) {
        Ok(s) => s,
        Err(e) => {
            complain!("lonca-audit: {}", open_error(&dir, &e));
            return ExitCode::from(2);
        }
    };
    let report = match audit(&store, opts) {
        Ok(r) => r,
        Err(e) => {
            complain!("lonca-audit: {e}");
            return ExitCode::from(2);
        }
    };
    if json {
        say!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serializable")
        );
    } else {
        say!("operations: {}", report.ops);
        say!("head:       {}", report.head_hash);
        for k in &report.key_switches {
            say!(
                "daemon key {:>6} {:<14} {} by {}",
                k.seq,
                k.kind,
                k.key,
                k.actor
            );
        }
        for c in &report.env_changes {
            say!("{}", env_line(c));
        }
        for f in &report.skipped {
            say!(
                "skipped  {:>6} {:<9} {}",
                f.seq.map(|s| s.to_string()).unwrap_or_default(),
                f.kind,
                f.detail
            );
        }
        for f in &report.findings {
            say!(
                "FINDING  {:>6} {:<9} {}",
                f.seq.map(|s| s.to_string()).unwrap_or_default(),
                f.kind,
                f.detail
            );
        }
        say!("{}", if report.ok() { "ok" } else { "FAILED" });
    }
    if !report.ok() {
        if let Some(flag) = freeze_flag {
            let reason = report
                .findings
                .first()
                .map(|f| format!("audit: {} {}", f.kind, f.detail))
                .unwrap_or_default();
            if let Err(e) = std::fs::write(&flag, reason) {
                complain!("lonca-audit: could not write freeze flag: {e}");
            }
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Why `dir` did not open. Git calls a path it can not read "not a git
/// repository"; a hardened store, the daemon's user's alone, is that case,
/// so the real reason is named and the way that works there.
fn open_error(dir: &std::path::Path, e: &impl std::fmt::Display) -> String {
    match std::fs::read_dir(dir) {
        Err(io) if io.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "cannot read {}: permission denied. A hardened daemon's store is readable by \
             its user only: verify a backup bundle instead (`lonca backup`, then \
             git init --bare x.git && git -C x.git fetch <bundle> '+refs/*:refs/*' && \
             lonca-audit verify x.git)",
            dir.display()
        ),
        _ => e.to_string(),
    }
}

fn compare_cmd(args: &[String]) -> ExitCode {
    let [local, published] = args else {
        return usage();
    };
    let read = |p: &str| -> Result<Vec<lonca_core::oplog::SignedOp>, String> {
        let p = std::path::Path::new(p);
        let s = Store::open(p).map_err(|e| open_error(p, &e))?;
        OpLog::new(&s).read_all().map_err(|e| e.to_string())
    };
    let (l, p) = match (read(local), read(published)) {
        (Ok(l), Ok(p)) => (l, p),
        (Err(e), _) | (_, Err(e)) => {
            complain!("lonca-audit: {e}");
            return ExitCode::from(2);
        }
    };
    let findings = compare(&l, &p);
    for f in &findings {
        say!(
            "FINDING  {:>6} {:<9} {}",
            f.seq.map(|s| s.to_string()).unwrap_or_default(),
            f.kind,
            f.detail
        );
    }
    if findings.is_empty() {
        say!(
            "ok: published log ({} entries) is a prefix of the local log ({} entries)",
            p.len(),
            l.len()
        );
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_environment_change_is_one_line() {
        let c = EnvChange {
            seq: 12,
            check: "tests".into(),
            since: 7,
        };
        assert_eq!(env_line(&c), "env           12 tests     changed since 7");
    }
}
