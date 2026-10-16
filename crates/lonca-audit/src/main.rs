//! `lonca-audit`: independent verification of a Lonca repository.
//!
//! ```text
//! lonca-audit verify <git-dir> [--shallow] [--no-refs] [--json] [--freeze-flag <file>]
//! lonca-audit compare <local-git-dir> <published-git-dir>
//! ```
//!
//! Exit status: 0 when clean, 1 when findings exist, 2 on usage or I/O errors.
//! `--freeze-flag` writes a flag file on findings; the daemon freezes the
//! repository when it sees it. That file is the auditor's only write.

use std::path::PathBuf;
use std::process::ExitCode;

use lonca_audit::{Options, audit, compare};
use lonca_core::Store;
use lonca_core::oplog::OpLog;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  lonca-audit verify <git-dir> [--shallow] [--no-refs] [--json] [--freeze-flag <file>]\n  lonca-audit compare <local-git-dir> <published-git-dir>"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("verify") => verify(&args[1..]),
        Some("compare") => compare_cmd(&args[1..]),
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
            eprintln!("lonca-audit: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match audit(&store, opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("lonca-audit: {e}");
            return ExitCode::from(2);
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("serializable")
        );
    } else {
        println!("operations: {}", report.ops);
        println!("head:       {}", report.head_hash);
        for f in &report.skipped {
            println!(
                "skipped  {:>6} {:<9} {}",
                f.seq.map(|s| s.to_string()).unwrap_or_default(),
                f.kind,
                f.detail
            );
        }
        for f in &report.findings {
            println!(
                "FINDING  {:>6} {:<9} {}",
                f.seq.map(|s| s.to_string()).unwrap_or_default(),
                f.kind,
                f.detail
            );
        }
        println!("{}", if report.ok() { "ok" } else { "FAILED" });
    }
    if !report.ok() {
        if let Some(flag) = freeze_flag {
            let reason = report
                .findings
                .first()
                .map(|f| format!("audit: {} {}", f.kind, f.detail))
                .unwrap_or_default();
            if let Err(e) = std::fs::write(&flag, reason) {
                eprintln!("lonca-audit: could not write freeze flag: {e}");
            }
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn compare_cmd(args: &[String]) -> ExitCode {
    let [local, published] = args else {
        return usage();
    };
    let read = |p: &str| -> Result<Vec<lonca_core::oplog::SignedOp>, String> {
        let s = Store::open(std::path::Path::new(p)).map_err(|e| e.to_string())?;
        OpLog::new(&s).read_all().map_err(|e| e.to_string())
    };
    let (l, p) = match (read(local), read(published)) {
        (Ok(l), Ok(p)) => (l, p),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("lonca-audit: {e}");
            return ExitCode::from(2);
        }
    };
    let findings = compare(&l, &p);
    for f in &findings {
        println!(
            "FINDING  {:>6} {:<9} {}",
            f.seq.map(|s| s.to_string()).unwrap_or_default(),
            f.kind,
            f.detail
        );
    }
    if findings.is_empty() {
        println!(
            "ok: published log ({} entries) is a prefix of the local log ({} entries)",
            p.len(),
            l.len()
        );
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
