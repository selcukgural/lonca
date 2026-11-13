//! Timings of what a verification does around its commands, by the size of
//! the tree: writing the files out, and a whole run of a command that does
//! nothing (the files written, the command, the directory removed).
//! Nothing here asserts a time: they print, and are run by hand
//! (`cargo test --release -p lonca-verify --test perf -- --ignored --nocapture`).

use lonca_core::{FileEntry, FileMap, FileMode, Store};
use lonca_policy::config::Verification;
use lonca_verify::{Verifier, materialize};
use std::time::Instant;

fn ms<T>(f: impl FnOnce() -> T) -> (f64, T) {
    let started = Instant::now();
    let out = f();
    (started.elapsed().as_secs_f64() * 1000.0, out)
}

#[test]
#[ignore = "a timing, run by hand"]
fn a_run_by_the_size_of_the_tree() {
    println!("files  dirs  bytes     written  run_of_true  entries_left   (ms)");
    for (files, dirs, bytes) in [
        (200, 10, 2_000),
        (5_000, 50, 2_000),
        (5_000, 1_000, 2_000),
        (20_000, 500, 2_000),
        (2_000, 50, 200_000),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("s.git")).unwrap();
        let mut map = FileMap::new();
        for i in 0..files {
            let text = format!("// file {i}\n{}", "x".repeat(bytes));
            let blob = store.write_blob(text.as_bytes()).unwrap();
            let mode = match i % 10 {
                0 => FileMode::Executable,
                _ => FileMode::Regular,
            };
            let path = format!("src/m{}/sub{}/f{i}.rs", i % dirs, i % 3);
            map.insert(path, FileEntry { mode, blob });
        }
        let tree = store.write_tree(&map).unwrap();
        let out = dir.path().join("out");
        let (written, r) = ms(|| materialize(&store, &map, &out));
        r.unwrap();
        let scratch = dir.path().join("scratch");
        let cfg = Verification {
            build: Some("true".into()),
            timeout_seconds: 60,
            ..Default::default()
        };
        let v = Verifier::new(scratch.clone());
        let (run, r) = ms(|| v.run(&store, &map, &tree, &cfg));
        assert_eq!(r.unwrap().len(), 1);
        // The run's directory is gone when it is over.
        let left = std::fs::read_dir(&scratch).unwrap().count();
        println!("{files:<6} {dirs:<5} {bytes:<9} {written:<8.0} {run:<12.0} {left}");
    }
}
