//! Timings of requests by the length of the log and the size of the tree,
//! through the daemon's request handler. Nothing here asserts a time: they
//! print, and are run by hand
//! (`cargo test --release -p lonca-daemon --test perf -- --ignored --nocapture`).

mod common;
use common::*;

use std::time::Instant;

fn ms<T>(f: impl FnOnce() -> T) -> (f64, T) {
    let started = Instant::now();
    let out = f();
    (started.elapsed().as_secs_f64() * 1000.0, out)
}

fn next_seq(e: &mut Env) -> u64 {
    e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap()
}

fn body(i: usize, k: usize) -> String {
    format!(
        "pub fn f{i}(a: u64) -> u64 {{\n    a + {k}\n}}\n\npub fn g{i}(a: u64) -> u64 {{\n    a\n}}\n"
    )
}

#[test]
#[ignore = "a timing, run by hand"]
fn requests_by_log_length_and_tree_size() {
    println!(
        "entries files  append  read_all  reopen  events  log_page0  change_get  inbox_first  inbox_next  lease  propose  tree_read   (ms)"
    );
    for (entries, files) in [(1_000, 200), (5_000, 200), (5_000, 5_000), (20_000, 5_000)] {
        let mut e = Env::new();
        e.init(None);
        let seed: Vec<_> = (0..files)
            .map(|i| file(&format!("src/m{}/f{i}.rs", i % 50), &body(i, 0)))
            .collect();
        // A change has at most 200 files under the default policy.
        for part in seed.chunks(200) {
            e.human_change(part.to_vec(), "seed");
            e.svc.process_all();
        }
        let a = e.session("s1", &["src/**"]);
        e.bind(&a);
        let start = next_seq(&mut e);
        let (filled, _) = ms(|| {
            let mut i = 0;
            while next_seq(&mut e) < entries {
                for _ in 0..50 {
                    e.wrote(&a, &format!("src/m0/w{i}.rs"));
                    i += 1;
                }
                // Time between bursts: the session's rate is its own.
                e.advance(5_000);
            }
        });
        let n = next_seq(&mut e);
        let append = filled / (n - start) as f64;
        let store = e.store();
        let (read_all, ops) = ms(|| OpLog::new(&store).read_all().unwrap());
        assert_eq!(ops.len() as u64, n);
        let trunk = e.trunk();
        let (tree_read, map) = ms(|| store.commit_files(&trunk).unwrap());
        assert_eq!(map.len(), files);
        let (events, _) = ms(|| e.ok("events", None, Some(&a), json!({"from": n})));
        let (log, page) = ms(|| e.ok("log", Some("demo"), None, json!({"from": 0, "limit": 1000})));
        assert_eq!(page.as_array().unwrap().len(), 1000);
        let (lease, r) = ms(|| e.lease(&a, "src/m0/f0.rs#f0"));
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        let change = vec![file("src/m0/f0.rs", &body(0, 1))];
        let (propose, r) = ms(|| e.propose(&a, &trunk, change, &["src/m0/f0.rs#f0"]));
        assert_ne!(r["decision"]["outcome"], "deny", "{r}");
        let id = r["change"].clone();
        let (change_get, _) = ms(|| e.ok("change.get", Some("demo"), None, json!({"change": id})));
        let b = e.session("s2", &["src/**"]);
        let (inbox_first, _) = ms(|| e.ok("inbox", None, Some(&b), json!({})));
        let (inbox_next, _) = ms(|| e.ok("inbox", None, Some(&b), json!({})));
        let (reopen, _) = ms(|| e.reopen());
        println!(
            "{n:<7} {files:<6} {append:<7.2} {read_all:<9.0} {reopen:<7.0} {events:<7.0} {log:<10.0} {change_get:<11.0} {inbox_first:<12.0} {inbox_next:<11.2} {lease:<6.1} {propose:<8.1} {tree_read:.1}"
        );
    }
}
