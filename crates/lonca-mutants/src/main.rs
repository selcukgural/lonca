//! Carries mutation results from one push of a pull request to the next, so a
//! run does not repeat what the last one settled. Used by
//! `.github/workflows/mutants.yml`; the reasoning is in docs/decisions.md,
//! "Mutation testing".
//!
//! A result is kept under a hash of the mutant and the whole text of its
//! function, not under its line number. Lines moved by an edit elsewhere keep
//! their result, and any change to the function drops it.
//!
//! ```text
//! lonca-mutants skip <mutants.json> <state.json>            # names to skip
//! lonca-mutants record <mutants.json> <done.txt> <state.json>
//! ```
//!
//! `mutants.json` is `cargo mutants --list --json`, read from the current
//! directory's tree. `done.txt` has one mutant name per line: those that need
//! no further run.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: lonca-mutants skip <mutants.json> <state.json>\n       lonca-mutants record <mutants.json> <done.txt> <state.json>";

/// Files whose mutants run on every push: docs/decisions.md lists them as the
/// ones where a result is not taken on trust.
const CRITICAL_FILES: [&str; 7] = [
    "decide.rs",
    "chain.rs",
    "state.rs",
    "oplog.rs",
    "canonical.rs",
    "changeid.rs",
    "keys.rs",
];

fn is_critical(file: &str) -> bool {
    let name = Path::new(file).file_name().and_then(|n| n.to_str());
    file.starts_with("crates/lonca-audit/")
        || file == "crates/lonca-symbols/src/merge.rs"
        || name.is_some_and(|n| CRITICAL_FILES.contains(&n))
}

#[derive(Debug)]
struct Mutant {
    name: String,
    file: String,
    /// `None` for a mutant outside any function: its result is never kept.
    key: Option<String>,
}

fn hash(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What identifies a mutant whatever the lines around its function do: the
/// function's text, and where in it the mutant sits.
fn key_of(mutant: &Value, name: &str, file: &str, source: &str) -> Option<String> {
    let function = mutant.get("function")?;
    let line = |v: &Value, end: &str| v["span"][end]["line"].as_u64();
    let first = usize::try_from(line(function, "start")?).ok()?;
    let last = usize::try_from(line(function, "end")?).ok()?;
    let lines = last.checked_sub(first)?.checked_add(1)?;
    let body: Vec<&str> = source
        .lines()
        .skip(first.checked_sub(1)?)
        .take(lines)
        .collect();
    let place = serde_json::to_string(&json!([
        line(mutant, "start")?.checked_sub(first as u64)?,
        mutant["span"]["start"]["column"],
        line(mutant, "end")?.checked_sub(first as u64)?,
        mutant["span"]["end"]["column"],
    ]))
    .ok()?;
    let (_, what) = name.split_once(": ")?;
    Some(hash(&[file, what, &place, &body.join("\n")]))
}

fn load_mutants(list: &Path, root: &Path) -> Result<Vec<Mutant>, String> {
    let text = read(list)?;
    let parsed: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", list.display()))?;
    let items = parsed
        .as_array()
        .ok_or_else(|| format!("{}: not a list", list.display()))?;
    let mut sources: HashMap<String, String> = HashMap::new();
    let mut mutants = Vec::with_capacity(items.len());
    for item in items {
        let field = |k: &str| {
            item[k]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{}: mutant without {k}", list.display()))
        };
        let (name, file) = (field("name")?, field("file")?);
        if !sources.contains_key(&file) {
            sources.insert(file.clone(), read(&root.join(&file))?);
        }
        let key = key_of(item, &name, &file, &sources[&file]);
        mutants.push(Mutant { name, file, key });
    }
    Ok(mutants)
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn tests_in(source: &str, file: &str, out: &mut BTreeSet<String>) {
    let mut after_attribute = false;
    for line in source.lines().map(str::trim) {
        if line == "#[test]" {
            after_attribute = true;
        } else if after_attribute
            && let Some(rest) = line
                .strip_prefix("fn ")
                .or_else(|| line.strip_prefix("async fn "))
        {
            let name = rest.split(['(', '<']).next().unwrap_or(rest);
            out.insert(format!("{file}::{name}"));
            after_attribute = false;
        }
    }
}

/// What a kept result depends on beyond its function.
#[derive(Debug, PartialEq)]
struct World {
    /// The dependencies: a new version of one opens every result again. The
    /// settings in `.cargo/mutants.toml` do not: a mutant excluded there says
    /// nothing about the others, and it is what a fix often adds.
    guard: String,
    /// Every test: a result may rest on one that is gone.
    tests: BTreeSet<String>,
}

fn world(root: &Path) -> Result<World, String> {
    let lock = read(&root.join("Cargo.lock"))?;
    let mut files = Vec::new();
    rs_files(&root.join("crates"), &mut files)?;
    let mut tests = BTreeSet::new();
    for path in files {
        let file = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        tests_in(&read(&path)?, &file, &mut tests);
    }
    Ok(World {
        guard: hash(&[&lock]),
        tests,
    })
}

#[derive(Debug, PartialEq)]
struct State {
    world: World,
    keys: BTreeSet<String>,
}

/// The state a run left, or `None` when there is none to trust: the first run
/// of a pull request, or a file this version can not read.
fn load_state(path: &Path) -> Option<State> {
    let text = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let strings = |k: &str| -> Option<BTreeSet<String>> {
        value[k]
            .as_array()?
            .iter()
            .map(|s| s.as_str().map(str::to_string))
            .collect()
    };
    Some(State {
        world: World {
            guard: value["guard"].as_str()?.to_string(),
            tests: strings("tests")?,
        },
        keys: strings("keys")?,
    })
}

fn to_skip<'a>(mutants: &'a [Mutant], state: &State, now: &World) -> Vec<&'a str> {
    if state.world.guard != now.guard || !state.world.tests.is_subset(&now.tests) {
        return Vec::new();
    }
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for key in mutants.iter().filter_map(|m| m.key.as_deref()) {
        *seen.entry(key).or_default() += 1;
    }
    // Two mutants with one key are in functions that read the same: the result
    // of either says nothing about the other.
    let settled = |key: &str| seen[key] == 1 && state.keys.contains(key);
    mutants
        .iter()
        .filter(|m| !is_critical(&m.file) && m.key.as_deref().is_some_and(settled))
        .map(|m| m.name.as_str())
        .collect()
}

fn state_json(mutants: &[Mutant], done: &BTreeSet<&str>, now: &World) -> Value {
    let keys: BTreeSet<&str> = mutants
        .iter()
        .filter(|m| done.contains(m.name.as_str()))
        .filter_map(|m| m.key.as_deref())
        .collect();
    json!({"guard": now.guard, "tests": now.tests, "keys": keys})
}

fn run(args: &[String], root: &Path) -> Result<String, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["skip", list, state] => {
            let mutants = load_mutants(Path::new(list), root)?;
            let Some(state) = load_state(Path::new(state)) else {
                return Ok(String::new());
            };
            let names = to_skip(&mutants, &state, &world(root)?);
            Ok(names.iter().map(|n| format!("{n}\n")).collect())
        }
        ["record", list, done, state] => {
            let mutants = load_mutants(Path::new(list), root)?;
            let done = read(Path::new(done))?;
            let done: BTreeSet<&str> = done.lines().collect();
            let value = state_json(&mutants, &done, &world(root)?);
            fs::write(state, value.to_string()).map_err(|e| format!("{state}: {e}"))?;
            Ok(String::new())
        }
        _ => Err(USAGE.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args, Path::new(".")) {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("lonca-mutants: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str =
        "fn before() {}\n\nfn f(a: u32) -> bool {\n    a > 1\n}\n\n#[test]\nfn f_works() {}\n";

    /// A mutant of `f`'s `>` as cargo-mutants lists it, the function starting
    /// at `line`.
    fn listed(file: &str, line: u64) -> Value {
        json!({
            "name": format!("{file}:{}:7: replace > with < in f", line + 1),
            "file": file,
            "function": {"span": {"start": {"line": line, "column": 1}, "end": {"line": line + 2, "column": 2}}},
            "span": {"start": {"line": line + 1, "column": 7}, "end": {"line": line + 1, "column": 8}},
        })
    }

    struct Repo {
        dir: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Repo {
            let repo = Repo {
                dir: tempfile::tempdir().unwrap(),
            };
            repo.write("Cargo.lock", "lock");
            repo.write("crates/a/src/lib.rs", SOURCE);
            repo
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn arg(&self, name: &str) -> String {
            self.path(name).to_str().unwrap().to_string()
        }

        fn write(&self, name: &str, text: &str) {
            let path = self.path(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }

        fn list(&self, mutants: &[Value]) {
            self.write("mutants.json", &json!(mutants).to_string());
        }

        fn record(&self, done: &str) {
            self.write("done.txt", done);
            let args = ["record", "m", "d", "s"].map(|a| match a {
                "m" => self.arg("mutants.json"),
                "d" => self.arg("done.txt"),
                "s" => self.arg("state.json"),
                other => other.to_string(),
            });
            assert_eq!(run(&args, self.dir.path()).unwrap(), "");
        }

        fn skip(&self) -> String {
            let args = [
                "skip".to_string(),
                self.arg("mutants.json"),
                self.arg("state.json"),
            ];
            run(&args, self.dir.path()).unwrap()
        }
    }

    const NAME: &str = "crates/a/src/lib.rs:4:7: replace > with < in f";

    fn settled_repo() -> Repo {
        let repo = Repo::new();
        repo.list(&[listed("crates/a/src/lib.rs", 3)]);
        repo.record(NAME);
        repo
    }

    #[test]
    fn what_a_run_settled_is_skipped_by_the_next() {
        assert_eq!(settled_repo().skip(), format!("{NAME}\n"));
    }

    #[test]
    fn a_first_run_skips_nothing() {
        let repo = Repo::new();
        repo.list(&[listed("crates/a/src/lib.rs", 3)]);
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn a_mutant_not_settled_runs_again() {
        let repo = Repo::new();
        repo.list(&[listed("crates/a/src/lib.rs", 3)]);
        repo.record("some other mutant\n");
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn lines_moved_above_the_function_keep_the_result() {
        let repo = settled_repo();
        repo.write("crates/a/src/lib.rs", &format!("// new\n// new\n{SOURCE}"));
        repo.list(&[listed("crates/a/src/lib.rs", 5)]);
        assert_eq!(
            repo.skip(),
            "crates/a/src/lib.rs:6:7: replace > with < in f\n"
        );
    }

    #[test]
    fn a_change_in_the_function_drops_the_result() {
        let repo = settled_repo();
        repo.write("crates/a/src/lib.rs", &SOURCE.replace("a > 1", "a > 2"));
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn a_change_on_the_functions_last_line_drops_the_result() {
        let repo = settled_repo();
        repo.write(
            "crates/a/src/lib.rs",
            &SOURCE.replace("    a > 1\n}", "    a > 1\n} //"),
        );
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn a_change_outside_the_function_keeps_the_result() {
        let repo = settled_repo();
        repo.write("crates/a/src/lib.rs", &SOURCE.replace("before", "earlier"));
        assert_eq!(repo.skip(), format!("{NAME}\n"));
    }

    #[test]
    fn another_mutant_in_the_function_has_its_own_key() {
        let first = listed("crates/a/src/lib.rs", 3);
        let mut other = first.clone();
        other["name"] = json!("crates/a/src/lib.rs:4:7: replace > with == in f");
        let name = |v: &Value| v["name"].as_str().unwrap().to_string();
        let key = |v: &Value| key_of(v, &name(v), "f.rs", SOURCE).unwrap();
        assert_ne!(key(&first), key(&other));
        let mut moved = first.clone();
        moved["span"]["start"]["line"] = json!(5);
        assert_ne!(key(&first), key(&moved));
        let mut wider = first.clone();
        wider["span"]["end"]["line"] = json!(5);
        assert_ne!(key(&first), key(&wider));
        let mut column = first.clone();
        column["span"]["start"]["column"] = json!(9);
        assert_ne!(key(&first), key(&column));
        let mut end_column = first.clone();
        end_column["span"]["end"]["column"] = json!(9);
        assert_ne!(key(&first), key(&end_column));
        assert_ne!(
            key(&first),
            key_of(&first, &name(&first), "g.rs", SOURCE).unwrap()
        );
    }

    #[test]
    fn a_mutant_outside_any_function_has_no_key() {
        let mut item = listed("f.rs", 3);
        item["function"] = Value::Null;
        assert_eq!(key_of(&item, "f.rs:4:7: x", "f.rs", SOURCE), None);
        item.as_object_mut().unwrap().remove("function");
        assert_eq!(key_of(&item, "f.rs:4:7: x", "f.rs", SOURCE), None);
    }

    #[test]
    fn a_span_that_makes_no_sense_has_no_key() {
        let mut backwards = listed("f.rs", 3);
        backwards["function"]["span"]["end"]["line"] = json!(1);
        assert_eq!(key_of(&backwards, "f.rs:4:7: x", "f.rs", SOURCE), None);
        let mut line_zero = listed("f.rs", 3);
        line_zero["function"]["span"]["start"]["line"] = json!(0);
        assert_eq!(key_of(&line_zero, "f.rs:4:7: x", "f.rs", SOURCE), None);
        let before_function = listed("f.rs", 3);
        let mut early = before_function.clone();
        early["span"]["start"]["line"] = json!(2);
        assert_eq!(key_of(&early, "f.rs:4:7: x", "f.rs", SOURCE), None);
        assert_eq!(
            key_of(&before_function, "no separator", "f.rs", SOURCE),
            None
        );
    }

    #[test]
    fn two_mutants_of_one_key_both_run() {
        let repo = Repo::new();
        repo.write("crates/a/src/b.rs", SOURCE);
        let twin = |line| {
            let mut item = listed("crates/a/src/lib.rs", 3);
            item["name"] = json!(format!(
                "crates/a/src/lib.rs:{line}:7: replace > with < in f"
            ));
            item
        };
        let mutants = [
            Mutant {
                name: "one".to_string(),
                file: "f.rs".to_string(),
                key: Some("k".to_string()),
            },
            Mutant {
                name: "two".to_string(),
                file: "f.rs".to_string(),
                key: Some("k".to_string()),
            },
            Mutant {
                name: "three".to_string(),
                file: "f.rs".to_string(),
                key: Some("l".to_string()),
            },
        ];
        let now = world(repo.dir.path()).unwrap();
        let state = State {
            world: world(repo.dir.path()).unwrap(),
            keys: ["k", "l"].map(str::to_string).into(),
        };
        assert_eq!(to_skip(&mutants, &state, &now), ["three"]);
        repo.list(&[twin(4), twin(4)]);
        repo.record(NAME);
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn critical_files_run_on_every_push() {
        for file in [
            "crates/lonca-policy/src/decide.rs",
            "crates/lonca-policy/src/chain.rs",
            "crates/lonca-policy/src/state.rs",
            "crates/lonca-core/src/oplog.rs",
            "crates/lonca-core/src/canonical.rs",
            "crates/lonca-core/src/changeid.rs",
            "crates/lonca-core/src/keys.rs",
            "crates/lonca-audit/src/main.rs",
            "crates/lonca-symbols/src/merge.rs",
        ] {
            assert!(is_critical(file), "{file}");
            let repo = Repo::new();
            repo.write(file, SOURCE);
            let item = listed(file, 3);
            repo.list(std::slice::from_ref(&item));
            repo.record(item["name"].as_str().unwrap());
            assert_eq!(repo.skip(), "", "{file}");
        }
        for file in [
            "crates/lonca-symbols/src/mentions.rs",
            "crates/lonca-daemon/src/merge.rs",
            "crates/a/lonca-audit/x.rs",
        ] {
            assert!(!is_critical(file), "{file}");
        }
    }

    #[test]
    fn a_new_dependency_opens_every_result() {
        let repo = settled_repo();
        repo.write("Cargo.lock", "changed");
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn a_mutant_excluded_in_the_settings_keeps_the_others_results() {
        let repo = settled_repo();
        repo.write(".cargo/mutants.toml", "exclude_re = ['x']");
        assert_eq!(repo.skip(), format!("{NAME}\n"));
    }

    #[test]
    fn a_deleted_test_opens_every_result() {
        let repo = settled_repo();
        repo.write(
            "crates/a/src/lib.rs",
            &SOURCE.replace("#[test]\nfn f_works() {}\n", ""),
        );
        assert_eq!(repo.skip(), "");
    }

    #[test]
    fn a_new_test_keeps_the_results() {
        let repo = settled_repo();
        repo.write(
            "crates/a/src/lib.rs",
            &format!("{SOURCE}#[test]\nfn another() {{}}\n"),
        );
        assert_eq!(repo.skip(), format!("{NAME}\n"));
    }

    #[test]
    fn tests_are_found_by_their_attribute() {
        let source = "#[test]\n#[ignore]\n// why\nfn a() {}\n\
                      fn helper() {}\n\
                      #[test]\n  async fn b() {}\n\
                      #[test]\nfn c<T>() {}\n";
        let mut found = BTreeSet::new();
        tests_in(source, "f.rs", &mut found);
        let expected: BTreeSet<String> =
            ["f.rs::a", "f.rs::b", "f.rs::c"].map(str::to_string).into();
        assert_eq!(found, expected);
    }

    #[test]
    fn the_world_reads_tests_in_nested_files_only_from_rs() {
        let repo = Repo::new();
        repo.write("crates/a/tests/deep/more.rs", "#[test]\nfn deep() {}\n");
        repo.write("crates/a/tests/notes.txt", "#[test]\nfn text() {}\n");
        let tests = world(repo.dir.path()).unwrap().tests;
        let expected: BTreeSet<String> = [
            "crates/a/src/lib.rs::f_works",
            "crates/a/tests/deep/more.rs::deep",
        ]
        .map(str::to_string)
        .into();
        assert_eq!(tests, expected);
    }

    #[test]
    fn a_state_that_can_not_be_read_is_no_state() {
        let repo = settled_repo();
        for broken in [
            "not json",
            "[]",
            r#"{"guard": 1, "tests": [], "keys": []}"#,
            r#"{"guard": "g", "keys": []}"#,
            r#"{"guard": "g", "tests": []}"#,
            r#"{"guard": "g", "tests": [1], "keys": []}"#,
        ] {
            repo.write("state.json", broken);
            assert_eq!(load_state(&repo.path("state.json")), None, "{broken}");
            assert_eq!(repo.skip(), "", "{broken}");
        }
    }

    #[test]
    fn a_bad_list_is_an_error() {
        let repo = Repo::new();
        let root = repo.dir.path();
        repo.write("l.json", "{}");
        assert!(load_mutants(&repo.path("l.json"), root).is_err());
        repo.write("l.json", "not json");
        assert!(load_mutants(&repo.path("l.json"), root).is_err());
        repo.write("l.json", r#"[{"file": "crates/a/src/lib.rs"}]"#);
        assert!(load_mutants(&repo.path("l.json"), root).is_err());
        repo.write("l.json", r#"[{"name": "n"}]"#);
        assert!(load_mutants(&repo.path("l.json"), root).is_err());
        repo.write("l.json", r#"[{"name": "n", "file": "gone.rs"}]"#);
        assert!(load_mutants(&repo.path("l.json"), root).is_err());
        assert!(load_mutants(&repo.path("missing.json"), root).is_err());
    }

    #[test]
    fn hashing_keeps_the_parts_apart() {
        assert_ne!(hash(&["ab", "c"]), hash(&["a", "bc"]));
    }

    #[test]
    fn a_wrong_call_is_refused() {
        let args = ["what".to_string()];
        assert_eq!(run(&args, Path::new(".")), Err(USAGE.to_string()));
    }
}

// TEMPORARY PROBE, dropped before merge: no test reaches this, so its mutants
// must fail the check after the workspace stage.
#[allow(dead_code)]
fn probe(a: u32) -> bool {
    a > 1
}
