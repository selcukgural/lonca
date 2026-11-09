//! Backup and restore: a bundle of the store at one point of the log,
//! restored into a daemon that holds the key (same machine) or does not
//! (another machine, hardened mode), from a bundle, a mirror or the remote
//! Lonca pushed to; and what a restore refuses.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::oplog::OpEntry;
use lonca_policy::chain::{Chain, Submission};
use lonca_policy::config::PolicyBundle;
use lonca_policy::state::State;

/// A second daemon in `home` under the same root, with or without the
/// first daemon's key.
struct Other {
    svc: Arc<Service>,
    home: PathBuf,
    next_id: u64,
    human: KeyPair,
    clock: Arc<AtomicI64>,
    /// The human session of `ayse`, opened once a restored repository
    /// knows her key; before that the daemon is in bootstrap.
    token: Option<String>,
}

impl Other {
    fn open(e: &Env, name: &str, with_key: bool) -> Other {
        let home = e.root.join(name);
        std::fs::create_dir_all(&home).unwrap();
        if with_key {
            std::fs::copy(e.root.join("home/daemon.key"), home.join("daemon.key")).unwrap();
        }
        let c = e.clock.clone();
        let svc = Service::open(
            Home::new(&home),
            e.settings.clone(),
            Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
        )
        .unwrap();
        Other {
            svc,
            home,
            next_id: 1000,
            human: e.human.clone(),
            clock: e.clock.clone(),
            token: None,
        }
    }

    fn raw(
        &mut self,
        method: &str,
        repo: Option<&str>,
        token: Option<&str>,
        params: Value,
    ) -> Result<Value, (String, String)> {
        self.next_id += 1;
        let r = self.svc.handle(Request {
            id: self.next_id,
            method: method.into(),
            repo: repo.map(String::from),
            token: token.map(String::from),
            params,
        });
        if r.ok {
            Ok(r.result)
        } else {
            Err(r.error.map(|e| (e.code, e.message)).unwrap())
        }
    }

    /// Like `Env::call`: the human session when there is one to open.
    fn call(
        &mut self,
        method: &str,
        repo: Option<&str>,
        params: Value,
    ) -> Result<Value, (String, String)> {
        if self.token.is_none() {
            let ttl = 24 * 3_600_000;
            let now = self.clock.load(Ordering::SeqCst);
            let sig = sign_login_ed25519(&self.human, "ayse", None, ttl, now);
            self.token = self
                .raw(
                    "human.login",
                    None,
                    None,
                    json!({"sig": sig, "ttl_ms": ttl}),
                )
                .ok()
                .map(|r| r["token"].as_str().unwrap().to_string());
        }
        let t = self.token.clone();
        self.raw(method, repo, t.as_deref(), params)
    }

    fn ok(&mut self, method: &str, repo: Option<&str>, params: Value) -> Value {
        self.call(method, repo, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    fn restore(&mut self, repo: &str, from: &Path) -> Result<Value, (String, String)> {
        self.call(
            "repo.restore",
            None,
            json!({"repo": repo, "from": from.to_string_lossy()}),
        )
    }

    fn store(&self, repo: &str) -> Store {
        Store::open(&self.home.join(format!("repos/{repo}.git"))).unwrap()
    }
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A busy repository whose last operation moved trunk.
fn repo() -> Env {
    let mut e = busy_repo();
    e.human_change(vec![file("notes.md", "a\nb\n")], "notes");
    e.svc.process_all();
    e
}

fn backup(e: &mut Env) -> PathBuf {
    let r = e.ok("repo.backup", Some("demo"), None, json!({}));
    PathBuf::from(r["path"].as_str().unwrap())
}

fn status(v: &Value) -> (Value, Value, Value) {
    (
        v["trunk"].clone(),
        v["head_hash"].clone(),
        v["next_seq"].clone(),
    )
}

fn deep() -> Options {
    Options {
        deep: true,
        check_refs: true,
        all_refs: true,
    }
}

#[test]
fn a_backup_is_a_bundle_of_every_ref_at_one_point_of_the_log() {
    let mut e = repo();
    let st = e.ok("status", Some("demo"), None, json!({}));
    let r = e.ok("repo.backup", Some("demo"), None, json!({}));
    let seq = st["next_seq"].as_u64().unwrap() - 1;
    let path = PathBuf::from(r["path"].as_str().unwrap());
    assert_eq!(
        path,
        e.root.join(format!("home/backups/demo-{seq:06}.bundle"))
    );
    assert_eq!(r["seq"], json!(seq));
    assert_eq!(r["head_hash"], st["head_hash"]);
    assert_eq!(r["daemon_key"], st["daemon_key"]);
    assert_eq!(mode(&path), 0o640);
    assert_eq!(mode(path.parent().unwrap()), 0o750);
    assert!(!path.with_extension("bundle.tmp").exists());

    let heads = git(&e.root, &["bundle", "list-heads", path.to_str().unwrap()]);
    for r in ["refs/heads/main", "refs/lonca/oplog", "refs/lonca/policy"] {
        assert!(heads.contains(r), "{heads}");
    }
    let changes = e
        .store()
        .refs_with_prefix("refs/lonca/changes/")
        .unwrap()
        .len();
    assert!(changes > 0);
    assert_eq!(heads.matches("refs/lonca/changes/").count(), changes);
    assert!(
        heads
            .lines()
            .any(|l| l.starts_with(st["trunk"].as_str().unwrap())
                && l.ends_with("refs/heads/main")),
        "{heads}"
    );

    // Taken again at the same point: the same file.
    assert_eq!(backup(&mut e), path);
    let err = e
        .call("repo.backup", Some("nope"), None, json!({}))
        .unwrap_err();
    assert_eq!(err.0, "forbidden");

    // Somewhere else than the home (hardened mode).
    let elsewhere = e.root.join("elsewhere");
    let c = e.clock.clone();
    let svc = Service::open(
        Home::new(e.root.join("home")).with_backups(&elsewhere),
        e.settings.clone(),
        Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    let r = svc.handle(Request {
        id: 1,
        method: "repo.backup".into(),
        repo: Some("demo".into()),
        token: e.human_token.clone(),
        params: json!({}),
    });
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(
        r.result["path"].as_str().unwrap(),
        elsewhere
            .join(format!("demo-{seq:06}.bundle"))
            .to_str()
            .unwrap()
    );
}

#[test]
fn a_restore_on_the_same_key_continues_the_repository_and_audits() {
    let mut e = repo();
    let t1 = e.session("s9", &["src/**"]);
    let before = e.ok("status", Some("demo"), None, json!({}));
    let bundle = backup(&mut e);
    let changes = e
        .store()
        .refs_with_prefix("refs/lonca/changes/")
        .unwrap()
        .len();

    let mut o = Other::open(&e, "home2", true);
    let r = o.restore("demo", &bundle).unwrap();
    assert_eq!(r["foreign"], json!(false));
    assert_eq!(
        r["path"],
        json!(o.home.join("repos/demo.git")),
        "where to audit it"
    );
    assert_eq!(r["seq"], json!(before["next_seq"].as_u64().unwrap() - 1));
    assert_eq!(r["head_hash"], before["head_hash"]);
    let after = o.ok("status", Some("demo"), json!({}));
    assert_eq!(status(&after), status(&before));
    assert_eq!(after["daemon_key"], before["daemon_key"]);
    assert_eq!(
        o.store("demo")
            .refs_with_prefix("refs/lonca/changes/")
            .unwrap()
            .len(),
        changes
    );
    let rep = audit(&o.store("demo"), deep()).unwrap();
    assert!(rep.ok(), "{:#?}", rep.findings);
    assert_eq!(rep.head_hash, before["head_hash"].as_str().unwrap());

    // The log's sessions are there; their tokens were not backed up.
    assert_eq!(
        after["sessions"].as_array().unwrap().len(),
        before["sessions"].as_array().unwrap().len()
    );
    let err = o.raw("whoami", None, Some(&t1), json!({})).unwrap_err();
    assert_eq!(err.0, "unauthenticated");
    // The daemon goes on writing with its key.
    let op = Op::Freeze { reason: "x".into() };
    let r = o.ok("human.submit", Some("demo"), e.sign(&op)).clone();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert!(audit(&o.store("demo"), deep()).unwrap().ok());
}

#[test]
fn a_restore_on_another_daemon_is_foreign_until_a_human_recovers_it() {
    let mut e = repo();
    let before = e.ok("status", Some("demo"), None, json!({}));
    let bundle = backup(&mut e);

    let mut o = Other::open(&e, "home3", false);
    let r = o.restore("demo", &bundle).unwrap();
    assert_eq!(r["foreign"], json!(true));
    assert_eq!(r["daemon_key"], before["daemon_key"]);
    let err = o.call("status", Some("demo"), json!({})).unwrap_err();
    assert_eq!(err.0, "foreign_key", "{err:?}");
    assert_eq!(o.ok("repo.list", None, json!({})), json!([]));
    // Deleting the store behind the daemon's back does not let a restore
    // in: the daemon's view counts, until it is restarted.
    std::fs::rename(o.home.join("repos/demo.git"), o.home.join("aside")).unwrap();
    let err = o.restore("demo", &bundle).unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
    std::fs::rename(o.home.join("aside"), o.home.join("repos/demo.git")).unwrap();
    // Still foreign after a restart, and the store is where it belongs.
    o = Other::open(&e, "home3", false);
    let err = o.call("status", Some("demo"), json!({})).unwrap_err();
    assert_eq!(err.0, "foreign_key", "{err:?}");

    let new = o.ok("ping", None, json!({}))["daemon_key"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(new, before["daemon_key"].as_str().unwrap());
    let op = Op::DaemonRecover { key: new.clone() };
    let r = o.ok("human.submit", Some("demo"), e.sign(&op));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let after = o.ok("status", Some("demo"), json!({}));
    assert_eq!(after["daemon_key"], json!(new));
    assert_eq!(after["trunk"], before["trunk"]);
    assert!(
        after["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["active"] == json!(false))
    );
    let rep = audit(&o.store("demo"), deep()).unwrap();
    assert!(rep.ok(), "{:#?}", rep.findings);
    assert_eq!(rep.key_switches.len(), 1);
    assert_eq!(rep.key_switches[0].kind, "daemon.recover");
}

#[test]
fn a_restore_from_the_pushed_remote_or_a_mirror_is_complete() {
    let mut e = repo();
    let before = e.ok("status", Some("demo"), None, json!({}));
    let remote = e.root.join("remote.git");
    git(&e.root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
    let prep = e.ok(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": remote}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let pushed = e.ok("status", Some("demo"), None, json!({}));

    let mut o = Other::open(&e, "home2", true);
    let r = o.restore("demo", &remote).unwrap();
    assert_eq!(r["head_hash"], pushed["head_hash"]);
    assert_eq!(
        status(&o.ok("status", Some("demo"), json!({}))),
        status(&pushed)
    );
    let rep = audit(&o.store("demo"), deep()).unwrap();
    assert!(rep.ok(), "{:#?}", rep.findings);
    assert!(
        rep.skipped.is_empty(),
        "every object was pushed: {:#?}",
        rep.skipped
    );

    let mirror = e.root.join("mirror.git");
    git(
        &e.root,
        &[
            "clone",
            "-q",
            "--mirror",
            e.root.join("home/repos/demo.git").to_str().unwrap(),
            mirror.to_str().unwrap(),
        ],
    );
    let mut o3 = Other::open(&e, "home3", true);
    o3.restore("demo", &mirror).unwrap();
    assert_eq!(
        status(&o3.ok("status", Some("demo"), json!({}))),
        status(&pushed)
    );
    assert!(audit(&o3.store("demo"), deep()).unwrap().ok());
    let _ = before;
}

/// A copy taken between appending an entry and applying it (or an older
/// trunk ref in a mirror) is repaired from the log, without an unmediated
/// import: the log says what trunk is.
#[test]
fn a_restore_puts_trunk_where_the_log_says() {
    let mut e = repo();
    let before = e.ok("status", Some("demo"), None, json!({}));
    let bundle = backup(&mut e);
    let copy = e.root.join("copy.git");
    git(&e.root, &["init", "-q", "--bare", copy.to_str().unwrap()]);
    git(
        &copy,
        &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
    );
    git(
        &copy,
        &["update-ref", "refs/heads/main", "refs/heads/main~1"],
    );
    assert_ne!(
        git(&copy, &["rev-parse", "refs/heads/main"]),
        before["trunk"].as_str().unwrap()
    );

    let mut o = Other::open(&e, "home2", true);
    o.restore("demo", &copy).unwrap();
    let after = o.ok("status", Some("demo"), json!({}));
    assert_eq!(status(&after), status(&before), "nothing was logged");
    assert_eq!(
        git(
            &o.home.join("repos/demo.git"),
            &["rev-parse", "refs/heads/main"]
        ),
        before["trunk"].as_str().unwrap()
    );
    assert!(audit(&o.store("demo"), deep()).unwrap().ok());
}

#[test]
fn a_restore_refuses_what_it_can_not_trust_and_leaves_nothing_behind() {
    let mut e = repo();
    let bundle = backup(&mut e);
    let mut o = Other::open(&e, "home2", true);

    // Names and sources.
    let err = o.restore("../x", &bundle).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    let err = o.restore("demo", Path::new("relative.bundle")).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    let err = o
        .restore("demo", &e.root.join("missing.bundle"))
        .unwrap_err();
    assert_eq!(err.0, "forbidden", "{err:?}");
    assert!(err.1.contains("does not exist"), "{err:?}");
    assert!(
        !o.home.join("repos/demo.git").exists(),
        "nothing left behind"
    );
    // Under another name than the log's.
    let err = o.restore("other", &bundle).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    assert!(err.1.contains("backup of repository demo"), "{err:?}");
    assert!(!o.home.join("repos/other.git").exists());
    // An empty store.
    let empty = e.root.join("empty.git");
    git(&e.root, &["init", "-q", "--bare", empty.to_str().unwrap()]);
    let err = o.restore("demo", &empty).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    assert!(err.1.contains("no operation log"), "{err:?}");
    assert!(!o.home.join("repos/demo.git").exists());

    // A tampered copy: an entry signed by a stranger. Refused, nothing kept.
    let copy = e.root.join("copy.git");
    git(&e.root, &["init", "-q", "--bare", copy.to_str().unwrap()]);
    git(
        &copy,
        &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
    );
    let store = Store::open(&copy).unwrap();
    let ops = OpLog::new(&store).read_all().unwrap();
    let state = State::replay(&ops);
    let attacker = KeyPair::generate();
    let t = state.last_time_ms + 1;
    let entry: OpEntry = Chain::from_state(attacker.clone(), state)
        .prepare(
            Submission::new(
                lonca_core::ops::Actor::Daemon,
                Op::Freeze { reason: "x".into() },
            ),
            t,
            &PolicyBundle::default_bundle(),
        )
        .entry;
    let head = OpLog::new(&store).head().unwrap();
    append_raw(&store, &SignedOp::sign(entry, &attacker), head.as_ref());
    let err = o.restore("demo", &copy).unwrap_err();
    assert_eq!(err.0, "integrity", "{err:?}");
    assert!(!o.home.join("repos/demo.git").exists());

    // Never over an existing repository: not in the restoring daemon, and
    // not in the one that made the backup.
    o.restore("demo", &bundle).unwrap();
    let err = o.restore("demo", &bundle).unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
    let err = e
        .call(
            "repo.restore",
            None,
            None,
            json!({"repo": "demo", "from": bundle.to_string_lossy()}),
        )
        .unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
    assert!(err.1.contains("never replaces"), "{err:?}");
    // A directory in repos/ the daemon does not know counts as existing.
    std::fs::create_dir_all(o.home.join("repos/junk.git")).unwrap();
    let err = o.restore("junk", &bundle).unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
    // A prepared but never initialised repository counts as existing too.
    let key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    e.ok(
        "repo.prepare_init",
        None,
        None,
        json!({"repo": "pending", "human": "ayse", "human_key": key}),
    );
    let err = e
        .call(
            "repo.restore",
            None,
            None,
            json!({"repo": "pending", "from": bundle.to_string_lossy()}),
        )
        .unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
}

/// A hardened daemon reads a backup the developer left in its import
/// directory: the developer can not write its backups directory.
#[test]
fn a_restore_reads_a_bundle_from_the_import_directory() {
    let mut e = repo();
    let before = e.ok("status", Some("demo"), None, json!({}));
    let bundle = backup(&mut e);
    let dir = e.root.join("import");
    std::fs::create_dir_all(&dir).unwrap();
    let left = dir.join("demo.bundle");
    std::fs::copy(&bundle, &left).unwrap();
    e.settings.local_roots = Some(vec![]);
    e.settings.import_dir = Some(dir.clone());
    let mut o = Other::open(&e, "home2", true);
    let r = o.restore("demo", &left).unwrap();
    assert_eq!(r["head_hash"], before["head_hash"]);
    assert!(audit(&o.store("demo"), deep()).unwrap().ok());
    assert_eq!(
        std::fs::read_dir(o.home.join("imports")).unwrap().count(),
        0
    );
    // The first daemon's backups are not this one's: refused.
    std::fs::remove_dir_all(o.home.join("repos/demo.git")).unwrap();
    let mut o = Other::open(&e, "home3", true);
    let err = o.restore("demo", &bundle).unwrap_err();
    assert_eq!(err.0, "forbidden", "{err:?}");
}
