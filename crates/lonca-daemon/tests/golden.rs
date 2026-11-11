//! Golden operation logs: one frozen log per format version, written by the
//! release that introduced that version. Every later build must still read,
//! verify, replay and audit them (docs/decisions.md, "Log format versions").
//!
//! A fixture is never regenerated. To add one for a new format version:
//!
//! ```sh
//! LONCA_GOLDEN_OUT=$PWD/crates/lonca-daemon/tests/fixtures/oplog-vN.bundle \
//!   cargo test -p lonca-daemon --test golden -- --ignored write_golden_log
//! ```
//!
//! then add a test below that pins its head hash.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::canonical::canonical_bytes;
use lonca_core::oplog::{FORMAT_CURRENT, FORMAT_LEGACY, OpEntry};
use lonca_core::ops::{CheckKind, Claim, ObsKind, ObservationLevel};
use lonca_symbols::engine::ENGINE_CURRENT;
use std::collections::BTreeSet;

const LEDGER_RS: &str = "pub struct Ledger {\n    total: u64,\n}\n\nimpl Ledger {\n    pub fn add(&mut self, v: u64) {\n        self.total += v;\n    }\n\n    pub fn total(&self) -> u64 {\n        self.total\n    }\n}\n";
const LEDGER_PY: &str = "import os\n\n\nclass Ledger:\n    def add(self, v):\n        self.total += v\n\n    def total(self):\n        return self.total\n";

/// `busy_repo` plus lease release, session end, freeze and unfreeze, and
/// human changes to methods in Rust and Python, so the facts and merges in
/// the log depend on more of the symbol engine (qualified member names,
/// imports, signatures).
fn golden_repo() -> Env {
    let mut e = busy_repo();
    e.human_change(
        vec![
            file("src/ledger.rs", LEDGER_RS),
            file("app/ledger.py", LEDGER_PY),
        ],
        "ledger",
    );
    e.svc.process_all();
    e.human_change(
        vec![
            file(
                "src/ledger.rs",
                &LEDGER_RS.replace(
                    "self.total += v;",
                    "self.total = self.total.saturating_add(v);",
                ),
            ),
            file(
                "app/ledger.py",
                &LEDGER_PY
                    .replace("import os\n", "import os\nimport sys\n")
                    .replace("def add(self, v):", "def add(self, v, note):"),
            ),
        ],
        "ledger methods",
    );
    e.svc.process_all();
    let t = e.session("s3", &["notes.md"]);
    let set = e.lease(&t, "notes.md#<file>")["set"]
        .as_str()
        .expect("lease set")
        .to_string();
    e.ok("lease.release", None, Some(&t), json!({ "set": set }));
    // It ends with work nobody proposed: an `unproposed` observation.
    e.ok(
        "session.end",
        None,
        Some(&t),
        json!({"files": [{"path": "notes.md", "entry": null}]}),
    );
    e.human(Op::Freeze {
        reason: "golden".into(),
    });
    e.human(Op::Unfreeze {
        reason: "golden".into(),
    });
    human_keys(&mut e);
    daemon_keys(&mut e);
    scratch_roots(&mut e);
    rejection(&mut e);
    pins(&mut e);
    liveness(&mut e);
    continuation(&mut e);
    queue(&mut e);
    wide_wait(&mut e);
    keyed_names(&mut e);
    renames(&mut e);
    unparsed(&mut e);
    batch(&mut e);
    reach(&mut e);
    shared(&mut e);
    insert_names(&mut e);
    give_back(&mut e);
    unhooked(&mut e);
    named_checks(&mut e);
    replaces(&mut e);
    lost_mac(&mut e);
    security_keys(&mut e);
    e
}

/// A software key standing in for a FIDO security key: it signs what the
/// device signs, in the form `ssh-keygen -Y sign` gives it.
enum SoftSk {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl SoftSk {
    fn kind(&self) -> lonca_policy::human::sk::Kind {
        use lonca_policy::human::sk::Kind;
        match self {
            SoftSk::P256(_) => Kind::P256,
            SoftSk::Ed25519(_) => Kind::Ed25519,
        }
    }

    fn public(&self) -> Vec<u8> {
        match self {
            SoftSk::P256(k) => k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            SoftSk::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
        }
    }

    fn key(&self) -> HumanKey {
        HumanKey {
            alg: self.kind().alg().into(),
            public: hex::encode(self.public()),
        }
    }

    /// The signature blob over `msg`, in hex; `flags` is what the device
    /// says of the person (1: touched).
    fn sign(&self, msg: &[u8], flags: u8) -> String {
        use lonca_policy::human::sk::{self, Assertion, Hash};
        let (hash, counter) = (Hash::Sha512, 5);
        let data = sk::signed_data(msg, hash, flags, counter);
        let signature: [u8; 64] = match self {
            SoftSk::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(&data);
                sig.to_bytes()[..].try_into().unwrap()
            }
            SoftSk::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(&data).to_bytes()
            }
        };
        let a = Assertion {
            hash,
            flags,
            counter,
            signature,
        };
        hex::encode(sk::encode(self.kind(), &self.public(), &a))
    }
}

/// From format 28: two humans with keys on security keys, one of each
/// kind. Each signs in and signs operations with a touch; a signature
/// made without one is denied, and that denial is in the log too.
fn security_keys(e: &mut Env) {
    use lonca_core::ops::HumanSignature;
    use lonca_policy::human::{intent_bytes, login_bytes};
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let seed =
        |k: &KeyPair| -> [u8; 32] { hex::decode(k.public_hex()).unwrap().try_into().unwrap() };
    let humans = [
        (
            "cem",
            SoftSk::P256(p256::ecdsa::SigningKey::from_slice(&seed(&KeyPair::generate())).unwrap()),
        ),
        (
            "deniz",
            SoftSk::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed(
                &KeyPair::generate(),
            ))),
        ),
    ];
    for (name, sk) in &humans {
        allowed(e.human(Op::HumanEnroll {
            human: (*name).into(),
            key: sk.key(),
        }));
        let signature = |sig: String, nonce: String, issued_ms: i64| HumanSignature {
            human: (*name).into(),
            nonce,
            issued_ms,
            sig,
        };
        let (nonce, now, ttl) = (lonca_core::canonical::nonce(), e.now(), 3_600_000);
        let login = sk.sign(&login_bytes(None, name, ttl, &nonce, now), 1);
        let login = json!({"sig": signature(login, nonce, now), "ttl_ms": ttl});
        let session = e.anon("human.login", None, None, login).unwrap()["token"]
            .as_str()
            .expect("token")
            .to_string();
        let submit = |e: &mut Env, op: Op, flags: u8| {
            let (nonce, now) = (lonca_core::canonical::nonce(), e.now());
            let sig = sk.sign(&intent_bytes("demo", &op, &nonce, now), flags);
            let body = json!({"op": op, "sig": signature(sig, nonce, now)});
            e.anon("human.submit", Some("demo"), Some(&session), body)
                .unwrap()
        };
        let freeze = || Op::Freeze {
            reason: format!("{name} touched"),
        };
        let r = submit(e, freeze(), 0);
        assert_eq!(r["decision"]["outcome"], "deny", "{r}");
        assert_eq!(r["decision"]["reasons"], json!(["bad_human_signature"]));
        allowed(submit(e, freeze(), 1));
        let unfreeze = Op::Unfreeze {
            reason: "golden".into(),
        };
        allowed(submit(e, unfreeze, 1));
    }
}

/// From format 27: ayse sets a recovery key, then the daemon key and her
/// key are both lost; her recovery key alone moves the log onto the new
/// daemon key and replaces her key. Her new key signs on.
fn lost_mac(e: &mut Env) {
    use lonca_core::ops::Recovery;
    use lonca_policy::human::sign_ed25519;
    let key = |k: &KeyPair| HumanKey {
        alg: "ed25519".into(),
        public: k.public_hex(),
    };
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let rec = KeyPair::generate();
    allowed(e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: key(&rec),
    }));
    std::fs::remove_file(e.root.join("home/daemon.key")).unwrap();
    e.reopen();
    let daemon = e.ok("ping", None, None, json!({}))["daemon_key"]
        .as_str()
        .expect("key")
        .to_string();
    let fresh = KeyPair::generate();
    let op = Op::DaemonRecover {
        key: daemon,
        recover: Some(Recovery {
            human: "ayse".into(),
            key: key(&fresh),
        }),
    };
    let body = json!({"op": op, "sig": sign_ed25519(&rec, "ayse", "demo", &op, e.now())});
    allowed(e.anon("human.submit", Some("demo"), None, body).unwrap());
    e.human = fresh;
    e.session("s-mac", &["notes.md"]);
}

/// From format 26: a workspace proposes twice while the first waits; the
/// second replaces it, and its approval lands the work once.
fn replaces(e: &mut Env) {
    let base = e.trunk();
    let t = e.session("s-rep", &["card.md"]);
    e.lease(&t, "card.md#<file>");
    let first = vec![file("card.md", "first draft\n")];
    let r = e.propose(&t, &base, first, &["card.md#<file>"]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let older = r["change"].as_str().expect("change").to_string();
    let second = vec![file("card.md", "second draft\n")];
    let r = e.propose(&t, &base, second, &["card.md#<file>"]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let reasons = r["decision"]["reasons"].to_string();
    assert!(reasons.contains(&format!("replaces:{older}")), "{r}");
    let d = e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
        checks: vec![],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    assert_eq!(e.svc.process_all(), 1);
}

/// From format 25: a human approves a proposal with a named check, and the
/// queue runs it; its evidence is `named`.
fn named_checks(e: &mut Env) {
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "\nchecks = {}\n",
        "\nchecks = { card = \"test -f card.md\" }\n",
    );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    e.human_change(vec![file("card.md", "a card\n")], "card");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let t = e.session("s-card", &["card.md"]);
    e.lease(&t, "card.md#<file>");
    let files = vec![file("card.md", "accepted when card passes\n")];
    let r = e.propose(&t, &base, files, &["card.md#<file>"]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let d = e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
        checks: vec!["card".into()],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    assert_eq!(e.svc.process_all(), 1);
}

/// From format 24: a call to `lonca mcp` whose before-tool event never came
/// marks the session `unhooked`, and what it proposes waits for a human
/// under that word.
fn unhooked(e: &mut Env) {
    e.advance(lonca_daemon::hooked::START_GRACE_MS);
    let fresh = "src/hookless.rs";
    let t = e.session("s-uh", &["src/**"]);
    e.bind(&t);
    e.wrote(&t, fresh);
    let items = json!([{"symbol": "src/hookless.rs#<file>", "kind": "edit"}]);
    let args = json!({"items": items, "intent": "a file", "ttl_ms": 600_000});
    let r = e.ok("lease.acquire", None, Some(&t), args);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let r = e.ok("mcp.call", None, Some(&t), json!({"tool": "propose"}));
    assert_eq!(r["hooked"], false, "{r}");
    let base = e.trunk();
    let files = vec![file(fresh, "pub fn hookless() {}\n")];
    let preview = json!({"base": base, "files": files});
    let r = e.ok("facts.preview", None, Some(&t), preview);
    let adds: Vec<String> = serde_json::from_value(r["facts"]["adds"].clone()).unwrap();
    let claim = Claim {
        intent: "a file".into(),
        adds,
        ..Default::default()
    };
    let args = json!({"base": base, "files": files, "claim": claim});
    let r = e.ok("change.propose", None, Some(&t), args);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let reasons = r["decision"]["reasons"].to_string();
    assert!(reasons.contains("unhooked_session"), "{r}");
}

/// From format 23: a child whose time runs out gives the set it was handed
/// back to its parent, so another session's acquire meets the parent.
fn give_back(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let a = e.session("s-ga", &["back.md"]);
    let b = e.session("s-gb", &["back.md"]);
    let set = e.lease(&a, "back.md#<file>");
    allowed(set.clone());
    let set = set["set"].clone();
    let scope = json!({"paths": ["back.md"], "symbols": null, "ops": ["lease.release"],
                       "max_files": null, "max_lines": null});
    let expires = e.now() + 60_000;
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&a),
        json!({"agent": "sub", "scope": scope, "expires_ms": expires, "leases": [set.clone()]}),
    );
    allowed(child);
    e.advance(60_001);
    let r = e.lease(&b, "back.md#<file>");
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert!(
        r["decision"]["reasons"][0]
            .as_str()
            .is_some_and(|x| x.starts_with("lease_held:back.md#<file>:s-ga:")),
        "{r}"
    );
    allowed(e.ok("lease.release", None, Some(&a), json!({ "set": set })));
    allowed(e.lease(&b, "back.md#<file>"));
}

/// From format 22: two inserts into one type reserve the names they add, a
/// third that wants one of them is refused, and a new file is created under
/// an exclusive lease on its path.
fn insert_names(e: &mut Env) {
    let path = "src/limits.rs";
    let seed = "pub struct Limits;\n\nimpl Limits {\n    pub fn new() -> Self {\n        Limits\n    }\n}\n";
    let r = e.human_change(vec![file(path, seed)], "limits");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let acquire = |e: &mut Env, t: &str, items: Value| {
        let args = json!({"items": items, "intent": "a member", "ttl_ms": 600_000});
        e.ok("lease.acquire", None, Some(t), args)
    };
    let container = "src/limits.rs#Limits";
    let mut proposals = vec![];
    for (name, member) in [("s-na", "low"), ("s-nb", "high")] {
        let t = e.session(name, &["src/**"]);
        e.bind(&t);
        e.wrote(&t, path);
        let items = json!([{"symbol": container, "kind": "insert", "names": [member]}]);
        let r = acquire(e, &t, items);
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        let method = format!("    pub fn {member}() -> u8 {{\n        1\n    }}\n}}\n");
        let text = seed.replace("    }\n}\n", &format!("    }}\n\n{method}"));
        proposals.push((t, vec![file(path, &text)]));
    }
    let t = e.session("s-nc", &["src/**"]);
    let items = json!([{"symbol": container, "kind": "insert", "names": ["low"]}]);
    let r = acquire(e, &t, items);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let fresh = "src/fresh.rs";
    let t = e.session("s-nd", &["src/**"]);
    e.bind(&t);
    e.wrote(&t, fresh);
    let r = acquire(
        e,
        &t,
        json!([{"symbol": "src/fresh.rs#<file>", "kind": "edit"}]),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    proposals.push((t, vec![file(fresh, "pub fn fresh() {}\n")]));
    for (t, files) in proposals {
        let preview = json!({"base": base, "files": files});
        let r = e.ok("facts.preview", None, Some(&t), preview);
        let adds: Vec<String> = serde_json::from_value(r["facts"]["adds"].clone()).unwrap();
        let claim = Claim {
            intent: "a member".into(),
            adds,
            ..Default::default()
        };
        let args = json!({"base": base, "files": files, "claim": claim});
        let r = e.ok("change.propose", None, Some(&t), args);
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    }
    assert_eq!(e.svc.process_all(), 3);
    let head = e.trunk();
    let text = e.store().read_file(&head, path).unwrap().unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("fn low()") && text.contains("fn high()"),
        "{text}"
    );
    assert!(e.store().read_file(&head, fresh).unwrap().is_some());
}

/// From format 21 and engine 14: two agents hold one function `shared`, and
/// the merge joins their lines.
fn shared(e: &mut Env) {
    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace("shared = false", "shared = true")
        .replace("required = false", "required = true")
        .replace("# test = \"cargo test --offline\"", "test = \"true\"");
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let path = "src/joined.rs";
    let seed = "pub fn joined() -> u8 {\n    let a = 1;\n    let b = 2;\n    let c = 3;\n    a + b + c\n}\n";
    let r = e.human_change(vec![file(path, seed)], "joined");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    for (name, from, to) in [("s-ja", "a = 1", "a = 10"), ("s-jb", "c = 3", "c = 30")] {
        let t = e.session(name, &["src/**"]);
        e.bind(&t);
        e.wrote(&t, path);
        let items = json!([{"symbol": "src/joined.rs#joined", "kind": "shared"}]);
        let r = e.ok(
            "lease.acquire",
            None,
            Some(&t),
            json!({"items": items, "intent": "a line", "ttl_ms": 600_000}),
        );
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        let files = vec![file(path, &seed.replace(from, to))];
        let r = e.propose(&t, &base, files, &["src/joined.rs#joined"]);
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    }
    assert_eq!(e.svc.process_all(), 2);
    let head = e.trunk();
    let text = e.store().read_file(&head, path).unwrap().unwrap();
    let joined = seed.replace("a = 1", "a = 10").replace("c = 3", "c = 30");
    assert_eq!(String::from_utf8(text).unwrap(), joined);
}

/// From format 18: facts say what mentions a changed signature, the decision
/// who holds it, and the queue runs what the policy keeps for such changes.
fn reach(e: &mut Env) {
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "# on_signature_change = \"cargo test --offline --workspace --all-features\"",
        "on_signature_change = \"true\"",
    );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let (lib, user) = ("src/reach.rs", "src/reach_user.rs");
    let caller = "pub fn g() -> u8 {\n    reached(1)\n}\n";
    let files = vec![
        file(lib, "pub fn reached(a: u8) -> u8 {\n    a\n}\n"),
        file(user, caller),
    ];
    let r = e.human_change(files, "reached and its caller");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let t = e.session("s-reach", &["src/**"]);
    e.lease(&t, &format!("{user}#g"));
    let files = vec![file(lib, "pub fn reached(a: u16) -> u16 {\n    a\n}\n")];
    let r = e.human_change(files, "a new signature");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
}

/// From format 17: one entry integrates the head of the queue.
fn batch(e: &mut Env) {
    let config = lonca_policy::config::DEFAULT_CONFIG.replace("batch_size = 1", "batch_size = 2");
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    for name in ["src/one.zig", "src/two.zig"] {
        let r = e.human_change(vec![file(name, "const a = 1;\n")], "one of two");
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    }
    assert_eq!(e.svc.process_all(), 2);
}

/// From format 15: facts list the text files no parser reads.
fn unparsed(e: &mut Env) {
    let text = "const a = 1;\n";
    e.human_change(vec![file("src/a.zig", text)], "seed");
    e.svc.process_all();
    let r = e.human_change(vec![file("src/a.zig", &text.replace("1", "2"))], "edit");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    e.svc.process_all();
    unread(e);
}

/// From format 16: facts list a file a grammar stopped reading.
fn unread(e: &mut Env) {
    let java = "class A {\n}\n";
    e.human_change(vec![file("src/A.java", java)], "seed");
    e.svc.process_all();
    let broken = format!("{java}@@@\n");
    let r = e.human_change(vec![file("src/A.java", &broken)], "edit");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    e.svc.process_all();
}

/// From format 14: facts say what was renamed, and the old name meets the
/// new one.
fn renames(e: &mut Env) {
    let seed = "def charge(card):\n    pay(card)\n    log(card)\n";
    e.human_change(vec![file("src/pay.py", seed)], "seed");
    e.svc.process_all();
    let r = e.human_change(
        vec![file("src/pay.py", &seed.replace("charge", "bill"))],
        "a better name",
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    e.svc.process_all();
    let a = e.session("s23", &["src/pay.py"]);
    let b = e.session("s24", &["src/pay.py"]);
    let r = e.lease(&a, "src/pay.py#charge");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let r = e.lease(&b, "src/pay.py#bill");
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
}

/// From format 13: symbols of one name have a key, and the name alone stands
/// for all of them.
fn keyed_names(e: &mut Env) {
    let overloads = "class Client\n{\n    public void Charge(int a)\n    {\n    }\n\n    public void Charge(string s)\n    {\n    }\n}\n";
    e.human_change(vec![file("src/client.cs", overloads)], "overloads");
    e.svc.process_all();
    let a = e.session("s21", &["src/client.cs"]);
    let b = e.session("s22", &["src/client.cs"]);
    let r = e.lease(&a, "src/client.cs#Client.Charge");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let r = e.lease(&b, "src/client.cs#Client.Charge(int)");
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
}

/// From format 12: a waiting interest stops a new lease inside what it
/// waits for, and goes first when what it waits for is freed.
fn wide_wait(e: &mut Env) {
    let a = e.session("s18", &["wide.md"]);
    let b = e.session("s19", &["wide.md"]);
    let c = e.session("s20", &["wide.md"]);
    let (member, whole) = ("wide.md#Part.one", "wide.md#Part");
    let set = e.lease(&a, member)["set"].clone();
    let item = json!([{"symbol": whole, "kind": "edit"}]);
    let r = e.ok(
        "lease.interest",
        None,
        Some(&b),
        json!({"items": item, "intent": "the whole part"}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let d = e.lease(&c, "wide.md#Part.two");
    assert_eq!(d["decision"]["reasons"][0], "lease_wanted:s19", "{d}");
    e.ok("lease.release", None, Some(&a), json!({ "set": set }));
    let r = e.lease(&b, whole);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

/// From format 10: an interest gets the freed set, a yield moves a set in
/// one entry, a delegated set comes back when the child ends.
fn queue(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let a = e.session("s16", &["queue.md"]);
    let b = e.session("s17", &["queue.md"]);
    let item = json!([{"symbol": "queue.md#<file>", "kind": "edit"}]);
    let set = e.lease(&a, "queue.md#<file>")["set"].clone();
    allowed(e.ok(
        "lease.interest",
        None,
        Some(&b),
        json!({"items": item, "intent": "next"}),
    ));
    allowed(e.ok("lease.release", None, Some(&a), json!({ "set": set })));
    let set = e.lease(&b, "queue.md#<file>");
    allowed(set.clone());
    let set = set["set"].clone();
    allowed(e.ok(
        "negotiate",
        None,
        Some(&b),
        json!({"thread": "q1", "to_session": "s16",
               "message": {"type": "yield", "set": set, "to": "s16"}}),
    ));
    let scope = json!({"paths": ["queue.md"], "symbols": null, "ops": ["lease.release"],
                       "max_files": null, "max_lines": null});
    let expires = e.now() + 600_000;
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&a),
        json!({"agent": "sub", "scope": scope, "expires_ms": expires, "leases": [set]}),
    );
    allowed(child.clone());
    allowed(e.ok(
        "session.end",
        None,
        Some(child["token"].as_str().expect("token")),
        json!({}),
    ));
}

/// From format 9: a session with a change in flight is continued; the
/// pin passes on, a human approves, integration releases it.
fn continuation(e: &mut Env) {
    e.human_change(vec![file("cont.md", "first\n")], "continued file");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session_in("s14", &["cont.md"], "/ws/s14");
    e.lease(&a, "cont.md#<file>");
    let r = e.propose(
        &a,
        &base,
        vec![file("cont.md", "continued\n")],
        &["cont.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let seq = r["seq"].as_u64().expect("seq");
    let c = e.continue_session("s15", "s14", &["cont.md"]);
    assert_eq!(c["decision"]["outcome"], "allow", "{c}");
    let d = e.human(Op::Approve {
        target_seq: seq,
        note: "golden".into(),
        checks: vec![],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    e.svc.process_all();
}

/// From format 8: a session beats and stops, its lease goes at the
/// timeout; a denied acquire is on record as interest.
fn liveness(e: &mut Env) {
    let a = e.session("s12", &["pins.md"]);
    let b = e.session("s13", &["pins.md"]);
    e.lease(&a, "pins.md#<file>");
    let r = e.ok("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(r["decision"]["reasons"][0], "heartbeat_timeout=300000");
    assert_eq!(e.lease(&b, "pins.md#<file>")["decision"]["outcome"], "deny");
    e.advance(300_001);
    assert_eq!(
        e.lease(&b, "pins.md#<file>")["decision"]["outcome"],
        "allow"
    );
}

/// From format 7: a proposal pins its lease past the TTL, the human
/// approves, integration releases it; a lease set nobody renewed is pruned.
fn pins(e: &mut Env) {
    let base = e.trunk();
    let a = e.session("s10", &["notes.md", "pins.md"]);
    let b = e.session("s11", &["notes.md"]);
    e.lease(&a, "notes.md#<file>");
    e.lease(&a, "pins.md#<file>");
    let r = e.propose(
        &a,
        &base,
        vec![file("notes.md", "pinned\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    e.advance(601_000);
    assert_eq!(
        e.lease(&b, "notes.md#<file>")["decision"]["outcome"],
        "deny"
    );
    let d = e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
        checks: vec![],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    e.svc.process_all();
    assert_eq!(
        e.lease(&b, "notes.md#<file>")["decision"]["outcome"],
        "allow"
    );
}

/// From format 6: an unobserved session proposes, a human rejects it with
/// a reason, the session proposes again and the human approves.
fn rejection(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let base = e.trunk();
    let t = e.session("s9", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "golden\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    allowed(e.human(Op::Reject {
        target_seq: r["seq"].as_u64().expect("seq"),
        reason: "golden: say more".into(),
    }));
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "golden, more\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    allowed(e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
        checks: vec![],
    }));
    e.svc.process_all();
}

/// From format 5: a session whose scope names scratch roots, a child
/// session narrowed to one of them, and an observation from each.
fn scratch_roots(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let start = Op::SessionStart {
        session: "s8".into(),
        agent: "bot-s8".into(),
        model: None,
        task: "T-8".into(),
        scope: Scope {
            paths: vec!["notes.md".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire, OpKind::CapAttenuate],
            max_files: None,
            max_lines: None,
            scratch: vec!["/tmp/golden/scratch".into(), "/tmp/golden/logs".into()],
        },
        expires_ms: e.now() + 3_600_000,
        continues: None,
        harness: None,
        workspace: None,
    };
    let r = e.human(start);
    allowed(r.clone());
    let t = r["token"].as_str().expect("token").to_string();
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&t),
        json!({"agent": "bot-s8-child", "scope": {"paths": ["notes.md"], "symbols": null, "ops": ["lease.acquire"], "max_files": null, "max_lines": null, "scratch": ["/tmp/golden/logs"]}, "expires_ms": e.now() + 60_000}),
    );
    allowed(r.clone());
    let ws = e.root.join("ws");
    e.ok(
        "hook.event",
        None,
        Some(&t),
        json!({"hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "/tmp/golden/scratch/notes.txt"}, "workspace": ws}),
    );
    e.ok(
        "hook.event",
        None,
        Some(&t),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/tmp/golden/logs/run.log"}, "workspace": ws}),
    );
}

/// From format 4: the daemon key is rotated, a session starts, then the
/// key is lost and a human recovers the log onto a new daemon key, which
/// ends the session; one more entry follows under the new key.
fn daemon_keys(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let next = e.ok("daemon.prepare_rotate", None, None, json!({}))["key"]
        .as_str()
        .expect("key")
        .to_string();
    allowed(e.human(Op::DaemonRotate { key: next }));
    let t = e.session("s6", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    std::fs::remove_file(e.root.join("home/daemon.key")).unwrap();
    e.reopen();
    let key = e.ok("ping", None, None, json!({}))["daemon_key"]
        .as_str()
        .expect("key")
        .to_string();
    allowed(e.human(Op::DaemonRecover { key, recover: None }));
    e.session("s7", &["notes.md"]);
}

/// From format 3: a second human with a session, then ayse sets a recovery
/// key, rotates, recovers and revokes the second human.
fn human_keys(e: &mut Env) {
    let key = |k: &KeyPair| HumanKey {
        alg: "ed25519".into(),
        public: k.public_hex(),
    };
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let bora = KeyPair::generate();
    allowed(e.human(Op::HumanEnroll {
        human: "bora".into(),
        key: key(&bora),
    }));
    let start = Op::SessionStart {
        session: "s4".into(),
        agent: "bot-s4".into(),
        model: None,
        task: "T-4".into(),
        scope: Scope {
            paths: vec!["notes.md".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire],
            max_files: None,
            max_lines: None,
            scratch: vec![],
        },
        expires_ms: e.now() + 3_600_000,
        continues: None,
        harness: None,
        workspace: None,
    };
    let body = json!({"op": start, "sig": sign_ed25519(&bora, "bora", "demo", &start, e.now())});
    // Bora submits on bora's own session (logins are not log entries).
    let sig = sign_login_ed25519(&bora, "bora", None, 3_600_000, e.now());
    let bora_session = e
        .anon(
            "human.login",
            None,
            None,
            json!({"sig": sig, "ttl_ms": 3_600_000}),
        )
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    allowed(
        e.anon("human.submit", Some("demo"), Some(&bora_session), body)
            .unwrap(),
    );
    let t = e.session("s5", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");

    let rec = KeyPair::generate();
    allowed(e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: key(&rec),
    }));
    let rotated = KeyPair::generate();
    allowed(e.human(Op::HumanRotate {
        human: "ayse".into(),
        key: key(&rotated),
    }));
    e.human = rotated;
    let recovered = KeyPair::generate();
    let op = Op::HumanRecover {
        human: "ayse".into(),
        key: key(&recovered),
    };
    let body = json!({"op": op, "sig": sign_ed25519(&rec, "ayse", "demo", &op, e.now())});
    allowed(e.ok("human.submit", Some("demo"), None, body));
    e.human = recovered;
    allowed(e.human(Op::HumanRevoke {
        human: "bora".into(),
        reason: "golden".into(),
    }));
}

#[test]
#[ignore = "writes a new fixture; run by hand when the log format version changes"]
fn write_golden_log() {
    let out = std::env::var("LONCA_GOLDEN_OUT").expect("set LONCA_GOLDEN_OUT");
    let out = std::path::absolute(out).unwrap();
    assert!(!out.exists(), "fixtures are never overwritten: {out:?}");
    let e = golden_repo();
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    let repo = e.root.join("home/repos/demo.git");
    git(
        &repo,
        &["bundle", "create", "-q", out.to_str().unwrap(), "--all"],
    );
    eprintln!("wrote {out:?}, head hash {}", r.head_hash);
}

/// Unpacks a fixture bundle into a fresh bare repository.
fn load(name: &str) -> (tempfile::TempDir, Store) {
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("r.git");
    git(
        dir.path(),
        &["init", "-q", "--bare", repo.to_str().unwrap()],
    );
    git(
        &repo,
        &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
    );
    let store = Store::open(&repo).unwrap();
    (dir, store)
}

/// Reads, verifies, replays and deeply audits a golden log, and checks that
/// re-encoding every entry reproduces the stored bytes.
fn check_golden(name: &str, head_hash: &str, format: u32) -> Vec<SignedOp> {
    let (_dir, store) = load(name);
    let log = OpLog::new(&store);
    let ops = log.read_all().unwrap();
    assert_eq!(verify_chain(&ops).unwrap(), head_hash, "{name}: head hash");

    let mut cur = log.head().unwrap();
    while let Some(c) = cur {
        let stored = store.read_file(&c, "op.json").unwrap().unwrap();
        let op = log.read_at(&c).unwrap();
        assert_eq!(op.entry.format, format, "{name}: op {}", op.entry.seq);
        assert_eq!(
            canonical_bytes(&op),
            stored,
            "{name}: op {} re-encodes differently",
            op.entry.seq
        );
        cur = store.read_commit(&c).unwrap().parents.into_iter().next();
    }

    let r = audit(&store, Options::default()).unwrap();
    assert!(r.ok(), "{name}: {:#?}", r.findings);
    assert!(r.skipped.is_empty(), "{name}: {:#?}", r.skipped);
    ops
}

#[test]
fn golden_v0_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v0.bundle",
        "d71753b35ca99db8c7a3b748b4d99567793467d4f96dcc421cc70a5fa6a3fe63",
        FORMAT_LEGACY,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    for k in [
        "repo.init",
        "policy.update",
        "session.start",
        "session.bind",
        "session.end",
        "lease.acquire",
        "lease.release",
        "change.propose",
        "change.integrate",
        "observe",
        "freeze",
        "unfreeze",
    ] {
        assert!(kinds.contains(k), "fixture lacks {k}: {kinds:?}");
    }
}

#[test]
fn golden_v1_log_still_verifies_replays_and_audits() {
    check_golden(
        "oplog-v1.bundle",
        "3761c7aefd055c300110e1277b8461d9fee782de8aba3c4591275023860a88e5",
        1,
    );
}

#[test]
fn golden_v2_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v2.bundle",
        "ec816526807edc4243261b1cdd649ec847509488fc86e921adcdcd0b29b66af1",
        2,
    );
    assert!(
        ops.iter()
            .filter(|o| o.entry.uses_symbols_engine())
            .all(|o| o.entry.symbols_engine == Some(0)),
        "v2 entries record symbol engine 0"
    );
}

#[test]
fn golden_v3_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v3.bundle",
        "9d6b940cf79c0872bf8bff2e3a0b61e805f8ebb31c5ce3f70419de44d92b2e33",
        3,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    for k in [
        "human.enroll",
        "human.recovery_key",
        "human.rotate",
        "human.recover",
        "human.revoke",
    ] {
        assert!(kinds.contains(k), "fixture lacks {k}: {kinds:?}");
    }
    assert!(
        ops.iter()
            .filter(|o| o.entry.op.kind().as_str().starts_with("human."))
            .all(|o| o.entry.decision.is_allow()),
        "the key operations in the fixture are allowed"
    );
}

#[test]
fn golden_v4_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v4.bundle",
        "bdda8f61008981ccab907c4aa6d156621bb4dcca57b992229ffbccebf7aa7a5f",
        4,
    );
    let switches: Vec<&str> = ops
        .iter()
        .filter(|o| o.entry.switches_daemon_key().is_some())
        .map(|o| o.entry.op.kind().as_str())
        .collect();
    assert_eq!(switches, ["daemon.rotate", "daemon.recover"]);
    // Three daemon keys signed it: genesis, rotation, recovery.
    let (_dir, store) = load("oplog-v4.bundle");
    let r = audit(&store, Options::default()).unwrap();
    assert_eq!(r.key_switches.len(), 2);
    assert_ne!(r.key_switches[0].key, r.key_switches[1].key);
}

/// A scope with scratch roots needs format 5: an older entry carrying one
/// is refused by the chain check, like an operation type from a later
/// format.
#[test]
fn scratch_roots_in_an_old_format_entry_are_refused() {
    let mut e = Env::new();
    e.init(None);
    let start = Op::SessionStart {
        session: "s1".into(),
        agent: "bot".into(),
        model: None,
        task: "T".into(),
        scope: Scope {
            paths: vec!["src/**".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire],
            max_files: None,
            max_lines: None,
            scratch: vec!["/tmp/s".into()],
        },
        expires_ms: e.now() + 60_000,
        continues: None,
        harness: None,
        workspace: None,
    };
    assert_eq!(e.human(start)["decision"]["outcome"], "allow");
    assert!(*formats(&e).last().unwrap() >= 5);
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = 4;
        }
    });
    let err = match open_service(&e) {
        Ok(_) => panic!("a format 4 entry with scratch roots was accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("session.start needs log format 5"), "{err}");
}

/// `reject` needs format 6: an older entry carrying one is refused.
#[test]
fn a_reject_in_an_old_format_entry_is_refused() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("notes.md", "a\n")], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let t = e.session("s1", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "b\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let d = e.human(Op::Reject {
        target_seq: r["seq"].as_u64().unwrap(),
        reason: "no".into(),
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    assert!(*formats(&e).last().unwrap() >= 6);
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = 5;
            forget_harness(&e, x);
        }
    });
    let err = match open_service(&e) {
        Ok(_) => panic!("a format 5 entry with a reject was accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("reject needs log format 6"), "{err}");
}

#[test]
fn golden_v6_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v6.bundle",
        "f2acaf21486501f40f99312aa5e9c287880bf13ec6cd19eb990be4cc3ec0d60c",
        6,
    );
    let rejects: Vec<&str> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::Reject { reason, .. } if o.entry.decision.is_allow() => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(rejects, ["golden: say more"]);
    let (_dir, store) = load("oplog-v6.bundle");
    let state = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    let rejected = state
        .changes
        .values()
        .filter(|c| matches!(c.status, lonca_policy::state::ChangeStatus::Rejected { .. }))
        .count();
    assert_eq!(rejected, 1);
    assert!(state.pending.is_empty());
}

#[test]
fn golden_v7_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v7.bundle",
        "a12aac062cca0b4ea0bc8bd18b94a36be15c1822b3ce65f53d2a3749cf572282",
        7,
    );
    let (_dir, store) = load("oplog-v7.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    // The set that outlived its TTL is pruned, the pin left with the change.
    assert_eq!(s.leases.len(), 1, "{:?}", s.leases);
    let (set, lease) = s.leases.iter().next().unwrap();
    assert_eq!(lease.session, "s11", "{set}");
    assert!(lease.pins.is_empty());
    assert!(s.queue.is_empty());
    assert!(ops.iter().any(|o| o.entry.format == 7));
}

#[test]
fn golden_v8_log_still_verifies_replays_and_audits() {
    check_golden(
        "oplog-v8.bundle",
        "79046d371007a8b39e9434318f28ea1bfe3d7d1782a7ab7b95bac1f57d420083",
        8,
    );
    let (_dir, store) = load("oplog-v8.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    let beat = s.sessions["s12"].heartbeat.expect("heartbeat recorded");
    assert_eq!(beat.timeout_ms, 300_000);
    assert!(s.sessions["s13"].heartbeat.is_none());
    let holders: Vec<&str> = s.leases.values().map(|l| l.session.as_str()).collect();
    assert_eq!(holders, ["s11", "s13"]);
}

#[test]
fn golden_v9_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v9.bundle",
        "daa7ce053bda8c6360435f9e13faf3ffc8fe7901f3fbe2f08b472c57f25933bd",
        9,
    );
    let continued: Vec<_> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::SessionStart {
                session,
                continues: Some(c),
                ..
            } => Some((session.as_str(), c.session.as_str(), c.widen)),
            _ => None,
        })
        .collect();
    assert_eq!(continued, [("s15", "s14", false)]);
    let (_dir, store) = load("oplog-v9.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert_eq!(s.sessions["s14"].ended.as_deref(), Some("continued by s15"));
    assert_eq!(s.sessions["s14"].continued_by.as_deref(), Some("s15"));
    assert_eq!(s.sessions["s15"].continued_from.as_deref(), Some("s14"));
    assert!(s.sessions["s15"].ended.is_none());
}

#[test]
fn golden_v10_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v10.bundle",
        "b2c546223ec30380f0f8b3824c237c944f7430e058d81fd025997f3f9e471f45",
        10,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    assert!(kinds.contains("lease.interest"), "{kinds:?}");
    let (_dir, store) = load("oplog-v10.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert!(s.interests.is_empty(), "served");
    assert!(s.reservations.is_empty(), "consumed");
    let queue: Vec<_> = s.leases.values().filter(|l| l.session == "s16").collect();
    assert_eq!(queue.len(), 1, "yielded to s16, delegated, given back");
    assert_eq!(queue[0].delegated_from, None);
}

#[test]
fn golden_v11_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v11.bundle",
        "81244b1c0db63ccf554a1d308a6853f19f9af63cd4e132e6e8bdb5de68db5bb7",
        11,
    );
    let reported = ops.iter().any(|o| {
        matches!(&o.entry.op, Op::Observe { events, .. }
            if events.iter().any(|e| matches!(&e.kind, ObsKind::Unproposed { total: 1, .. })))
    });
    assert!(reported, "s3 ended with work it never proposed");
    let (_dir, store) = load("oplog-v11.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    let left = s.sessions["s3"].unproposed.as_ref().expect("the mark");
    assert_eq!(left.paths, ["notes.md"]);
    assert_eq!(left.rounds, 1);
}

#[test]
fn golden_v12_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v12.bundle",
        "87b5b88c192477f7954a709b57521bb6e08754c25dfc9ea0f14be0898650f33a",
        12,
    );
    let stopped = ops
        .iter()
        .any(|o| o.entry.decision.reasons == ["lease_wanted:s19"]);
    assert!(stopped, "a new lease stopped by a waiting interest");
    let (_dir, store) = load("oplog-v12.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert!(s.interests.is_empty(), "served");
    let wide = s.leases.values().find(|l| l.session == "s19").expect("set");
    assert_eq!(wide.items[0].symbol, "wide.md#Part");
}

#[test]
fn golden_v13_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v13.bundle",
        "3cca6e32db6117b176675d4fda8b419728f259dc3abbf1823872eb5794493212",
        13,
    );
    let held = "lease_held:src/client.cs#Client.Charge:s21:";
    let stopped = ops.iter().any(|o| {
        let reasons = &o.entry.decision.reasons;
        reasons.iter().any(|r| r.starts_with(held))
    });
    assert!(stopped, "a key met the lease on its name");
}

/// A log from before format 20 has no harness on a start, and what the human
/// signed did not either.
fn forget_harness(e: &Env, x: &mut OpEntry) {
    if let Op::SessionStart { harness, .. } = &mut x.op {
        *harness = None;
        let sig = lonca_policy::human::sign_ed25519(&e.human, "ayse", "demo", &x.op, x.time_ms);
        x.human = Some(sig);
    }
}

#[test]
fn golden_v14_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v14.bundle",
        "da4e0fb625a65552eb148ec095f1c5079869ad76ca9361d933b94146e2ebde4f",
        14,
    );
    let renamed = ops.iter().filter_map(|o| o.entry.facts.as_ref());
    let renamed = renamed.flat_map(|f| f.renames.iter()).collect::<Vec<_>>();
    assert_eq!(renamed, [&["src/pay.py#charge", "src/pay.py#bill"]]);
    let held = "lease_held:src/pay.py#charge:s23:";
    let reasons = ops.iter().flat_map(|o| o.entry.decision.reasons.iter());
    assert!(
        reasons.into_iter().any(|r| r.starts_with(held)),
        "the old name met the new one"
    );
}

#[test]
fn golden_v20_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v20.bundle",
        "c09b860f11355bf6604dab51ae448b93febfc3adf589948dbd6a5e8c6d721f56",
        20,
    );
    let named = ops.iter().filter(
        |o| matches!(&o.entry.op, Op::SessionStart { harness: Some(h), .. } if h == "claude-code"),
    );
    assert!(named.count() > 0);
    let bound = ops.iter().filter(|o| {
        matches!(
            o.entry.op,
            Op::SessionBind {
                level: ObservationLevel::HooksSandbox,
                ..
            }
        )
    });
    assert!(bound.count() > 0);
}

/// Two `shared` holders of one function, joined by engine 14: the auditor
/// recomputes the join from the state it replays.
#[test]
fn golden_v21_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v21.bundle",
        "715d6f35aadb16aa13d611626ebfb7086615fa1e92eb94b299bebf917268f8bc",
        21,
    );
    let shared = ops.iter().filter(|o| match &o.entry.op {
        Op::LeaseAcquire { items, .. } => items.iter().any(|i| i.kind == LeaseKind::Shared),
        _ => false,
    });
    assert_eq!(shared.count(), 2);
    let joined = ops.iter().filter(|o| {
        o.entry.symbols_engine == Some(14)
            && matches!(
                &o.entry.op,
                Op::ChangeIntegrate {
                    merged: Some(_),
                    ..
                }
            )
    });
    assert!(joined.count() >= 2);
}

/// Inserts that reserve names, one refused for a name taken, and a new file
/// created under an exclusive lease on its path.
#[test]
fn golden_v22_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v22.bundle",
        "8c08a2d460cba30b4a6a18f9e7eb42c4294b8694f6a7dd8e59d62b1d258164cd",
        22,
    );
    let named = |allowed: bool| {
        let named = ops.iter().filter(|o| match &o.entry.op {
            Op::LeaseAcquire { items, .. } => items.iter().any(|i| !i.names.is_empty()),
            _ => false,
        });
        named
            .filter(|o| o.entry.decision.is_allow() == allowed)
            .count()
    };
    assert_eq!((named(true), named(false)), (2, 1));
    let created = ops.iter().filter(|o| {
        o.entry.decision.is_allow()
            && o.entry
                .facts
                .as_ref()
                .is_some_and(|f| f.added_files == ["src/fresh.rs"])
    });
    assert_eq!(created.count(), 1);
}

/// A child expires holding a set it was handed; the next acquire of it by
/// another session meets the parent.
#[test]
fn golden_v23_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v23.bundle",
        "09a5af4ef0fd73dcec41877fa2ef4c88f71b98aa07fb289c3651a0c04cc31f63",
        23,
    );
    let at = ops
        .iter()
        .rposition(|o| matches!(o.entry.op, Op::CapAttenuate { .. }))
        .expect("a delegation");
    let met = ops[at..].iter().any(|o| {
        o.entry
            .decision
            .reasons
            .iter()
            .any(|r| r.starts_with("lease_held:back.md#<file>:s-ga:"))
    });
    assert!(met, "the parent holds what its expired child had");
}

/// A session marked `unhooked`, and its proposal escalated under that word.
#[test]
fn golden_v24_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v24.bundle",
        "7b30d64f144ec4afa56b73d8ba4e3d56ed895622e7b955cf0dd2c50bf4d20efc",
        24,
    );
    let marks = ops.iter().filter(|o| {
        matches!(&o.entry.op, Op::Observe { session, events }
            if session == "s-uh" && matches!(&events[0].kind, ObsKind::Unhooked { tool } if tool == "propose"))
    });
    assert_eq!(marks.count(), 1);
    let escalated = ops.iter().filter(|o| {
        o.entry.actor.session() == Some("s-uh")
            && o.entry
                .decision
                .reasons
                .iter()
                .any(|r| r == "unhooked_session")
    });
    assert_eq!(escalated.count(), 1);
}

/// An approval that names a check, and the integration whose evidence of
/// it is `named`.
#[test]
fn golden_v25_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v25.bundle",
        "5887236c1ace8c52668fb69e0983f29d167e4c4e99d7062ec24b3f0fec271125",
        25,
    );
    let asked = ops.iter().filter(
        |o| matches!(&o.entry.op, Op::Approve { checks, .. } if checks == &["card".to_string()]),
    );
    assert_eq!(asked.count(), 1);
    let ran = ops.iter().flat_map(|o| &o.entry.evidence).filter(|a| {
        a.check == CheckKind::Named
            && a.details.get("name").map(String::as_str) == Some("card")
            && a.result == lonca_core::ops::CheckResult::Pass
    });
    assert_eq!(ran.count(), 1);
}

/// A workspace's second proposal names the first in `replaces:`; the first
/// is never approved, and the second integrates.
#[test]
fn golden_v26_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v26.bundle",
        "23493ecb2bf18f990b6e13d29fd8e58861b188f1140815cd58f2a92289509b4d",
        26,
    );
    let reasons = ops.iter().flat_map(|o| &o.entry.decision.reasons);
    let replaced: Vec<&String> = reasons.filter(|r| r.starts_with("replaces:")).collect();
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    let older = replaced[0].strip_prefix("replaces:").unwrap();
    let s = lonca_policy::state::State::replay(&ops);
    let rec = s.changes.values().find(|c| c.change.to_string() == older);
    let rec = rec.expect("the replaced change");
    assert_eq!(rec.status, lonca_policy::state::ChangeStatus::Withdrawn);
}

/// A lost Mac recovered with the recovery key alone: a `daemon.recover`
/// with `recover`, signed by the new daemon key, then ayse's new key signs.
#[test]
fn golden_v27_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v27.bundle",
        "923d0590d3a5e10cb0b77624c3e8e49d2ecf61be464cfb4010980a1d0ed4a492",
        27,
    );
    let at = ops.iter().position(|o| {
        matches!(
            &o.entry.op,
            Op::DaemonRecover {
                recover: Some(r),
                ..
            } if r.human == "ayse"
        )
    });
    let at = at.expect("the recovery");
    let s = lonca_policy::state::State::replay(&ops[..=at]);
    let Op::DaemonRecover {
        key,
        recover: Some(r),
    } = &ops[at].entry.op
    else {
        unreachable!()
    };
    assert_eq!(&s.daemon_key, key);
    assert_eq!(s.humans["ayse"], r.key);
    assert!(!s.recovery.contains_key("ayse"));
    assert!(
        ops[at + 1..]
            .iter()
            .any(|o| o.entry.actor.label() == "human:ayse")
    );
}

/// Human keys on security keys: both kinds enrolled, each signs with a
/// touch, and a signature without one is a recorded denial.
/// Format 30: a session's workspace is in its start, a continuation names
/// the same one and starts unobserved.
#[test]
fn golden_v30_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v30.bundle",
        "3309afef9b68f700e9d6297373cb14234aa907844e851a1c711cd6069687630c",
        30,
    );
    let s = lonca_policy::state::State::replay(&ops);
    let (old, new) = (&s.sessions["s14"], &s.sessions["s15"]);
    assert_eq!(old.workspace.as_deref(), Some("/ws/s14"));
    assert_eq!(new.workspace, old.workspace);
    assert_eq!(new.continued_from.as_deref(), Some("s14"));
    assert_eq!(new.level, ObservationLevel::Unobserved);
    let placed = s.sessions.values().filter(|x| x.workspace.is_some());
    assert_eq!(placed.count(), 2, "the others name none");
}

#[test]
fn golden_v28_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v28.bundle",
        "283eb54d53a598fee642d9da8415160cfa2757afb5069f3b147005efe3265c91",
        28,
    );
    let s = lonca_policy::state::State::replay(&ops);
    for (name, alg) in [("cem", "sk-p256"), ("deniz", "sk-ed25519")] {
        assert_eq!(s.humans[name].alg, alg);
        assert!(lonca_policy::human::valid_key(&s.humans[name], 28));
        let label = format!("human:{name}");
        let theirs: Vec<_> = ops
            .iter()
            .filter(|o| o.entry.actor.label() == label)
            .map(|o| (o.entry.op.kind().as_str(), o.entry.decision.reasons.clone()))
            .collect();
        let denied = vec!["bad_human_signature".to_string()];
        assert_eq!(
            theirs,
            [("freeze", denied), ("freeze", vec![]), ("unfreeze", vec![])],
            "{name}"
        );
    }
    assert!(s.frozen.is_none());
}

#[test]
fn golden_v18_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v18.bundle",
        "42fb4e5933c7a8a295ab5d35e61a72692c67c96726ba7b9da4b8305a30a0f3d6",
        18,
    );
    let affected = ops.iter().filter_map(|o| o.entry.facts.as_ref());
    let affected = affected.flat_map(|f| f.affected.clone());
    assert_eq!(
        affected.collect::<Vec<_>>(),
        ["src/lib.rs#charge", "src/reach_user.rs#g"]
    );
    let reasons = ops.iter().flat_map(|o| &o.entry.decision.reasons);
    let held = reasons.filter(|r| r.starts_with("affected_lease:s-reach:"));
    assert_eq!(held.count(), 1);
    let extended = ops.iter().flat_map(|o| &o.entry.evidence);
    let extended = extended.filter(|a| a.check == CheckKind::Extended);
    assert_eq!(extended.count(), 1);
}

#[test]
fn golden_v17_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v17.bundle",
        "128a65ae614b1e3751bcc7f9174103cb3b9967fb8669275335742b4a21df2acc",
        17,
    );
    let batches = ops.iter().filter_map(|o| match &o.entry.op {
        Op::ChangeIntegrateBatch { merged, .. } => Some(merged.len()),
        _ => None,
    });
    assert_eq!(batches.collect::<Vec<_>>(), [2]);
}

#[test]
fn golden_v16_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v16.bundle",
        "56362eb64a10396314acb63ff20650bfc4b916ba7c7e7b8a2e36ae8e3bc012dc",
        16,
    );
    let listed = ops.iter().filter_map(|o| o.entry.facts.as_ref());
    let listed = listed
        .flat_map(|f| f.unread_files.iter())
        .collect::<Vec<_>>();
    assert_eq!(listed, ["src/A.java"]);
}

#[test]
fn golden_v15_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v15.bundle",
        "12bc536d9139deec8e9e0c418a75c064f08b2205ba3441962058ba26e8605797",
        15,
    );
    let listed = ops.iter().filter_map(|o| o.entry.facts.as_ref());
    let listed = listed
        .flat_map(|f| f.unparsed_files.iter())
        .collect::<Vec<_>>();
    assert_eq!(listed, ["src/A.java"]);
}

#[test]
fn golden_v5_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v5.bundle",
        "fa1d0352acbfae3e47ec30f79d357055dccbd4326a1d989effd789f24655fa76",
        5,
    );
    // The scratch roots are in the log, in order, and the child kept one.
    let scratches: Vec<Vec<String>> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::SessionStart { scope, .. } | Op::CapAttenuate { scope, .. }
                if !scope.scratch.is_empty() =>
            {
                Some(scope.scratch.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        scratches,
        [
            vec!["/tmp/golden/scratch".to_string(), "/tmp/golden/logs".into()],
            vec!["/tmp/golden/logs".to_string()]
        ]
    );
    // The read under a scratch root was observed and did not taint.
    let (_dir, store) = load("oplog-v5.bundle");
    let state = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert!(state.sessions["s8"].taint.is_none());
}

fn open_service(e: &Env) -> lonca_core::Result<Arc<Service>> {
    Service::open(
        Home::new(e.root.join("home")),
        e.settings.clone(),
        Arc::new(|| T0),
    )
}

fn formats(e: &Env) -> Vec<u32> {
    OpLog::new(&e.store())
        .read_all()
        .unwrap()
        .iter()
        .map(|o| o.entry.format)
        .collect()
}

#[test]
fn an_upgraded_daemon_continues_a_v0_log_with_current_entries() {
    let mut e = busy_repo();
    // The log as an older lonca wrote it.
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = FORMAT_LEGACY;
            x.symbols_engine = None;
            forget_harness(&e, x);
        }
    });
    let old = formats(&e).len();
    let store = e.store();
    let head = OpLog::new(&store).head().unwrap().unwrap();
    let bytes = store.read_file(&head, "op.json").unwrap().unwrap();
    assert!(
        !String::from_utf8(bytes).unwrap().contains("\"format\""),
        "v0 entries carry no format field"
    );

    e.reopen();
    e.human_change(vec![file("notes.md", "b\n")], "after upgrade");
    e.svc.process_all();
    let f = formats(&e);
    assert!(f.len() > old);
    assert!(f[..old].iter().all(|&v| v == FORMAT_LEGACY), "{f:?}");
    assert!(f[old..].iter().all(|&v| v == FORMAT_CURRENT), "{f:?}");

    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    // The daemon still opens the mixed log.
    e.reopen();
}

#[test]
fn daemon_and_auditor_refuse_a_format_they_do_not_know() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        entries.last_mut().unwrap().format = FORMAT_CURRENT + 1;
    });
    let refused = |r: lonca_core::Error| {
        assert!(
            matches!(&r, lonca_core::Error::Unsupported(m) if m.contains("upgrade lonca")),
            "{r}"
        );
    };
    refused(open_service(&e).err().expect("daemon refuses the log"));
    refused(audit(&e.store(), Options::default()).expect_err("auditor refuses"));
}

#[test]
fn a_format_downgrade_along_the_chain_is_refused() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        entries.last_mut().unwrap().format = FORMAT_LEGACY;
    });
    let err = open_service(&e).err().expect("daemon refuses the log");
    assert!(err.to_string().contains("log format goes back"), "{err}");
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == "chain" && f.detail.contains("log format goes back")),
        "{:#?}",
        r.findings
    );
}

#[test]
fn the_daemon_records_the_symbol_engine_on_proposals_and_integrations() {
    let e = busy_repo();
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let mut used = 0;
    for o in &ops {
        let x = &o.entry;
        if x.uses_symbols_engine() {
            used += 1;
            assert_eq!(x.symbols_engine, Some(ENGINE_CURRENT), "op {}", x.seq);
        } else {
            assert_eq!(x.symbols_engine, None, "op {}", x.seq);
        }
    }
    assert!(used >= 4, "busy_repo proposes and integrates");
}

#[test]
fn daemon_and_auditor_refuse_a_symbol_engine_they_do_not_know() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        let x = entries
            .iter_mut()
            .find(|x| matches!(x.op, Op::ChangeIntegrate { .. }))
            .unwrap();
        x.symbols_engine = Some(ENGINE_CURRENT + 1);
    });
    let err = open_service(&e).err().expect("daemon refuses the log");
    assert!(
        matches!(&err, lonca_core::Error::Unsupported(m) if m.contains("symbol engine")),
        "{err}"
    );
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == "engine" && f.detail.contains("upgrade lonca")),
        "{:#?}",
        r.findings
    );
}
