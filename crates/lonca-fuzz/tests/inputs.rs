//! Every saved input of every fuzz target, through its check: the seeds
//! (`fuzz/seeds/<target>/`) and each crash the fuzzer found, kept once it
//! was fixed (`fuzz/regressions/<target>/`). So a crash, once fixed, stays
//! fixed under plain `cargo test`, with no fuzzer and on stable.
//!
//! `write_seeds` (ignored) writes the seeds again from what the workspace
//! holds: `cargo test -p lonca-fuzz --test inputs -- --ignored write_seeds`.

use std::path::{Path, PathBuf};

use lonca_core::canonical::canonical_bytes;
use lonca_fuzz::{CUT, TARGETS, parse, template};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY, Profile};
use lonca_symbols::engine::{ENGINE_CURRENT, ENGINES_KNOWN};
use serde_json::json;

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn inputs(kind: &str, target: &str) -> Vec<PathBuf> {
    let dir = fuzz_dir().join(kind).join(target);
    let Ok(read) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    let mut files: Vec<PathBuf> = read
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file() && !p.ends_with(".gitkeep"))
        .collect();
    files.sort();
    files
}

#[test]
fn every_saved_input_passes_its_check() {
    for &(target, check) in TARGETS {
        let seeds = inputs("seeds", target);
        assert!(!seeds.is_empty(), "fuzz/seeds/{target} has no seed");
        for path in seeds.iter().chain(&inputs("regressions", target)) {
            let data = std::fs::read(path).unwrap();
            eprintln!("{target}: {}", path.display());
            check(&data);
        }
    }
}

/// Every fuzz target has a binary in `fuzz/`, and every binary a target.
#[test]
fn every_target_has_a_binary() {
    let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
    let doc: toml::Table = toml::from_str(&manifest).unwrap();
    let bins: Vec<&str> = doc["bin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    let targets: Vec<&str> = TARGETS.iter().map(|(n, _)| *n).collect();
    assert_eq!(bins, targets);
    for name in targets {
        let file = fuzz_dir().join(format!("fuzz_targets/{name}.rs"));
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.contains(&format!("lonca_fuzz::{name}::check")),
            "{}",
            file.display()
        );
    }
}

/// CI runs every target: the list in `fuzz.yml`'s `plan` job is `TARGETS`,
/// sorted.
#[test]
fn ci_runs_every_target() {
    let workflow = fuzz_dir().join("../.github/workflows/fuzz.yml");
    let text = std::fs::read_to_string(&workflow).unwrap();
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("all=\""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("an all=\"...\" line in fuzz.yml");
    let listed: Vec<&str> = line.split(' ').collect();
    let mut targets: Vec<&str> = TARGETS.iter().map(|(n, _)| *n).collect();
    targets.sort_unstable();
    assert_eq!(listed, targets);
}

fn write(target: &str, name: &str, data: &[u8]) {
    // `LONCA_SEEDS_ONLY=<target>` leaves the seeds of the others as they are.
    if std::env::var("LONCA_SEEDS_ONLY").is_ok_and(|only| only != target) {
        return;
    }
    let dir = fuzz_dir().join("seeds").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), data).unwrap();
}

fn cut(parts: &[&str]) -> Vec<u8> {
    parts
        .join(std::str::from_utf8(&[CUT]).unwrap())
        .into_bytes()
}

/// The two header bytes `parse::header` reads back as `ext` and `engine`.
fn header(ext: &str, engine: u32) -> Option<Vec<u8>> {
    let path = parse::paths()
        .iter()
        .position(|p| p.ends_with(&format!(".{ext}")))?;
    let e = ENGINES_KNOWN.iter().position(|&x| x == engine)?;
    Some(vec![u8::try_from(path).ok()?, u8::try_from(e).ok()?])
}

/// Signatures by the software keys whose public halves the `signature`
/// target has enrolled: touched (with either hash), touched with a PIN,
/// and untouched; and each public key as OpenSSH writes it.
fn signature_seeds() {
    use lonca_fuzz::signature::{MESSAGE, PUBLIC};
    use lonca_policy::human::sk::{self, Assertion, Hash, Kind};
    for (c, (kind, public_hex)) in PUBLIC.into_iter().enumerate() {
        let sign = |data: &[u8]| -> ([u8; 64], Vec<u8>) {
            match kind {
                Kind::P256 => {
                    use p256::ecdsa::signature::Signer;
                    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
                    let sig: p256::ecdsa::Signature = key.sign(data);
                    let public = key.verifying_key().to_sec1_point(false);
                    (
                        sig.to_bytes()[..].try_into().unwrap(),
                        public.as_bytes().to_vec(),
                    )
                }
                Kind::Ed25519 => {
                    use ed25519_dalek::Signer;
                    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
                    (
                        key.sign(data).to_bytes(),
                        key.verifying_key().to_bytes().to_vec(),
                    )
                }
            }
        };
        let c = u8::try_from(c).unwrap();
        let name = kind.alg();
        for (what, hash, flags) in [
            ("touch", Hash::Sha512, 1),
            ("touch-sha256", Hash::Sha256, 1),
            ("touch-pin", Hash::Sha512, 5),
            ("untouched", Hash::Sha512, 0),
        ] {
            let (signature, public) = sign(&sk::signed_data(MESSAGE, hash, flags, 9));
            assert_eq!(hex::encode(&public), public_hex, "{name}");
            let a = Assertion {
                hash,
                flags,
                counter: 9,
                signature,
            };
            let mut data = vec![c];
            data.extend(sk::encode(kind, &public, &a));
            write("signature", &format!("{name}-{what}"), &data);
        }
        let mut data = vec![c];
        data.extend(sk::public_blob(kind, &hex::decode(public_hex).unwrap()));
        write("signature", &format!("{name}-public"), &data);
    }
}

/// The seeds of `signature` do what their names say.
#[test]
fn signature_seeds_verify_when_touched() {
    use lonca_fuzz::signature::{MESSAGE, PUBLIC};
    use lonca_policy::human::sk;
    for (c, (kind, public)) in PUBLIC.into_iter().enumerate() {
        let name = kind.alg();
        let verifies = |what: &str| {
            let path = fuzz_dir().join(format!("seeds/signature/{name}-{what}"));
            let data = std::fs::read(path).unwrap();
            assert_eq!(usize::from(data[0]), c);
            let sig = hex::encode(&data[1..]);
            match kind {
                sk::Kind::P256 => sk::verify_p256(public, MESSAGE, &sig),
                sk::Kind::Ed25519 => sk::verify_ed25519(public, MESSAGE, &sig),
            }
        };
        for what in ["touch", "touch-sha256", "touch-pin"] {
            assert!(verifies(what), "{name}-{what}");
        }
        assert!(!verifies("untouched"), "{name}");
        assert!(!verifies("public"), "{name}");
    }
}

#[test]
#[ignore = "writes fuzz/seeds; run by hand"]
fn write_seeds() {
    signature_seeds();
    let t = template::get();

    for (i, op) in t.log.iter().enumerate() {
        write(
            "entry",
            &format!("{i:02}-{}", op.entry.op.kind().as_str()),
            &canonical_bytes(op),
        );
    }

    let lines = |ops: &[lonca_core::oplog::SignedOp]| {
        let mut out = Vec::new();
        for op in ops {
            out.extend(canonical_bytes(&op.entry));
            out.push(b'\n');
        }
        out
    };
    write("replay", "template", &lines(&t.log));
    write(
        "replay",
        "first-three",
        &lines(&t.log[..3.min(t.log.len())]),
    );

    let req = |method: &str, repo: Option<&str>, token: &str, params: serde_json::Value| {
        json!({"id": 1, "method": method, "repo": repo, "token": token, "params": params})
            .to_string()
    };
    let requests = [
        ("ping", vec![req("ping", None, "", json!({}))]),
        (
            "human-reads",
            vec![
                req("status", Some("demo"), "$HUMAN", json!({})),
                req("log", Some("demo"), "$HUMAN", json!({"limit": 5})),
                req("tree", Some("demo"), "$HUMAN", json!({"commit": "$TRUNK"})),
                req(
                    "change.resolve",
                    Some("demo"),
                    "$HUMAN",
                    json!({"prefix": "a"}),
                ),
            ],
        ),
        (
            "agent-lease",
            vec![
                req(
                    "lease.acquire",
                    None,
                    "$AGENT",
                    json!({"items": [{"symbol": "src/app.py#main", "kind": "edit"}], "intent": "x", "ttl_ms": 60000}),
                ),
                req("lease.release", None, "$AGENT", json!({"set": "x"})),
            ],
        ),
        (
            "agent-propose",
            vec![req(
                "change.propose",
                None,
                "$AGENT2",
                json!({"base": "$TRUNK", "files": [{"path": "src/app.py", "content_b64": "ZGVmIG1haW4oKToKICAgIHJldHVybiAyCg=="}], "claim": {"intent": "two", "edits": ["src/app.py#main"]}}),
            )],
        ),
        (
            "agent-hooks",
            vec![
                req(
                    "hook.event",
                    None,
                    "$AGENT",
                    json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat /etc/passwd"}, "workspace": "$WS"}),
                ),
                req(
                    "hook.input",
                    None,
                    "$AGENT",
                    json!({"harness": "claude-code", "input": {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "$WS/../x"}}, "workspace": "$WS"}),
                ),
                req(
                    "hook.stop",
                    None,
                    "$AGENT",
                    json!({"harness": "claude-code", "files": []}),
                ),
                req("mcp.call", None, "$AGENT", json!({"tool": "propose"})),
            ],
        ),
        (
            "agent-negotiate",
            vec![
                req(
                    "negotiate",
                    None,
                    "$AGENT",
                    json!({"to": "s2", "msg": {"kind": "ask", "symbols": ["src/lib.rs#refund"]}}),
                ),
                req("whoami", None, "$AGENT", json!({})),
                req("session.end", None, "$AGENT", json!({})),
            ],
        ),
        (
            "human-unsigned",
            vec![req(
                "human.submit",
                Some("demo"),
                "$HUMAN",
                json!({"op": {"op": "repo.freeze", "reason": "x"}}),
            )],
        ),
    ];
    for (name, lines) in requests {
        write("request", name, lines.join("\n").as_bytes());
    }

    for (h, (name, profile)) in lonca_policy::harness::built_in().iter().enumerate() {
        let c = u8::try_from(h).unwrap();
        for (tool, rule) in profile.tools.iter().take(12) {
            let mut input = serde_json::Map::new();
            for f in &rule.fields {
                input.insert(f.clone(), json!("/tmp/lonca-fuzz-ws/src/lib.rs"));
            }
            for phase in ["PreToolUse", "PostToolUse"] {
                let ev = json!({"hook_event_name": phase, "tool_name": tool, "tool_input": input,
                    "workspace": "/tmp/lonca-fuzz-ws", "harness": name});
                let mut data = vec![c];
                data.extend(ev.to_string().into_bytes());
                write("hook", &format!("{name}-{tool}-{phase}"), &data);
            }
        }
    }

    let (hard_config, hard_policy) = Profile::Hardened.files(true);
    write("policy", "default", &cut(&[DEFAULT_CONFIG, DEFAULT_POLICY]));
    write("policy", "hardened", &cut(&[&hard_config, &hard_policy]));
    write(
        "policy",
        "trust",
        &cut(&["daemon_uid = 501\n", "forbid(principal, action, resource);"]),
    );

    let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../lonca-symbols/tests/engine/v{ENGINE_CURRENT}"));
    let mut cases: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    for case in cases {
        let side = |s: &str| {
            std::fs::read_dir(&case)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.file_stem().is_some_and(|f| f == s))
        };
        let (Some(b), Some(o), Some(t)) = (side("base"), side("ours"), side("theirs")) else {
            continue;
        };
        let ext = b.extension().unwrap().to_str().unwrap().to_string();
        let read = |p: &Path| std::fs::read_to_string(p).unwrap();
        let (b, o, t) = (read(&b), read(&o), read(&t));
        if b.len() + o.len() + t.len() > 4096 {
            continue;
        }
        let name = case.file_name().unwrap().to_str().unwrap();
        for engine in [ENGINE_CURRENT, 0] {
            let Some(head) = header(&ext, engine) else {
                continue;
            };
            let mut parse = head.clone();
            parse.extend(cut(&[&b, &t]));
            write("parse", &format!("{name}-e{engine}"), &parse);
            let mut merge = head;
            merge.extend(cut(&[&b, &o, &t]));
            write("merge", &format!("{name}-e{engine}"), &merge);
        }
    }
}
