//! `lonca`: the command line for humans and agents.

mod ctx;
mod hook;
mod mcp;
mod undo;
mod workspace;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use lonca_core::GitId;
use lonca_core::keys::KeyPair;
use lonca_core::ops::{Claim, HumanKey, LeaseItem, LeaseKind, Op, OpKind, Scope};
use lonca_daemon::Client;
use serde_json::{Value, json};

use crate::ctx::{call, connect};
use crate::workspace::Workspace;

#[derive(Parser)]
#[command(
    name = "lonca",
    version,
    about = "Agent-native, Git-compatible version control"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (the Gatekeeper) in the foreground.
    Daemon {
        /// Daemon home (default: $LONCA_HOME or ~/.lonca).
        #[arg(long)]
        home: Option<PathBuf>,
        /// Accept harness settings that are not root-owned (testing only).
        #[arg(long)]
        allow_user_owned_settings: bool,
        /// Claude Code managed settings to inspect when binding sessions.
        #[arg(long)]
        managed_settings: Option<PathBuf>,
    },
    /// Human identities (development file keys).
    #[command(subcommand)]
    Human(HumanCmd),
    /// Create a repository, optionally importing an existing Git branch.
    Init {
        repo: String,
        #[arg(long)]
        import: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Agent sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Workspaces.
    #[command(subcommand)]
    Workspace(WorkspaceCmd),
    /// Bring trunk into the current workspace, merging local edits.
    Sync,
    /// Repository status.
    Status {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Facts of the local changes in this workspace.
    Diff,
    /// Symbol leases (agent workspaces).
    #[command(subcommand)]
    Lease(LeaseCmd),
    /// Propose the local changes of this workspace.
    Propose {
        #[arg(long, short)]
        intent: String,
        /// Use the computed facts as the claim (an explicit acknowledgement).
        #[arg(long)]
        accept_facts: bool,
        #[arg(long, value_delimiter = ',')]
        edits: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        adds: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        deletes: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        deleted_files: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        signature_changes: Vec<String>,
    },
    /// Show a change.
    Change {
        change: String,
        #[arg(long)]
        repo: Option<String>,
    },
    /// Operations waiting for human approval.
    Pending {
        #[arg(long)]
        repo: Option<String>,
    },
    /// Approve an escalated operation.
    Approve {
        seq: u64,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Operation log.
    Log {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// Show or change the repository policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Push trunk, the operation log and policy to a Git remote.
    Push {
        remote: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Import new commits from a Git remote (fast-forward only).
    Pull {
        remote: String,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Stop all work on a repository.
    Freeze {
        reason: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    Unfreeze {
        reason: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Undo one operation with a compensating operation.
    Undo {
        seq: u64,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Plan (and with --apply, run) the undo of everything an actor did since a sequence number.
    Revert {
        #[arg(long)]
        actor: String,
        #[arg(long, default_value_t = 0)]
        since_seq: u64,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Run the merge queue now.
    Queue,
    /// Claude Code hook handler (reads the hook event on stdin).
    Hook,
    /// MCP server for agents (stdio).
    Mcp,
    /// List the symbols of a file (lease ids).
    Symbols { path: PathBuf },
}

#[derive(Subcommand)]
enum HumanCmd {
    /// Create a file key for a human and make it the default identity.
    Keygen { name: String },
    /// Print the default identity and public key.
    Whoami,
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Start an agent session and create its workspace.
    Start {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        agent: String,
        #[arg(long, value_delimiter = ',', required = true)]
        paths: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        symbols: Option<Vec<String>>,
        #[arg(long, default_value = "2h")]
        ttl: String,
        #[arg(long, default_value = "")]
        task: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        max_files: Option<u32>,
        #[arg(long)]
        max_lines: Option<u32>,
        /// Directory for the agent's workspace.
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Revoke a session and everything derived from it.
    Revoke {
        session: String,
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "revoked")]
        reason: String,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// End the session of the current agent workspace.
    End,
}

#[derive(Subcommand)]
enum WorkspaceCmd {
    /// Create a human workspace.
    Create {
        dir: PathBuf,
        #[arg(long)]
        repo: String,
        #[arg(long = "as")]
        human: Option<String>,
    },
}

#[derive(Subcommand)]
enum LeaseCmd {
    Acquire {
        #[arg(required = true)]
        symbols: Vec<String>,
        #[arg(long, default_value = "edit")]
        kind: String,
        #[arg(long, short, default_value = "")]
        intent: String,
        #[arg(long, default_value = "10m")]
        ttl: String,
    },
    Release {
        set: String,
    },
    Renew {
        set: String,
        #[arg(long, default_value = "10m")]
        ttl: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Show {
        #[arg(long)]
        repo: Option<String>,
    },
    Set {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Hook => hook::run(),
        cmd => match run(cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("lonca: {e:#}");
                ExitCode::from(1)
            }
        },
    }
}

fn human_name(h: Option<String>) -> Result<String> {
    match h {
        Some(h) => Ok(h),
        None => ctx::default_human(),
    }
}

/// Repository from the flag, else from the current workspace.
fn repo_name(r: Option<String>) -> Result<String> {
    match r {
        Some(r) => Ok(r),
        None => Ok(Workspace::current()
            .context("pass --repo or run inside a workspace")?
            .meta
            .repo),
    }
}

fn human_client(repo: &str) -> Result<Client> {
    let mut c = connect()?;
    c.repo = Some(repo.to_string());
    Ok(c)
}

/// Signs and submits a human operation; prints the decision.
pub(crate) fn submit(c: &mut Client, human: &str, repo: &str, op: Op) -> Result<Value> {
    let sig = ctx::sign(human, repo, &op)?;
    let r = call(c, "human.submit", json!({"op": op, "sig": sig}))?;
    print_decision(&r);
    Ok(r)
}

fn print_decision(r: &Value) {
    let outcome = r["decision"]["outcome"].as_str().unwrap_or("?");
    let reasons: Vec<&str> = r["decision"]["reasons"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let seq = r["seq"]
        .as_u64()
        .map(|s| format!("#{s} "))
        .unwrap_or_default();
    if reasons.is_empty() {
        println!("{seq}{outcome}");
    } else {
        println!("{seq}{outcome}: {}", reasons.join(", "));
    }
}

fn agent_client() -> Result<(Client, Workspace)> {
    let ws = Workspace::current()?;
    let mut c = connect()?;
    c.token = Some(ws.token()?);
    Ok((c, ws))
}

fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Daemon {
            home,
            allow_user_owned_settings,
            managed_settings,
        } => {
            let home = home
                .map(lonca_daemon::Home::new)
                .unwrap_or_else(lonca_daemon::Home::from_env);
            let defaults = lonca_daemon::Settings::default();
            let settings = lonca_daemon::Settings {
                require_root_settings: !allow_user_owned_settings,
                managed_settings: managed_settings.unwrap_or(defaults.managed_settings),
                git: defaults.git,
            };
            let svc =
                lonca_daemon::Service::open(home.clone(), settings, lonca_daemon::system_clock())?;
            let listener = lonca_daemon::server::bind(&home.socket())?;
            svc.spawn_worker();
            eprintln!(
                "lonca daemon: listening on {} (key {})",
                home.socket().display(),
                &svc.public_key()[..16]
            );
            lonca_daemon::server::serve(listener, svc);
            Ok(())
        }
        Cmd::Human(HumanCmd::Keygen { name }) => {
            if !lonca_policy::decide::valid_token(&name, 64) {
                bail!("human names: letters, digits, '.', '_', '-'");
            }
            let p = ctx::human_key_path(&name);
            let k = KeyPair::load_or_create(&p)?;
            std::fs::write(ctx::humans_dir().join("default"), &name)?;
            println!("{name}: ed25519 {} ({})", k.public_hex(), p.display());
            println!(
                "note: file keys have no user presence; anything running as you can sign with them."
            );
            Ok(())
        }
        Cmd::Human(HumanCmd::Whoami) => {
            let name = ctx::default_human()?;
            println!("{name}: ed25519 {}", ctx::human_key(&name)?.public_hex());
            Ok(())
        }
        Cmd::Init {
            repo,
            import,
            branch,
            human,
        } => {
            let human = human_name(human)?;
            let key = ctx::human_key(&human)?;
            let mut c = connect()?;
            let prep = call(
                &mut c,
                "repo.prepare_init",
                json!({"repo": repo, "human": human, "human_key": HumanKey { alg: "ed25519".into(), public: key.public_hex() }, "import_from": import, "branch": branch}),
            )?;
            let op: Op = serde_json::from_value(prep["op"].clone())?;
            let sig = ctx::sign(&human, &repo, &op)?;
            let r = call(&mut c, "repo.init", json!({"op": op, "sig": sig}))?;
            print_decision(&r);
            Ok(())
        }
        Cmd::Session(SessionCmd::Start {
            repo,
            agent,
            paths,
            symbols,
            ttl,
            task,
            model,
            max_files,
            max_lines,
            workspace,
            human,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            let session = lonca_core::canonical::random_id("ses");
            let op = Op::SessionStart {
                session: session.clone(),
                agent,
                model,
                task,
                scope: Scope {
                    paths,
                    symbols,
                    ops: vec![
                        OpKind::ChangePropose,
                        OpKind::ChangeWithdraw,
                        OpKind::LeaseAcquire,
                        OpKind::LeaseRelease,
                        OpKind::LeaseRenew,
                        OpKind::Negotiate,
                        OpKind::CapAttenuate,
                    ],
                    max_files,
                    max_lines,
                },
                expires_ms: ctx::now_ms() + ctx::duration_ms(&ttl)?,
            };
            let r = submit(&mut c, &human, &repo, op)?;
            let Some(token) = r["token"].as_str() else {
                bail!("session was not started")
            };
            let mut ac = connect()?;
            ac.token = Some(token.to_string());
            let dir = ctx::absolute(&workspace)?;
            let ws = Workspace::create(&mut ac, &dir, &repo, Some(session.clone()), None)?;
            ws.write_token(token)?;
            println!("session {session}; workspace {}", ws.root.display());
            Ok(())
        }
        Cmd::Session(SessionCmd::Revoke {
            session,
            repo,
            reason,
            human,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            submit(&mut c, &human, &repo, Op::CapRevoke { session, reason })?;
            Ok(())
        }
        Cmd::Session(SessionCmd::End) => {
            let (mut c, _) = agent_client()?;
            print_decision(&call(&mut c, "session.end", json!({}))?);
            Ok(())
        }
        Cmd::Workspace(WorkspaceCmd::Create { dir, repo, human }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            let ws = Workspace::create(&mut c, &ctx::absolute(&dir)?, &repo, None, Some(human))?;
            println!(
                "workspace {} at {}",
                ws.root.display(),
                ws.meta.base.short()
            );
            Ok(())
        }
        Cmd::Sync => {
            let mut ws = Workspace::current()?;
            let mut c = connect()?;
            match &ws.meta.session {
                Some(_) => c.token = Some(ws.token()?),
                None => c.repo = Some(ws.meta.repo.clone()),
            }
            let r = ws.sync(&mut c)?;
            println!(
                "{} -> {}: {} updated, {} merged, {} conflicts",
                r.from.short(),
                r.to.short(),
                r.updated.len(),
                r.merged.len(),
                r.conflicts.len()
            );
            for p in &r.conflicts {
                println!("  conflict: {p} (trunk version written to {p}.trunk)");
            }
            Ok(())
        }
        Cmd::Status {
            repo,
            json: as_json,
        } => {
            let mut c = match repo {
                Some(r) => human_client(&r)?,
                None => {
                    let ws =
                        Workspace::current().context("pass --repo or run inside a workspace")?;
                    let mut c = connect()?;
                    match ws.meta.session {
                        Some(_) => c.token = Some(ws.token()?),
                        None => c.repo = Some(ws.meta.repo.clone()),
                    }
                    c
                }
            };
            let s = call(&mut c, "status", json!({}))?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                print_status(&s);
            }
            Ok(())
        }
        Cmd::Diff => {
            let ws = Workspace::current()?;
            let changes = ws.changes()?;
            if changes.is_empty() {
                println!("no local changes");
                return Ok(());
            }
            let mut c = connect()?;
            let facts = match &ws.meta.session {
                Some(_) => {
                    c.token = Some(ws.token()?);
                    call(
                        &mut c,
                        "facts.preview",
                        json!({"base": ws.meta.base, "files": changes}),
                    )?
                }
                None => {
                    c.repo = Some(ws.meta.repo.clone());
                    let human = ws.meta.human.clone().unwrap_or(ctx::default_human()?);
                    call(
                        &mut c,
                        "human.prepare_change",
                        json!({"base": ws.meta.base, "files": changes, "author": human}),
                    )?
                }
            };
            println!("{}", serde_json::to_string_pretty(&facts["facts"])?);
            Ok(())
        }
        Cmd::Lease(l) => {
            let (mut c, _) = agent_client()?;
            let r = match l {
                LeaseCmd::Acquire {
                    symbols,
                    kind,
                    intent,
                    ttl,
                } => {
                    let kind = match kind.as_str() {
                        "edit" => LeaseKind::Edit,
                        "insert" => LeaseKind::Insert,
                        "rename" => LeaseKind::Rename,
                        k => bail!("unknown lease kind {k}"),
                    };
                    let items: Vec<LeaseItem> = symbols
                        .into_iter()
                        .map(|symbol| LeaseItem { symbol, kind })
                        .collect();
                    let r = call(
                        &mut c,
                        "lease.acquire",
                        json!({"items": items, "intent": intent, "ttl_ms": ctx::duration_ms(&ttl)?}),
                    )?;
                    if let Some(set) = r["set"].as_str()
                        && r["decision"]["outcome"] == "allow"
                    {
                        println!("lease set {set}");
                    }
                    r
                }
                LeaseCmd::Release { set } => call(&mut c, "lease.release", json!({"set": set}))?,
                LeaseCmd::Renew { set, ttl } => call(
                    &mut c,
                    "lease.renew",
                    json!({"set": set, "ttl_ms": ctx::duration_ms(&ttl)?}),
                )?,
            };
            print_decision(&r);
            Ok(())
        }
        Cmd::Propose {
            intent,
            accept_facts,
            edits,
            adds,
            deletes,
            deleted_files,
            signature_changes,
        } => {
            let mut ws = Workspace::current()?;
            let changes = ws.changes()?;
            if changes.is_empty() {
                bail!("no local changes");
            }
            let mut c = connect()?;
            let r = match &ws.meta.session {
                Some(_) => {
                    c.token = Some(ws.token()?);
                    let mut claim = Claim {
                        intent,
                        edits,
                        adds,
                        deletes,
                        deleted_files,
                        signature_changes,
                        ..Default::default()
                    };
                    if accept_facts {
                        let p = call(
                            &mut c,
                            "facts.preview",
                            json!({"base": ws.meta.base, "files": changes}),
                        )?;
                        let f: lonca_core::ops::Facts = serde_json::from_value(p["facts"].clone())?;
                        claim = Claim {
                            intent: claim.intent,
                            edits: f.edits,
                            adds: f.adds,
                            deletes: f.deletes,
                            deleted_files: f.deleted_files,
                            signature_changes: f.signature_changes,
                            tests: f.tests,
                            revert_of: None,
                        };
                    }
                    call(
                        &mut c,
                        "change.propose",
                        json!({"base": ws.meta.base, "files": changes, "claim": claim}),
                    )?
                }
                None => {
                    let human = ws.meta.human.clone().unwrap_or(ctx::default_human()?);
                    c.repo = Some(ws.meta.repo.clone());
                    let prep = call(
                        &mut c,
                        "human.prepare_change",
                        json!({"base": ws.meta.base, "files": changes, "author": human, "intent": intent}),
                    )?;
                    let op: Op = serde_json::from_value(prep["op"].clone())?;
                    let repo = ws.meta.repo.clone();
                    let r = submit(&mut c, &human, &repo, op.clone())?;
                    if let (Op::ChangePropose { change, commit, .. }, false) =
                        (&op, r["decision"]["outcome"] == "deny")
                    {
                        ws.meta.submitted = Some((*change, commit.clone()));
                        ws.save()?;
                    }
                    return Ok(());
                }
            };
            print_decision(&r);
            if let Some(ch) = r["change"].as_str() {
                println!("change {ch}");
            }
            if r["decision"]["outcome"] != "deny" {
                ws.meta.submitted = Some((
                    serde_json::from_value(r["change"].clone())?,
                    serde_json::from_value(r["commit"].clone())?,
                ));
                ws.save()?;
            }
            Ok(())
        }
        Cmd::Change { change, repo } => {
            let mut c = human_client(&repo_name(repo)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&call(
                    &mut c,
                    "change.get",
                    json!({"change": change})
                )?)?
            );
            Ok(())
        }
        Cmd::Pending { repo } => {
            let mut c = human_client(&repo_name(repo)?)?;
            let s = call(&mut c, "status", json!({}))?;
            for p in s["pending"].as_array().cloned().unwrap_or_default() {
                println!(
                    "#{} {} {} [{}/{}] {}",
                    p["seq"],
                    p["op"].as_str().unwrap_or(""),
                    p["actor"].as_str().unwrap_or(""),
                    p["approvals"].as_array().map(|a| a.len()).unwrap_or(0),
                    p["required"],
                    p["reasons"]
                );
            }
            Ok(())
        }
        Cmd::Approve {
            seq,
            repo,
            note,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            submit(
                &mut c,
                &human,
                &repo,
                Op::Approve {
                    target_seq: seq,
                    note,
                },
            )?;
            Ok(())
        }
        Cmd::Log {
            repo,
            from,
            limit,
            json: as_json,
        } => {
            let mut c = human_client(&repo_name(repo)?)?;
            let ops = call(&mut c, "log", json!({"from": from, "limit": limit}))?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&ops)?);
                return Ok(());
            }
            for o in ops.as_array().cloned().unwrap_or_default() {
                let e = &o["entry"];
                let actor = match e["actor"]["kind"].as_str() {
                    Some("human") => format!("human:{}", e["actor"]["name"].as_str().unwrap_or("")),
                    Some("agent") => format!(
                        "agent:{}/{}",
                        e["actor"]["name"].as_str().unwrap_or(""),
                        e["actor"]["session"].as_str().unwrap_or("")
                    ),
                    _ => "daemon".into(),
                };
                let reasons: Vec<&str> = e["decision"]["reasons"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                println!(
                    "{:>5} {:<17} {:<7} {:<34} {}",
                    e["seq"],
                    e["op"]["op"].as_str().unwrap_or(""),
                    e["decision"]["outcome"].as_str().unwrap_or(""),
                    actor,
                    reasons.join(", ")
                );
            }
            Ok(())
        }
        Cmd::Policy(PolicyCmd::Show { repo }) => {
            let repo = repo_name(repo)?;
            let mut c = human_client(&repo)?;
            let s = call(&mut c, "status", json!({}))?;
            let policy: GitId = serde_json::from_value(s["policy"].clone())?;
            for f in workspace::fetch(&mut c, &policy, None)? {
                use base64::Engine;
                let text = base64::engine::general_purpose::STANDARD
                    .decode(f.content_b64.unwrap_or_default())?;
                println!("==> {} <==\n{}", f.path, String::from_utf8_lossy(&text));
            }
            Ok(())
        }
        Cmd::Policy(PolicyCmd::Set {
            config,
            policy,
            repo,
            human,
        }) => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            let prep = call(
                &mut c,
                "human.prepare_policy",
                json!({"config": std::fs::read_to_string(config)?, "policy": std::fs::read_to_string(policy)?}),
            )?;
            submit(
                &mut c,
                &human,
                &repo,
                serde_json::from_value(prep["op"].clone())?,
            )?;
            Ok(())
        }
        Cmd::Push {
            remote,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            let prep = call(&mut c, "human.prepare_push", json!({"remote": remote}))?;
            let r = submit(
                &mut c,
                &human,
                &repo,
                serde_json::from_value(prep["op"].clone())?,
            )?;
            if let Some(p) = r["push"].as_str() {
                print!("{p}");
            }
            Ok(())
        }
        Cmd::Pull {
            remote,
            branch,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            let prep = call(
                &mut c,
                "human.prepare_import",
                json!({"remote": remote, "branch": branch}),
            )?;
            submit(
                &mut c,
                &human,
                &repo,
                serde_json::from_value(prep["op"].clone())?,
            )?;
            Ok(())
        }
        Cmd::Freeze {
            reason,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let mut c = human_client(&repo)?;
            submit(&mut c, &human_name(human)?, &repo, Op::Freeze { reason })?;
            Ok(())
        }
        Cmd::Unfreeze {
            reason,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let mut c = human_client(&repo)?;
            submit(&mut c, &human_name(human)?, &repo, Op::Unfreeze { reason })?;
            Ok(())
        }
        Cmd::Undo { seq, repo, human } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            undo::undo(&mut c, &human, &repo, seq)
        }
        Cmd::Revert {
            actor,
            since_seq,
            apply,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo)?;
            undo::revert(&mut c, &human, &repo, &actor, since_seq, apply)
        }
        Cmd::Queue => {
            let mut c = connect()?;
            println!("{}", call(&mut c, "queue.run", json!({}))?);
            Ok(())
        }
        Cmd::Hook => unreachable!("handled in main"),
        Cmd::Mcp => mcp::run(),
        Cmd::Symbols { path } => {
            let text = std::fs::read_to_string(&path)?;
            let p = path.to_string_lossy().replace('\\', "/");
            let lang =
                lonca_symbols::Lang::detect(&p).context("no symbol support for this file type")?;
            let parsed = lonca_symbols::parse(lang, &text);
            fn walk(s: &[lonca_symbols::Sym], depth: usize) {
                for x in s {
                    let mut tags = Vec::new();
                    if x.is_test {
                        tags.push(if x.skipped { "test, skipped" } else { "test" });
                    }
                    let tags = if tags.is_empty() {
                        String::new()
                    } else {
                        format!("  ({})", tags.join(", "))
                    };
                    println!("{}{}{}", "  ".repeat(depth), x.name, tags);
                    walk(&x.children, depth + 1);
                }
            }
            walk(&parsed.syms, 0);
            if parsed.has_error {
                println!("(the file has syntax errors)");
            }
            Ok(())
        }
    }
}

fn print_status(s: &Value) {
    println!("repo   {}", s["repo"].as_str().unwrap_or(""));
    println!("trunk  {}", s["trunk"].as_str().unwrap_or(""));
    if let Some(f) = s["frozen"].as_str() {
        println!("FROZEN {f}");
    }
    let q = s["queue"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("queue  {q} change(s)");
    let now = s["now_ms"].as_i64().unwrap_or(0);
    println!("sessions:");
    for x in s["sessions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|x| x["active"] == true)
    {
        let taint = x["taint"]
            .as_str()
            .map(|t| format!("  TAINTED: {t}"))
            .unwrap_or_default();
        println!(
            "  {} {} [{}] task={}{}",
            x["id"].as_str().unwrap_or(""),
            x["agent"].as_str().unwrap_or(""),
            x["level"].as_str().unwrap_or(""),
            x["task"].as_str().unwrap_or(""),
            taint
        );
    }
    println!("leases:");
    for l in s["leases"].as_array().cloned().unwrap_or_default() {
        let items: Vec<String> = l["items"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|i| {
                format!(
                    "{}({})",
                    i["symbol"].as_str().unwrap_or(""),
                    i["kind"].as_str().unwrap_or("")
                )
            })
            .collect();
        let left = (l["expires_ms"].as_i64().unwrap_or(0) - now) / 1000;
        println!(
            "  {} {} {}s \"{}\" {}",
            l["set"].as_str().unwrap_or(""),
            l["session"].as_str().unwrap_or(""),
            left,
            l["intent"].as_str().unwrap_or(""),
            items.join(" ")
        );
    }
    let pending = s["pending"].as_array().map(|a| a.len()).unwrap_or(0);
    if pending > 0 {
        println!("pending approvals: {pending} (lonca pending)");
    }
}
