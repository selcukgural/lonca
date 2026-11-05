//! `lonca`: the command line for humans and agents.

mod advise;
mod checkout;
mod ctx;
mod doctor;
mod gitdir;
mod hook;
mod keys;
mod mcp;
mod setup;
mod undo;
mod workspace;
mod wsfs;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{Claim, Continuation, HumanKey, LeaseItem, LeaseKind, Op, OpKind, Scope};
use lonca_core::{ChangeId, GitId};
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
        /// Where `lonca backup` bundles are written (default: $LONCA_BACKUPS
        /// or backups/ in the home). In hardened mode a directory the
        /// developer's group can read.
        #[arg(long)]
        backups: Option<PathBuf>,
        /// Accept harness settings that are not root-owned (testing only).
        #[arg(long)]
        allow_user_owned_settings: bool,
        /// Claude Code managed settings to inspect when binding sessions.
        #[arg(long)]
        managed_settings: Option<PathBuf>,
        /// Network proxy for sandboxed commands (loopback only).
        #[arg(long, default_value = "127.0.0.1:8471")]
        proxy: String,
        #[arg(long)]
        no_proxy: bool,
        /// Socket permissions, octal (hardened mode: 660 with --socket-group).
        #[arg(long, default_value = "600")]
        socket_mode: String,
        #[arg(long)]
        socket_group: Option<String>,
        /// Only these uids may connect (repeatable).
        #[arg(long = "allow-uid")]
        allow_uids: Vec<u32>,
    },
    /// Human identities: file keys or Secure Enclave keys.
    #[command(subcommand)]
    Human(HumanCmd),
    /// The daemon's signing key: rotate it, or recover repositories whose
    /// daemon key is lost.
    #[command(subcommand)]
    DaemonKey(DaemonKeyCmd),
    /// Create a repository, optionally importing an existing Git branch.
    Init {
        repo: String,
        #[arg(long)]
        import: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Agent sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Agent harnesses.
    #[command(subcommand)]
    Harness(HarnessCmd),
    /// Print the rules an agent works by, with neutral tool names.
    Rules,
    /// Workspaces.
    #[command(subcommand)]
    Workspace(WorkspaceCmd),
    /// Bring trunk into the current workspace, merging local edits.
    Sync {
        #[arg(long)]
        json: bool,
    },
    /// Repository status.
    Status {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        json: bool,
        /// The human whose session reads (default identity otherwise).
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Facts of the local changes in this workspace; with a change id, the
    /// unified diff of that change as the daemon computes it.
    Diff {
        change: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Symbol leases (agent workspaces).
    #[command(subcommand)]
    Lease(LeaseCmd),
    /// Propose the local changes of this workspace.
    Propose {
        /// What and why, for humans. Required from a workspace; with
        /// --commit it defaults to the commit's subject.
        #[arg(long, short)]
        intent: Option<String>,
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
        /// From a git checkout: propose this commit (everything it changes
        /// against the last fetched trunk) as a human change.
        #[arg(long)]
        commit: Option<String>,
        /// With --commit: the repository (default: the checkout's
        /// `lonca.repo` git config, else --repo is required).
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Bring trunk into a git checkout as `refs/lonca/trunk`, through the
    /// daemon; merge or reset to it as with any remote.
    Fetch {
        #[arg(long)]
        repo: Option<String>,
        /// The checkout (default: the current directory).
        #[arg(long)]
        into: Option<PathBuf>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show a change (with --evidence, the checks of its last integration
    /// attempt and their logs).
    Change {
        change: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        evidence: bool,
    },
    /// Operations waiting for human approval.
    Pending {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
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
        #[arg(long)]
        json: bool,
    },
    /// Decline an escalated operation with a reason for its requester.
    Reject {
        seq: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
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
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Show or change the repository policy.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Back up repositories: one Git bundle each, with every ref (trunk,
    /// operation log, policy, proposals), written by the daemon into its
    /// backups directory and optionally copied to --out.
    Backup {
        /// Repositories (comma-separated; default: every repository).
        #[arg(long, value_delimiter = ',')]
        repo: Vec<String>,
        /// Copy each bundle into this directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore a repository from a backup bundle, a bare store or a Git
    /// remote Lonca pushed to. Never replaces an existing repository.
    Restore {
        /// Name of the repository to create.
        repo: String,
        /// The bundle, bare store directory or remote URL.
        #[arg(long)]
        from: String,
    },
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
    /// Withhold a blob (leaked secret, personal data) from every reader.
    Redact {
        blob: String,
        #[arg(long)]
        reason: String,
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
    /// Resume work on a frozen repository.
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
    /// What happened that this session should know of (agent workspaces).
    Events {
        /// The sequence number to start from: `next` of the last answer.
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long)]
        json: bool,
    },
    /// Run the merge queue now.
    Queue,
    /// Check the setup: daemon, socket, hooks, sandbox, humans, logs.
    Doctor {
        /// Claude Code's managed settings, if not at the system's path.
        #[arg(long)]
        managed_settings: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Harness hook handler (reads the hook event on stdin).
    Hook {
        /// The harness profile to read the event with: claude-code, codex,
        /// gemini, opencode, or one the repository's policy describes.
        #[arg(long, default_value = "claude-code")]
        harness: String,
        /// A failure lets the harness go on instead of blocking: for the
        /// stop event, where blocking would keep an agent working for ever.
        #[arg(long)]
        fail_open: bool,
    },
    /// MCP server for agents (stdio).
    Mcp,
    /// AI advisory for a change: summary and risk flags (no authority).
    Advise {
        change: String,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the symbols of a file (lease ids).
    Symbols { path: PathBuf },
}

#[derive(Subcommand)]
enum HumanCmd {
    /// Create a key for a human and make it the default identity.
    Keygen {
        name: String,
        /// Secure Enclave key: every signature needs Touch ID or the password.
        #[arg(long)]
        secure_enclave: bool,
    },
    /// Print the default identity and public key.
    Whoami {
        #[arg(long)]
        json: bool,
    },
    /// Open a human session: reads, prepares and `lonca queue` use it
    /// until it expires. Every human command does this by itself when
    /// needed; run it to choose the length or to sign in up front.
    Login {
        /// Verify against this repository's enrolment (default: any).
        #[arg(long)]
        repo: Option<String>,
        /// Session length, e.g. `30m`, `8h` (default 1h, at most 24h).
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// End the human session and forget its token.
    Logout {
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Enroll another human (signed by you).
    Enroll {
        name: String,
        /// `ed25519` or `p256-se`.
        #[arg(long)]
        alg: String,
        /// Public key (hex), as printed by their `lonca human whoami`.
        #[arg(long)]
        public: String,
        #[arg(long)]
        repo: String,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Replace your key with a new one, signed by the current key. Ends
    /// your sessions and withdraws what you have in flight.
    Rotate {
        /// Every repository you are enrolled in (comma-separated). The new
        /// key is installed only once all of them accept it; rerun to
        /// resume.
        #[arg(long, value_delimiter = ',', required = true)]
        repo: Vec<String>,
        /// The new key is a Secure Enclave key.
        #[arg(long)]
        secure_enclave: bool,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Withdraw a human's keys and end everything they set in motion.
    Revoke {
        name: String,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        reason: String,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Create a recovery key and register it. Keep the file off this
    /// machine: it replaces your key once, without user presence.
    RecoveryKey {
        #[arg(long, value_delimiter = ',', required = true)]
        repo: Vec<String>,
        /// Where to write the recovery key (an existing file is reused).
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Replace a lost key using the recovery key. Uses the recovery key up.
    Recover {
        #[arg(long, value_delimiter = ',', required = true)]
        repo: Vec<String>,
        #[arg(long)]
        recovery_key: PathBuf,
        /// The new key is a Secure Enclave key.
        #[arg(long)]
        secure_enclave: bool,
        /// The human to recover (on a new machine there is no default).
        #[arg(long = "as")]
        human: Option<String>,
    },
}

#[derive(Subcommand)]
enum DaemonKeyCmd {
    /// Move repositories to a new daemon key (signed by the current one).
    /// The old key is deleted once no repository uses it; rerun to resume.
    Rotate {
        /// Repositories to move (comma-separated; default: every repository
        /// still on the current key).
        #[arg(long, value_delimiter = ',')]
        repo: Vec<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
    /// Continue repositories whose daemon key is lost, or that come from
    /// another daemon (moving to hardened mode), on this daemon's key.
    /// Ends every session in them.
    Recover {
        #[arg(long, value_delimiter = ',', required = true)]
        repo: Vec<String>,
        #[arg(long = "as")]
        human: Option<String>,
    },
}

#[derive(Subcommand)]
enum HarnessCmd {
    /// Give a harness the rules, the MCP server and the hooks, as its
    /// profile says. Run in a workspace.
    Setup {
        /// claude-code, codex, gemini, opencode, or one the repository's
        /// policy describes. Another name still gets the rules and the MCP
        /// server.
        harness: String,
        /// Write nothing: show the flags and the files.
        #[arg(long)]
        print: bool,
        #[arg(long)]
        json: bool,
    },
    /// Print a built-in profile as a table for lonca.toml. There it replaces
    /// the built-in one, signed with `lonca policy set`: for a harness that
    /// has changed before Lonca has.
    Show { harness: String },
}

// Built once, from the command line.
#[allow(clippy::large_enum_variant)]
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
        #[arg(long, required_unless_present = "continue_dir")]
        workspace: Option<PathBuf>,
        /// Take over this workspace: its files, base and manifest stay, its
        /// session ends. Taint and observation level carry over; leases do
        /// not.
        #[arg(long = "continue", conflicts_with = "workspace")]
        continue_dir: Option<PathBuf>,
        /// Keep the workspace a plain directory: no `.git`.
        #[arg(long, conflicts_with = "continue_dir")]
        no_git: bool,
        /// With --continue: allow a scope wider than the old session's.
        #[arg(long)]
        widen: bool,
        /// A directory outside the workspace the agent may write to
        /// (notes, logs). Writes there are not facts and can not be
        /// proposed. Repeatable; recorded in the session's scope.
        #[arg(long)]
        scratch: Vec<PathBuf>,
        /// Set this harness up in the workspace (`lonca harness setup`).
        #[arg(long)]
        harness: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
        #[arg(long)]
        json: bool,
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
    /// Report the session of the current agent workspace alive. `lonca mcp`
    /// does this by itself; for agents that do not run it.
    Heartbeat {
        #[arg(long)]
        json: bool,
    },
    /// End the session of the current agent workspace.
    End {
        #[arg(long)]
        json: bool,
    },
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
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LeaseCmd {
    Acquire {
        #[arg(required = true)]
        symbols: Vec<String>,
        #[arg(long, default_value = "edit")]
        kind: String,
        /// What you are doing and why; others read it
        #[arg(long, short)]
        intent: String,
        #[arg(long, default_value = "10m")]
        ttl: String,
        #[arg(long)]
        json: bool,
    },
    Release {
        set: String,
        #[arg(long)]
        json: bool,
    },
    Renew {
        set: String,
        #[arg(long, default_value = "10m")]
        ttl: String,
        #[arg(long)]
        json: bool,
    },
    /// Wait for symbols others hold: when they are freed, the oldest
    /// interest gets a short reservation. Holds nothing, and for a while
    /// no new lease can be taken that conflicts with it.
    Interest {
        #[arg(required = true)]
        symbols: Vec<String>,
        #[arg(long, default_value = "edit")]
        kind: String,
        /// What you are doing and why; others read it
        #[arg(long, short)]
        intent: String,
        #[arg(long)]
        json: bool,
    },
    /// The leases the local changes need, and who holds them.
    Needed {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Show {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "as")]
        human: Option<String>,
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

/// Exit codes: 0 done; 1 the daemon refused (its error code, or a denied
/// decision, on stderr as `code: message`); 2 the daemon is unreachable;
/// 3 usage and everything else that never reached the daemon.
fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { 3 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    match cli.cmd {
        Cmd::Hook { harness, fail_open } => hook::run(&harness, fail_open),
        cmd => match run(cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("lonca: {e:#}");
                ExitCode::from(ctx::exit_code(&e))
            }
        },
    }
}

/// Sets `harness` up in `ws`, or with `print` only says how.
fn setup_harness(
    ws: &mut Workspace,
    harness: &str,
    print: bool,
) -> Result<(setup::Prepared, Vec<String>)> {
    let mut client = connect()?;
    client.token = Some(ws.token()?);
    let prepared = setup::prepare(&mut client, ws, harness)?;
    let written = if print { vec![] } else { prepared.write(ws)? };
    Ok((prepared, written))
}

fn human_name(h: Option<String>) -> Result<String> {
    match h {
        Some(h) => Ok(h),
        None => ctx::default_human(),
    }
}

/// `lonca backup`: the daemon writes a bundle per repository; with `--out`
/// each is copied there (the daemon's copy stays; its directory may be
/// pruned freely). Repositories on another daemon key are not listed by the
/// daemon and must be recovered first.
fn backup(repos: &[String], out: Option<&Path>) -> Result<()> {
    let human = ctx::default_human()?;
    let mut c = human_client_any(&human)?;
    let repos: Vec<String> = if repos.is_empty() {
        serde_json::from_value(call(&mut c, "repo.list", json!({}))?)?
    } else {
        repos.to_vec()
    };
    if repos.is_empty() {
        bail!("no repositories to back up");
    }
    if let Some(out) = out {
        std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    }
    for repo in &repos {
        let mut c = human_client(repo, &human)?;
        let r = call(&mut c, "repo.backup", json!({}))?;
        let mut path = PathBuf::from(r["path"].as_str().unwrap_or_default());
        if let Some(out) = out {
            let dest = out.join(path.file_name().unwrap_or_default());
            std::fs::copy(&path, &dest)
                .with_context(|| format!("cannot copy {} to {}", path.display(), dest.display()))?;
            path = dest;
        }
        println!(
            "{repo}: {} (operations 0..={}, head {})",
            path.display(),
            r["seq"],
            r["head_hash"]
                .as_str()
                .unwrap_or_default()
                .get(..16)
                .unwrap_or_default()
        );
    }
    println!(
        "Verify a backup before trusting it: git init --bare x.git && git -C x.git fetch <bundle> \
         '+refs/*:refs/*' && lonca-audit verify x.git"
    );
    Ok(())
}

/// `lonca restore`: the daemon fetches the Lonca refs from a bundle, a bare
/// store or a remote into a new repository and replays its log.
fn restore(repo: &str, from: &str) -> Result<()> {
    let from = source(from)?;
    let mut c = session_or_bootstrap(ctx::default_human().ok().as_deref())?;
    let r = call(&mut c, "repo.restore", json!({"repo": repo, "from": from}))?;
    println!(
        "{repo}: restored operations 0..={} (head {})",
        r["seq"],
        r["head_hash"]
            .as_str()
            .unwrap_or_default()
            .get(..16)
            .unwrap_or_default()
    );
    if r["foreign"].as_bool() == Some(true) {
        println!(
            "its log is on daemon key {}, which this daemon does not hold: run \
             `lonca daemon-key recover --repo {repo}` as an enrolled human to continue it.",
            r["daemon_key"]
                .as_str()
                .unwrap_or_default()
                .get(..16)
                .unwrap_or_default()
        );
    } else {
        println!("ready; sessions in the log continue only if their tokens survived.");
    }
    println!("Audit it: lonca-audit verify <home>/repos/{repo}.git");
    Ok(())
}

/// A restore source as the daemon must see it: URLs (`https://`, `ssh://`,
/// `user@host:path`) unchanged, everything else an absolute path.
fn source(from: &str) -> Result<String> {
    if from.contains("://") || (from.contains('@') && from.contains(':')) {
        Ok(from.to_string())
    } else {
        Ok(ctx::absolute(Path::new(from))?
            .to_string_lossy()
            .into_owned())
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

/// A client acting for `human` on `repo`, with a human session.
pub(crate) fn human_client(repo: &str, human: &str) -> Result<Client> {
    ctx::human_client(Some(repo), human)
}

/// A client with a human session that is not about one repository
/// (`repo.list`, `queue.run`, `daemon.prepare_rotate`).
pub(crate) fn human_client_any(human: &str) -> Result<Client> {
    ctx::human_client(None, human)
}

/// For `init` and `restore`: a human session when the human has one to
/// open, else no credential, which the daemon accepts only while it
/// serves no repository yet (bootstrap).
fn session_or_bootstrap(human: Option<&str>) -> Result<Client> {
    match human {
        Some(h) => match human_client_any(h) {
            Ok(c) => Ok(c),
            Err(_) => connect(),
        },
        None => connect(),
    }
}

/// Scratch roots as the daemon records them: absolute, normalized, and
/// neither inside the workspace nor containing it. Created if missing.
fn scratch_roots(workspace: &Path, dirs: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for d in dirs {
        let abs = ctx::absolute(d)?;
        std::fs::create_dir_all(&abs)
            .with_context(|| format!("cannot create scratch directory {}", abs.display()))?;
        let abs = abs
            .canonicalize()
            .with_context(|| format!("scratch directory {}", abs.display()))?;
        if abs.starts_with(workspace) || workspace.starts_with(&abs) {
            bail!(
                "scratch directory {} overlaps the workspace {}",
                abs.display(),
                workspace.display()
            );
        }
        let s = abs.to_string_lossy().into_owned();
        if !lonca_policy::decide::valid_scratch_root(&s) {
            bail!("scratch directory {s} is not a plain absolute path");
        }
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// The human a workspace was created for, else the default identity.
fn workspace_human(ws: &Workspace) -> Result<String> {
    match &ws.meta.human {
        // It names key files, and workspace.json can be edited.
        Some(h) if h.contains('/') || h.starts_with('.') => bail!("bad human name {h:?}"),
        Some(h) => Ok(h.clone()),
        None => ctx::default_human(),
    }
}

/// Signs and submits a human operation; prints the decision and returns
/// it, a denial included, for the commands that go over several
/// repositories and report at the end.
pub(crate) fn submit_outcome(c: &mut Client, human: &str, repo: &str, op: Op) -> Result<Value> {
    let sig = ctx::sign(human, repo, &op)?;
    let r = call(c, "human.submit", json!({"op": op, "sig": sig}))?;
    print_decision(&r);
    Ok(r)
}

/// As [`submit_outcome`]; a denial is an error, so the command exits 1.
pub(crate) fn submit(c: &mut Client, human: &str, repo: &str, op: Op) -> Result<Value> {
    let r = submit_outcome(c, human, repo, op)?;
    ctx::denied(&r)?;
    Ok(r)
}

pub(crate) fn print_decision(r: &Value) {
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

fn lease_items(symbols: Vec<String>, kind: &str) -> Result<Vec<LeaseItem>> {
    let kind = match kind {
        "edit" => LeaseKind::Edit,
        "insert" => LeaseKind::Insert,
        "rename" => LeaseKind::Rename,
        k => bail!("unknown lease kind {k}"),
    };
    let items = symbols.into_iter();
    Ok(items.map(|symbol| LeaseItem { symbol, kind }).collect())
}

fn agent_client() -> Result<(Client, Workspace)> {
    let ws = Workspace::current()?;
    let mut c = connect()?;
    c.token = Some(ws.token()?);
    Ok((c, ws))
}

fn run(cmd: Cmd) -> Result<()> {
    let is_reject = matches!(cmd, Cmd::Reject { .. });
    match cmd {
        Cmd::Doctor {
            managed_settings,
            json: as_json,
        } => doctor::run(managed_settings, as_json),
        Cmd::Daemon {
            home,
            backups,
            allow_user_owned_settings,
            managed_settings,
            proxy,
            no_proxy,
            socket_mode,
            socket_group,
            allow_uids,
        } => {
            let home = home
                .map(lonca_daemon::Home::new)
                .unwrap_or_else(lonca_daemon::Home::from_env);
            let home = match backups {
                Some(b) => home.with_backups(b),
                None => home,
            };
            let defaults = lonca_daemon::Settings::default();
            let settings = lonca_daemon::Settings {
                require_root_settings: !allow_user_owned_settings,
                managed_settings: managed_settings.unwrap_or(defaults.managed_settings),
                git: defaults.git,
                line_cap: defaults.line_cap,
            };
            let svc =
                lonca_daemon::Service::open(home.clone(), settings, lonca_daemon::system_clock())?;
            let access = lonca_daemon::server::Access {
                mode: u32::from_str_radix(&socket_mode, 8)
                    .context("--socket-mode is octal, e.g. 660")?,
                group: match socket_group {
                    Some(g) => Some(
                        lonca_daemon::server::group_id(&g)
                            .with_context(|| format!("unknown group {g}"))?,
                    ),
                    None => None,
                },
                allowed_uids: if allow_uids.is_empty() {
                    None
                } else {
                    Some(allow_uids)
                },
            };
            let listener = lonca_daemon::server::bind_with(&home.socket(), &access)?;
            svc.spawn_worker();
            if !no_proxy {
                match lonca_daemon::proxy::bind(&proxy) {
                    Ok(l) => {
                        let s = svc.clone();
                        std::thread::spawn(move || lonca_daemon::proxy::serve(l, s));
                        eprintln!("lonca daemon: network proxy on {proxy}");
                    }
                    Err(e) => eprintln!("lonca daemon: proxy not started on {proxy}: {e}"),
                }
            }
            eprintln!(
                "lonca daemon: listening on {} (key {})",
                home.socket().display(),
                &svc.public_key()[..16]
            );
            lonca_daemon::server::serve_with(listener, svc, access);
            Ok(())
        }
        Cmd::Human(HumanCmd::Keygen {
            name,
            secure_enclave,
        }) => {
            if !lonca_policy::decide::valid_token(&name, 64) {
                bail!("human names: letters, digits, '.', '_', '-'");
            }
            if secure_enclave {
                if ctx::se_key_path(&name).exists() {
                    bail!("{} already exists", ctx::se_key_path(&name).display());
                }
                let public = ctx::se_keygen(&name)?;
                std::fs::write(ctx::humans_dir().join("default"), &name)?;
                println!("{name}: p256-se {public}");
                println!("every signature will ask for Touch ID or your password.");
                return Ok(());
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
        Cmd::Human(HumanCmd::Whoami { json: as_json }) => {
            let name = ctx::default_human()?;
            let k = ctx::human_public(&name)?;
            if as_json {
                return ctx::print_json(&json!({"human": name, "alg": k.alg, "public": k.public}));
            }
            println!("{name}: {} {}", k.alg, k.public);
            Ok(())
        }
        Cmd::Human(HumanCmd::Login {
            repo,
            ttl,
            human,
            json: as_json,
        }) => {
            let human = human_name(human)?;
            let ttl = match ttl {
                Some(t) => ctx::duration_ms(&t)?,
                None => lonca_daemon::service::HUMAN_SESSION_DEFAULT_MS,
            };
            let mut c = connect()?;
            c.repo = repo;
            let s = ctx::login(&mut c, &human, ttl)?;
            let who = call(&mut c, "whoami", json!({}))?;
            let repos: Vec<&str> = who["repos"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if as_json {
                // The token is in the file, never here.
                return ctx::print_json(&json!({
                    "human": human, "expires_ms": s.expires_ms,
                    "session_file": ctx::session_path(&human), "repos": repos,
                }));
            }
            println!(
                "{human}: signed in for {} (until {}); enrolled in: {}",
                ctx::describe_ms(ttl),
                s.expires_ms,
                if repos.is_empty() {
                    "no repository".to_string()
                } else {
                    repos.join(", ")
                }
            );
            Ok(())
        }
        Cmd::Human(HumanCmd::Logout { human }) => {
            let human = human_name(human)?;
            if let Some(s) = ctx::read_session(&human)
                && let Ok(mut c) = connect()
            {
                c.token = Some(s.token);
                // A session the daemon no longer knows is already ended.
                let _ = c.call("human.logout", json!({}));
            }
            ctx::clear_session(&human)?;
            println!("{human}: signed out");
            Ok(())
        }
        Cmd::Human(HumanCmd::Enroll {
            name,
            alg,
            public,
            repo,
            human,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            submit(
                &mut c,
                &human,
                &repo,
                Op::HumanEnroll {
                    human: name,
                    key: HumanKey { alg, public },
                },
            )?;
            Ok(())
        }
        Cmd::Human(HumanCmd::Rotate {
            repo,
            secure_enclave,
            human,
        }) => keys::rotate(&keys::name(human)?, &repo, secure_enclave),
        Cmd::Human(HumanCmd::Revoke {
            name,
            repo,
            reason,
            human,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            submit(
                &mut c,
                &human,
                &repo,
                Op::HumanRevoke {
                    human: name,
                    reason,
                },
            )?;
            Ok(())
        }
        Cmd::Human(HumanCmd::RecoveryKey { repo, out, human }) => {
            keys::recovery_key(&keys::name(human)?, &repo, &ctx::absolute(&out)?)
        }
        Cmd::Human(HumanCmd::Recover {
            repo,
            recovery_key,
            secure_enclave,
            human,
        }) => keys::recover(
            &keys::name(human)?,
            &repo,
            &ctx::absolute(&recovery_key)?,
            secure_enclave,
        ),
        Cmd::DaemonKey(DaemonKeyCmd::Rotate { repo, human }) => {
            keys::daemon_rotate(&keys::name(human)?, &repo)
        }
        Cmd::DaemonKey(DaemonKeyCmd::Recover { repo, human }) => {
            keys::daemon_recover(&keys::name(human)?, &repo)
        }
        Cmd::Init {
            repo,
            import,
            branch,
            human,
            json: as_json,
        } => {
            let human = human_name(human)?;
            let key = ctx::human_public(&human)?;
            let mut c = session_or_bootstrap(Some(&human))?;
            let prep = call(
                &mut c,
                "repo.prepare_init",
                json!({"repo": repo, "human": human, "human_key": key, "import_from": import, "branch": branch}),
            )?;
            let op: Op = serde_json::from_value(prep["op"].clone())?;
            if !as_json {
                for w in prep["warnings"].as_array().into_iter().flatten() {
                    eprintln!("warning: {}", w.as_str().unwrap_or_default());
                }
            }
            let sig = ctx::sign(&human, &repo, &op)?;
            let r = call(&mut c, "repo.init", json!({"op": op, "sig": sig}))?;
            if as_json {
                let Op::RepoInit { trunk, .. } = &op else {
                    bail!("repo.prepare_init did not return an init")
                };
                ctx::print_json(&json!({
                    "repo": repo, "trunk": trunk, "seq": r["seq"], "decision": r["decision"],
                    "warnings": prep["warnings"],
                }))?;
            } else {
                print_decision(&r);
            }
            ctx::denied(&r)
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
            continue_dir,
            no_git,
            widen,
            scratch,
            harness,
            human,
            json: as_json,
        }) => {
            if widen && continue_dir.is_none() {
                bail!("--widen goes with --continue");
            }
            let human = human_name(human)?;
            let target = continue_dir.as_ref().or(workspace.as_ref());
            let dir = ctx::absolute(target.context("pass --workspace or --continue")?)?;
            let continuing = match continue_dir {
                Some(_) => Some(Workspace::to_continue(&dir, &repo)?),
                None => None,
            };
            let scratch = scratch_roots(&dir, &scratch)?;
            let mut c = human_client(&repo, &human)?;
            let session = lonca_core::canonical::random_id("ses");
            let expires_ms = ctx::now_ms() + ctx::duration_ms(&ttl)?;
            let op = Op::SessionStart {
                session: session.clone(),
                agent,
                model,
                task,
                scope: Scope {
                    paths: paths.clone(),
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
                    scratch: scratch.clone(),
                },
                expires_ms,
                continues: continuing.as_ref().map(|(_, old)| Continuation {
                    session: old.clone(),
                    widen,
                }),
            };
            let r = if as_json {
                let sig = ctx::sign(&human, &repo, &op)?;
                call(&mut c, "human.submit", json!({"op": op, "sig": sig}))?
            } else {
                submit(&mut c, &human, &repo, op)?
            };
            ctx::denied(&r)?;
            let Some(token) = r["token"].as_str() else {
                bail!("session was not started: {}", r["decision"]["outcome"])
            };
            let (continued, old) = continuing.unzip();
            let mut ws = match continued {
                Some(ws) => ws,
                None => {
                    let mut ac = connect()?;
                    ac.token = Some(token.to_string());
                    Workspace::create(&mut ac, &dir, &repo, Some(session.clone()), None, !no_git)?
                }
            };
            // The token first: it is what the workspace runs on.
            ws.write_token(token)?;
            ws.meta.session = Some(session.clone());
            ws.meta.scratch_roots = scratch.clone();
            ws.save()?;
            let setup = match &harness {
                Some(h) => Some(
                    setup_harness(&mut ws, h, false)
                        .with_context(|| format!("session {session} started, its setup failed"))?,
                ),
                None => None,
            };
            if as_json {
                return ctx::print_json(&json!({
                    "session": session, "workspace": ws.root, "expires_ms": expires_ms,
                    "paths": paths, "scratch": scratch, "seq": r["seq"], "decision": r["decision"],
                    "continues": old, "setup": setup.as_ref().map(|(p, w)| p.report(w)),
                }));
            }
            println!("session {session}; workspace {}", ws.root.display());
            if let Some(old) = old {
                println!("continues {old}");
            }
            for s in &scratch {
                println!("scratch {s}");
            }
            match setup {
                Some((prepared, written)) => prepared.print(&written, false),
                None => Ok(()),
            }
        }
        Cmd::Harness(HarnessCmd::Setup {
            harness,
            print,
            json: as_json,
        }) => {
            let mut ws = Workspace::current()?;
            let (prepared, written) = setup_harness(&mut ws, &harness, print)?;
            if as_json {
                return ctx::print_json(&prepared.report(&written));
            }
            prepared.print(&written, print)
        }
        Cmd::Harness(HarnessCmd::Show { harness }) => {
            let Some(table) = lonca_policy::harness::built_in_table(&harness) else {
                bail!("no built-in profile for harness {harness}");
            };
            print!("{}", table.map_err(anyhow::Error::msg)?);
            Ok(())
        }
        Cmd::Rules => {
            println!(
                "{}",
                setup::neutral_rules(Workspace::current().ok().as_ref())
            );
            Ok(())
        }
        Cmd::Session(SessionCmd::Revoke {
            session,
            repo,
            reason,
            human,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            submit(&mut c, &human, &repo, Op::CapRevoke { session, reason })?;
            Ok(())
        }
        Cmd::Session(SessionCmd::Heartbeat { json: as_json }) => {
            let (mut c, ws) = agent_client()?;
            let r = call(&mut c, "session.heartbeat", json!({}))?;
            if as_json {
                ctx::print_json(&json!({
                    "session": ws.meta.session, "seq": r["seq"], "timeout_ms": r["timeout_ms"],
                    "leases": r["leases"],
                }))?;
            } else {
                print_decision(&r);
            }
            ctx::denied(&r)
        }
        Cmd::Session(SessionCmd::End { json: as_json }) => {
            let (mut c, ws) = agent_client()?;
            let files = ws.local_files()?;
            let r = call(&mut c, "session.end", json!({ "files": files }))?;
            if as_json {
                ctx::print_json(&json!({
                    "session": ws.meta.session, "seq": r["seq"], "decision": r["decision"],
                    "unproposed": r["unproposed"], "unproposed_total": r["unproposed_total"],
                }))?;
            } else {
                print_decision(&r);
                let total = r["unproposed_total"].as_u64().unwrap_or(0);
                if total > 0 {
                    println!("left unproposed: {total} file(s) never reached the repository");
                }
            }
            ctx::denied(&r)
        }
        Cmd::Workspace(WorkspaceCmd::Create {
            dir,
            repo,
            human,
            json: as_json,
        }) => {
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            let dir = ctx::absolute(&dir)?;
            let ws = Workspace::create(&mut c, &dir, &repo, None, Some(human), false)?;
            if as_json {
                return ctx::print_json(&json!({
                    "workspace": ws.root, "repo": repo, "base": ws.meta.base,
                }));
            }
            println!(
                "workspace {} at {}",
                ws.root.display(),
                ws.meta.base.short()
            );
            Ok(())
        }
        Cmd::Sync { json: as_json } => {
            let mut ws = Workspace::current()?;
            let mut c = match &ws.meta.session {
                Some(_) => {
                    let mut c = connect()?;
                    c.token = Some(ws.token()?);
                    c
                }
                None => human_client(&ws.meta.repo, &workspace_human(&ws)?)?,
            };
            let r = ws.sync(&mut c)?;
            if as_json {
                let conflicts: Vec<Value> = r
                    .conflicts
                    .iter()
                    .map(|p| {
                        json!({
                            "path": p,
                            "trunk_copy": format!("{p}.trunk"),
                            "symbols": r.symbols_of(p),
                        })
                    })
                    .collect();
                return ctx::print_json(&json!({
                    "base_before": r.from, "base_after": r.to,
                    "updated": r.updated, "merged": r.merged, "conflicts": conflicts,
                    "git_warning": r.git_warning,
                }));
            }
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
                for s in r.symbols_of(p) {
                    println!("    {s}");
                }
            }
            if let Some(w) = &r.git_warning {
                eprintln!("warning: .git still shows the old base: {w}");
            }
            Ok(())
        }
        Cmd::Status {
            repo,
            json: as_json,
            human,
        } => {
            let mut c = match repo {
                Some(r) => human_client(&r, &human_name(human)?)?,
                None => {
                    let ws =
                        Workspace::current().context("pass --repo or run inside a workspace")?;
                    match ws.meta.session {
                        Some(_) => {
                            let mut c = connect()?;
                            c.token = Some(ws.token()?);
                            c
                        }
                        None => {
                            let human = match human {
                                Some(h) => h,
                                None => workspace_human(&ws)?,
                            };
                            human_client(&ws.meta.repo, &human)?
                        }
                    }
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
        Cmd::Diff {
            change: Some(change),
            repo,
            human,
            json: as_json,
        } => {
            let mut c = human_client(&repo_name(repo)?, &human_name(human)?)?;
            let d = call(&mut c, "change.diff", json!({"change": change}))?;
            if as_json {
                return ctx::print_json(&d);
            }
            for f in d["files"].as_array().into_iter().flatten() {
                println!(
                    "{:<9} +{} -{} {}",
                    f["status"].as_str().unwrap_or(""),
                    f["added"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or("-".into()),
                    f["removed"]
                        .as_u64()
                        .map(|n| n.to_string())
                        .unwrap_or("-".into()),
                    f["path"].as_str().unwrap_or("")
                );
            }
            for p in d["redacted"].as_array().into_iter().flatten() {
                println!("redacted  {}", p.as_str().unwrap_or(""));
            }
            print!("{}", d["diff"].as_str().unwrap_or(""));
            if d["truncated"] == true {
                println!("[diff truncated]");
            }
            Ok(())
        }
        Cmd::Diff { change: None, .. } => {
            let ws = Workspace::current()?;
            let changes = ws.changes()?;
            if changes.is_empty() {
                println!("no local changes");
                return Ok(());
            }
            let facts = match &ws.meta.session {
                Some(_) => {
                    let mut c = connect()?;
                    c.token = Some(ws.token()?);
                    call(
                        &mut c,
                        "facts.preview",
                        json!({"base": ws.meta.base, "files": changes}),
                    )?
                }
                None => {
                    let human = workspace_human(&ws)?;
                    let mut c = human_client(&ws.meta.repo, &human)?;
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
            let (mut c, ws) = agent_client()?;
            let (r, as_json) = match l {
                LeaseCmd::Needed { json: as_json } => {
                    let r = mcp::lease_needed(&mut c, &ws)?;
                    if as_json {
                        ctx::print_json(&r)?;
                    } else {
                        print_lease_needs(&r);
                    }
                    return Ok(());
                }
                LeaseCmd::Interest {
                    symbols,
                    kind,
                    intent,
                    json: as_json,
                } => {
                    let items = lease_items(symbols, &kind)?;
                    let params = json!({"items": items, "intent": intent});
                    (call(&mut c, "lease.interest", params)?, as_json)
                }
                LeaseCmd::Acquire {
                    symbols,
                    kind,
                    intent,
                    ttl,
                    json: as_json,
                } => {
                    let items = lease_items(symbols, &kind)?;
                    let r = call(
                        &mut c,
                        "lease.acquire",
                        json!({"items": items, "intent": intent, "ttl_ms": ctx::duration_ms(&ttl)?}),
                    )?;
                    if !as_json
                        && let Some(set) = r["set"].as_str()
                        && r["decision"]["outcome"] == "allow"
                    {
                        println!("lease set {set}");
                    }
                    (r, as_json)
                }
                LeaseCmd::Release { set, json: as_json } => {
                    let mut r = call(&mut c, "lease.release", json!({"set": set}))?;
                    r["set"] = json!(set);
                    (r, as_json)
                }
                LeaseCmd::Renew {
                    set,
                    ttl,
                    json: as_json,
                } => {
                    let ttl_ms = ctx::duration_ms(&ttl)?;
                    let mut r = call(&mut c, "lease.renew", json!({"set": set, "ttl_ms": ttl_ms}))?;
                    r["set"] = json!(set);
                    (r, as_json)
                }
            };
            if as_json {
                ctx::print_json(&json!({
                    "seq": r["seq"], "decision": r["decision"], "set": r["set"],
                    "details": ctx::details(&r),
                }))?;
            } else {
                print_decision(&r);
            }
            ctx::denied(&r)
        }
        Cmd::Events {
            from,
            json: as_json,
        } => {
            let (mut c, _) = agent_client()?;
            let r = call(&mut c, "events", json!({"from": from}))?;
            if as_json {
                return ctx::print_json(&r);
            }
            for e in r["events"].as_array().into_iter().flatten() {
                println!("{e}");
            }
            println!("next {}", r["next"]);
            Ok(())
        }
        Cmd::Fetch {
            repo,
            into,
            human,
            json: as_json,
        } => {
            let dir = ctx::absolute(into.as_deref().unwrap_or(Path::new(".")))?;
            let repo = checkout::repo_name(&dir, repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            let r = checkout::fetch(&mut c, &dir, &repo)?;
            if as_json {
                return ctx::print_json(&r);
            }
            println!(
                "refs/lonca/trunk -> {} ({} bytes{}){}",
                r["trunk"].as_str().unwrap_or("").get(..12).unwrap_or(""),
                r["bytes"],
                if r["thin"] == true { ", thin" } else { "" },
                match r["behind"].as_u64() {
                    Some(0) => String::new(),
                    Some(n) => format!("; the previous trunk ref was {n} behind"),
                    None => String::new(),
                }
            );
            Ok(())
        }
        Cmd::Propose {
            intent,
            commit: Some(rev),
            repo,
            human,
            json: as_json,
            ..
        } => {
            let dir = ctx::absolute(Path::new("."))?;
            let repo = checkout::repo_name(&dir, repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            let r = checkout::propose(
                &mut c,
                &dir,
                &repo,
                &human,
                &rev,
                intent.as_deref().unwrap_or(""),
            )?;
            let status = ctx::proposal_status(&r);
            if as_json {
                ctx::print_json(&json!({
                    "change": r["change"], "commit": r["commit"], "base": r["base"], "seq": r["seq"],
                    "decision": r["decision"], "status": status, "details": ctx::details(&r),
                }))?;
            } else {
                print_decision(&r);
                println!("change {}", r["change"].as_str().unwrap_or(""));
            }
            ctx::denied(&r)
        }
        Cmd::Propose {
            intent,
            accept_facts,
            edits,
            adds,
            deletes,
            deleted_files,
            signature_changes,
            commit: None,
            json: as_json,
            ..
        } => {
            let intent = intent.context("pass --intent (-i): what the change does and why")?;
            let mut ws = Workspace::current()?;
            let changes = ws.changes()?;
            if changes.is_empty() {
                bail!("no local changes");
            }
            // (change, commit, logged result)
            let (change, commit, r) = match &ws.meta.session {
                Some(_) => {
                    let mut c = connect()?;
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
                    let r = call(
                        &mut c,
                        "change.propose",
                        json!({"base": ws.meta.base, "files": changes, "claim": claim}),
                    )?;
                    let change: ChangeId = serde_json::from_value(r["change"].clone())?;
                    let commit: GitId = serde_json::from_value(r["commit"].clone())?;
                    (change, commit, r)
                }
                None => {
                    let human = workspace_human(&ws)?;
                    let mut c = human_client(&ws.meta.repo, &human)?;
                    let prep = call(
                        &mut c,
                        "human.prepare_change",
                        json!({"base": ws.meta.base, "files": changes, "author": human, "intent": intent}),
                    )?;
                    let op: Op = serde_json::from_value(prep["op"].clone())?;
                    let repo = ws.meta.repo.clone();
                    let Op::ChangePropose { change, commit, .. } = &op else {
                        bail!("human.prepare_change did not return a change")
                    };
                    let (change, commit) = (*change, commit.clone());
                    let sig = ctx::sign(&human, &repo, &op)?;
                    let r = call(&mut c, "human.submit", json!({"op": op, "sig": sig}))?;
                    (change, commit, r)
                }
            };
            let status = ctx::proposal_status(&r);
            if as_json {
                ctx::print_json(&json!({
                    "change": change, "commit": commit, "seq": r["seq"],
                    "decision": r["decision"], "status": status, "details": ctx::details(&r),
                }))?;
            } else {
                print_decision(&r);
                println!("change {change}");
            }
            if status != "denied" {
                ws.meta.submitted = Some((change, commit));
                ws.save()?;
            }
            ctx::denied(&r)
        }
        Cmd::Change {
            change,
            repo,
            human,
            evidence,
        } => {
            let mut c = human_client(&repo_name(repo)?, &human_name(human)?)?;
            let rec = call(&mut c, "change.get", json!({"change": change}))?;
            if !evidence {
                println!("{}", serde_json::to_string_pretty(&rec)?);
                return Ok(());
            }
            let checks = rec["evidence"].as_array().cloned().unwrap_or_default();
            if checks.is_empty() {
                println!("no integration attempt yet");
            }
            for a in checks {
                println!(
                    "{}: {} (exit {}, {} ms, sandbox {})",
                    a["check"].as_str().unwrap_or(""),
                    a["result"].as_str().unwrap_or(""),
                    a["exit"]
                        .as_i64()
                        .map(|n| n.to_string())
                        .unwrap_or("-".into()),
                    a["duration_ms"].as_i64().unwrap_or(0),
                    a["sandbox"].as_str().unwrap_or("-")
                );
                if let Some(log) = a["log"].as_str().filter(|l| !l.is_empty()) {
                    if a["log_truncated"] == true {
                        println!("  [log tail]");
                    }
                    for line in log.lines() {
                        println!("  {line}");
                    }
                }
            }
            Ok(())
        }
        Cmd::Pending {
            repo,
            human,
            json: as_json,
        } => {
            let mut c = human_client(&repo_name(repo)?, &human_name(human)?)?;
            let s = call(&mut c, "status", json!({}))?;
            if as_json {
                return ctx::print_json(&s["pending"]);
            }
            for p in s["pending"].as_array().cloned().unwrap_or_default() {
                let change = p["change"]
                    .as_str()
                    .map(|c| format!(" change {}", c.get(..12).unwrap_or(c)))
                    .unwrap_or_default();
                let intent = p["intent"]
                    .as_str()
                    .filter(|i| !i.is_empty())
                    .map(|i| format!(" \"{i}\""))
                    .unwrap_or_default();
                println!(
                    "#{} {} {}{change}{intent} [{}/{}] {}",
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
            json: as_json,
        }
        | Cmd::Reject {
            seq,
            repo,
            reason: note,
            human,
            json: as_json,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            let op = if is_reject {
                Op::Reject {
                    target_seq: seq,
                    reason: note,
                }
            } else {
                Op::Approve {
                    target_seq: seq,
                    note,
                }
            };
            let r = if as_json {
                // The change the pending entry is about, before it is released.
                let st = call(&mut c, "status", json!({}))?;
                let change = st["pending"]
                    .as_array()
                    .and_then(|a| a.iter().find(|p| p["seq"] == seq))
                    .map(|p| p["change"].clone())
                    .unwrap_or(Value::Null);
                let sig = ctx::sign(&human, &repo, &op)?;
                let r = call(&mut c, "human.submit", json!({"op": op, "sig": sig}))?;
                ctx::print_json(&json!({
                    "seq": r["seq"], "target_seq": seq, "change": change, "decision": r["decision"],
                }))?;
                r
            } else {
                submit(&mut c, &human, &repo, op)?
            };
            ctx::denied(&r)
        }
        Cmd::Log {
            repo,
            from,
            limit,
            json: as_json,
            human,
        } => {
            let mut c = human_client(&repo_name(repo)?, &human_name(human)?)?;
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
        Cmd::Policy(PolicyCmd::Show { repo, human }) => {
            let repo = repo_name(repo)?;
            let mut c = human_client(&repo, &human_name(human)?)?;
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
            let mut c = human_client(&repo, &human)?;
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
            let mut c = human_client(&repo, &human)?;
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
            let mut c = human_client(&repo, &human)?;
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
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            submit(&mut c, &human, &repo, Op::Freeze { reason })?;
            Ok(())
        }
        Cmd::Redact {
            blob,
            reason,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            let blob = GitId::parse(&blob)?;
            submit(&mut c, &human, &repo, Op::Redact { blob, reason })?;
            println!(
                "note: the blob is withheld by Lonca; copies already pushed to other remotes are not removed."
            );
            Ok(())
        }
        Cmd::Unfreeze {
            reason,
            repo,
            human,
        } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
            submit(&mut c, &human, &repo, Op::Unfreeze { reason })?;
            Ok(())
        }
        Cmd::Undo { seq, repo, human } => {
            let repo = repo_name(repo)?;
            let human = human_name(human)?;
            let mut c = human_client(&repo, &human)?;
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
            let mut c = human_client(&repo, &human)?;
            undo::revert(&mut c, &human, &repo, &actor, since_seq, apply)
        }
        Cmd::Backup { repo, out } => {
            let out = out.map(|o| ctx::absolute(&o)).transpose()?;
            backup(&repo, out.as_deref())
        }
        Cmd::Restore { repo, from } => restore(&repo, &from),
        Cmd::Queue => {
            let mut c = human_client_any(&ctx::default_human()?)?;
            println!("{}", call(&mut c, "queue.run", json!({}))?);
            Ok(())
        }
        Cmd::Hook { .. } => unreachable!("handled in main"),
        Cmd::Mcp => mcp::run(),
        Cmd::Advise {
            change,
            repo,
            json: as_json,
        } => {
            let mut c = human_client(&repo_name(repo)?, &ctx::default_human()?)?;
            let advice = advise::advise(&mut c, &change)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&advice)?);
            } else {
                advise::print(&advice);
            }
            Ok(())
        }
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
                        let test = if x.skipped { "test, skipped" } else { "test" };
                        tags.push(test.to_string());
                    }
                    if let Some(ty) = &x.def_of {
                        tags.push(format!("definition: {ty}.{}", lonca_symbols::DEF));
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

/// A session that stopped with work nobody proposed: "done" and "stopped"
/// read differently here, for a session that has ended too.
fn left_unproposed(session: &Value) -> Option<String> {
    let left = session.get("unproposed").filter(|u| !u.is_null())?;
    let paths: Vec<&str> = left["paths"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    Some(format!(
        "{} {} file(s) after {} stop(s): {}",
        session["id"].as_str().unwrap_or(""),
        left["total"],
        left["rounds"],
        paths.join(", ")
    ))
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
    let sessions = s["sessions"].as_array().cloned().unwrap_or_default();
    let left: Vec<String> = sessions.iter().filter_map(left_unproposed).collect();
    if !left.is_empty() {
        println!("unproposed work:");
        for line in left {
            println!("  {line}");
        }
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
            "  {} {} {}s \"{}\" {}{}",
            l["set"].as_str().unwrap_or(""),
            l["session"].as_str().unwrap_or(""),
            left,
            l["intent"].as_str().unwrap_or(""),
            items.join(" "),
            pin_note(&l)
        );
    }
    let pending = s["pending"].as_array().map(|a| a.len()).unwrap_or(0);
    if pending > 0 {
        println!("pending approvals: {pending} (lonca pending)");
    }
}

/// One line for each lease a change needs.
fn lease_need_lines(report: &Value) -> Vec<String> {
    let needs = report["leases"].as_array().cloned().unwrap_or_default();
    let line = |d: &Value| {
        let what = format!(
            "{} {}",
            d["needed_kind"].as_str().unwrap_or(""),
            d["symbol"].as_str().unwrap_or("")
        );
        match (d["code"].as_str(), d["holder_session"].as_str()) {
            (Some("lease_wanted"), Some(holder)) => format!("{what}: {holder} goes first"),
            (_, Some(holder)) => format!("{what}: held by {holder}"),
            (Some("held_by_you"), None) => format!("{what}: yours"),
            _ => format!("{what}: free"),
        }
    };
    needs.iter().map(line).collect()
}

fn print_lease_needs(report: &Value) {
    for l in lease_need_lines(report) {
        println!("{l}");
    }
    if let Some(advice) = report["advice"].as_str() {
        println!("{advice}");
    }
}

/// What `lonca status` adds to a lease set with pins.
fn pin_note(lease: &Value) -> String {
    match lease["pinned"].as_array().map_or(0, Vec::len) {
        0 => String::new(),
        n => format!(" [pinned to {n} change(s)]"),
    }
}

#[cfg(test)]
mod tests {
    use super::{lease_need_lines, pin_note, source};

    #[test]
    fn a_session_that_left_work_reads_as_one_line() {
        let s = serde_json::json!({"id": "s1", "unproposed": {"paths": ["a", "b"], "total": 5, "rounds": 2}});
        assert_eq!(
            super::left_unproposed(&s).unwrap(),
            "s1 5 file(s) after 2 stop(s): a, b"
        );
        assert_eq!(
            super::left_unproposed(&serde_json::json!({"id": "s1"})),
            None
        );
        assert_eq!(
            super::left_unproposed(&serde_json::json!({"unproposed": null})),
            None
        );
    }

    #[test]
    fn needed_leases_read_as_one_line_each() {
        let report = serde_json::json!({"leases": [
            {"code": "held_by_you", "needed_kind": "edit", "symbol": "a#f"},
            {"code": "free", "needed_kind": "insert", "symbol": "a#<file>"},
            {"code": "lease_held", "needed_kind": "rename", "symbol": "a#g", "holder_session": "s2"},
            {"code": "lease_wanted", "needed_kind": "edit", "symbol": "a#T", "holder_session": "s3"},
        ]});
        assert_eq!(
            lease_need_lines(&report),
            [
                "edit a#f: yours",
                "insert a#<file>: free",
                "rename a#g: held by s2",
                "edit a#T: s3 goes first"
            ]
        );
    }

    #[test]
    fn status_marks_a_lease_set_with_pins() {
        let lease = |pinned| serde_json::json!({ "pinned": pinned });
        assert_eq!(pin_note(&lease(serde_json::json!([]))), "");
        assert_eq!(pin_note(&serde_json::json!({})), "");
        assert_eq!(
            pin_note(&lease(serde_json::json!([{"change": "c"}]))),
            " [pinned to 1 change(s)]"
        );
    }

    #[test]
    fn a_restore_source_is_a_url_or_an_absolute_path() {
        for url in ["https://h/x.git", "ssh://h/x.git", "git@h:x.git"] {
            assert_eq!(source(url).unwrap(), url);
        }
        assert_eq!(source("/abs/x.bundle").unwrap(), "/abs/x.bundle");
        let cwd = std::env::current_dir().unwrap();
        for rel in ["x.bundle", "a@b", "a:b"] {
            assert_eq!(source(rel).unwrap(), cwd.join(rel).to_string_lossy());
        }
    }
}
