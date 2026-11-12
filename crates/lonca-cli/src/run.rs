//! `lonca run`: any agent, with no hooks, in a sandbox Lonca owns.
//!
//! The launcher runs as the human. It builds the sandbox, the human signs for
//! it (`session.isolate`), the daemon replaces the session's token, and only
//! the sandbox is given the new one: the level belongs to what runs inside.
//! When the command ends so does the session, so the level does not outlive
//! the sandbox.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use lonca_core::FileMode;
use lonca_core::ops::Op;
use lonca_daemon::Client;
use lonca_daemon::protocol::TreeFile;
use lonca_policy::config::{env_name_forbidden, valid_env_name};
use lonca_verify::Sandbox;
use lonca_verify::jail::{Jail, holding_secrets, mark_of, program_trees};
use serde_json::{Value, json};

use crate::ctx::{self, call};
use crate::mcp;
use crate::setup::{self, Prepared};
use crate::workspace::{Workspace, fetch};

/// What the command gets of the launcher's environment, besides `--env`.
const KEPT_ENV: [&str; 8] = [
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "USER", "LOGNAME", "TZ",
];

/// A `ps` that sees nothing: see [`write_shims`].
const PS_SHIM: &str = "#!/bin/sh\nexit 0\n";

/// How many paths `session.end` carries: what fits in a request.
const MAX_REPORTED: usize = 1000;

/// How long the command's output may lag behind its end. Something it left
/// running can hold the pipes open, so this is not waited for without end.
const DRAIN: Duration = Duration::from_secs(2);

/// How long the command has between SIGTERM and SIGKILL.
const GRACE: Duration = Duration::from_secs(5);

/// What `lonca run` was told.
pub struct Args {
    pub session: String,
    pub workspace: Option<PathBuf>,
    pub env: Vec<String>,
    pub read: Vec<PathBuf>,
    pub loopback: bool,
    pub human: Option<String>,
    pub command: Vec<OsString>,
}

/// The signal that asked the launcher to stop, or 0.
static STOP: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(n: libc::c_int) {
    STOP.store(n, Ordering::SeqCst);
}

/// `--env NAME` and `--env NAME=VALUE`, as pairs. Names that change what a
/// program loads are refused, as for verification, and so are Lonca's own.
pub fn env_pairs(
    specs: &[String],
    get: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for spec in specs {
        let (name, value) = match spec.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (spec.as_str(), None),
        };
        if !valid_env_name(name) || env_name_forbidden(name) || name.starts_with("LONCA_") {
            bail!("--env {name}: not a name the sandbox may be given");
        }
        let value = value
            .or_else(|| get(name))
            .with_context(|| format!("--env {name}: not set"))?;
        out.push((name.to_string(), value));
    }
    Ok(out)
}

/// An environment in which a name stands once, with the value set last.
#[derive(Default)]
struct Env(Vec<(String, String)>);

impl Env {
    fn set(&mut self, name: &str, value: String) {
        self.0.retain(|(k, _)| k != name);
        self.0.push((name.to_string(), value));
    }

    fn extend(&mut self, pairs: impl IntoIterator<Item = (String, String)>) {
        for (k, v) in pairs {
            self.set(&k, v);
        }
    }
}

/// Every variable programs look for a proxy in.
pub fn proxy_env(port: u16) -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{port}");
    let names = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ];
    let mut out: Vec<_> = names.map(|n| (n.to_string(), url.clone())).to_vec();
    // Node reads none of them unless it is told to.
    out.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    out
}

/// Where a program name leads: `PATH` is searched for a bare name.
pub fn find_program(name: &OsStr, path: &OsStr) -> Option<PathBuf> {
    let name = Path::new(name);
    if name.components().count() > 1 {
        return name.is_file().then(|| name.to_path_buf());
    }
    let dirs = std::env::split_paths(path);
    dirs.map(|d| d.join(name)).find(|p| p.is_file())
}

/// macOS will not start a setuid program in a sandbox, and programs that
/// walk their own process tree stop when `ps` can not be started. It can not
/// be let out either: outside the sandbox `ps` reads the environment of every
/// process of this user. So here it reports no process.
fn write_shims(dir: &Path) -> Result<()> {
    fs::create_dir(dir)?;
    let ps = dir.join("ps");
    fs::write(&ps, PS_SHIM)?;
    fs::set_permissions(&ps, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// `PATH` with `first` in front.
fn path_with(first: &[PathBuf], path: &OsStr) -> Result<String> {
    let dirs = first.iter().cloned().chain(std::env::split_paths(path));
    let joined = std::env::join_paths(dirs)?;
    joined
        .into_string()
        .map_err(|_| anyhow!("PATH is not text"))
}

/// The paths of `paths` that exist, as they really are.
fn real_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = paths
        .into_iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Copies from one stream to the other until either ends.
fn pump(mut from: impl io::Read, mut to: impl io::Write) {
    let _ = io::copy(&mut from, &mut to);
}

/// One connection through the relay, both ways.
fn splice<A, B>(a: A, b: B) -> Result<()>
where
    A: Duplex,
    B: Duplex,
{
    let (a2, b2) = (a.again()?, b.again()?);
    std::thread::spawn(move || pump(a2, b2));
    std::thread::spawn(move || pump(b, a));
    Ok(())
}

/// A stream that can be read on one thread and written on another.
trait Duplex: io::Read + io::Write + Send + Sized + 'static {
    fn again(&self) -> io::Result<Self>;
}

impl Duplex for TcpStream {
    fn again(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

impl Duplex for UnixStream {
    fn again(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

/// Outside the sandbox: each connection on the relay's socket goes to the
/// proxy. On Linux the agent has no network to reach the proxy by.
fn relay_out(listener: UnixListener, proxy: SocketAddr) {
    for client in listener.incoming().map_while(Result::ok) {
        if let Ok(upstream) = TcpStream::connect(proxy) {
            let _ = splice(client, upstream);
        }
    }
}

/// Inside the sandbox, where it is a program of its own: `port` on the
/// sandbox's loopback leads to `socket`, for as long as `argv` runs.
pub fn relay_in(port: u16, socket: &Path, argv: &[OsString]) -> Result<i32> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let socket = socket.to_path_buf();
    std::thread::spawn(move || {
        for client in listener.incoming().map_while(Result::ok) {
            if let Ok(upstream) = UnixStream::connect(&socket) {
                let _ = splice(client, upstream);
            }
        }
    });
    let (program, args) = argv.split_first().context("no command")?;
    let status = Command::new(program).args(args).status()?;
    Ok(exit_code(status))
}

/// The launcher's exit code for how the command ended.
pub fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or(status.signal().map(|s| 128 + s))
        .unwrap_or(1)
}

/// What is run in the sandbox: on Linux, behind the relay's loopback end.
fn inner_argv(jail: &Jail, command: &[OsString]) -> Result<Vec<OsString>> {
    let (Some(relay), Some(port)) = (&jail.relay, jail.proxy_port) else {
        return Ok(command.to_vec());
    };
    let mut argv: Vec<OsString> = vec![
        std::env::current_exe()?.into(),
        "__relay".into(),
        port.to_string().into(),
        relay.into(),
    ];
    argv.extend_from_slice(command);
    Ok(argv)
}

/// Starts `command` as the leader of a session of its own, with three pipes
/// and nothing else. Given the launcher's terminal, it could type into the
/// shell it came from or, from a process left running, read what the human
/// types next; other inherited descriptors would be ways out that no sandbox
/// rule sees.
fn spawn(mut command: Command) -> Result<Child> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    crate::sys::new_session_closing_from(&mut command, 3);
    Ok(command.spawn()?)
}

/// Carries the launcher's standard streams to and from the command. The
/// returned channels are closed when its output has ended.
fn carry_streams(child: &mut Child) -> Vec<Receiver<()>> {
    if let Some(mut to) = child.stdin.take() {
        std::thread::spawn(move || {
            let _ = io::copy(&mut io::stdin(), &mut to);
        });
    }
    let mut done = Vec::new();
    let mut carry = |from: Box<dyn io::Read + Send>, to: Box<dyn io::Write + Send>| {
        let (over, wait) = channel::<()>();
        std::thread::spawn(move || {
            let (mut from, mut to) = (from, to);
            let _ = io::copy(&mut from, &mut to);
            drop(over);
        });
        done.push(wait);
    };
    if let Some(out) = child.stdout.take() {
        carry(Box::new(out), Box::new(io::stdout()));
    }
    if let Some(err) = child.stderr.take() {
        carry(Box::new(err), Box::new(io::stderr()));
    }
    done
}

/// Waits for `child`, passing on a signal the launcher got. A setsid child
/// is out of reach of the terminal's Ctrl-C.
fn wait(child: &mut Child, stop: &AtomicI32, grace: Duration) -> Result<ExitStatus> {
    let group = child.id() as libc::pid_t;
    let mut stopping: Option<Instant> = None;
    // A short command is not kept waiting: looked at often first, then as
    // seldom as before.
    let mut pause = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let signal = stop.load(Ordering::SeqCst);
        match stopping {
            None if signal != 0 => {
                crate::sys::kill_group(group, libc::SIGTERM);
                stopping = Some(Instant::now());
            }
            Some(at) if at.elapsed() > grace => {
                crate::sys::kill_group(group, libc::SIGKILL);
            }
            _ => {}
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(50));
    }
}

/// Runs the session's heartbeat until the process ends: a command that
/// never heard of Lonca keeps its leases for as long as it runs.
fn keep_alive(token: &str) -> Result<()> {
    let mut c = ctx::connect()?;
    c.token = Some(token.to_string());
    std::thread::spawn(move || mcp::keep_alive(c, Default::default(), || None));
    Ok(())
}

/// Ends the session the command ran in. Its work stays in the workspace;
/// what was not proposed is on the record and told to the human.
fn finish(token: &str, root: &Path) -> Result<()> {
    let mut c = ctx::connect()?;
    c.token = Some(token.to_string());
    // Read again: the command may have synced. What it left there is only
    // counted, and a workspace that can not be read must not stop the end.
    let ws = Workspace::find(root);
    let files = ws.and_then(|ws| ws.local_files().ok()).map(|mut files| {
        files.truncate(MAX_REPORTED);
        files
    });
    let r = match call(&mut c, "session.end", json!({ "files": files })) {
        Ok(r) => r,
        // The agent ended it first.
        Err(e) if mcp::session_over(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let total = r["unproposed_total"].as_u64().unwrap_or(0);
    if total > 0 {
        errln!("lonca run: left unproposed: {total} file(s) never reached the repository");
    }
    Ok(())
}

/// What the sandbox is made of: everything that decides what it allows is
/// from the log or from the human, never from a file in the workspace.
struct Plan {
    sandbox: Sandbox,
    jail: Jail,
    env: Vec<(String, String)>,
    proxy: Option<SocketAddr>,
}

fn plan(
    sandbox: Sandbox,
    a: &Args,
    workspace: &Path,
    run: &Path,
    prepared: &Value,
    setup: Option<&Prepared>,
    token_file: &Path,
) -> Result<Plan> {
    let real = |p: &Path| p.canonicalize().with_context(|| format!("{}", p.display()));
    let workspace = real(workspace)?;
    let daemon_home = prepared["home"].as_str().map(PathBuf::from);
    let secrets = real_paths(
        [ctx::lonca_home(), ctx::humans_dir()]
            .into_iter()
            .chain(daemon_home),
    );
    if let Some(s) = holding_secrets(&workspace, &secrets) {
        bail!("the workspace overlaps {}, which stays closed", s.display());
    }
    let home = ctx::home_dir();
    let home = home.canonicalize().unwrap_or(home);

    let mut writable = Vec::new();
    for root in scratch_roots(prepared)? {
        fs::create_dir_all(&root).with_context(|| format!("{}", root.display()))?;
        refuse_scratch(&root, &real(&root)?, &secrets, &home)?;
        writable.push(root);
    }
    for dir in ["home", "tmp"] {
        let dir = run.join(dir);
        fs::create_dir(&dir)?;
        writable.push(real(&dir)?);
    }
    let shims = run.join("bin");
    if sandbox == Sandbox::Seatbelt {
        write_shims(&shims)?;
    }

    let path = std::env::var_os("PATH").unwrap_or_default();
    let program = find_program(&a.command[0], &path)
        .with_context(|| format!("{}: not found", a.command[0].to_string_lossy()))?;
    let closed: Vec<PathBuf> = secrets.iter().cloned().chain([home.clone()]).collect();
    let lonca = std::env::current_exe()?;
    let lonca_dir = lonca.parent().context("no directory")?.to_path_buf();
    let programs = [program, lonca];
    let trees: Vec<PathBuf> = writable
        .iter()
        .cloned()
        .chain([workspace.clone()])
        .collect();
    let mut readable = program_trees(&path, &programs, &closed, &trees);
    readable.push(real(token_file)?);
    if sandbox == Sandbox::Seatbelt {
        readable.push(real(&shims)?);
    }
    for p in &a.read {
        let p = real(&ctx::absolute(p)?)?;
        if let Some(s) = holding_secrets(&p, &secrets) {
            bail!(
                "--read {} overlaps {}, which stays closed",
                p.display(),
                s.display()
            );
        }
        readable.push(p);
    }

    let proxy = match prepared["proxy"].as_str() {
        Some(addr) => Some(addr.parse::<SocketAddr>().context("the daemon's proxy")?),
        None => None,
    };
    let relay = (sandbox == Sandbox::Bubblewrap && proxy.is_some()).then(|| run.join("net"));
    if let Some(relay) = &relay {
        fs::write(relay, b"")?;
    }

    let run_home = writable[writable.len() - 2].clone();
    let tmp = writable[writable.len() - 1].clone();
    let text = |p: &Path| p.to_string_lossy().into_owned();
    // Later sets win: the harness's profile, then the person's `--env`, then
    // what the run itself must hold.
    let mut env = Env::default();
    for n in KEPT_ENV {
        if let Ok(v) = std::env::var(n) {
            env.set(n, v);
        }
    }
    if let Some(setup) = setup {
        env.extend(setup.run_env(&text(&run_home), &text(&tmp))?);
    }
    env.extend(env_pairs(&a.env, |n| std::env::var(n).ok())?);
    let mut first = vec![lonca_dir];
    if sandbox == Sandbox::Seatbelt {
        first.insert(0, real(&shims)?);
    }
    env.set("PATH", path_with(&first, &path)?);
    env.extend([
        ("HOME".to_string(), text(&run_home)),
        ("TMPDIR".to_string(), text(&tmp)),
        ("LONCA_WORKSPACE".to_string(), text(&workspace)),
        ("LONCA_SOCKET".to_string(), text(&ctx::socket())),
        ("LONCA_TOKEN_FILE".to_string(), text(token_file)),
    ]);
    env.extend(proxy.iter().flat_map(|p| proxy_env(p.port())));
    let env = env.0;

    let socket = ctx::socket();
    let jail = Jail {
        workspace,
        writable,
        readable,
        secrets,
        socket: Some(socket.canonicalize().unwrap_or(socket)),
        proxy_port: proxy.map(|p| p.port()),
        relay,
        loopback: a.loopback,
        mark: mark_of(sandbox, "run", run),
        // The sandbox a human signed: its `/tmp` and `/dev` stay as they were.
        tmp: None,
        shm: None,
    };
    Ok(Plan {
        sandbox,
        jail,
        env,
        proxy,
    })
}

/// Fails before anything is signed if the operating system will not run the
/// sandbox as it was written.
fn probe(p: &Plan) -> Result<()> {
    let argv: [OsString; 3] = ["/bin/sh".into(), "-c".into(), ":".into()];
    let mut c = p.jail.command(p.sandbox, &argv).context("no sandbox")?;
    let out = c.env_clear().output()?;
    if !out.status.success() {
        bail!(
            "the sandbox did not start: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The scratch roots the daemon named.
fn scratch_roots(prepared: &Value) -> Result<Vec<PathBuf>> {
    let roots = prepared["scratch"].as_array().into_iter().flatten();
    let root = |r: &Value| {
        let text = r.as_str().context("a scratch root is not text")?;
        Ok(PathBuf::from(text))
    };
    roots.map(root).collect()
}

/// A scratch root opens for writing, so it must be what the log says, as it
/// really was when the session started: a link put in its place would make
/// the sandbox write through it.
fn refuse_scratch(root: &Path, real: &Path, secrets: &[PathBuf], home: &Path) -> Result<()> {
    if real != root {
        bail!("scratch root {} has been replaced", root.display());
    }
    if let Some(s) = holding_secrets(root, secrets) {
        bail!("scratch root {} overlaps {}", root.display(), s.display());
    }
    if home.starts_with(root) {
        bail!("scratch root {} holds the home directory", root.display());
    }
    Ok(())
}

/// Refuses a workspace that is not the commit it says it stands on, as the
/// daemon has that commit: what is in there would pass for the sandbox's work
/// without having been made in it. Nothing the workspace says about itself
/// counts, and a scratch root must be empty for the same reason. Returns the
/// commit's files.
fn refuse_outside_work(ws: &Workspace, c: &mut Client, prepared: &Value) -> Result<Vec<TreeFile>> {
    if prepared["base_known"] != true {
        bail!("the workspace stands on a commit that was never trunk");
    }
    let files = fetch(c, &ws.meta.base, None)?;
    let tree = files.iter().filter(|f| f.mode != FileMode::Submodule);
    let tree = tree.map(|f| (f.path.clone(), f.blob.clone())).collect();
    let differs = ws.differs_from(&tree)?;
    if let Some(first) = differs.first() {
        bail!(
            "{} file(s) differ from the commit the workspace was made from, {first} among them: \
             a run needs a new session in a new workspace",
            differs.len(),
        );
    }
    for root in scratch_roots(prepared)? {
        // One that is not there yet is empty. One that can not be read is
        // not known to be, and the command may open it again.
        let empty = match fs::read_dir(&root) {
            Ok(mut entries) => entries.next().is_none(),
            Err(e) => e.kind() == io::ErrorKind::NotFound,
        };
        if !empty {
            bail!("scratch root {} is not empty", root.display());
        }
    }
    Ok(files)
}

/// What a run starts from, once the daemon has said it may run.
struct Start<'a> {
    ws: &'a mut Workspace,
    files: &'a [TreeFile],
    setup: Option<&'a Prepared>,
}

/// From the moment the session is isolated: nothing here may skip its end.
fn in_sandbox(plan: &Plan, a: &Args, start: Start, token: &str) -> Result<ExitStatus> {
    start.ws.start_clean(start.files)?;
    if let Some(setup) = start.setup {
        setup.write_over(start.ws)?;
    }
    if let (Some(relay), Some(proxy)) = (&plan.jail.relay, plan.proxy) {
        fs::remove_file(relay)?;
        let listener = UnixListener::bind(relay)?;
        // What the sandbox sends out connects to the proxy from this
        // process, the one the daemon knows the session by: it asked for
        // the isolation.
        std::thread::spawn(move || relay_out(listener, proxy));
    }
    keep_alive(token)?;
    let argv = inner_argv(&plan.jail, &a.command)?;
    let mut command = plan
        .jail
        .command(plan.sandbox, &argv)
        .context("no sandbox")?;
    command
        .env_clear()
        .envs(plan.env.iter().map(|(k, v)| (k, v)));
    let mut child = spawn(command)?;
    let output = carry_streams(&mut child);
    let status = wait(&mut child, &STOP, GRACE);
    // Before the session ends: nothing of the sandbox writes here after it.
    let left = plan
        .jail
        .mark
        .as_deref()
        .map(lonca_verify::sweep::end_what_is_left);
    if let Some(left @ 1..) = left {
        errln!("lonca run: {left} process(es) of the sandbox would not end");
    }
    drain(output, DRAIN);
    status
}

/// Waits until the output has ended, or for `within`: something the command
/// left running can hold the pipes open.
fn drain(output: Vec<Receiver<()>>, within: Duration) {
    let deadline = Instant::now() + within;
    for over in output {
        let left = deadline.saturating_duration_since(Instant::now());
        let _ = over.recv_timeout(left);
    }
}

/// `lonca run`. The exit code is the command's.
pub fn run(a: Args) -> Result<i32> {
    // From the start: a signal between the isolation and the command must
    // reach the command, not end the launcher with the session still alive.
    // The handler only stores to an atomic.
    crate::sys::on_signals(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP], on_signal);
    let sandbox = Sandbox::detect();
    if sandbox == Sandbox::None {
        bail!("no sandbox on this machine (macOS: sandbox-exec; Linux: install bubblewrap)");
    }
    let dir = match &a.workspace {
        Some(d) => ctx::absolute(d)?,
        None => std::env::current_dir()?,
    };
    let mut ws = Workspace::find(&dir)
        .filter(|ws| ws.root == dir)
        .with_context(|| format!("{} is not a Lonca workspace", dir.display()))?;
    if ws.meta.session.as_deref() != Some(a.session.as_str()) {
        bail!(
            "{} is not the workspace of session {}",
            dir.display(),
            a.session
        );
    }
    let repo = ws.meta.repo.clone();
    let human = match &a.human {
        Some(h) => h.clone(),
        None => ctx::default_human()?,
    };
    let mut c: Client = ctx::human_client(Some(&repo), &human)?;
    let prepared = call(
        &mut c,
        "human.prepare_isolate",
        json!({"session": a.session, "base": ws.meta.base}),
    )?;
    // The log's word, not the workspace's: only the named harness's files
    // may stand, and then only as its setup writes them.
    ws.meta.scratch_roots = serde_json::from_value(prepared["scratch"].clone())?;
    let setup = setup::of_session(&ws, &prepared)?;
    let of_setup = |p: &String| setup.as_ref().is_some_and(|s| s.writes(p));
    ws.meta.generated.retain(of_setup);
    let files = refuse_outside_work(&ws, &mut c, &prepared)?;

    let run_dir = tempfile::Builder::new().prefix("lonca-run-").tempdir()?;
    fs::set_permissions(run_dir.path(), fs::Permissions::from_mode(0o700))?;
    let token_file = run_dir.path().join("token");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&token_file)?;
    let plan = plan(
        sandbox,
        &a,
        &ws.root,
        run_dir.path(),
        &prepared,
        setup.as_ref(),
        &token_file,
    )?;
    probe(&plan)?;

    let op = Op::SessionIsolate {
        session: a.session.clone(),
        sandbox: plan.jail.name(sandbox),
        profile: plan.jail.digest(sandbox).context("no sandbox")?,
    };
    let sig = ctx::sign(&mut c, &human, &repo, &op)?;
    let r = call(
        &mut c,
        "human.submit",
        json!({"op": op, "sig": sig, "workspace": plan.jail.workspace}),
    )?;
    ctx::denied(&r)?;
    let token = r["token"]
        .as_str()
        .ok_or_else(|| anyhow!("the session was not isolated: {}", r["decision"]["outcome"]))?;
    fs::write(&token_file, token)?;

    let start = Start {
        ws: &mut ws,
        files: &files,
        setup: setup.as_ref(),
    };
    let status = in_sandbox(&plan, &a, start, token);
    // Whatever became of the command, the session does not go on without it.
    let ended = finish(token, &ws.root);
    let status = status?;
    if let Err(e) = ended {
        errln!("lonca run: the session was not ended: {e:#}");
    }
    Ok(exit_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(specs: &[&str]) -> Result<Vec<(String, String)>> {
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        env_pairs(&specs, |n| (n == "SET").then(|| "from-launcher".into()))
    }

    #[test]
    fn env_is_passed_by_name_or_given_a_value() {
        let got = pairs(&["SET", "OTHER=a=b", "EMPTY="]).unwrap();
        let want = [("SET", "from-launcher"), ("OTHER", "a=b"), ("EMPTY", "")];
        assert_eq!(got, want.map(|(k, v)| (k.to_string(), v.to_string())));
        let e = pairs(&["UNSET"]).unwrap_err().to_string();
        assert!(e.contains("not set"), "{e}");
    }

    #[test]
    fn env_can_not_reach_what_loads_a_program_or_lonca_itself() {
        for name in [
            "PATH=/x",
            "DYLD_INSERT_LIBRARIES=/x",
            "LONCA_SOCKET=/x",
            "A B=1",
            "=x",
        ] {
            let e = pairs(&[name]).unwrap_err().to_string();
            assert!(e.contains("not a name"), "{name}: {e}");
        }
    }

    #[test]
    fn every_way_of_asking_for_a_proxy_leads_to_it() {
        let env = proxy_env(8080);
        assert_eq!(env.len(), 7);
        for (name, value) in &env[..6] {
            assert_eq!(value, "http://127.0.0.1:8080", "{name}");
        }
        let names: Vec<_> = env.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"HTTPS_PROXY") && names.contains(&"http_proxy"));
        assert_eq!(env[6], ("NODE_USE_ENV_PROXY".into(), "1".into()));
    }

    #[test]
    fn a_program_is_found_as_a_shell_would() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::write(b.join("tool"), "").unwrap();
        let path = std::env::join_paths([&a, &b]).unwrap();
        let tool = b.join("tool");
        assert_eq!(find_program(OsStr::new("tool"), &path), Some(tool.clone()));
        assert_eq!(find_program(OsStr::new("gone"), &path), None);
        assert_eq!(find_program(tool.as_os_str(), &path), Some(tool.clone()));
        let missing = a.join("tool");
        assert_eq!(find_program(missing.as_os_str(), &path), None);
        // A relative path is not looked for on `PATH`.
        let here = OsStr::new("src/run.rs");
        assert!(find_program(here, &path).is_some());
        // A directory of that name is not a program.
        fs::create_dir(a.join("tool")).unwrap();
        assert_eq!(find_program(OsStr::new("tool"), &path), Some(tool));
    }

    #[test]
    fn real_paths_are_resolved_unique_and_leave_out_what_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (a, link) = (root.join("a"), root.join("link"));
        fs::create_dir(&a).unwrap();
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert_eq!(real_paths([a.clone(), link, root.join("gone")]), [a]);
    }

    #[test]
    fn an_exit_code_says_how_the_command_ended() {
        let plain = ExitStatus::from_raw(7 << 8);
        assert_eq!(exit_code(plain), 7);
        let killed = ExitStatus::from_raw(libc::SIGKILL);
        assert_eq!(exit_code(killed), 128 + libc::SIGKILL);
    }

    #[test]
    fn with_no_relay_the_command_runs_as_it_is() {
        let command: Vec<OsString> = vec!["agent".into()];
        let jail = Jail {
            proxy_port: Some(1),
            ..Default::default()
        };
        assert_eq!(inner_argv(&jail, &command).unwrap(), command);
        let jail = Jail {
            proxy_port: Some(1),
            relay: Some("/run/net".into()),
            ..Default::default()
        };
        let argv = inner_argv(&jail, &command).unwrap();
        let tail: Vec<OsString> = vec![
            "__relay".into(),
            "1".into(),
            "/run/net".into(),
            "agent".into(),
        ];
        assert_eq!(argv[1..], tail);
    }

    #[test]
    fn the_shims_come_first_and_are_programs() {
        let dir = tempfile::tempdir().unwrap();
        let shims = dir.path().join("bin");
        write_shims(&shims).unwrap();
        let ps = shims.join("ps");
        let out = Command::new(&ps).arg("-axeww").output().unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(out.stdout.is_empty(), "{out:?}");
        let path = path_with(std::slice::from_ref(&shims), OsStr::new("/usr/bin:/bin")).unwrap();
        assert_eq!(path, format!("{}:/usr/bin:/bin", shims.display()));
    }

    /// A sandbox planned on any machine: planning runs nothing.
    struct Planned {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Planned {
        fn new() -> Planned {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            for d in ["ws", "run", "daemon"] {
                fs::create_dir(root.join(d)).unwrap();
            }
            fs::write(root.join("run/token"), "").unwrap();
            Planned { _dir: dir, root }
        }

        fn args(&self) -> Args {
            Args {
                session: "s".into(),
                workspace: None,
                env: vec![],
                read: vec![],
                loopback: false,
                human: None,
                command: vec!["/bin/sh".into()],
            }
        }

        fn prepared(&self, proxy: Option<&str>) -> Value {
            json!({"scratch": [], "proxy": proxy, "home": self.root.join("daemon")})
        }

        fn plan(&self, sandbox: Sandbox, a: &Args, prepared: &Value) -> Result<Plan> {
            self.plan_for(sandbox, a, prepared, None)
        }

        fn plan_for(
            &self,
            sandbox: Sandbox,
            a: &Args,
            prepared: &Value,
            setup: Option<&Prepared>,
        ) -> Result<Plan> {
            let (ws, run) = (self.root.join("ws"), self.root.join("run"));
            plan(sandbox, a, &ws, &run, prepared, setup, &run.join("token"))
        }
    }

    fn env_of<'a>(p: &'a Plan, name: &str) -> Vec<&'a str> {
        let hits = p.env.iter().filter(|(k, _)| k == name);
        hits.map(|(_, v)| v.as_str()).collect()
    }

    /// Seatbelt alone needs telling its processes from others', and the
    /// mark must be this run's.
    #[test]
    fn a_plan_marks_a_seatbelt_sandbox_with_the_run_s_own_name() {
        let t = Planned::new();
        let p = t
            .plan(Sandbox::Seatbelt, &t.args(), &t.prepared(None))
            .unwrap();
        assert_eq!(p.jail.mark.as_deref(), Some("lonca.run.run"));
        let t = Planned::new();
        let p = t
            .plan(Sandbox::Bubblewrap, &t.args(), &t.prepared(None))
            .unwrap();
        assert_eq!(p.jail.mark, None);
    }

    /// The profile's environment comes in under the person's `--env`, and
    /// neither moves what the run holds itself.
    #[test]
    fn a_plan_starts_the_harness_with_its_profile_s_environment() {
        let t = Planned::new();
        let claude = lonca_policy::harness::built_in()["claude-code"]
            .setup
            .clone();
        let setup = Prepared::of_setup("claude-code", claude, "/w");
        let prepared = t.prepared(None);
        let p = t
            .plan_for(Sandbox::Seatbelt, &t.args(), &prepared, Some(&setup))
            .unwrap();
        let tmp = t.root.join("run/tmp");
        assert_eq!(env_of(&p, "CLAUDE_CODE_TMPDIR"), [tmp.to_str().unwrap()]);

        let mut extra = lonca_policy::harness::Setup::default();
        extra.env.insert("SHARED".into(), "profile".into());
        extra.env.insert("KEPT".into(), "profile".into());
        extra.run_env.insert("HOME".into(), "/elsewhere".into());
        let setup = Prepared::of_setup("acme", extra, "/w");
        let mut a = t.args();
        a.env = vec!["SHARED=person".into()];
        let t = Planned::new();
        let p = t
            .plan_for(Sandbox::Seatbelt, &a, &prepared, Some(&setup))
            .unwrap();
        assert_eq!(env_of(&p, "SHARED"), ["person"]);
        assert_eq!(env_of(&p, "KEPT"), ["profile"]);
        let home = t.root.join("run/home");
        assert_eq!(env_of(&p, "HOME"), [home.to_str().unwrap()]);
    }

    #[test]
    fn a_plan_gives_the_command_a_home_and_a_temp_of_its_own() {
        let t = Planned::new();
        let p = t
            .plan(Sandbox::Seatbelt, &t.args(), &t.prepared(None))
            .unwrap();
        let run = t.root.join("run");
        assert_eq!(env_of(&p, "HOME"), [run.join("home").to_str().unwrap()]);
        assert_eq!(env_of(&p, "TMPDIR"), [run.join("tmp").to_str().unwrap()]);
        assert_eq!(p.jail.workspace, t.root.join("ws"));
        assert_eq!(p.jail.writable, [run.join("home"), run.join("tmp")]);
        assert!(p.jail.secrets.contains(&t.root.join("daemon")));
        assert!(p.jail.readable.contains(&run.join("token")));
        let token = run.join("token");
        assert_eq!(env_of(&p, "LONCA_TOKEN_FILE"), [token.to_str().unwrap()]);
        assert_eq!(p.proxy, None);
        assert_eq!(p.jail.proxy_port, None);
        assert!(env_of(&p, "HTTPS_PROXY").is_empty());
    }

    #[test]
    fn on_macos_the_shims_come_first_and_lonca_next() {
        let t = Planned::new();
        let p = t
            .plan(Sandbox::Seatbelt, &t.args(), &t.prepared(None))
            .unwrap();
        let shims = t.root.join("run/bin");
        assert!(shims.join("ps").is_file());
        assert!(p.jail.readable.contains(&shims));
        let path = env_of(&p, "PATH");
        assert_eq!(path.len(), 1, "{path:?}");
        let mut dirs = std::env::split_paths(path[0]);
        assert_eq!(dirs.next().unwrap(), shims);
        let exe = std::env::current_exe().unwrap();
        assert_eq!(dirs.next().as_deref(), exe.parent());
    }

    #[test]
    fn on_linux_there_are_no_shims_and_the_proxy_comes_by_the_relay() {
        let t = Planned::new();
        let prepared = t.prepared(Some("127.0.0.1:8080"));
        let p = t.plan(Sandbox::Bubblewrap, &t.args(), &prepared).unwrap();
        assert!(!t.root.join("run/bin").exists());
        let relay = t.root.join("run/net");
        assert_eq!(p.jail.relay.as_ref(), Some(&relay));
        assert!(relay.is_file());
        assert_eq!(p.jail.proxy_port, Some(8080));
        assert_eq!(env_of(&p, "HTTPS_PROXY"), ["http://127.0.0.1:8080"]);
        let path = env_of(&p, "PATH");
        let exe = std::env::current_exe().unwrap();
        let first = std::env::split_paths(path[0]).next().unwrap();
        assert_eq!(Some(first.as_path()), exe.parent());

        let t = Planned::new();
        let p = t
            .plan(Sandbox::Bubblewrap, &t.args(), &t.prepared(None))
            .unwrap();
        assert_eq!(p.jail.relay, None, "no proxy, nothing to relay");
        let t = Planned::new();
        let p = t.plan(Sandbox::Seatbelt, &t.args(), &prepared).unwrap();
        assert_eq!(p.jail.relay, None, "the profile opens the proxy's port");
    }

    #[test]
    fn a_plan_opens_nothing_it_was_not_told_to_and_stays_off_the_secrets() {
        let t = Planned::new();
        let mut a = t.args();
        a.loopback = true;
        a.env = vec!["NAME=value".into()];
        let extra = t.root.join("extra");
        fs::create_dir(&extra).unwrap();
        a.read = vec![extra.clone()];
        let p = t.plan(Sandbox::Seatbelt, &a, &t.prepared(None)).unwrap();
        assert!(p.jail.loopback);
        assert!(p.jail.readable.contains(&extra));
        assert_eq!(env_of(&p, "NAME"), ["value"]);

        let t = Planned::new();
        let mut a = t.args();
        a.read = vec![t.root.join("daemon")];
        let e = t
            .plan(Sandbox::Seatbelt, &a, &t.prepared(None))
            .err()
            .unwrap();
        assert!(e.to_string().contains("stays closed"), "{e}");
        let t = Planned::new();
        let mut a = t.args();
        a.command = vec!["no-such-program-here".into()];
        let e = t
            .plan(Sandbox::Seatbelt, &a, &t.prepared(None))
            .err()
            .unwrap();
        assert!(e.to_string().contains("not found"), "{e}");

        let t = Planned::new();
        let inside = json!({"scratch": [], "home": t.root.join("ws")});
        let e = t.plan(Sandbox::Seatbelt, &t.args(), &inside).err().unwrap();
        assert!(e.to_string().contains("the workspace overlaps"), "{e}");
    }

    #[test]
    fn a_plan_builds_on_the_scratch_roots_of_the_log() {
        let t = Planned::new();
        let scratch = t.root.join("scratch");
        let prepared = json!({"scratch": [scratch], "home": t.root.join("daemon")});
        assert_eq!(
            scratch_roots(&prepared).unwrap(),
            std::slice::from_ref(&scratch)
        );
        let p = t.plan(Sandbox::Seatbelt, &t.args(), &prepared).unwrap();
        assert!(p.jail.writable.contains(&scratch), "it is made if missing");
        assert!(scratch_roots(&json!({"scratch": [1]})).is_err());
    }

    #[test]
    fn a_scratch_root_stays_off_what_is_closed() {
        let secrets = [PathBuf::from("/h/.lonca")];
        let refuse = |root: &str, real: &str, home: &str| {
            let (root, real, home) = (Path::new(root), Path::new(real), Path::new(home));
            refuse_scratch(root, real, &secrets, home).map_err(|e| e.to_string())
        };
        assert!(refuse("/w/s", "/w/s", "/h").is_ok());
        assert!(refuse("/h/s", "/h/s", "/h").is_ok());
        let e = refuse("/w/s", "/h", "/h").unwrap_err();
        assert!(e.contains("has been replaced"), "{e}");
        let e = refuse("/h/.lonca/s", "/h/.lonca/s", "/h").unwrap_err();
        assert!(e.contains("overlaps"), "{e}");
        let e = refuse("/h", "/h", "/h").unwrap_err();
        assert!(e.contains("overlaps"), "{e}");
        let e = refuse("/u", "/u", "/u/me").unwrap_err();
        assert!(e.contains("holds the home directory"), "{e}");
    }

    #[test]
    fn a_stop_reaches_the_commands_whole_group() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > {}; wait", file.display());
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &script]).stdin(Stdio::null());
        let mut child = spawn(c).unwrap();
        while fs::read_to_string(&file).map_or(true, |t| !t.ends_with('\n')) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let helper: libc::pid_t = fs::read_to_string(&file).unwrap().trim().parse().unwrap();
        let stop = AtomicI32::new(libc::SIGTERM);
        let status = wait(&mut child, &stop, Duration::from_secs(20)).unwrap();
        assert_eq!(exit_code(status), 128 + libc::SIGTERM);
        let alive = || crate::sys::alive(helper);
        for _ in 0..200 {
            if !alive() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the group outlived the stop");
    }

    #[test]
    fn a_group_that_will_not_stop_is_killed_after_its_grace() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pid");
        // The helper inherits the ignored signal, so only SIGKILL ends it,
        // and it only gets that as a member of the group.
        let script = format!(
            "trap '' TERM; sleep 30 & echo $! > {}; while :; do sleep 1; done",
            file.display()
        );
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &script]).stdin(Stdio::null());
        let mut child = spawn(c).unwrap();
        while fs::read_to_string(&file).map_or(true, |t| !t.ends_with('\n')) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let helper: libc::pid_t = fs::read_to_string(&file).unwrap().trim().parse().unwrap();
        let stop = AtomicI32::new(libc::SIGTERM);
        let started = Instant::now();
        let status = wait(&mut child, &stop, Duration::from_millis(300)).unwrap();
        assert_eq!(exit_code(status), 128 + libc::SIGKILL);
        assert!(started.elapsed() >= Duration::from_millis(300));
        for _ in 0..200 {
            if !crate::sys::alive(helper) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("a member of the group outlived SIGKILL");
    }

    #[test]
    fn with_no_stop_a_command_ends_by_itself() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "sleep 0.2; exit 4"]).stdin(Stdio::null());
        let mut child = spawn(c).unwrap();
        let stop = AtomicI32::new(0);
        let status = wait(&mut child, &stop, Duration::ZERO).unwrap();
        assert_eq!(exit_code(status), 4);
    }

    #[test]
    fn a_command_gets_pipes_and_its_own_session() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "exec sleep 0"]);
        let mut child = spawn(c).unwrap();
        let (leader, id) = (
            crate::sys::session_of(child.id() as i32),
            crate::sys::session_of(0),
        );
        assert_ne!(leader, id);
        assert!(child.stdin.is_some() && child.stdout.is_some() && child.stderr.is_some());
        assert_eq!(carry_streams(&mut child).len(), 2);
        child.wait().unwrap();
    }

    #[test]
    fn the_output_is_waited_for_but_not_for_ever() {
        let (over, wait_for) = channel::<()>();
        let (slow, left) = (Duration::from_millis(100), Duration::from_secs(20));
        std::thread::spawn(move || {
            std::thread::sleep(slow);
            drop(over);
        });
        let started = Instant::now();
        drain(vec![wait_for], left);
        assert!(started.elapsed() >= slow);
        assert!(started.elapsed() < left);

        let (held, wait_for) = channel::<()>();
        let started = Instant::now();
        drain(vec![wait_for], Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
    }

    #[test]
    fn a_probe_fails_when_the_sandbox_can_not_start() {
        let t = Planned::new();
        let mut p = t
            .plan(Sandbox::Seatbelt, &t.args(), &t.prepared(None))
            .unwrap();
        p.sandbox = Sandbox::None;
        let e = probe(&p).unwrap_err().to_string();
        assert!(e.contains("no sandbox"), "{e}");
        let sandbox = Sandbox::detect();
        if sandbox == Sandbox::None {
            return;
        }
        let t = Planned::new();
        let mut p = t.plan(sandbox, &t.args(), &t.prepared(None)).unwrap();
        // No daemon here: bubblewrap would refuse to mount a missing socket.
        p.jail.socket = Some(t.root.join("run/token"));
        assert!(probe(&p).is_ok());
        p.jail.workspace = t.root.join("gone");
        assert!(probe(&p).is_err());
    }

    #[test]
    fn the_relay_gives_back_the_commands_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let free = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let argv: [OsString; 3] = ["/bin/sh".into(), "-c".into(), "exit 3".into()];
        let code = relay_in(port, &dir.path().join("s"), &argv).unwrap();
        assert_eq!(code, 3);
    }

    #[test]
    fn the_relay_carries_bytes_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("r");
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = upstream.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = upstream.accept().unwrap();
            let mut byte = [0];
            s.read_exact(&mut byte).unwrap();
            s.write_all(&[byte[0] + 1]).unwrap();
        });
        let listener = UnixListener::bind(&socket).unwrap();
        std::thread::spawn(move || relay_out(listener, proxy));
        use std::io::{Read, Write};
        let mut c = UnixStream::connect(&socket).unwrap();
        c.write_all(&[41]).unwrap();
        let mut byte = [0];
        c.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [42]);
    }
}
