# lonca-client

A client of the [Lonca](https://selcukgural.github.io/lonca/) daemon
socket, for harnesses and runners: what a program that starts agents on
Lonca, or speaks to the daemon for them, depends on.

Only what a client needs: the protocol's request and response types and
its number (`PROTOCOL`), the socket client with the checks that make sure
the daemon is on the other end (`trust`), framing, timeouts and typed
errors (`client`), and the human session file (`session`). No store, no
policy evaluation, no daemon: a client is never a second writer.

```rust,no_run
use std::path::Path;
use std::time::Duration;

use lonca_client::{Client, PROTOCOL};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // $LONCA_SOCKET, else $LONCA_HOME/lonca.sock, else ~/.lonca/lonca.sock.
    let home = std::env::var("HOME")?;
    let socket = Path::new(&home).join(".lonca/lonca.sock");

    // Checks that the daemon this machine trusts is on the other end
    // before anything is sent: a token goes nowhere unverified.
    let mut client = Client::connect(&socket)?;
    client.set_timeout(Some(Duration::from_secs(30)))?;

    let ping = client.call("ping", json!({}))?;
    if ping["protocol"] != PROTOCOL {
        return Err("a daemon of another protocol".into());
    }

    // An agent's token, from the workspace `lonca session start` made.
    let token = std::fs::read_to_string("/work/claude-1/.lonca/session")?;
    client.token = Some(token.trim().to_owned());
    client.repo = Some("demo".into());
    let status = client.call("status", json!({}))?;
    println!("{status:#}");
    Ok(())
}
```

A runner wakes an idle agent when something happens to its session,
with the human session it started the agents with and one open request
(`events.watch`). It gets the kind of news, never another agent's words,
and takes nothing from the agent's own inbox:

```rust,no_run
# use std::path::Path;
# use lonca_client::Client;
use lonca_client::protocol::Watch;
use lonca_client::session::{humans_dir, read_session, session_path};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let socket = Path::new("/home/me/.lonca/lonca.sock");
let mut client = Client::connect(socket)?;
// The session `lonca human login --as ayse` left.
let file = session_path(&humans_dir().ok_or("no humans dir")?, "ayse")?;
let human = read_session(&file)?.ok_or("log in first")?;
client.token = Some(human.token);
client.repo = Some("demo".into());

let mut watch = Watch {
    wait_ms: Some(30_000),
    ..Watch::default()
};
loop {
    let got = client.watch(&watch)?;
    for event in &got.events {
        // Resume the agent of `event.session`: it reads its inbox itself.
        println!("wake {} for {}", event.session, event.kind);
    }
    watch = watch.after(&got);
}
# }
```

Every method, its credential and its shapes are in
[the daemon protocol](https://selcukgural.github.io/lonca/docs/protocol);
running agents on Lonca is in
[the runners guide](https://selcukgural.github.io/lonca/docs/guide/runners).

Versions: a change of `PROTOCOL` is a major version of this crate (while
it is 0.x, a minor one). Fields added to a shape are not a change of the
number. Pin an exact version and read the
[release notes](https://selcukgural.github.io/lonca/docs/release-notes)
when you move. The version is the workspace's: every Lonca crate has the
same one.

- Repository: <https://github.com/selcukgural/lonca>
- Licence: Apache-2.0 ([LICENSE](https://github.com/selcukgural/lonca/blob/main/LICENSE))
