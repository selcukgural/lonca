# lonca-net

A small network proxy for sandboxed commands, from
[Lonca](https://selcukgural.github.io/lonca/) and usable on its own.

A sandbox lets commands reach only this proxy, on loopback. Every
connection (`CONNECT host:port` or an absolute `http://` request) is put
to a `Gate`, which decides whether it goes through. Loopback, private and
link-local destinations are refused unless the gate allows them, and the
proxy connects to the address it checked, so DNS cannot swap in a private
address after the check. That address may serve other names too, so a
connection is held to the host it was asked for: a tunnel whose TLS client
asks for another server name is cut before a byte of it gets there, and a
plain request has to name its host in `Host` and is the only one on its
connection. The proxy never looks inside TLS itself; a gate may serve a
tunnel it let through (`Gate::relay`).

It has no dependencies and knows nothing about who uses it: the gate
holds all the policy.

```rust
use std::sync::Arc;

use lonca_net::{Gate, Request, Verdict};

/// Lets a build fetch crates and nothing else.
struct CratesOnly;

impl Gate for CratesOnly {
    fn decide(&self, request: &Request<'_>) -> Verdict {
        match (request.host, request.port) {
            ("index.crates.io" | "static.crates.io", 443) => Verdict::allow(),
            _ => Verdict::deny("only crates.io"),
        }
    }
}

fn main() -> std::io::Result<()> {
    // Loopback only: `bind` refuses any other address.
    let listener = lonca_net::bind("127.0.0.1:0")?;
    let server = lonca_net::spawn(listener, Arc::new(CratesOnly))?;

    // The sandboxed command gets HTTPS_PROXY=http://<this address>.
    println!("proxy on {}", server.local_addr());

    // Closes the listener and cuts every open connection.
    server.stop();
    Ok(())
}
```

`Gate::finished`, `Gate::carried` and `Gate::relay` are told how each
connection ended, see every byte relayed (and may cut it when a budget is
spent), and may serve a tunnel themselves.

A client is not waited for: a request head has 10 seconds in all, and a
tunnel through which nothing moves either way for 10 minutes is cut
(`Limits`, set with `spawn_with` and `serve_with`). At most 256
connections are served at once. `peer_pid` names the process of a
connection, for a gate that decides by who is asking.

Its API has no stability promise yet, and its version moves with Lonca's
workspace (every Lonca crate has the same version): pin an exact one.

- Repository: <https://github.com/selcukgural/lonca>
- Licence: Apache-2.0 ([LICENSE](https://github.com/selcukgural/lonca/blob/main/LICENSE))
