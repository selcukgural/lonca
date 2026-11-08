# lonca-daemon

The Lonca daemon: the single writer every operation goes through. It
decides, signs, appends to the operation log and only then applies; it
also serves the socket, the harness hooks and the network proxy. Run it
with `lonca daemon`.

This crate is a part of [Lonca](https://selcukgural.github.io/lonca/),
agent-native, Git-compatible version control. Most people want the
command line instead:

```sh
cargo install --locked lonca
```

Its API has no stability promise: it is shaped by what Lonca's other
crates need, and its version moves with the workspace (every Lonca crate
has the same version). A client of the daemon depends on
[`lonca-client`](https://crates.io/crates/lonca-client) instead.

- Site and guide: <https://selcukgural.github.io/lonca/>
- Repository: <https://github.com/selcukgural/lonca>
- Licence: Apache-2.0 ([LICENSE](https://github.com/selcukgural/lonca/blob/main/LICENSE))
