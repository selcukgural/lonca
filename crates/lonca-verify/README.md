# lonca-verify

Sandboxed build and test runs for Lonca's merge queue (Seatbelt on
macOS, bubblewrap on Linux), with no network. Their results are recorded
in the log as evidence, never recomputed.

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
