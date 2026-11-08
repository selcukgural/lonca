# lonca-policy

Lonca's decision layer: the pure `decide()` function, the replay of the
operation log into state, Cedar policies and human signatures. Every
input of a decision, time included, is in the log entry, so anyone can
replay it.

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
