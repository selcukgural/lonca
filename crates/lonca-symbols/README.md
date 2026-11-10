# lonca-symbols

Symbols, facts and the structural merge of Lonca, as pure functions of
file contents. tree-sitter finds the functions and types a change
touches in thirteen languages, and a symbol-level three-way merge lets
agents change different symbols of one file at the same time. What each
grammar reads of its language's recent syntax, and what it does not yet:
[Languages](https://selcukgural.github.io/lonca/docs/guide/languages).

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
