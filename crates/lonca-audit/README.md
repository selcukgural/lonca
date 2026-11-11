# lonca-audit

The independent auditor of a Lonca repository, also as the `lonca-audit`
binary. It replays every decision of the signed operation log,
recomputes every fact and merge, and catches forgeries even when they
are signed with the daemon's own key. Run it in CI on a pushed remote:
`lonca-audit verify <repo.git> --genesis <hash>`.

```sh
cargo install --locked lonca-audit
lonca-audit verify ~/.lonca/repos/demo.git   # a cooperative daemon's store
lonca-audit verify .git --genesis <hash> --extends <hash>   # in CI
```

A log proves that it is whole, not that it is yours: `--genesis` (the
`genesis:` line of a run on your own machine) says which log is expected,
and `--extends` (a `head:` seen before) that it was not taken back.

A hardened daemon's store is readable by its user only; the auditor says
so (permission denied) and you verify a pushed remote or a `lonca backup`
bundle instead.

This crate is a part of [Lonca](https://selcukgural.github.io/lonca/),
agent-native, Git-compatible version control; the `lonca` command
(`cargo install --locked lonca`) is the rest of it.

The binary's command line is the interface. The library's API has no
stability promise, and its version moves with the workspace (every Lonca
crate has the same version).

- Site and guide: <https://selcukgural.github.io/lonca/>
- Repository: <https://github.com/selcukgural/lonca>
- Licence: Apache-2.0 ([LICENSE](https://github.com/selcukgural/lonca/blob/main/LICENSE))
