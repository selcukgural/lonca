# Acceptance tests

What a release must do for the people who install it, checked against the
binaries it ships. `cargo test` proves the parts, mostly against a daemon
inside the test process; the acceptance tests run `lonca daemon`,
`lonca` and `lonca-audit` as separate processes, from a fresh home, the
way the guides tell a user to, and check what the user would see.

## When they run

- **Every pull request and every merge to main:** the `test` jobs of
  `ci.yml` (Linux and macOS) run them on the build `cargo test` just made.
  They are part of the required checks.
- **Every release:** `release.yml` runs them on the archives it built, one
  job per target a runner can execute (macOS arm64, Linux x86_64 and
  arm64). The draft release is made only when all of them pass, so no
  release is published without them. The x86_64 macOS archive is not run
  (Apple silicon runners may lack Rosetta); its build is the same code.
- **By hand:** `cargo build --release -p lonca -p lonca-audit` and
  `acceptance/run.sh`. `--bin DIR` runs another build or an unpacked
  archive, names after the options pick scenarios by prefix
  (`acceptance/run.sh 03 05`), `--keep` keeps each scenario's home.
  A failed scenario's home is always kept and its path printed.

The manual criteria below are part of the release checklist
(`docs/release-checklist.md`) and are done before a draft is published.

## Keeping them true

Every change asks: which criterion describes what I changed, and does it
still say the truth? In the same pull request:

- **New user-visible behaviour** (a command, a flag, a refusal, an output a
  script reads, a file Lonca writes) gets a criterion and the scenario
  lines that prove it, or a line under "Not covered yet" saying why not.
- **Changed behaviour** changes its criterion and scenario.
- **Removed behaviour** removes its criterion and its lines. A criterion
  is never left skipped, and never weakened only to get a release out: a
  failing criterion is fixed in the code, or changed in a pull request
  that says why the old promise no longer holds.

`acceptance/run.sh --check` (also the first thing every run does) fails
when this table and the scenarios disagree: a criterion no scenario
proves, one proved by another scenario than the table says, or a
scenario line whose criterion is not here.

## Writing a scenario

A scenario is a bash file in `acceptance/scenarios/` (bash 3.2, the one
macOS ships). It sources `acceptance/lib.sh`, which gives it a home of
its own (`$HOME`; nothing of the caller's `LONCA_*`, `XDG_*` or
`ANTHROPIC_*` reaches it) and these helpers:

| Helper | Does |
| --- | --- |
| `criterion ID "text"` | starts the checks of one criterion; failures name it |
| `ok CMD...` | CMD succeeds; its output is in `$OUT` |
| `refused CMD...` | CMD is refused (exit 1); `exits N CMD...` for another status |
| `has ERE`, `lacks ERE` | `$OUT` matches, or does not match, the pattern |
| `eventually DESC CMD...` | CMD succeeds within 20 s (the merge queue works in the background) |
| `start_daemon [ARGS]` | a daemon in the background, stopped when the scenario ends |
| `standard_setup` | daemon, human `ayse`, repository `demo` imported from `~/src/shop` |
| `seq_of`, `change_of` | the sequence number and change id in `$OUT` |
| `trunk_file PATH` | the file as trunk has it |

Any output with a Rust panic fails the check it is in. A scenario uses no
network and no model: those go to the manual criteria.

## Criteria

Every row is proved by the `criterion` lines of the scenario named in its
last column.

| ID | Criterion | Scenario |
| --- | --- | --- |
| A01 | `lonca --version` and `lonca-audit --version` print the release's version | `01-install` |
| A02 | A daemon starts in a fresh home; `lonca doctor` finds it at the same version, in cooperative mode, and fails no check | `01-install` |
| A03 | `lonca human keygen` makes a key and the default identity; `human whoami` prints it | `02-repository` |
| A04 | `lonca init --import` keeps the branch: trunk is the imported commit, and a second `init` of the name is refused | `02-repository` |
| A05 | `lonca session start` makes a workspace: a git repository with trunk's files | `03-agents` |
| A06 | `lonca symbols` lists a file's methods as lease ids | `03-agents` |
| A07 | A leased symbol is refused to another agent, naming the holder and the intent; another symbol of the same file is free | `03-agents` |
| A08 | A proposal with a file outside the session's paths is refused, naming the path, and never waits for approval | `03-agents` |
| A09 | An unobserved session's proposal waits for a human; after approval, two agents' changes to different methods of one file both land in trunk | `03-agents` |
| A10 | `lonca sync` brings trunk into a workspace | `03-agents` |
| A11 | After `lonca session end` the session's token is refused | `03-agents` |
| A12 | A rejected proposal does not land, and its agent reads the reason in `lonca events` | `04-review` |
| A13 | `lonca undo` of an integration is a compensating change: trunk goes back and the log only grows; an approval can not be undone automatically | `04-review` |
| A14 | A frozen repository refuses agents' work with the reason; `unfreeze` resumes it | `04-review` |
| A15 | A human's git checkout: `lonca fetch`, a commit, `lonca propose --commit HEAD`, and the commit lands in trunk | `04-review` |
| A16 | `lonca-audit verify` passes on the store, and `lonca doctor` says the log verifies | `05-audit` |
| A17 | A log entry edited in the store fails the audit | `05-audit` |
| A18 | Trunk moved behind the log's back fails the audit | `05-audit` |
| A19 | `lonca push` sends trunk, log and policy to a bare remote; a plain `git clone` gets trunk, and the remote audits | `06-git` |
| A20 | `lonca-audit compare` accepts the published log and catches a local log rewound after the push | `06-git` |
| A21 | `lonca backup` writes one bundle per repository, mode 0640, into its backups and `--out`; the bundle audits | `07-backup` |
| A22 | A restore never replaces an existing repository | `07-backup` |
| A23 | A restore onto a new daemon gives the same trunk and log, and work continues after `daemon-key recover` | `07-backup` |
| A24 | `--harness claude-code` writes `.mcp.json` (`lonca mcp`) and `.claude/settings.local.json` (`lonca hook` on session start, before and after a tool) | `08-harness` |
| A25 | The hook gives the agent Lonca's rules at session start and denies a write outside the workspace | `08-harness` |
| A26 | `lonca mcp` answers `initialize` with the version and lists the agent's tools; `lonca rules` prints the rules | `08-harness` |
| A27 | In a keyed directory (`[paths.keyed]`), `--name next` reserves the next free key and says which; another agent can not reserve that key | `09-keyed` |
| A28 | A new file in a keyed directory without its key reserved is refused, naming the key; with it, it lands | `09-keyed` |
| A29 | A key a file on trunk already has is refused (`key_taken`); a person's change and an agent's that would land one key: the second is conflicted on the key, and the log audits | `09-keyed` |
| A30 | A runner's `lonca events --watch`, with the human session, wakes when a lease is handed over between two sessions, with the sender but no message text, and the receiving agent still reads it in `lonca events` | `10-watch` |
| A31 | `lonca events --watch --follow` prints one JSON line per event and stops by itself when every session it watches by name has ended | `10-watch` |
| A32 | With `identify` in `[verification]`, `lonca change --evidence` of an integrated change names the toolchain each check ran with (a digest and each command's first line), and an identify command that fails is shown as failed while the check passes | `11-evidence` |
| A33 | `lonca-audit verify` notes a check that ran with another toolchain than the last time it ran (`env … changed since …`), and the log still verifies | `11-evidence` |

## Manual criteria

These need a model, an account or a machine CI does not have. They are
done for every release; one that could not be done is written down in the
release notes.

| ID | Criterion | How |
| --- | --- | --- |
| M01 | Every built-in harness profile, live: it leases, proposes and reaches `integrated` after approval; two harnesses on one file integrate; an early stop is sent back | `docs/release-checklist.md`, "A live run per harness" |
| M02 | The published release installs: Homebrew, `install.sh` on a clean account, an archive's attestation verifies | `docs/release-checklist.md`, "Releasing", steps 3, 6 and 7 |

## Not covered yet

What a user can do that no criterion holds yet, so that the gap is
visible. Each becomes a criterion when it is automated.

- Isolated mode (`lonca run`): needs a sandbox on the runner (bubblewrap
  on Linux); `ci.yml`'s `sandbox` job covers it with `cargo test`.
- Hardened mode (`install-hardened.sh`, a daemon as its own user): needs
  root on the runner.
- Secure Enclave and security keys: need the hardware (`lonca human keygen
  --secure-enclave`, FIDO2 keys).
- The advisor (`lonca advise`): needs a model.
- Policy changes (`lonca policy`), human enrollment and revocation,
  negotiation between agents beyond a handover, `lonca revert`, `lonca redact`, `lonca pull`,
  session rotation and `--continue`.
