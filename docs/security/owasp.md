# Lonca and the OWASP lists

How Lonca meets the current OWASP guidance, where it falls short, and which
issue tracks each gap. It started as the mapping of epic #66 and lives here so
it stays next to the code it describes. Review it at every release
(`docs/release-checklist.md`); a change that makes a row untrue changes the row
in the same pull request.

Lists used (versions checked 2026-11): OWASP Top 10:2025, Top 10 for LLM
Applications 2025, Top 10 for Agentic Applications (2026, OWASP GenAI Security
Project), ASVS 5.0, CI/CD Security Top 10.

Lonca is a gatekeeper for AI agents, so it follows zero-trust principles:
every request is authenticated and authorized, privilege only narrows, unknown
things are refused, and a breach is assumed and looked for (hash-chained log,
auditor, reconcile). The invariants are in `CLAUDE.md`; the cryptographic
inventory is `docs/crypto.md`; decisions and deviations are
`docs/decisions.md`. The threat model, [threat-model.md](threat-model.md), says
what each mode prevents and what it only detects.

Status words: **met** (in place, with where), **gap** (missing, with an open
issue), **accepted** (a known limit, with where it is written down), **n/a**.

## OWASP Top 10:2025

| Item | Status | In place | Open |
|---|---|---|---|
| A01 Broken Access Control (incl. SSRF) | met | every daemon method names its credential, deny by default (`METHODS`, `crates/lonca-daemon/src/service.rs`); capabilities only narrow and a child session keeps its parent's agent name (`cap.attenuate`, `scope_within` in `decide.rs`); peer uid allowlist (`server.rs`); proxy: private ranges, metadata always, port allowlist, per-host rules (`crates/lonca-net`, #64); local-path remotes kept out of the daemon home (#57) | — |
| A02 Security Misconfiguration | met | hardened profile and installers, root-owned hook and managed-settings checks, no silent unsandboxed verification (#54); key and home ownership checks (#62); `lonca policy check` tries a policy against the log before it is set, and a guide to writing one (#13) | — |
| A03 Software Supply Chain Failures | met | cargo-deny (crates.io only, advisories, licenses), actions pinned by commit and allowlisted, Dependabot with cooldown, pinned toolchain, zizmor, SBOM and build provenance attestation of a release (#7), Scorecard (#60) | — |
| A04 Cryptographic Failures | met | Ed25519 `verify_strict`, Secure Enclave P-256, SHA-256 chain, tokens stored as hashes, keys private on load and wiped in memory (`docs/crypto.md`, #62); human and daemon key rotation and recovery (#4, #5); FIDO security keys (`sk-p256`, `sk-ed25519`) verified as OpenSSH does, a signature without a touch refused (#17) | — |
| A05 Injection | met | git: `--`, scheme allowlist, clean environment, no hooks, `GIT_ALLOW_PROTOCOL`, paths taken literally (`GIT_LITERAL_PATHSPECS`) (#57); strict repository paths (`crates/lonca-core/src/paths.rs`); Cedar context built from typed values; advisor input framed as data (#63); every parser of untrusted input fuzzed, found crashes kept as regressions (#15, `docs/fuzzing.md`) | — |
| A06 Insecure Design | met | pure `decide()`, single writer, append-only log replayed by the auditor; socket, request and rate limits (#50); verifier process-tree kill, rlimits, quota (#59); the threat model ([threat-model.md](threat-model.md), #14) | — |
| A07 Authentication Failures | met | random 32-byte tokens, presence signatures with nonce and age checks (`human.rs`), clients verify the daemon (#52), token expiry, sweep and rotation (#53) | — |
| A08 Software or Data Integrity Failures | met | hash-chained signed log, every ref held to it by `reconcile()` and the auditor (#58), anchors in pushed remotes | accepted: the auditor shares `decide()` with the daemon (`docs/decisions.md`, "The auditor shares the decision code"; #18 closed) |
| A09 Security Logging & Alerting Failures | met | every decision logged, denials included; security events outside the log and notification of freezes (#56) | — |
| A10 Mishandling of Exceptional Conditions | met | Cedar errors deny; hooks fail closed; no panics on extreme numbers, overflow checks, panic lints on the trusted core (#61); a failed reconcile is an event (#56); the parsers and the merge fuzzed (#15); a symbol parse stops at a budget of work (engine 16); a Cedar evaluation runs on a stack of its own, so no platform's stack turns a decision into a denial (#260); keyed-directory patterns compile to bounded automata that never backtrack (#261) | — |

## Top 10 for LLM Applications 2025

| Item | Status | In place | Open |
|---|---|---|---|
| LLM01 Prompt Injection | met | taint tracking: outside content marks a session and its changes wait for a human; unobserved sessions count as tainted; agent instruction and tool config files are critical paths (#55); the advisor gets agent text as framed data (#63) | — |
| LLM02 Sensitive Information Disclosure | met | tokens never logged (log, `daemon.log`, security log masks them); verification environment deny by default; credential directories unreadable in the sandbox; redaction | — |
| LLM03 Supply Chain | met | as A03; the advisor's model is named, not discovered | — |
| LLM04 Data and Model Poisoning | n/a | Lonca trains and fine-tunes nothing | — |
| LLM05 Improper Output Handling | met | advisor output never reaches a decision; printed text has no control or bidi characters and is labelled tainted (#63) | — |
| LLM06 Excessive Agency | met | agents get agent operations only (MCP and protocol), scopes by path and symbol, leases, blast-radius rules, critical paths escalate | — |
| LLM07 System Prompt Leakage | n/a | no secrets in prompts; the rules text is public | — |
| LLM08 Vector and Embedding Weaknesses | n/a | no retrieval | — |
| LLM09 Misinformation | met | advice is informational only and says so | — |
| LLM10 Unbounded Consumption | met | advisor daily budget, reserved before the call and failing closed (#63); daemon, verifier and proxy limits (#50, #59, #64) | — |

## Top 10 for Agentic Applications (2026)

| Item | Status | In place | Open |
|---|---|---|---|
| ASI01 Agent Goal Hijack | met | as LLM01; tainted work goes to a human | — |
| ASI02 Tool Misuse and Exploitation | met | hooks refuse tools that touch Lonca's own files, socket, keys or harness settings; refusals are security events (#56) | — |
| ASI03 Identity and Privilege Abuse | met | sessions per agent, attenuation only narrows, cascading revocation, tokens end with their session (#53); harness levels (#21) | — |
| ASI04 Agentic Supply Chain Vulnerabilities | met | build files and agent config are critical paths (#55); CI as A03 | — |
| ASI05 Unexpected Code Execution | met | verification of the merged tree in a sandbox; `lonca run` isolation; no silent unsandboxed run (#54, #59) | — |
| ASI06 Memory and Context Poisoning | met | provenance labels on changes and advice; instruction files are critical paths (#55) | — |
| ASI07 Insecure Inter-Agent Communication | met | negotiation only through the daemon, authenticated, logged, bounded rounds | — |
| ASI08 Cascading Failures | met | per-session rate limits, connection and byte budgets, quotas (#50, #59, #64); one session's denial touches no other | — |
| ASI09 Human-Agent Trust Exploitation | met | the daemon writes what a human approves; presence keys in the hardened profile (#54); advice labelled tainted (#63) | — |
| ASI10 Rogue Agents | met | taint, freeze, auditor, security events and alarms (#56, #58) | as A08 |

## CI/CD Security Top 10

| Item | Status | In place | Open |
|---|---|---|---|
| CICD-SEC-1 Insufficient Flow Control | met | main takes pull requests only, and requires the `ci.yml` jobs (Ubuntu, macOS, sandbox) as status checks; no approval is required (one maintainer) (`docs/decisions.md`, "CI runs on every pull request" and #60) | — |
| CICD-SEC-2 Inadequate IAM | met | one maintainer; workflows hold read-only tokens, `persist-credentials: false` | — |
| CICD-SEC-3 Dependency Chain Abuse | met | cargo-deny crates.io only, Dependabot cooldown, lockfile `--locked`; `cargo vet` not adopted (`docs/decisions.md`, #60) | — |
| CICD-SEC-4 Poisoned Pipeline Execution | met | no `pull_request_target`, no event data in `run:`; no run on a tag restores a cache; zizmor on workflow changes | — |
| CICD-SEC-5 Insufficient PBAC | met | `permissions: contents: read` per workflow; OIDC (`id-token: write`) only on the jobs that need it, none of which runs the tests: Scorecard, the Pages deploy, the release attestation, and the crates.io publish (environment `release`, tags `v*`) | — |
| CICD-SEC-6 Insufficient Credential Hygiene | met | no long-lived secrets in CI; secret scanning with push protection | — |
| CICD-SEC-7 Insecure System Configuration | met | pinned toolchain, timeouts, actions allowlist and SHA pinning required | — |
| CICD-SEC-8 Ungoverned 3rd Party Services | met | five named third-party actions, nothing else (`docs/decisions.md`, "CI and the repository's own settings") | — |
| CICD-SEC-9 Improper Artifact Integrity Validation | met | each release archive has a build provenance attestation (`gh attestation verify`), `SHA256SUMS` and a CycloneDX SBOM (`release.yml`, #7, #60) | — |
| CICD-SEC-10 Insufficient Logging and Visibility | met | Actions logs, Scorecard, CodeQL; the auditor workflow for pushed repositories (`docs/ci/lonca-audit.yml`) | — |

## ASVS 5.0, Level 2

Target: **Level 2** for the whole tool, which protects source and CI
integrity, and selected **Level 3** controls for the trusted core (operation
log, `decide()`, keys, auditor): V11 cryptography, V15.3 defensive coding, V16
logging. Not applicable: V3 (no web frontend), V10 (no OAuth or OIDC), V17 (no
WebRTC). V12 applies only to the advisor and the Git bridge. The checklist is
kept at the level of ASVS sections; a section marked met has every Level 2
requirement in it met, or the exception named.

| Section | Status | Where |
|---|---|---|
| V1.1 Encoding and sanitization architecture | met | protocol is JSON lines with typed shapes (`docs/protocol.md`); canonical JSON for the log (`canonical.rs`) |
| V1.2 Injection prevention | met | git arguments behind `--`, validated remotes and branches (`service.rs` `check_remote`, `check_branch`), clean git environment (`gitcmd.rs`); Cedar values typed |
| V1.3 Sanitization | met | everything the CLI and the auditor print for a person has its control and bidi characters written out, at the one place that writes (`lonca_core::terminal::printable`, `crates/lonca-cli/src/out.rs`); advisor output (`advise.rs` `printable`, `clean`); event text (`security.rs` `clean`); paths refuse bidi characters (`paths.rs`) |
| V1.4 Memory, string and unmanaged code | met | Rust; unsafe code refused outside named FFI modules with SAFETY notes (#61) |
| V1.5 Safe deserialization | met | serde into fixed types, `deny_unknown_fields` on policy, unknown operation types refused; line and size limits before parsing (#50) |
| V2.1 Validation documentation | met | `docs/protocol.md` names every field and limit |
| V2.2 Input validation | met | `decide()` checks every operation's values (`decide.rs`), extreme numbers denied (#61) |
| V2.3 Business logic security | met | single writer orders every operation; leases, quotas and approvals in `decide()`; the auditor replays them |
| V2.4 Anti-automation | met | per-session rate limit, connection caps (#50), proxy budgets (#64) and a rate on what the proxy records, a size limit on a log entry, advisor budget (#63) |
| V4.1 Generic web service security | met | one Unix socket, authenticated methods, explicit errors (`docs/protocol.md`) |
| V4.2 HTTP message structure | met | the proxy caps request heads at 16 KiB and parses only `CONNECT` and absolute `http://` (`crates/lonca-net`) |
| V4.3, V4.4 GraphQL, WebSocket | n/a | none |
| V5 File handling | met | repository paths validated, workspace paths opened one component at a time, scratch and size limits; backups written mode 0640 to their own directory |
| V6.1 Authentication documentation | met | `docs/decisions.md` "Daemon authentication", `docs/guide/humans.md` |
| V6.2 Password security | n/a | no passwords; keys and presence |
| V6.3 General authentication security | met | every method authenticated (#51); clients verify the daemon (#52) |
| V6.4 Factor lifecycle and recovery | met | key rotation, revocation and a one-time recovery key (#4, #5) |
| V6.5, V6.6 Multi-factor, out of band | accepted | presence (Secure Enclave and Touch ID, or a FIDO security key, #17) is the second factor where required; no out-of-band channel (`docs/guide/profiles.md`) |
| V6.7 Cryptographic authentication | met | Ed25519 and P-256 signatures over intent with nonce and age checks, and OpenSSH security-key signatures that prove presence (`human.rs`) |
| V6.8 Identity provider | n/a | none |
| V7.1 Session documentation | met | `docs/decisions.md` "Session tokens: expiry, sweep, rotation (#53)" |
| V7.2 Fundamental session security | met | 32 random bytes, stored as SHA-256, never logged (`home.rs`) |
| V7.3 Session timeout | met | agent sessions end at their `expires_ms` (at most `sessions.max_ttl_minutes`), human sessions at most a day; expired tokens refused and swept (#53) |
| V7.4 Session termination | met | end, revocation cascading to children and rotated tokens, key changes end sessions (#53) |
| V7.5 Defenses against session abuse | met | `session.rotate`; an isolated token works only in its sandbox |
| V7.6 Federated re-authentication | n/a | none |
| V8.1 Authorization documentation | met | `docs/guide/profiles.md`, default policy (`crates/lonca-policy/src/config.rs`) |
| V8.2 General authorization design | met | deny by default, Cedar errors deny, capabilities only narrow |
| V8.3 Operation-level authorization | met | `decide()` per operation; the daemon checks credentials per method |
| V8.4 Other considerations | met | an agent token reads its own repository only; a human sees only enrolled repositories |
| V9 Self-contained tokens | n/a | tokens are opaque and looked up; no JWTs |
| V11.1 Cryptographic inventory | met (L3) | `docs/crypto.md` |
| V11.2 Secure implementation | met (L3) | vetted libraries only, no custom constructions (`docs/crypto.md`) |
| V11.3 Encryption algorithms | n/a | Lonca encrypts nothing itself; TLS through rustls |
| V11.4 Hashing | met (L3) | SHA-256 for the chain and token hashes; SHA-1 only as Git's object ids (`docs/crypto.md`) |
| V11.5 Random values | met (L3) | OS random source for tokens, nonces and keys (`canonical.rs`) |
| V11.6 Public key cryptography | met (L3) | Ed25519 `verify_strict`, P-256 ECDSA |
| V11.7 In-use data | met (L3) | key secrets shared, not copied, and zeroized (#62) |
| V12.1, V12.2 TLS | met | advisor: rustls, https only except loopback (#63); bridge and imports: git's TLS or SSH |
| V12.3 Service to service | met | the socket is local; peer uid checked both ways (#52) |
| V13.1 Configuration documentation | met | `docs/guide/profiles.md`, `docs/guide/runners.md`, decisions |
| V13.2 Backend communication | met | git with a clean environment and time limit, local remotes restricted (#57); proxy allowlists (#64) |
| V13.3 Secret management | met | keys mode 0600, owner checked, hardened home of its own user (#62); daemon git credentials only in its own git home (#57) |
| V13.4 Unintended information leakage | met | errors carry codes and short messages, no tokens or contents; `lonca doctor` leaks no secrets |
| V14.1, V14.2 Data protection | met | redaction of published history (logical), backups readable only by the daemon's group, tokens never at rest in clear |
| V14.3 Client-side data | met | human session files mode 0600; workspace tokens written as secrets |
| V15.1 Architecture documentation | met | `docs/design.md`, `docs/decisions.md` |
| V15.2 Architecture and dependencies | met | trusted core without AI, network or clock; cargo-deny; pinned toolchain |
| V15.3 Defensive coding | met (L3) | panic lints on the trusted core, overflow checks, saturating arithmetic in `decide()` (#61) |
| V15.4 Safe concurrency | met | one writer under one lock; ref updates compare-and-swap; push outside the lock (#57) |
| V16.1 Logging documentation | met (L3) | `docs/decisions.md` "Security events outside the log (#56)" |
| V16.2 General logging | met (L3) | fixed fields, no tokens or contents, time from the daemon clock |
| V16.3 Security events | met (L3) | the kinds of #56; every decision in the operation log |
| V16.4 Log protection | met (L3) | operation log hash-chained and signed, every ref reconciled and audited (#58); security log mode 0600 in the daemon's home |
| V16.5 Error handling | met (L3) | errors deny or fail closed; panics turned into denials (#61) |

## Verification of the above

Tests stand behind each "met": decision scenarios end with a replay
(`assert_replay`), the auditor recomputes facts and merges, and mutation
testing (#27, on demand) checks that the tests would notice a broken check
in the trust model, and the fuzzer (#15) runs before every release and on its
tag. Nobody outside has reviewed the design yet (#23).
