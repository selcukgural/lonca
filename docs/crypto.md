# Cryptographic inventory

What Lonca uses cryptography for, where each key lives, who can read it and
how it is replaced (ASVS 5.0 V11.1.1). Keep it current: a change to any row
changes this file in the same pull request. The threat model (#14) and
`docs/security/owasp.md` point here.

## Algorithms

| Use | Algorithm | Library | Where |
|---|---|---|---|
| Daemon signature on every log entry | Ed25519, `verify_strict` | `ed25519-dalek` 3 | `crates/lonca-core/src/keys.rs`, `oplog.rs` |
| Human signatures, file keys (development) | Ed25519, `verify_strict` | `ed25519-dalek` 3 | `keys.rs`, `crates/lonca-policy/src/human.rs` |
| Human signatures, Secure Enclave keys | ECDSA P-256 with SHA-256 | Security framework (`lonca-se`), `p256` 0.14 to verify | `packaging/macos/lonca-se`, `human.rs` |
| Log entry digests, hash chain | SHA-256 over canonical JSON | `sha2` 0.11 | `crates/lonca-core/src/canonical.rs`, `oplog.rs` |
| Session tokens at rest | SHA-256 of the token | `sha2` | `crates/lonca-daemon/src/home.rs` (`Tokens`) |
| Tokens, nonces, ids, new keys | 32 (tokens, keys) or 8 to 16 bytes from the OS | `getrandom` 0.4 | `canonical.rs` (`random_bytes`) |
| Object ids of Git trees and commits | SHA-1 (Git's own format) | `gix` | `crates/lonca-core/src/store.rs` |
| Advisor calls to the Claude API | TLS (rustls with ring, webpki roots) | `ureq` 3 | `crates/lonca-cli/src/advise.rs` |
| Git bridge, imports | whatever `git` uses (HTTPS, SSH) | the system `git` | `crates/lonca-daemon/src/service.rs` |

Notes:

- **What a signature covers.** The daemon signs the SHA-256 digest of an
  entry's canonical bytes, and that digest names the previous entry's, so
  the chain and every entry are covered. A human signs the canonical bytes of
  the intent: the repository, the operation, a nonce and `issued_ms`. The
  daemon refuses a nonce it has seen and an `issued_ms` more than 10 minutes
  old or 1 minute ahead (`human.rs`, `MAX_AGE_MS`, `MAX_SKEW_MS`).
- **SHA-1 is Git's, not Lonca's.** Git object ids name trees and commits, and
  a collision would let two trees share a name. The log's integrity rests on
  SHA-256 and Ed25519; the auditor recomputes merges and facts from the
  objects it is given. A move to SHA-256 Git repositories is open.
- **No custom constructions.** No algorithm or mode is implemented in Lonca;
  each comes from the library in the table.

## Keys and secrets

| Secret | Where | Readable by | Created | Replaced |
|---|---|---|---|---|
| Daemon signing key | `<home>/daemon.key`, hex, mode 0600 | the daemon's user (`_lonca` / `lonca` when hardened) | first start | `lonca daemon-key rotate` (`daemon.rotate`); a lost key: `lonca daemon-key recover` (`daemon.recover`, signed by a human) |
| Key of a rotation in progress | `<home>/daemon.next.key`, mode 0600 | the daemon's user | `daemon.rotate` | becomes `daemon.key` once every repository has switched; the old secret is deleted |
| Human file key | `~/.config/lonca/humans/<name>.key` (`$LONCA_HUMANS`), mode 0600 | the developer's account | `lonca human keygen` | `lonca human rotate` (`human.rotate`) |
| Human Secure Enclave key | `<humans>/<name>.se`: a key blob only the Secure Enclave of that Mac can use; every signature needs Touch ID or the password | nobody: the private key never leaves the enclave | `lonca human keygen --secure-enclave` | `human.rotate`; a lost key: the recovery key, while the daemon's key survives (a lost Mac: [Recovery](guide/recovery.md#a-lost-mac)) |
| Recovery key | `--out` path, then off the machine (password manager, USB stick) | whoever holds the copy | `lonca human recovery-key` | spent by `lonca human recover`; set a new one after |
| Agent session tokens | given once to the harness (session file in the workspace, MCP), stored in `<home>/tokens.json` only as SHA-256 | the agent's process; the daemon keeps no copy | `session.start` | end, revocation (cascades), expiry (#53) |
| Human session tokens | `<humans>/<name>.session`, mode 0600 | the developer's account | `lonca human login` (presence) | expiry, `lonca human logout` |
| Anthropic credentials | `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` in the environment, or `ant auth` | the developer's account | outside Lonca | outside Lonca |

How keys are held:

- **Loading checks the file.** A key file must be a regular file (a link is
  not followed), owned by the uid of the process that loads it, with no
  access for group or others; otherwise the load fails and says what to do
  (`check_private` in `keys.rs`). The one exception is the recovery key,
  which is often carried on a file system that shows every file as readable:
  only its owner is checked, and others being able to read it is a warning.
- **The daemon home must belong to the daemon.** `Home::ensure` refuses a
  home owned by another uid and sets it to mode 0700.
- **Secrets are wiped.** `KeyPair` shares one `SigningKey` through an `Arc`,
  so a clone copies no secret; `SigningKey` zeroizes itself when the last
  clone is dropped. The hex text read from disk, the decoded bytes and the
  text written for a new key are `Zeroizing` buffers.
- **Agents hold no long-lived keys.** An agent has a session token, which
  ends with the session; nothing an agent holds can sign a log entry or a
  human operation.
- **Hardened mode.** The daemon home, its key and `tokens.json` belong to the
  daemon's own system user, mode 0700, where the developer's account can not
  read or write them (`packaging/*/install-hardened.sh`).

## Not done

- The daemon key is a file. Keeping it in the System keychain or the Secure
  Enclave on macOS goes with #5.
- No hardware key for the daemon on Linux (TPM).
- Session tokens are bearer tokens: nothing binds one to the process it was
  given to, apart from the sandbox check of isolated sessions.
