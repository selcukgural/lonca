# Recovery

What to do when a key is lost or must be replaced, and how to bring
repositories back from a backup. Every step here is a signed operation in
the log, so an auditor sees each key change and who made it. Where each key
lives and which algorithm it uses: [Cryptography](../crypto.md).

| What happened | Go to |
|---|---|
| You want a new key, or suspect yours was used | [Rotate your key](#rotate-your-key) |
| Your human key is gone, the daemon is fine | [A lost human key](#a-lost-human-key) |
| A person must lose access | [Revoke a human](#revoke-a-human) |
| You want a new daemon key | [Rotate the daemon key](#rotate-the-daemon-key) |
| The daemon's home or `daemon.key` is gone, your human key is fine | [A lost daemon key](#a-lost-daemon-key) |
| A repository must come back from a backup, or move to another machine | [Restore a repository](#restore-a-repository) |
| The Mac is gone, and with it both keys | [A lost Mac](#a-lost-mac) |

## Before anything is lost

Two things to do on the first day, because they can not be done afterwards:

```sh
lonca human recovery-key --repo demo,web --out /Volumes/usb/ayse.recovery
lonca push git@github.com:me/demo.git --repo demo     # or: lonca backup --out /Volumes/usb
```

- **A recovery key** replaces your key once, without Touch ID, in every
  repository it was registered in. Move the file off the machine (a
  password manager, a USB stick): anything that can read it can take over
  your identity once. A rotation keeps it; a recovery uses it up, so
  register a new one after recovering. Running the command again replaces
  the registered one (give a new `--out` file: an existing one is reused).
- **A copy of each repository** off the machine: a Git remote that
  `lonca push` keeps current (audited in CI), or the bundles of
  `lonca backup` ([Quick start](quick-start.md#backup-and-moving)).
- **A file key** is a file: back it up like any other secret, or better,
  use a Secure Enclave key and the recovery key. A Secure Enclave key can
  not be backed up; it lives and dies with its Mac.

## Rotate your key

```sh
lonca human rotate --repo demo,web                    # a new file key
lonca human rotate --repo demo,web --secure-enclave   # a new Secure Enclave key
```

The new key is signed by the current one. Give every repository you are
enrolled in, comma-separated: the key is shared between them, and the new
one is installed only after all of them accepted it (rerun to resume; the
ones already moved are skipped). The old key file stays as
`<name>.key.retired-<ms>`; a retired key is never accepted again.

A rotation **ends everything you set in motion**, as a revocation does:
every session you started and every session made from them (with their
leases, proposals and queued verification), your changes in flight, your
requests waiting for approval and the approvals you gave to others' that
still wait. Rotating is also the answer to a suspected compromise, and then
nothing started under the old key should still be moving. Start the
sessions you need again afterwards. Entries signed before stay valid.

## A lost human key

The file was deleted, or the Secure Enclave key went with a logic board,
but the daemon (its home and `daemon.key`) is still there:

```sh
lonca human recover --repo demo,web --recovery-key /Volumes/usb/ayse.recovery
lonca human recover --repo demo,web --recovery-key /Volumes/usb/ayse.recovery \
      --secure-enclave --as ayse     # a Secure Enclave key; --as where no default identity is left
```

The recovery key signs one operation, `human.recover`, which installs a new
key; it is the one signature that needs no presence even where the
repository requires it, because the key with presence is the one that was
lost. It is used up: delete the file, and register a new recovery key. The
same cascade as a rotation ends what you had running.

Without a recovery key, another enrolled human can revoke you and enrol your
new key (`lonca human revoke`, then `lonca human enroll`). With neither, the
repository can not be signed for again.

## Revoke a human

```sh
lonca human revoke bora --repo demo --reason "left the project"
```

Any enrolled human can withdraw a human's key and recovery key, their own
included. Everything that human set in motion ends, as above. The last
enrolled human can not be revoked, since nobody could sign afterwards. The
name can be enrolled again later, with a new key. A policy may send key
operations to approval; the approval that releases one checks again that it
would not revoke the last human.

## Rotate the daemon key

```sh
lonca daemon-key rotate                 # every repository still on the current key
lonca daemon-key rotate --repo demo     # only these
```

The daemon prepares a new key (`daemon.next.key`); each repository gets a
`daemon.rotate` entry signed by the old key and by you (Touch ID names the
first 16 hex digits of the new key), and every later entry is signed by the
new one. When no repository uses the old key any more, its secret is
deleted. Rerun to resume. Sessions go on: the daemon and its tokens stay.

## A lost daemon key

`daemon.key` was deleted, the disk was replaced, Lonca was reinstalled: the
stores are there (or come back from a backup) but the key that signed their
logs is not. The daemon starts with a new key and lists those repositories
as being on a key it does not hold; they accept nothing but a recovery:

```sh
lonca daemon-key recover --repo demo,web
```

An enrolled human signs it, with presence if the repository requires it,
and the daemon's new key signs the entry. The repository continues on the
new key, and every auditor sees the switch. **Every session ends**, because
the daemon that held their tokens is gone; what they proposed keeps its
place in the queue. Start new sessions; `lonca session start --continue
<dir>` keeps a workspace.

## Restore a repository

```sh
lonca restore demo --from /Volumes/usb/lonca/demo-000412.bundle   # a bundle
lonca restore demo --from git@github.com:me/demo.git              # a pushed remote
lonca daemon-key recover --repo demo      # only on another daemon than the one that wrote it
```

- A restore creates the repository under the name its log was created
  with; human signatures bind the name, so another name is refused.
- It never replaces a repository. Move a broken store away first (as the
  daemon's user), or restore under a fresh `LONCA_HOME` to look at it.
- Restored into the daemon that wrote it, it is live at once. Into another
  daemon (another machine, a hardened install), it waits for
  `lonca daemon-key recover`, signed by an enrolled human whose key you have
  on this machine.
- Sessions in a restored log need new tokens, that is new sessions; agent
  workspaces are not in a backup.
- Audit what you restored: `lonca restore` prints the command, and on a
  hardened daemon says to audit the source instead.

Moving cooperative repositories into a hardened install is the same
restore and recovery: [Install](install.md#hardened-mode).

## A lost Mac

The Mac is lost, stolen or dead, and with it the daemon's key and your
Secure Enclave key. The repositories come back from a pushed remote or a
bundle, onto a new daemon.

The recovery key brings each repository back, on the new Mac:

```sh
lonca restore demo --from git@github.com:me/demo.git
lonca human recover --repo demo --recovery-key /Volumes/usb/ayse.recovery \
      --secure-enclave --as ayse
```

A restored log is on the daemon key that was lost, so `human.recover` alone
can not be signed for it (`foreign_key`). `lonca human recover` then sends
one `daemon.recover` signed with the recovery key instead: it moves the
repository onto the new daemon's key and installs your new key, in one entry
and without a session. As after any daemon recovery, every session ends;
start new ones. The recovery key is used up: register a new one. Audit the
repository (`lonca-audit verify`): the switch is listed, with you as the one
who asked for it.

Without a recovery key, one of these has to have survived:

- **Another enrolled key you can use on the new Mac**: a second human's,
  or a file key of yours kept off the machine, where the repository does not
  require presence. With it: `lonca restore`, `lonca daemon-key recover
  --repo demo`, then `lonca human revoke ayse` and `lonca human enroll ayse
  --alg p256-se --public <hex>` for your new key (the algorithm and the hex
  from `lonca human whoami`).
- **A backup of the old daemon's key**, for example in a Time Machine backup
  of the Mac: `daemon.key` in the daemon's home (`~/.lonca`, or
  `/Library/Lonca/home` when hardened). Put it into the new daemon's home
  before its first start, owned by the daemon's user with mode 0600. That
  copy signs entries as the daemon: keep it as safe as the recovery key.

Without any of them, the history is still yours: the remote holds trunk and
the whole log, and `lonca-audit verify` checks it. To go on working,
`lonca init <new-name> --import` creates a new repository from that trunk,
with a new log.
