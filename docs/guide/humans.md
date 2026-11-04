# Working on a Lonca repository as a human

Trunk lives in the daemon's store. A person reaches it in one of two
ways; both go through the daemon, never through the store's files.

## A Lonca workspace

```sh
lonca workspace create ~/work/demo --repo demo
cd ~/work/demo
# edit
lonca diff                      # facts of the local edits
lonca propose -i "what and why" # a human change: integrated by the queue
lonca sync                      # trunk into the workspace, local edits merged
```

A workspace is a plain directory with trunk's files and
`.lonca/workspace.json`. It is not a git repository: no commits, no
branches, no history to push. Use it when the editing is the point and
git is not.

## A git checkout

Your existing clone, where you commit, run your IDE, and push to GitHub.

```sh
cd ~/src/demo
lonca fetch --repo demo          # trunk -> refs/lonca/trunk (through the daemon)
git merge refs/lonca/trunk       # or: git reset --hard refs/lonca/trunk
# commit as usual
lonca propose --commit HEAD      # the commit's changes as a human change
lonca fetch                      # after the queue integrated it
```

- `lonca fetch` asks the daemon for a bundle of trunk, thin against what
  the checkout already has, and fetches it into `refs/lonca/trunk`. The
  first `--repo` is remembered in the checkout's git config
  (`lonca.repo`). The line it prints says how many integrations the
  previous `refs/lonca/trunk` was behind.
- `lonca propose --commit REV` proposes everything `REV` changes against
  its merge base with `refs/lonca/trunk`: several commits ahead are one
  proposal; the intent is the commit's subject unless `-i` says
  otherwise. A human change needs no approval and no lease (as from a
  workspace); if trunk moved meanwhile, the merge queue merges
  structurally like any proposal, and `lonca change CHANGE` shows the
  result. The checkout's own history is not what lands: trunk gets a
  new commit built by the daemon, with the same tree. Fetch and merge
  (or reset) to continue on it.
- Symlinks and submodules in the commit are refused; large files meet
  the change cap (`changes.max_file_bytes`).
- A repository with redacted history can not be fetched as git (a
  bundle carries whole objects); work from a workspace then.

## Both

`lonca status --repo demo`, `lonca pending`, `lonca approve`,
`lonca reject`, `lonca log`, `lonca diff CHANGE` and `lonca change CHANGE
--evidence` work from anywhere; every command signs in by itself
(`docs/protocol.md`, "CLI for runners").
