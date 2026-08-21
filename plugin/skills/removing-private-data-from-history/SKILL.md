---
name: removing-private-data-from-history
description: Use when private data has reached a commit — a secret, an account name, a home path, an environment dump in a commit message — and has to come out of git history. Covers repairing the commit, proving the repair, and destroying the old object. Not for a hook that merely fired on a file you have not committed yet.
---

# Removing private data from git history

## When this applies

Private data is **already in a commit**. Something must be rewritten.

If it is only staged or only in the working tree, you do not need this: fix the
file and commit normally. If a hook fired and you are unsure whether the data is
committed, run `git log --all --format='%B' | grep -c …` on a shape you can
name, or `scripts/githooks/verify-history.sh` if the repository has it.

**Report it to the operator before rewriting anything.** Removal is their
decision, not a cleanup you perform quietly. Name what and where; never paste the
value into the conversation, because the transcript is a file that travels.

## The order

### 1. Find the extent before touching anything

Scan the commit and record what is in it — patterns and line numbers, not values.
Then decide whether the message, the file content, or both are affected. The
answer changes the tool: a message needs a reword, content needs a filter.

Take a safety ref: `git branch backup/pre-rewrite HEAD`. It costs nothing and it
is the difference between a mistake and a disaster.

### 2. Do not reach for `git commit --amend`

It needs the offending commit checked out, and that is where it bites: if the
repository's hooks are newer than the commit, the checkout has no hooks, and a
fail-closed dispatcher refuses the amend. The refusal is correct. `--no-verify`
would work and is the wrong habit to build here.

Use plumbing, which was never gated:

```bash
# Same tree, same parent, same identity — only the message differs.
tree="$(git rev-parse "$target^{tree}")"
parent="$(git rev-parse "$target^")"
export GIT_AUTHOR_NAME="$(git log -1 --format='%an' "$target")"
export GIT_AUTHOR_EMAIL="$(git log -1 --format='%ae' "$target")"
export GIT_AUTHOR_DATE="$(git log -1 --format='%aI' "$target")"
export GIT_COMMITTER_NAME="$(git log -1 --format='%cn' "$target")"
export GIT_COMMITTER_EMAIL="$(git log -1 --format='%ce' "$target")"
export GIT_COMMITTER_DATE="$(git log -1 --format='%cI' "$target")"

new="$(git commit-tree "$tree" -p "$parent" -F new-message.txt)"
git rebase --onto "$new" "$target" "$branch"
```

The `export` prefix on those six lines is not incidental. Written as bare
`NAME=value` they are six consecutive unindented assignments, which is the exact
shape of an environment dump — vouch's own `pre-commit` refused this file for it,
correctly, on the first attempt to commit it. Changing the snippet was the honest
fix; marking six lines exempt would have taught the reader that the check is
noise.

Scan the replacement message yourself first. Plumbing skips the hook, so the
check the hook would have run is now yours to run deliberately — skipping it is
not the same as it passing.

For CONTENT rather than a message, `git filter-repo` is the tool.
`--replace-text` rewrites blobs only: a commit message needs `--replace-message`,
and forgetting that is a known way to report success while the data is still in
metadata.

### 3. Preserve what should not change, and prove it

A reword must change the message and nothing else. Prove it rather than assume it:

- `git diff <backup-ref> <new-tip>` must be **empty** — same content throughout.
- The reworded commit's tree hash must equal the original's.
- Author and committer identity and dates must match. Compare the strings; do not
  read them out, and do not print them.

If the diff is not empty, the rebase replayed something unexpectedly. Stop.

### 4. Write down what was rewritten, in the commit itself

The new message should say it was rewritten, when, on whose approval, and what
was removed in the abstract — never the data. A future reader finding a
discontinuity in history deserves to know why it is there, and a rewrite that
hides that it happened invites someone to "restore" it.

### 5. The old object is still there until you destroy it

This is the step people skip, and skipping it means the data is still in the
repository while every check reports clean:

```bash
git branch -D backup/pre-rewrite                 # while it exists, so does the data
git reflog expire --expire=now --expire-unreachable=now --all
git gc --prune=now
git cat-file -e <old-sha>                        # must FAIL
```

`git cat-file -e` failing is the proof. A ref you kept "just in case" keeps the
data reachable, and `git push --all` would send it.

### 6. Verify all of history, not the commit you fixed

Six places, and a scrub is verified only when all six read zero. A past scrub in
one repository reported "0 hits" and shipped the data twice anyway, because the
checks could not see where it hid:

1. Commit messages — `git log --all --format='%B'`
2. Author and committer metadata — `git log --all --format='%an <%ae> %cn <%ce>'`
3. Full patch text, added AND removed lines — `git log --all -p`, unfiltered
4. Tag messages — `git for-each-ref refs/tags --format='%(contents)'`
5. Every path ever added — `git log --all --diff-filter=A --name-only`
   (a deleted file is still in history, so `git ls-files` cannot answer this)
6. Unreachable objects — `git fsck --unreachable`

In vouch this is one command: `scripts/githooks/verify-history.sh`.

**Two traps in running these by hand,** both of which have produced a wrong
answer:

- **`git log -p` without `--format=''`** prefixes each patch with a
  `commit <40 hex>` header, and any secret-shaped-hex check reports one hit per
  commit. That is a false FINDING, which is the safe direction only by luck.
- **A shape grep is not a clean bill.** Finding no `ghp_`/`sk-`/`AKIA` proves
  those prefixes are absent, nothing more. Real secrets are bare hex, chosen
  passwords, and plain values in shell variables. Parse structured files; do not
  grep them as flat text.

### 7. Nothing is pushed until step 6 is clean

A push cannot be undone. Deleting the remote ref afterwards does not remove the
objects from the remote and does not remove them from anyone who fetched. If the
data was **already pushed**, the rewrite is not the end: the remote copy needs
force-pushing over, every fork and clone is out of reach, and any credential
involved must be rotated — treat rotation as the real fix, because it is the only
one you control.

**The push itself is always the operator's decision, every time.**

## Preventing the repeat

A commit message assembled by a shell is the case no diff review catches:
`git commit -m "… \`cmd\` …"` RUNS cmd and pastes its output into repository
metadata. On 2026-08-11 that put about ninety lines of environment — account
name, home paths, hostname, session ids, a real name and a second email address
— into a vouch commit message. It reached one step from a push.

So: a commit message goes through a file (`git commit -F`) or a single-quoted
here-document, or it contains no backticks at all. `$(…)` and bare `$NAME` expand
the same way. After writing any commit, read the message back — substitution is
silent, and a message is metadata nobody re-reads.

## Common mistakes

| Mistake | What it costs |
|---|---|
| `--no-verify` to get past a refused amend | Builds the habit that the check is the obstacle. Use plumbing. |
| Keeping the backup ref "for safety" | The data stays reachable and pushable. Delete it once the diff proves the rewrite. |
| Stopping at the rewrite | Old objects survive reflog + gc. `git cat-file -e` is the proof. |
| Checking only the commit you fixed | The other five hiding places are where it survives. |
| `--replace-text` alone in filter-repo | Rewrites blobs; leaves commit messages untouched. |
| Printing the value to show what was found | The transcript is a file. Name the pattern and the line. |
| Deciding to scrub quietly | It is the operator's call, and they need to know it happened. |
