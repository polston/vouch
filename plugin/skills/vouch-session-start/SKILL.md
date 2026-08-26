---
name: vouch-session-start
description: Use at the first turn of a working session in the vouch repository checkout or any of its worktrees, or whenever the operator asks what's next / where things stand there — before touching code or asking the operator anything. Starts the queue item and automatically carries ready work into vouch-landing through release verification.
---

# vouch session start

## Overview

Orient from the project's own state files, check that what they claim is
still true, clear leftovers from prior sessions, and start the top of the
queue. The operator should never have to re-explain the state or be asked
"what do you want to do?" — the roadmap IS the work queue (operator rule:
"roadmap = execution order"). A green implementation branch is not the
default stopping point: the session owns the queue item through its verified
live release.

## Default finish line and skill chain

The operator set a standing rule on 2026-08-25: when the scoped implementation
is good, proceed automatically through this repository's normal CI/CD and
release process. Plan the complete route at session start. After implementation,
the docs sweep, review, cleanup, tests, and privacy checks pass, invoke
`vouch-landing` without asking for another go. After landing, invoke
`vouch-session-end` to reconcile anything that changed later.

This standing authorization covers the fixed release route only. An explicit
local-only, no-push, or stop instruction overrides it. Stop for a repository or
credential exposure, a force/history rewrite, an unresolved conflict, missing
credentials, a live trust/config choice, or a required departure from the
exact-object publisher. A platform approval prompt may still be required to
execute an authorized command; request it and continue when granted.

## Do this, in order

Run from the vouch checkout root; every path below is relative to it.

### 1. Sweep the worktrees a prior session could not delete

A session whose shell cwd is pinned inside its own worktree cannot remove it
(fails "resource busy" / "permission denied" — see `vouch-landing`); it
defers the physical delete to the next session. A fresh session is not pinned
there, so it can finish the job.

```
root="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
git worktree list
git worktree prune
```

- For any checkout under `$root/.claude/worktrees/<name>` whose branch
  is already merged or gone, or that `worktree list` no longer shows:
  `rm -rf "$root/.claude/worktrees/<name>"` and
  `rm -rf "$root/.git/worktrees/<name>"`, then `worktree prune` again.
- **`worktree list` is the authority, not that directory.** A measurement or
  review checkout is often registered somewhere else entirely — under the
  system temp directory, for instance — and reading only
  `.claude/worktrees/` misses it while `git` still tracks it. Remove those
  with `git worktree remove --force <path>`.
- Confirm each is gone. If one is STILL busy, THIS session is pinned in it
  too — leave it, note it, do not loop.
- Never touch a worktree whose branch is unmerged or that is marked `locked`.
  That is in-flight work, not an orphan. Check with
  `git merge-base --is-ancestor <branch> master` rather than by the name.

### 2. Read the two state docs

`docs/HANDOFF.md` — what is live, what is in flight, what decision is open.
`docs/ROADMAP.md` — the one ordered queue; find the top item whose status is
not `DONE`, and read the ordered table near the top rather than the first
`OPEN` row you hit, because the queue's order is stated there.

### 3. Check the handoff against the machine before believing it

The handoff is a claim written by a session that has since ended. Two
questions are worth one command each, and both have been wrong before:

```
root="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
git fetch origin && git rev-list --count origin/master..master
cmp "$root/knowledge.toml" "$HOME/.config/vouch/knowledge.toml" && echo "installed knowledge matches the repo"
```

Anything the handoff asserts that these contradict is corrected in the
handoff before the session's work starts — not after, because everything
downstream reads it. The full list of checkable claims is in
`vouch-session-end` step 2; this is the fast subset worth paying for at
every start.

### 4. If a branch is mid-flight, trust its ledger over any summary

Its worktree holds `.superpowers/sdd/<plan>/progress.md` and often a
`RELOAD.md`. That ledger and `git log` are written as the work happens; a
summary is not (per `superpowers:subagent-driven-development`). Read the
ledger's last lines and the branch's last commits before deciding anything is
done or not done.

### 5. Report and proceed through the finish line

A few lines: what is live, the next OPEN roadmap item in plain words, and any
still-open landing obligation or operator decision. Then start that item and
continue through the default finish line above.

Do not ask "what's next" — the operator has said the roadmap is the queue.
Stop only if the top item needs a decision that is genuinely theirs, and then
ask exactly that one question.

## Common mistakes

- Asking the operator where things stand instead of reading the two docs.
- Believing the handoff's live-state sentences without checking the two
  commands in step 3. "Not pushed" and "the installed knowledge matches" are
  the two that go stale first.
- Deleting a worktree whose branch is unmerged or `locked`.
- Reading only `.claude/worktrees/` and missing a checkout registered
  elsewhere.
- Reporting the next item as a bare `M#.#` id — say what it IS (operator
  rule: "never talk to me in codes").
- Treating a long report as the deliverable. The deliverable is the work
  started.
- Treating passing tests or a clean branch as a natural stopping point instead
  of chaining into `vouch-landing`.

## This skill fixes itself

When a session-start turns up a step in the wrong order, a missing check, or
a claim that has gone stale, edit this file in the same turn and say one line
that you did (global rule: skills are living procedures).
