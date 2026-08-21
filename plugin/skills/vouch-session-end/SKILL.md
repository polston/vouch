---
name: vouch-session-end
description: Use when a working session in the vouch repository is ending — the operator says they are stopping, asks whether it is safe to start fresh, or the work reaches a natural stopping point. Makes the state docs true again before the session's memory disappears. Not for landing a branch (that is vouch-landing), and not a substitute for it.
---

# vouch session end

## Overview

A session ends when the machine and the state docs agree, and the next
session can be told everything it needs by reading two files. Nothing else
about ending is interesting.

The failure this exists to prevent is specific and it has happened: on
2026-08-18 the handoff said "not pushed" and "this setting is inert" twenty
minutes after the same session pushed and turned the setting on. Both were
written truthfully and both were false by the end of the turn. Nobody
noticed until the operator asked whether it was safe to stop — which is not
a control, it is luck.

**`docs/HANDOFF.md` is a claim about the machine. The machine is the
evidence.** Every live-state sentence in it is checkable in one command, so
check it rather than remembering whether it still holds.

Run from the vouch checkout root; every path below is relative to it.

## STEP ZERO — is there unmerged branch work? Then this is the wrong skill

Run this before anything else:

```
git worktree list
git branch --no-merged master
```

**If a branch has commits not on master, STOP. `vouch-landing` runs FIRST,
in full, and this skill runs after it.** Landing has preconditions this one
knows nothing about — a docs sweep, a clean whole-branch review, a cleanup
pass, the operator's explicit go on the merge — and none of them happen by
finishing a session tidily around the branch.

Added 2026-08-19, on the operator's correction, after this skill was run on a
session holding a five-commit unmerged branch and reported the session
"closed out". Everything it did was correct and the session was not over:
the branch had had no review, no `/simplify` pass, no docs sweep, and the
worktree was still live. Writing a truthful handoff ABOUT unfinished work
reads, to the next session and to the operator, exactly like finished work.

The old text below mentioned `vouch-landing` only in the past tense — "a
session that landed a branch has already done part of this" — which covers
the case where landing already happened and says nothing about the case
where it should. That silence was the defect.

Two things this does NOT mean. A branch the operator has deliberately parked
is not a landing — name it in the handoff as parked, with what it is waiting
on, and carry on with this skill. And if the operator says to stop with the
branch mid-flight, that is their call: end the session, and say plainly in
the handoff that the branch is unlanded and which landing steps remain.

## When this runs, and when it does not

- Runs at the end of ANY vouch session, including one that only investigated
  and changed no code. An investigation still produces findings, and a
  finding that lives only in the conversation is gone.
- `vouch-landing` covers the end of a BRANCH. It ends with its own state-doc
  step, so a session that landed a branch has already done part of this —
  but only the part about the branch. Anything the session did after the
  landing (a live config edit, a push, a knowledge reinstall) is exactly what
  goes stale, so run this too.
- Never invent the next task here. Deciding what runs next belongs to the
  roadmap and to `vouch-session-start`.

## Do this, in order

### 1. Find out what this session actually touched

Answer from commands, not from memory of the conversation:

```
git status --short
git log --oneline @{u}..HEAD
git worktree list
```

For every worktree: its own `status --short` and `log --oneline`. Uncommitted
work anywhere is either committed now or named in the handoff as
uncommitted — never left silent.

Also list what the session changed OUTSIDE the repository, because none of it
shows in git: the operator's live `config.toml` or `my-knowledge.toml`, an
installed binary, an installed knowledge or skill file, a push.

### 2. Reconcile every live-state claim in the handoff

Read `docs/HANDOFF.md` and check each sentence that asserts something about
the machine. These are the ones that go stale, with the command that settles
each:

| The claim | What settles it |
|---|---|
| "not pushed" / "N commits sit unpushed" | `git fetch origin` then `git rev-list --count origin/master..master` — fetch first, because the tracking ref is itself a stale claim |
| "merged and live" | the installed binary is newer than the merge, and `vouch explain 'ls -la'` shows no gap or refusal banner |
| "the installed knowledge matches the repo" | `cmp knowledge.toml "$HOME/.config/vouch/knowledge.toml"` — a commit after the last install stales it silently |
| "this construct/setting is on (or off)" | grep the live config for the KEY NAME, then probe the behaviour it governs — an unnamed construct inherits from its donor and decides nothing (M2.115) |
| "the skills are installed" | `diff` each `plugin/skills/*/SKILL.md` against `$HOME/.claude/skills/<name>/SKILL.md` |
| a measured number (gate, corpus, latency) | re-run it, or stamp it with the commit it was true at |

A claim that is now false is REWRITTEN, not annotated. A claim that has
become history ("it used to be X") is left alone — see
`core:finding-what-a-change-made-false` for the three-way classification,
which applies here in miniature.

### 3. Transfer anything living only in scratch

A finding in `.superpowers/`, in a review note, or in this conversation dies
with the worktree or the session. If it should outlive either, it goes in
`docs/ROADMAP.md` now — not "next time". CLAUDE.md §9 says never to ask
whether something goes on the roadmap; write it and say one line that you
did.

**Before writing a new row, check the number is free**: `grep -c "^| M2\.<n> |"
docs/ROADMAP.md`. Two concurrent branches both minted an `M2.132` in August
2026 and the collision only surfaced at the merge.

### 4. Say what the next session needs, in the handoff

The top of `docs/HANDOFF.md` is what a fresh session reads first. It should
answer, in this order: what is live right now, what is in flight and where,
what decision is open and waiting on the operator, and what was measured with
the numbers. Not a narrative of the session.

If a branch is mid-flight, name the worktree path and point at its own
progress ledger rather than summarising it — the ledger is written as the
work happens and the summary is not.

### 5. Report and stop

A few lines: what changed, what is now true that was not, what is open. Then
stop. Do not propose the next feature, do not re-run the gate to look busy,
do not tell the operator to rest.

## Common mistakes

- **Trusting the handoff because the session wrote it.** It was true when
  written. The question is whether it is true now.
- Treating "the tests pass" as the end of a session. The gate says the code
  is consistent; it says nothing about whether the docs describe the machine.
- Ending a session whose only output was investigation without writing the
  findings down, on the grounds that no code changed.
- Leaving a temporary measurement checkout registered. `git worktree list`
  shows every one; a checkout under the system temp directory is still the
  repository's problem.
- Announcing the next task. That is the next session's first move, and it is
  made from the roadmap, not from what felt unfinished.

## This skill fixes itself

Every rule above exists because something went wrong once. When a session-end
turns up another one, edit this file in the same turn and say one line that
you did (global rule: skills are living procedures). A rule without a real
miss behind it is padding, and padding is how a checklist stops being read.
