---
name: vouch-commit
description: Use when writing any commit message in the vouch repositories — the conventional prefix, the subject that becomes a release-notes line, the plain-prose body, and the composition traps the hooks exist to catch.
---

# vouch commit

## Why a message is worth a skill here

A `feat:` or `fix:` subject in this repository IS a public release-notes
line: release-please collects them verbatim into `CHANGELOG.md`, the
changelog publishes to the mirror, and the publisher puts that account in the
exact candidate commit that `--land` fast-forwards to mirror master. A subject
written lazily is published lazily. The other prefixes (`docs`, `test`,
`refactor`, `chore`) never appear in release notes — they are for the
private history's readers.

## The shape

```
<prefix>: <one plain sentence: what is true after this commit>

<body: why, and what it closes — a few short paragraphs>
```

1. **Prefix**, one of: `feat` `fix` `docs` `test` `refactor` `chore` —
   with `feat!:`/`fix!:` or a `BREAKING CHANGE:` footer for a break. The
   commit hook refuses anything else and names the set.
2. **Subject** — a sentence, not a label. It states the change's
   CONSEQUENCE, present tense, no trailing period, and it must read
   correctly alone in a release-notes list. The house test: would the
   line make sense to someone who sees only it?
   - yes: `fix: a relative cwd yields no project root, instead of
     borrowing the process's directory`
   - no: `fix: update route.rs`, `fix: address review feedback`
3. **Body** — why the change exists and what it closes, in plain prose.
   Consequence first, mechanism only where the mechanism is the lesson.
   Numbers that were measured, stated as measurements. No bullet-list
   fragments; short paragraphs.

## The composition rules (each one is a hook, not advice)

1. **Never compose a message on a shell command line.** Backticks,
   `$(…)` and `$NAME` inside a double-quoted `-m` EXPAND: one commit
   here once swallowed ninety lines of environment that way. Always:

   ```
   git commit -F - <<'MSG'
   feat: the subject
   
   The body.
   MSG
   ```

   The quoted `'MSG'` delimiter is what makes the content literal.
2. **No backticks anywhere in the message**, even for code names — the
   risk outlives the convenience. Quote names with nothing, or say them
   plainly.
3. **The message is scanned before it is accepted** (private data, then
   the prefix). A refusal names its cause and the message survives in
   the named file for editing. Never `--no-verify`.
4. **Read the message back after committing** (`git log -1 --format=%B`)
   — substitution and truncation are silent, and nobody re-reads
   messages later.

## Exemptions you do not need to work around

Messages git composes itself pass without a prefix: merges, reverts
(including a conflicted revert resumed with `--continue`), `fixup!`/
`squash!` markers, and any commit being replayed by rebase or
cherry-pick. If the hook refuses one of those shapes, that is a defect to
report, not a reason for `--no-verify`.

## Sizing

One commit per landable idea. If the body needs a heading, it is two
commits. If the subject needs "and", it is usually two commits — unless
the two halves are one mechanism, in which case say the mechanism.
