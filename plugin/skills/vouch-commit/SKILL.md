---
name: vouch-commit
description: Use when writing any commit message in the vouch repositories — the conventional prefix, the structured release-note block for feat/fix commits, the plain-prose body, and the composition traps the hooks exist to catch.
---

# vouch commit

## Why a message is worth a skill here

A `feat:` or `fix:` commit has two readers. Its subject summarizes the private
changeset. Its `BEGIN_NESTED_COMMIT` block is the public source release-please
expands into `CHANGELOG.md`; the manifest plugin removes the summary and keeps
the nested entries. The changelog then publishes to the mirror. The other
prefixes (`docs`, `test`, `refactor`, `chore`) stay in private history and need
no release-note block.

This split is deliberate. One summary cannot enumerate a changeset, and a diff
cannot decide automatically which paths represent visible outcomes. Record the
judgment while the change is understood; the commit hook and release workflow
then enforce that the source exists and expands.

## The shape

For a release-bearing commit:

```
<feat/fix prefix>: <one plain sentence summarizing the private changeset>

<body: why, and what it closes — a few short paragraphs>

BEGIN_NESTED_COMMIT
<feat/fix prefix>: <one independently observable public outcome>

<feat/fix prefix>: <another independently observable public outcome>
END_NESTED_COMMIT
```

For `docs`, `test`, `refactor`, or `chore`, stop after the ordinary subject and
body. Do not add an inert release-note block.

1. **Prefix**, one of: `feat` `fix` `docs` `test` `refactor` `chore`. The
   commit hook refuses anything else and names the set. For a breaking release,
   use `feat!:` or `fix!:` on the summary and on the affected nested entry;
   nested entries, not the filtered summary, determine the released version.
   The summary prefix must match the strongest nested impact: fix, then feat,
   then breaking.
2. **Subject** — a sentence, not a label. It summarizes the complete private
   commit in present tense with no trailing period. It need not be a good
   changelog bullet because it is deliberately filtered from public notes.
   - yes: `fix: a relative cwd yields no project root, instead of
     borrowing the process's directory`
   - no: `fix: update route.rs`, `fix: address review feedback`
3. **Body** — why the change exists and what it closes, in plain prose.
   Consequence first, mechanism only where the mechanism is the lesson.
   Numbers that were measured, stated as measurements. No bullet-list
   fragments; short paragraphs.
4. **Release-note block** — exactly one, at the bottom of every authored
   `feat`/`fix` message, even when it contains only one entry. Each nonblank
   line is a complete `feat:`/`fix:` entry; use `feat!:`/`fix!:` for a break.
   Include one line for each independently observable behavior, configuration
   or schema change, operator workflow change, and correction to prior notes.
   Omit tests, refactors, generated mirrors, and docs that only restate another
   line. Never put a private forge link or commit identifier in public notes.

## The composition rules (each one is a hook, not advice)

1. **Never compose a message on a shell command line.** Backticks,
   `$(…)` and `$NAME` inside a double-quoted `-m` EXPAND: one commit
   here once swallowed ninety lines of environment that way. Always:

   ```
   git commit -F - <<'MSG'
   feat: the subject
   
   The body.

   BEGIN_NESTED_COMMIT
   feat: the independently observable public outcome
   END_NESTED_COMMIT
   MSG
   ```

   The quoted `'MSG'` delimiter is what makes the content literal.
2. **No backticks anywhere in the message**, even for code names — the
   risk outlives the convenience. Quote names with nothing, or say them
   plainly.
3. **The message is scanned before it is accepted** (private data, then
   the prefix, then the structured release-note block). A refusal names its
   cause and the message survives in the named file for editing. Never
   `--no-verify`.
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

One commit per landable idea. One idea may have several independently visible
outcomes; that is what the release-note block enumerates. If the body needs a
heading, it is two commits. If the subject needs "and", it is usually two
commits — unless the two halves are one mechanism, in which case say the
mechanism and keep the public outcomes separate.
