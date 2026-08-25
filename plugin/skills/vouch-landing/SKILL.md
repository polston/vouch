---
name: vouch-landing
description: Use when a completed, reviewed vouch feature branch needs to be merged to master and landed live — the merge, push, binary rebuild, knowledge reinstall, live-config migration, and worktree teardown. Not for mid-branch work.
---

# vouch landing (finish + land a branch)

## Overview

The fixed landing sequence for a done vouch branch, in order, never
re-derived (operator rule: "landing an implementation branch — the fixed
pattern"). Merge and push happen ONLY on the operator's explicit go, after
they have seen the numbers.

## Preconditions

Final whole-branch review clean; full gate green
(`VOUCH_REQUIRE_REAL_CORPUS=1 cargo test --release`); working tree clean.

## Steps

Run from the vouch checkout root; every path below is relative to it.

1. **Cleanup on the branch, BEFORE merge.** Run `/simplify` (code-simplifier)
   over the branch diff, then re-run the full gate. Scoped-review the cleanup
   diff (it touched reviewed code). Transfer every deferred finding into
   `docs/ROADMAP.md` — scratch under `.superpowers/` dies with the worktree.

1a. **The docs sweep is a PLAN TASK, and it runs BEFORE the final
   whole-branch review — not here, and not "if the changeset didn't do it".**
   Learned 2026-08-10: a branch whose plan already contained a docs task, and
   which then passed a whole-branch review, still carried 20 false statements
   across 9 files. Both controls relied on someone remembering to look. Two
   rules follow, and they are not optional:
   - Every plan for this repo ends with a `finding-what-a-change-made-false`
     sweep task covering ALL of: `CLAUDE.md`, `docs/HANDOFF.md`,
     `docs/ROADMAP.md`, `docs/specs/` (INCLUDING earlier specs the change
     invalidated), `knowledge.toml` header and section comments,
     `vouch.example.toml`, `docs/reference/`, **`plugin/skills/`**, and source module
     doc comments. Skills are documentation and were swept for the first time
     on 2026-08-10 — one had been telling agents python has no scanner since
     the previous landing, which would have made an agent fabricate a
     verification result.
   - **This landing REFUSES to start without that sweep's report for this
     branch.** If there is no report, stop and run the sweep; do not proceed
     on the belief that a docs task covered it.
   Sweep first, review second: the reviewer must read corrected docs, so that
   what it catches is what the sweep MISSED rather than what the sweep was
   about to fix.

2. **Readiness.** Confirm a clean fast-forward
   (`git merge-base --is-ancestor master <branch>`), gate
   green at HEAD, and show the operator the numbers (test count, transition
   matrix, parse rate).

   **Before asking for the explicit go, show the complete route from this
   branch to the finished release.** Do not summarize landing as merge, push,
   reinstall and teardown; those are only part of this repository's flow.
   Derive and report all of these from the current branch and files:
   - how the implementation enters the private `master` (this procedure's
     direct fast-forward, not an implementation pull request);
   - the conventional prefixes in `master..<branch>`, whether release-please
     will open a private version pull request, and the expected next version
     from `.release-please-manifest.json`;
   - whether `git diff --name-only master...<branch>` intersects the publish
     `MANIFEST` in `scripts/publish-mirror.sh`;
   - every pull request the operator must merge, in order: the private version
     pull request when release-please opens one, then the public publish pull
     request when published files changed;
   - what follows those merges: mirror verification, public tag and release
     build, paired live reinstall, changed-skill reinstall, live probes, state
     docs, and branch teardown;
   - the final target state: versions aligned here and in the mirror, published
     archives verified, live binaries and knowledge matching, and no leftover
     feature branch.

   If any part is unavailable or not yet verified, name it as a readiness gap
   before asking. Then get the explicit go to merge + push.

2a. **If that check FAILS, master moved while the branch was in flight, and
   the landing is a different job.** Do not force it and do not rebase a long
   branch under the operator. Merge master INTO the branch, resolve, and land
   the merge — then everything below still applies. Three things this repo
   got wrong the first time it happened (2026-08-18, a 53-commit branch
   against 21 commits of master):
   - **Re-measure against MASTER, not against the fork.** The number the
     operator approved was "what this branch does to the code it forked
     from". What they are actually merging is "what this branch does to
     master as it stands now". Dump both and diff (see the measurement note);
     if master moved no rows, the two numbers agree and saying so is cheap.
   - **Never resolve a conflict in a SHARED test helper with
     `git checkout --theirs`.** It takes that whole file and silently drops
     everything your side added to it — a helper the branch introduced simply
     vanishes, and the failure surfaces as an unrelated compile error in a
     test file. Resolve by combining, then prove it: list the symbols BOTH
     sides declared and grep the merged file for each by name.
   - **Check for a duplicate roadmap number.** Two concurrent branches can
     both mint `M2.<n>`, and neither can see the other. Renumber the one that
     has not landed, correct whatever pointed at it, and say in the row why
     the number moved.

3. **Pre-push safety scan (mandatory — the corpus is gitignored and must never
   reach origin).** Over the push range `origin/master..master`, confirm with
   COUNTS ONLY (never print values): zero corpus / harvested-history / `.jsonl`
   files added (`--diff-filter=A --name-only`), and zero account-name / email /
   home-path in added lines AND in commit messages. Any hit → STOP and tell
   the operator.

   Since 2026-08-11 vouch also ENFORCES this: `scripts/githooks/pre-push`
   (installed by `scripts/install-hooks.sh`) refuses a push whose commit messages,
   author metadata, added paths or patch text carry private data, and
   `commit-msg`/`pre-commit` refuse it a step earlier. `core.hooksPath` points at
   generated dispatchers in the shared `.git`, and a checkout with no tracked
   hooks REFUSES rather than passing quietly. Still confirm the hooks are live in
   the tree you are in — `bash scripts/install-hooks.sh` regenerates and self-tests
   — rather than assuming an earlier session's install covers this worktree, and
   remember `--no-verify` bypasses all three, so the manual scan is still worth its
   two minutes on the final push.

   **What this step exists to catch, stated once so it is not re-learned:** on
   2026-08-11 a commit message was written as `git commit -m "… \`cmd\` …"`, the
   shell RAN the backticked command, and its output — about ninety lines of
   environment, including the account name, home paths, hostname, session ids, a
   real name and a second email address — became the commit message. This scan
   caught it; nothing was pushed. Never put backticks, `$(…)` or `$NAME` in a
   commit message that reaches a shell: pass the message with `git commit -F` or
   a quoted here-document, and read back what was actually written.

4. **Merge + push** (fast-forward), then `git push origin master` — only after
   the operator's explicit approval. The push goes to the private development
   remote; the public repository never receives dev history.

4a. **Publishing, when the changeset touches published files.** Landing does
   not publish; publishing is its own act, and it is the operator's:
   1. If release-please opened a version pull request here on the step 4
      push, fetch its generated branch and run the all-ref history audit before
      offering it for merge. The branch must be exactly one commit ahead of
      current private master, its final changelog and pull-request body must be
      forge-remnant-free, and all six history checks must be clean. The
      workflow's registered release-please plugin sanitizes both views and
      scans the title, body, paths and every candidate file before the remote write; a
      second cleanup commit is a defect, not an accepted transient. Merge the
      clean version pull request first — the mirror only picks up the new
      version once this repository's own version fields carry it.
   2. Dry run: `bash scripts/publish-mirror.sh <public-clone>` with no flag —
      read the scan result and the diffstat.
   3. `--push` — pushes a `publish/*` branch and opens a pull request in the
      mirror. Nothing has reached its master yet.
   4. The operator merges that pull request.
   5. `--verify` — proves the merge landed exactly what was published; refuses
      naming the differing paths if not.
   6. `--tag` — re-runs the verify itself, then tags the mirror, which starts
      the build. A cycle of only docs/test/refactor/chore commits has no new
      version to tag; that refusal is an ordinary idle cycle, not a failure —
      or the version pull request release-please opened here has not been
      merged yet, in which case merge it and publish again before tagging.

5. **Landing turn, same session.** The new binary HARD-REFUSES the old config
   and knowledge spellings (whole file → the gate recognises nothing and fails
   closed, every command asks), so the migrations MUST ride with the reinstall:
   1. **Rebuild and reinstall in ONE shell invocation — never two tool calls.**
      Derive the shared main checkout root first — this runs against the main
      checkout, not the branch's own worktree — then chain everything through
      it in the same invocation:
      `root="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")" && cd "$root" && cargo build --release && bash scripts/install-binaries.sh && bash scripts/install-knowledge.sh --force`
      Learned the hard way 2026-08-10: between a rebuilt binary and a
      reinstalled knowledge file the gate is DEAD — the new binary refuses the
      old file, so it recognises nothing and asks about every command,
      including the very command that repairs it, and the operator gets a
      wall-of-banner prompt for a later install call.
      Neither order avoids it (the old binary equally refuses the new file's
      unknown keys), so the only fix is to leave no gated tool call in the
      window. Chain them.
   2a. `scripts/install-skill.sh --force` **whenever the branch touched
      `plugin/skills/`** — the installed copy is what agents actually read, so a
      corrected skill left uninstalled keeps handing out the old, false claim.
      Check with `git diff <fork>..HEAD --name-only -- plugin/skills/`; do not assume
      the branch left them alone.
   3. Migrate the operator's live files IF they still use an old spelling (back
      each up first, then validate no old spelling remains): `config.toml`
      `[bash]`/`[powershell]` → `[lang.*]`; `my-knowledge.toml`
      `[[tool.payload]]` → `[[tool.snippet]]`. The current spellings are named
      in `docs/HANDOFF.md`'s landing note — read it, do not assume.
   4. Re-verify the live gate: `vouch explain 'ls -la'` shows NO gap/refusal
      banner, and a probe behaves (e.g. a write into a `deny_paths` tree DENYs).
   5. **Probe the changeset's OWN new asks against the operator's real
      config, and report every one that turns out to be inert.** A construct
      the live config does not NAME inherits its donor's action (M2.115), so
      a fix can be merged, installed, probed green — and decide nothing. On
      2026-08-18 the script-file ask landed while the live config named
      `dynamic_command = "allow"` and never named `evaluated_input`: `bash
      <script>` kept allowing, and the whole shell half of the changeset was
      switched off by a line that was not there.
      This is CLAUDE.md §8.1 in its live form. For each construct the
      changeset relies on: grep the live config for the KEY NAME (never the
      value), probe the behaviour, and if it is inert, tell the operator what
      naming it would cost — the per-view corpus number the changeset already
      measured. **Turning it on is their decision, not the landing's.**

6. **Teardown.** `git branch -d <branch>`; `git worktree remove --force <path>`
   deregisters it. The owning session CANNOT physically delete its own worktree
   dir — its shell cwd is pinned inside, so the delete fails "resource busy" /
   "permission denied". Leave the orphaned dir and note it; `vouch-session-start`
   deletes it next session. Do NOT loop retrying the delete.

7. **State docs.** Update `docs/ROADMAP.md` (item → DONE, merged + landed) and
   `docs/HANDOFF.md` (mark the landing obligations done), commit + push.

8. **If the session continues past the landing, it ends with
   `vouch-session-end`.** Step 7 makes the docs true about the BRANCH. A live
   config edit, a push, or a reinstall done afterwards makes them false again,
   and those are precisely the sentences a fresh session reads first.

## Measurement note

**Take both ends of a replay from the SAME directory, and from a tree
nobody else is editing.** A relative write resolves against the process's own
directory, so dumping the two ends from two places measures the places
(ROADMAP M2.47). On 2026-08-18 that reported 26 rows moving toward ALLOW on a
changeset that had moved 1 — 25 phantom rows, chased for half an hour, gone
the moment both dumps were taken from one checkout. If another session is
editing the worktree, make a detached checkout of the two commits and measure
there; two reviewers caught exactly that and re-took their numbers.

For any replay / transition-matrix number, use a before/after RECONSTRUCTION
(dump under old code+knowledge vs new, then diff). Since M2.103 the dumps are
ON-DEMAND MEASUREMENTS under `examples/`, not ignored tests (the old
`cargo test … -- --ignored` spelling no longer exists):
- per-row verdicts (the movement diff): `VOUCH_DUMP_PER_ROW=<abs path> cargo run --release --example dump_per_row_verdicts` (one JSON `{"i":N,"verdict":"…"}` per corpus row)
- verdict + reason first line: `VOUCH_DUMP_DECISIONS=<abs path> cargo run --release --example dump_decisions`
Destinations must be ABSOLUTE and outside the repo. For a knowledge-only
change, dump once, swap in the git-extracted old `knowledge.toml`
(`git show <base>:knowledge.toml > …`; the loader reads the working-tree
copy), dump again, restore, and diff. For a code change, dump at the branch
base BEFORE any src edit (once a src file has changed the baseline cannot be
taken on that tree), dump again at the tip, diff. The gate's `replay_test`
asserts NO target by design and cannot detect movement — never cite its PASS
as a zero-rows-moved number (that mistake was made and caught in the M2.132
plan review). `tests/fixtures/replay_baseline.jsonl`, if present, is a stale
artifact from before M2.103 — never diff against it (roadmap M2.81).

## This skill fixes itself

Every step below was written because something went wrong once. When a landing
turns up another one — a step in the wrong order, a missing step, a stale
claim, a warning that would have saved the turn you just spent — edit this file
in the same turn and say one line that you did. Do not work around it silently:
the next session reads this file, not that conversation. (Global rule: skills
are living procedures.) Three steps here exist only because of that: the
sweep-before-review rule, the skill reinstall, and chaining the rebuild with
the knowledge install.

## Common mistakes

- Migrating the live config/my-knowledge BEFORE the new binary is installed
  (the old binary then refuses the new spelling) — or forgetting them and
  breaking the live gate after the reinstall. Do them together (step 5).
- Looping on the worktree delete — the owning session cannot win that; defer it.
- Diffing the on-disk replay baseline and reporting a false zero.
- Merging or pushing before the operator's explicit go.
- Treating the docs sweep as a landing chore. It is a plan task that runs
  before the final review; this skill refuses to start without its report.
- Reinstalling the knowledge but not the skills when the branch changed both.
- Trusting that a doc is true because a task "did documentation". The parts of
  this repo that never drift are the ones with a test asserting doc against
  code; the parts that drift are the ones guarded by attention.
