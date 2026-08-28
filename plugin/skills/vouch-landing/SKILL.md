---
name: vouch-landing
description: Use automatically when a completed, reviewed vouch branch is ready to continue through the normal CI/CD and release route — private integration, CI, version pull request, exact mirror publication, tag/build verification, reinstall, probes, state docs, and teardown. Not for mid-branch work.
---

# vouch landing (finish + land a branch)

## Overview

The fixed landing sequence for a done vouch branch, in order, never
re-derived (operator rule: "landing an implementation branch — the fixed
pattern"). The operator's 2026-08-25 standing authorization covers the normal
remote writes in this sequence once readiness is established; do not stop to
ask for the same go again.

## Authorization boundary

Proceed automatically through private integration and push, CI inspection, an
exact release-please pull-request landing, public publish-branch push, exact-head
landing, tag, release verification, reinstall, probes, state docs, and cleanup.
Record the readiness numbers before the first remote write so the evidence is
auditable even though it is no longer an approval checkpoint.

Stop if the operator explicitly limited the task to local work or told the
session to stop. Also stop for a repository or credential exposure, a required
force/history rewrite, an unresolved conflict, missing credentials, a live
trust/config choice, or any departure from the scanned exact-object route.
Tooling may still display a platform approval prompt for an authorized command;
request that capability and continue when it is granted.

After the operator explicitly authorizes repairing a real privacy finding, do
not use `--no-verify` and do not hand the command back to them. If the clean
replacement is an ancestor of private master's exact advertised tip, use the
hook's only repair seam:
`VOUCH_ALLOW_SCANNED_ANCESTOR_REWIND=1 git push --force-with-lease=refs/heads/master:<bad-tip> origin <clean-ancestor>:refs/heads/master`.
The hook permits only private master, proves the ancestry direction, and scans
the replacement's complete reachable history before sending anything. A
divergent replacement, another ref, stale lease, or any finding still refuses;
those remain new operator decisions rather than reasons to bypass verification.

## Preconditions

Final whole-branch review clean; full gate green
(`VOUCH_REQUIRE_REAL_CORPUS=1 bash scripts/verify.sh`); working
tree clean. The ordinary spelling is not a weaker gate: its reusable PASS
is bound to the exact repository contents, real corpus, gate environment, and
toolchain. A cleanup edit makes it run again.

Before starting the final gate, include every intended new file in the index
and run `git diff --check` plus `git diff --cached --check`. The ordinary
worktree check cannot see untracked files, so gating before this preflight can
waste a valid receipt on whitespace that staging reveals afterward. Leave the
candidate bytes unchanged from that preflight through the commit.

### Required-gate recovery

A required gate is complete only when it records a successful PASS over the
final required inputs. If an already-authorized required gate fails, enter
bounded diagnose, fix, and rerun recovery automatically. A failed attempt does
not consume an "exactly once" condition, and an in-scope fix that changes gate
inputs makes the next execution owed rather than redundant. Do not pause for
new authorization when the approved finish line already requires that PASS.

Do not mechanically rerun unchanged failing inputs. Diagnose first, then rerun
only after a relevant fix, or when the failure is demonstrably transient and
the workflow already authorizes that retry. Keep the plan's turn and stall
bounds in force. Privacy findings, new permissions, scope expansion, and the
authorization boundary above still stop recovery.

Never repeat a matching successful PASS merely to recover output. Use the
receipt and report-recovery commands below. When the finish condition names
`--rerun-current-inputs`, rerun that spelling after a fix because the final
inputs changed; ordinary receipt-aware verification remains the recovery path
when no forced final observation was required.

## Observing long-running gates

Keep one attached watcher on a long-running verifier or publisher. Let that
watcher wait for output or process exit and notify the active turn; yield to
that completion event instead of repeatedly polling the process from the agent
turn. If the client only supports bounded waits, keep them inside that one
watcher rather than issuing a new process query each time.

Once an exact-input gate starts, freeze the entire worktree until it exits.
That includes tracked edits, untracked public-manifest files, formatting, and
temporary changes that will be restored: the publisher assembles the source
tree more than once, and the reusable receipt fingerprints its inputs. Record
a procedural note after the process exits and before the next gate instead of
changing the tree underneath the running one.

## Steps

Run from the vouch checkout root; every path below is relative to it.

1. **Cleanup on the branch, BEFORE merge.** Run `/simplify` (code-simplifier)
   over the branch diff, then run
   `VOUCH_REQUIRE_REAL_CORPUS=1 bash scripts/verify.sh`. Scoped-review
   the cleanup diff (it touched reviewed code). A changed input forces the full
   gate; an unchanged tree reuses its exact PASS. Transfer every deferred
   finding into `docs/ROADMAP.md` — scratch under `.superpowers/` dies with the
   worktree.

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
     on 2026-08-10 — one carried a scanner-capability claim that had lagged
     Python's M1.4 scanner, which would have made an agent fabricate a
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

   Recover already-measured gate numbers with `bash scripts/verify.sh --last`;
   use `--last-report` when the whole safe report is needed. Never rerun the
   full verifier merely because terminal output or session context was lost.
   Rerun only when `--last` refuses freshness, the latest attempt failed and
   recovery is owed, or an explicit post-change gate is owed. Live-state assertions are snapshots:
   refresh the relevant probe, not the release and publisher suites.

   When the latest attempt failed only in the isolated publisher phase, the
   same ordinary spelling reuses exact-input PASSes for the optimized core
   and the five independent short suites, refreshes the cheap live
   observations, and reruns the publisher. The top-level receipt correctly
   remains failed until that retry completes. Use `--rerun-current-inputs` only
   when a new observation over already-proven current inputs is explicitly
   required.

   **Before the first remote write, record the complete route from this
   branch to the finished release.** Do not summarize landing as merge, push,
   reinstall and teardown; those are only part of this repository's flow.
   Derive and report all of these from the current branch and files:
   - how the implementation enters the private `master` (this procedure's
     direct fast-forward, not an implementation pull request);
   - the conventional prefixes in `master..<branch>` and, for every authored
     `feat`/`fix`, the complete structured release-note block; derive whether
     release-please will open a private version pull request and the expected
     next version from the strongest nested entry plus
     `.release-please-manifest.json` — the private summary is filtered;
   - whether `git diff --name-only master...<branch>` intersects the publish
     `MANIFEST` in `scripts/publish-mirror.sh`;
   - every review boundary, in order: exact-land the private version pull
     request with `scripts/land-private-release.sh` when release-please opens
     one, then review the public publish pull request and exact-land its scanned
     head when published files changed;
   - what follows those landings: mirror verification, public tag and release
     build, paired live reinstall, changed-skill reinstall, live probes, state
     docs, and branch teardown;
   - the final target state: versions aligned here and in the mirror, published
     archives verified, live binaries and knowledge matching, and no leftover
     feature branch.

   If any part is unavailable or not yet verified, name it as a readiness gap
   and close it before proceeding. A genuine blocker uses the authorization
   boundary above; readiness itself does not require another operator answer.

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

4. **Merge + push** (fast-forward), then `git push origin master` after the
   readiness record and safety scan are complete. The standing authorization
   covers this normal push. It goes to the private development remote; the
   public repository never receives dev history.

4a. **Publishing, when the changeset touches published files.** Publishing is
   a distinct exact-object phase inside the automatic finish line:
   **The fixed route is automatic.** Run the local dry run, scans, history
   checks, private version pull-request exact landing, public publish pull request,
   exact landing, verification, and tag when this point is reached. The
   standing authorization covers those normal remote writes. It never covers
   a history rewrite or a departure from this route.
   1. If release-please opened a version pull request here on the step 4 push,
      run `bash scripts/land-private-release.sh <pr-number>` as the dry run,
      review its exact one-commit/head/body/range/all-ref evidence, then run
      `bash scripts/land-private-release.sh <pr-number> --land`. That executable
      repeats the reads at the mutation boundary, uses exact leases, and
      fast-forwards private master to the already-scanned PR head. It then
      proves the forge marked that exact object merged, repeats the all-ref
      audit, and deletes the generated branch. **Never use `gh pr merge`, the
      forge merge button, squash, rebase, or merge mode for a private release
      PR:** every one synthesizes an object that did not exist during review.
      The workflow's registered release-please plugin sanitizes both generated
      text views and scans the title, body, paths, and every candidate file
      before its remote write; a second cleanup commit is a defect, not an
      accepted transient. Exact-land the clean version PR before publishing —
      the mirror only picks up the new version once this repository's own
      version fields carry it.
   2. Dry run: `bash scripts/publish-mirror.sh <public-clone>` with no flag —
      read the scan result, diffstat, and assembled public candidate's locked
      release-test result. Before `--push`, the publisher repeats assembly,
      privacy checks, and mutation-boundary scans; it reuses only an exact
      matching candidate test PASS and otherwise runs the owed test. This
      catches tests or runtime code that still reach a private-only file after
      the manifest removes it without repeating an unchanged test.
   3. `--push` — pushes a `publish/*` branch and opens a pull request in the
      mirror. Nothing has reached its master yet.
   4. Review that pull request against the scanned candidate, but do not use a
      forge merge method: merge, squash, and rebase each create an object the
      publisher did not scan.
   5. `--land <publish-branch>` — fetches and rescans the exact remote head,
      requires an open, ready, clean pull request whose head and base match,
      then fast-forwards mirror master to that same commit without force. The
      forge marks the pull request merged because its head became reachable.
   6. `--verify <publish-branch>` — proves master is the exact published tree
      and audits published author, committer, and annotated-tagger identities.
   7. `--tag <publish-branch>` — re-runs the verify itself, scans the new tag's
      message and identity, then tags the mirror, which starts
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
- Merging or pushing before readiness, review, and privacy evidence are clean;
  asking again after they are clean recreates the friction this skill removes.
- Using the forge merge button on a public publish pull request; `--land` is
  the only path that preserves the exact scanned commit.
- Using any forge merge method on a private release pull request;
  `scripts/land-private-release.sh --land` is its only exact-object path.
- Treating the docs sweep as a landing chore. It is a plan task that runs
  before the final review; this skill refuses to start without its report.
- Reinstalling the knowledge but not the skills when the branch changed both.
- Trusting that a doc is true because a task "did documentation". The parts of
  this repo that never drift are the ones with a test asserting doc against
  code; the parts that drift are the ones guarded by attention.
