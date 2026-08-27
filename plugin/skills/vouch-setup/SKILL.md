---
name: vouch-setup
description: Use when installing vouch on a machine or auditing an existing vouch setup — surveys the machine, replays its own session history to show what would fire, proposes scoped changes with evidence, and writes only on explicit accept.
---

# vouch-setup — set vouch up on a machine by evidence, not by defaults

vouch is a PreToolUse permission gate: every tool call the host exposes to
hooks is parsed, judged
against declared knowledge of what programs do, and answered allow / ask /
deny before it runs. Setting it up badly is easy and quiet — a config written
from guesses either asks about everything (and trains reflexive approval) or
grants trees nobody looked at. This skill sets it up from what the machine has
actually done: it surveys what is already there, replays that machine's own
recorded session history against a candidate config to see what would fire,
proposes scoped changes, and writes nothing without an explicit accept.

## Host model

Run the survey and wiring steps for every requested host. Claude Code exposes
four events vouch uses. Codex exposes `PreToolUse` and `PostToolUse`, with two
deliberate routes. Live gating implements an Ask as a blocked first attempt,
Codex's native approval prompt on the local MCP broker, and one exact retry.
Passive `--shadow` evaluates and journals every delivered call but emits
nothing; it needs no broker and leaves `approvals_reviewer = "auto_review"` (or
whatever reviewer is configured) and the native policy unchanged. Codex Allow
also emits nothing, so its native sandbox and approval policy remain
authoritative in either route.

Codex tool hooks cover shell commands, `apply_patch`, MCP tools, and most local
function tools. Hosted tools and some specialized paths are outside that hook
boundary. Report that boundary plainly: vouch is a guardrail over observed
calls, not a replacement for Codex's sandbox.

**The judgment rules are `vouch-trust`'s hard rules, and that skill is the
authority for them** — narrowest entry that covers the command, destructive
operations get no entry, read a tool's declared schema rather than guessing
from its name, nothing written without an accept. They are not restated here.
This skill adds machine-level procedure, not a second philosophy. When a
proposal in phase 4 is about recognising a program or a tool, follow
`vouch-trust` for the entry itself.

## Hard rules

1. **Nothing is written to any config or knowledge file except on the
   operator's explicit accept, per change.** Never batched into one blanket
   yes: one accept covers one change, and the next change asks again. The hook
   registration is not written by this skill AT ALL — it is produced by
   `vouch install` and saved by the operator (phase 2).
2. **Destructive shapes get no rule, ever.** They keep asking on purpose
   (`vouch-trust` hard rule 3). Say in one line that it stays a prompt
   deliberately, and move on.
3. **Every proposal names the evidence row count behind it and the exact
   setting or entry it would write.** "This would allow N calls out of the M
   replayed, and writes `write.allow_paths = [...]`" — a proposal with no
   number attached is a guess wearing a procedure's clothes.
4. **A host's complete hook/config document never enters the conversation — not by read and not by
   capture.** It can hold credentials in MCP server headers, and
   `vouch install`'s output is the ENTIRE merged settings document. So
   **every** invocation of `vouch install`, in every form, is redirected
   straight to a scratch file; its stdout is NEVER captured into the
   transcript, and that holds for `--print` too. A flag the running binary
   does not parse is silently swallowed, so a `--print` that was expected to
   emit only the hooks block can emit the whole document instead — redirecting
   both forms means the skill is not relying on which binary it is talking to.
   What this skill relays is the command's stderr notes plus the HOOKS BLOCK
   extracted from that scratch file, values-blind: read only the `hooks` key
   out of the JSON and show that. MCP server configuration lives under a
   different key and is never touched. The only reads of the live Claude
   `settings.json` or Codex `hooks.json` are targeted, values-blind greps — event names, matcher
   presence, whether a hook command mentions vouch — never a whole-file read,
   and never a grep that can print a value.
5. **Everything harvested from session logs stays on this machine and out of
   every repository.** The replay harness holds extracted commands in memory
   and writes no file of them by default. `--samples-dest` must be passed
   explicitly, must be absolute, and is refused when its canonical form
   resolves under any directory containing a `.git` entry. The scratch the
   replay does need — the throwaway `VOUCH_STATE_DIR` — goes under this
   session's scratchpad directory when one exists, else under the OS temp
   directory's `vouch-setup/` folder, never a repo, and is deleted when the
   phase ends. The replay journals every call there, one row per replayed tool
   call, and a journal row carries the command text (`cmd`) by construction: a
   journal of replayed history IS harvested command text.
6. **Replay runs always set `VOUCH_STATE_DIR`, and always invoke the binary by
   ABSOLUTE PATH — never through cargo.** The real journal is `vouch review`'s
   evidence and must not be polluted with replayed rows. And a vouch checkout's
   `.cargo/config.toml` pins `VOUCH_CONFIG`, `VOUCH_KNOWLEDGE` and
   `VOUCH_MY_KNOWLEDGE` with `force = true`, so a cargo-invoked run silently
   measures the repository's own files instead of the candidate ones — the
   numbers come back plausible and wrong. The harness enforces both, and before
   reporting any number it runs a **sentinel**: one synthetic call against a
   scratch copy of the candidate config carrying a distinctive marker rule,
   which must come back `deny` with journal `mode` `live`. It also refuses to
   measure a candidate config that stands down at the permission mode the
   replay stamps (`default`) — a stood-down replay suppresses every ask and
   deny, so every number after it would describe something else. A sentinel
   miss aborts and reports nothing; do not work around it.
7. **The gate gating its own setup is expected, per write, and stays.** On a
   machine where vouch is already live, this skill's accepted config writes
   land on the protected list and prompt every time; the release unzip writes
   into `~/.config/vouch/` and asks under `write.default = "ask"`. These are
   the protections working — say so plainly and answer the prompt. Proposing
   to remove or narrow a `[protected]` entry, or any grant, to smooth this
   skill's own flow is out of bounds.

## Phase 1 — survey (read-only)

Nothing is written in this phase. Establish what this machine actually has.
Run each check and put the answers in one table.

1. **Binaries and versions.** `vouch --version` and
   `vouch-codex-broker --version` identify a matched installed pair. If the
   names do not resolve, look under `~/.config/vouch/bin/` (the release layout)
   and at the two corresponding source builds under `<clone>/target/release/`.
2. **Which files it actually resolves.** Not which files exist — which pair
   this binary loads, because later checks must compare the live pair and
   never a plugin-cache reference copy. The rule: `VOUCH_CONFIG`,
   `VOUCH_KNOWLEDGE` and `VOUCH_MY_KNOWLEDGE` win when set in the environment
   the hook runs under; otherwise the defaults are
   `~/.config/vouch/config.toml`, `~/.config/vouch/knowledge.toml` and
   `~/.config/vouch/my-knowledge.toml`. There is no next-to-the-executable
   lookup. Confirm the resolved pair loads by running `vouch explain 'ls -la'`
   and checking the output carries NO gap banner — a banner names which of the
   three files is absent, unparseable, or empty, and which one it is changes
   what the rest of this skill can conclude.
3. **`~/.config/vouch/` contents.** `ls ~/.config/vouch/` — which of the three
   files are present, and whether a `bin/` directory is there.
4. **The hook registration**, values-blind. For Claude Code, expect
   `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, and `PermissionDenied` in
   `~/.claude/settings.json`. For Codex, expect `PreToolUse` and `PostToolUse`
   in `~/.codex/hooks.json`, each with a command containing `--host codex`.
   Count event names, vouch command lines, `--shadow`, and `--state-dir`
   occurrences without printing values. A live Codex route also requires
   `codex mcp list` to name `vouch_approval`; a passive shadow route does not.
   Never read either file whole (hard rule 4).
5. **A cc-allow config at the old path**: `~/.config/cc-allow.toml`. Present
   means this is a migration, not a fresh install.
6. **A vouch clone**, if any — a directory holding `Cargo.toml` with the vouch
   package and a `knowledge.toml` beside it. A clone means the source route and
   the binary, knowledge, and skill install scripts are available.
7. **`gh` availability**: `gh --version`, and whether it is authenticated. The
   release-download path in phase 2 needs it.
8. **Plugin version lag.** On Claude Code, read the installed version from
   `~/.claude/plugins/installed_plugins.json` (the `plugins` map is keyed
   `<plugin>@<marketplace>`, and each key maps to a LIST of installed
   records — `version` and `installPath` live on the elements of that list,
   not on the key itself) and compare it against the marketplace entry's own
   `version` in
   `~/.claude/plugins/marketplaces/<marketplace>/.claude-plugin/marketplace.json`.
   The cache is version-keyed and a version bump alone moves nothing: an
   installed plugin sits at its install-time version until
   `claude plugin update <name>` runs (restart required). A lag is a FINDING —
   report it with both numbers. On Codex, use `codex plugin list` and compare
   the installed vouch plugin with the selected local marketplace entry.
9. **Session logs**: whether `~/.claude/projects/` exists and roughly how many
   `*.jsonl` files are under it. This is what phase 3 replays; no logs means
   phase 3 reports that and moves on. The current replay harness reads Claude
   Code's JSONL format only; do not present those counts as Codex traffic.

**End the phase with a one-table statement of which machine state applies.**
Exactly one:

| State | Recognised by |
|---|---|
| `fresh` | no `~/.config/vouch/config.toml`, and no `~/.config/cc-allow.toml` |
| `cc-allow` | no vouch config, but `~/.config/cc-allow.toml` present |
| `existing-vouch` | `~/.config/vouch/config.toml` present (whatever else is) |

`existing-vouch` wins over `cc-allow` when both are present: the migration
already happened, and phase 4 reviews the config that exists rather than
re-importing over it.

## Phase 2 — provision

The binary and its knowledge move together, from the same release, in one
step. They are version-gated against each other: between a new binary and an
old knowledge file the gate refuses everything, so never update one alone.

**Fresh machine, release route.**

1. Download the platform's bundle:
   `gh release download --pattern 'vouch-<target-triple>.zip'` — substitute the
   machine's Rust target triple (`x86_64-pc-windows-msvc`,
   `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`).
2. **Verify the archive against `SHA256SUMS` BEFORE anything is unpacked or
   run.** Download `SHA256SUMS` from the same release and check the archive's
   digest against it. Integrity first, semantics second: a file that fails this
   check is not unpacked, not run, and not reported as "probably fine".
3. Unzip into `~/.config/vouch/`. The archive's layout mirrors the destinations:
   both binaries land in `bin/`, `knowledge.toml` lands beside the config where
   the loader looks, and `vouch.example.toml` seeds `config.toml` only when no
   config exists.
4. Confirm the binary loads the pair — `vouch explain 'ls -la'` with no gap
   banner. This is the semantic check, and it comes after the integrity check,
   not instead of it.

**Dev machine with a clone.** In one shell invocation, run
`cargo build --release && scripts/install-binaries.sh && scripts/install-knowledge.sh`.
This gives source builds the same paired binary-and-knowledge layout as a
release. Skills arrive via the
plugin (already present if the operator reached this skill through
`/vouch:setup`) or via `scripts/install-skill.sh` from the clone. **One
delivery route per machine**: the plugin cache is version-keyed and updated by
hand, so a machine using both routes can hold two texts of the same skill under
two names. Plugin route for a machine that consumes vouch, `install-skill.sh`
for a machine that develops it — not both.

**Hook wiring.** Generate one merged document per host. These are the
operator's save, not this skill's write (hard rule 4, and the harness's own
guard refuses to let an agent change which program gates its tool calls).

1. For Claude Code, run `vouch install`. For Codex, run
   `vouch install --host codex --shell <bash|powershell>`; the shell must name
   how Codex executes `Bash` calls on this machine. For passive observation,
   add `--shadow --state-dir <absolute durable directory>`; the same explicit
   directory reaches both decision and outcome commands, so host-attributed
   rows do not split by session cwd. **Redirect every form to a scratch file**.
   Do not capture its stdout: that stdout is the entire merged settings
   document. This holds for every form of the command, `--print` included: an
   unparsed flag is swallowed silently, so a form expected to print only the
   hooks block can print the whole document instead.
2. Show the operator the HOOKS BLOCK, extracted from that scratch file rather
   than from a second invocation — read the JSON and print only its `hooks`
   key (MCP server configuration lives under a different key and never enters
   the extraction). Show the command's stderr notes alongside it: what it
   would change, the target path, and that nothing was written.
3. Record privately whether the target file was absent or take a byte-for-byte
   backup, then hand the operator the one command that saves the Claude scratch
   file over `~/.claude/settings.json`, or the Codex scratch file over
   `~/.codex/hooks.json`, and let them run it. Restoration returns that backup,
   or removes only the newly created file when no file existed before.
4. For a **live Codex gate only**, register the sibling release binary once
   using the exact command printed in `vouch install`'s notes:
   `codex mcp add vouch_approval -- <absolute-vouch-codex-broker-path>`.
5. For a **live Codex gate only**, have the operator keep
   `approval_policy = "on-request"` and `approvals_reviewer = "user"` at the
   top level of `~/.codex/config.toml`,
   and add `default_tools_approval_mode = "prompt"` inside the existing
   `[mcp_servers.vouch_approval]` section. Codex's native MCP prompt is the
   human decision: a denial prevents the broker call and creates no grant; an
   approval runs the broker, which validates the pending request and mints one
   exact one-use grant. There is no nested elicitation.
   For passive shadow, do not register the broker and do not change the
   existing reviewer or approval policy.
6. Have Codex reload the registration, then verify it landed by re-running the
   phase-1 survey's hook check (item 4). Claude has four events. Codex has two;
   only the live route also has broker registration. For passive shadow, run
   harmless supported calls and report counts only: Codex decision rows are
   `mode="shadow"`, both verdict classes are represented, delivered outcomes
   correlate on `host="codex"`, and no vouch steering output was emitted.

**Config.** A fresh machine gets a starter derived from `vouch.example.toml`:
every uncommented line in it is a genuinely shipped decision, and the commented
block is where the operator's own trees go. Proposing which trees is phase 4.

## Phase 3 — evidence

`what_would_fire.py` sits beside this file. It replays this machine's own
recorded session history against a CANDIDATE config and reports counts.

```
python <skill-dir>/what_would_fire.py \
  --binary <absolute path to vouch> \
  --config <candidate config.toml> \
  --knowledge <candidate knowledge.toml> \
  --my-knowledge <candidate my-knowledge.toml> \
  --scratch <this session's scratchpad, when one exists> \
  --samples-dest <absolute path outside every repository> \
  [--roots <transcript root> ...] [--cap N] [--workers N]
```

**Pass `--samples-dest` on this run.** It writes the snapshotted row set to
that file so phase 5 can replay the SAME rows; without it phase 5 has no way
to reuse the snapshot, because a second invocation has no memory of the first
one. The path must be absolute and outside every git worktree (the harness
refuses anything else), the file is harvested command text, and phase 5
deletes it when the delta table is printed.

What it does, and why each part is the way it is:

1. **It walks `~/.claude/projects/**/*.jsonl` and harvests `tool_use` blocks
   DIRECTLY** — tool name, input, and the containing record's `cwd` —
   independent of whether any hook ever decided them. This departs from the
   repository's older extractor on purpose, in four ways: no hook-attachment
   dependency (a fresh machine has no prior gate, and zero-rows-from-full-logs
   must be distinguishable from no-logs, so "tool calls found" and "of those,
   previously decided" print as separate numbers); every tool call is kept, not
   only shell commands (vouch judges tools too — file writes, MCP tools); the
   recorded per-row `cwd` is carried into the hook JSON, with the COUNT of rows
   that needed a fallback printed rather than a blanket caveat; and rows missing
   a field get stated defaults.
2. **It dedupes by tool-use id and prints the duplicate count.** Resumed and
   branched sessions rewrite prior history, so the same call appears in more
   than one transcript.
3. **It prints the subagent-sidechain split as its own figure**, never folded
   into one number — a large share of a machine's traffic can be subagent
   traffic, and an operator reading one total would not know.
4. **Classification comes from the journal, not stdout.** Three different
   things produce byte-identical empty stdout — a deliberate abstain, a
   mode-keyed stand-down, and an input the binary refused — and only the first
   two leave journal rows. So the harness reads the rows it just caused, joins
   them by session id, and **reconciles by count**: replayed = joined +
   refused + failed, each of the last two its own labelled class, with an
   assertion that the numbers agree. `failed` is separate on purpose — a call
   where the PROCESS timed out or exited nonzero wrote nothing and emitted
   nothing, which is indistinguishable from a deliberate abstain and from a
   refusal unless the process result is kept, and a dead binary has produced
   whole rounds of fabricated findings before. A snippet-bearing call writes
   one row per snippet, so the join is many-to-one and collapses to one
   decision per call, with the extra rows counted as their own figure. stdout
   is used only as a cross-check. `abstain` and `stood-down` are their own
   classes, never folded into allow.
5. **Cost, honestly stated.** The harness counts rows first, calibrates its
   first rows through the binary's `--hook-batch` JSONL transport, and prints
   the real row count and a MEASURED estimate before the bulk run starts. It
   fans out one persistent batch process per worker (`--workers`, default CPU
   count), each with its own state directory; config, knowledge, and process
   startup are loaded once per worker rather than once per recorded call.
   `--cap N` truncates AFTER the harvest counters print, so "found" is never
   understated by the cap; use it for a quick look, and drop it for the real
   number. A binary lacking `--hook-batch` is too old for this shipped harness:
   update the binary/plugin pair together rather than falling back silently to
   the process-per-call path this transport replaced.
6. **Output is counts only**, every figure printed twice — occurrences and
   distinct shapes, both labelled, because deduplication is itself a
   denominator choice and the operator should see both. Decisions by class; ask
   reasons by first-line class; head-program names by count. Program names
   appear in the terminal report on purpose (vouch's own prompts name them) and
   never in any repository. No command text is printed anywhere, and a head
   token that is not a plain program name is bucketed rather than shown.
7. **The scratch state directories are deleted when the run ends**, and the
   harness says so. Do not point `--scratch` at a repository.

**Relay the numbers to the operator, not the raw output dump.** Decisions by
class with both figures, the ask-reason classes, the top head-program names,
and the reconciliation line. Then the closing statement the harness prints:
these are default-mode numbers, and a `[shadow]` section changes what the live
gate emits in other modes.

**On a machine with no session logs**, the harness says so and this phase ends
there. Name the alternative in one line: shadow mode — a `[shadow]` section, or
`vouch install --shadow` beside a still-live older gate — accumulates evidence
while running, and the replay can be run later against a real journal.

## Phase 4 — shape

Judged per machine state, consistently. In every class, each item carries its
evidence source, named correctly.

**1. Fresh config.** Propose the starter config derived from
`vouch.example.toml`, with the phase-3 numbers beside it. Write walls —
`ask_paths` and `deny_paths` candidates such as the ssh tree and the vouch
config tree — are NAMED with their effect stated, and left to the operator.
Suggesting a protection is fine; deciding one is not.

**2. cc-allow migration.** Run `vouch import` and deliver its own honest report
unedited: what carried, what was dropped, and why. Then replay the imported
config through phase 3's harness, so the operator sees the ask rate it produces
BEFORE accepting it — an import is a proposal like any other.

**3. Existing vouch config.** The shape review. Four evidence sources, and each
finding says which one it came from:

- **The loader's own refusal and banner** surface retired or rejected
  spellings. A refused file is loud; a silently-discarded line is not, which is
  why the next source matters.
- **`vouch doctor`, run with `VOUCH_STATE_DIR` pointed at the phase-3 replay
  scratch.** Its journal-free buckets (inert place rules, silently-discarded
  my-knowledge lines) always answer. Its journal-derived buckets (undescribed
  programs, unreadable commands, undeclared options on dir-changing programs)
  exit early on a fresh journal — pointed at the replay's journal they
  populate from this machine's own replayed history instead, which is a
  strictly better evidence source than name matching, for one environment
  variable. Run the harness with `--keep-state` for this: it
  merges the per-worker journals into one directory and prints the path to hand
  `vouch doctor`. **Delete that directory when the phase ends** (the harness
  prints the path and says so) — it is harvested command text.
- **The standing re-read rule**: whenever a change widens what the config can
  express, settings written under the old constraints encode those
  constraints. Grants that exist only because nothing narrower could be said,
  and that a now-expressible narrower entry supersedes, are surfaced here.
- **A name-level approximation, with its blindness stated.** Entries naming
  programs that never appear in this machine's own history are found by
  matching NAME against phase 3's head-program counts. That approximation
  cannot see verb scopes or place scopes — an entry scoped to one verb or one
  tree looks the same to it as a whole-program grant — and vouch has no
  per-entry allow attribution today. Report it as fact, with the blindness said
  out loud, and leave removal to the operator: an unused grant is still a
  grant.

**4. In every class: proposals the evidence does not support are not made.**
Consistency means the same rules produce the same calls on two machines. The
rules live in this skill's text, so changing a judgment is a skill edit,
reviewed like one — not a decision taken once in a conversation.

## Phase 5 — accept and prove

Per accepted change, one at a time:

1. **Write it** — and expect vouch's own gate to prompt on the write, because
   the config is on the protected list (hard rule 7). That is the protection
   working; say so and answer it.
2. **Prove it with `vouch explain`, both directions.** The thing now allowed
   must allow; a neighbouring thing that must still ask must still ask. Pass
   `--cwd '<the directory it runs in>'` on both — every run-place rule is
   judged against where the command runs, relative executable and write paths
   resolve from there, and every run prints a `judged from:` line worth
   reading. An absolute executable-place rule is judged by the program file's
   own canonical location instead. For a recognition entry the neighbour is
   the same program with a different verb; for a write rule it is a path just
   outside the tree.
3. **On anything declined, say in one line that it stays a prompt on purpose**
   — and nothing more. A declined proposal is not a problem to solve.

Then **re-run the phase-3 replay once** — same cost statement up front — and
report the delta table: decisions before and after, by class, occurrences and
distinct shapes both. **Reuse the snapshotted row set** rather than
re-harvesting: the transcript store grows while it is being measured, and a
re-harvest folds new history into the delta, which would make the difference
unreadable. The mechanism is the file phase 3 wrote — pass
`--samples-source <that file>` in place of `--roots`, with the same
`--binary`/`--knowledge`/`--my-knowledge` and the ACCEPTED config as
`--config`:

```
python <skill-dir>/what_would_fire.py \
  --binary <absolute path to vouch> \
  --config <the config as accepted> \
  --knowledge <candidate knowledge.toml> \
  --my-knowledge <candidate my-knowledge.toml> \
  --scratch <this session's scratchpad, when one exists> \
  --samples-source <the file phase 3 wrote>
```

Finish by deleting the samples file and the replay scratch, and saying that
both are gone. Neither may outlive the phase: one is extracted command text
and the other is a journal of it.

Nothing about the operator's actual commands enters any repository. This
skill's report is numbers and setting names.

## This skill fixes itself

Every rule above was written because something can go wrong at that exact
step. When a setup turns up another one — a step in the wrong order, a missing
step, a claim that has gone stale, a warning that would have saved the turn you
just spent — edit this file in the same turn and say one line that you did. Do
not work around it silently: the next session reads this file, not that
conversation. (Global rule: skills are living procedures.)

Two rules here exist only because of that: the sentinel refusing to measure a
config that stands down at the replay's stamped permission mode, and the
head-token bucketing that keeps a command fragment out of the terminal report.

## Common mistakes

1. **Invoking the binary through cargo.** A vouch checkout's
   `.cargo/config.toml` replaces the candidate files with the repository's own
   and the numbers come back plausible and wrong. Absolute path, always.
2. **Capturing `vouch install`'s stdout — in any form.** That is the whole
   host hook document, and Claude's can carry MCP headers; a `--print` the running binary
   does not parse is swallowed rather than refused. Redirect every form to a
   file; display the `hooks` key read back out of it.
3. **Reporting a harness number when the sentinel did not pass.** It aborts
   for a reason: the overrides did not take, or the config stands down at the
   stamped mode. There is no partial answer to salvage.
4. **Batching accepts.** "Shall I apply all six?" is one blanket yes standing
   in for six decisions. One at a time, each with its number.
5. **Leaving the replay scratch or the samples file behind.** One is a journal
   of this machine's own command history and the other is the command history
   itself. Delete both when the phase ends, and say that they are gone.
6. **Reading a `binary-timeout` or `binary-error` count as a decision.** Those
   are calls where the process failed. They are not abstains, not refusals,
   and not evidence about the config — a nonzero count there means the numbers
   beside it were measured with something broken, and it is the first thing to
   explain.
