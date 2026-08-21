---
name: vouch-trust
description: Use when a vouch prompt says "no description of" a program, or "no scanner for" an MCP tool — recognises it safely by proposing the narrowest entry, showing what it would trust, writing only on explicit accept, and proving the entry fires
---

# vouch-trust — recognise a program or MCP tool without trusting more than was asked

A vouch `unmodeled_command` prompt means: this exact command contains
something vouch has no entry that covers. An `unmodeled_tool` prompt is the
same gap one layer up: the harness ran a tool (an `mcp__server__tool` name,
almost always) vouch has no `[[tool]]` entry for. This skill turns either
into a verified knowledge entry. It exists because a printed one-line
instruction cannot check what it is about to write, and four measured
defects came from that (vouch ROADMAP, M2.12) — the MCP-tool half exists
because the same failure mode, guessing instead of checking, is worse one
layer up: a program's man page is one `--help` away, but an MCP tool's
fields are only what the harness actually declares (rule 6 below).

## Hard rules

1. **Never write without the operator's explicit accept.** Show what the
   entry would trust first, then wait. An approval of one command is never a
   standing policy.
2. **Narrowest entry that covers the command.** A program with verbs gets
   `vouch trust <program> <verb>` for the verb that was actually run — never
   the bare program name, and never `--all-subcommands` unless the operator
   says those words. If they DO say them: state out loud that this trusts
   every verb the program has, including ones they have never run, and the
   still-asks proof in step 6 becomes a different unknown program instead of
   a sibling verb (there is no sibling left to ask).
   **Rule 2a — narrower still, when the program only ever runs in one
   tree:** an `only_under` list on the `[[program]]` entry — place-scoped
   recognition — recognises it inside those trees and nowhere else. `vouch
   trust` does not write it (it writes an unscoped entry), so it is a
   hand-edit under the header `vouch trust` just wrote, on the same accept,
   exactly like a snippet declaration (rule 9). Two shapes refuse the WHOLE
   `my-knowledge.toml` at load, so check both before proposing one: a name
   the SHIPPED knowledge already describes may not carry `only_under` at all
   (place-scoping is for the operator's own programs), and one name may not
   appear on two of the operator's entries. If a scoped entry for this name
   already exists, widen ITS `only_under` list — never add a second entry.
3. **Destructive operations get no entry.** If the command's point is
   deleting, force-pushing, or rewriting state, tell the operator vouch asks
   about it on purpose and stop. Applies to a tool the same way: if its
   DECLARED schema (never the name — rule 6) shows that is what it does,
   propose no entry, same stop, same reason.
4. **A name defined as a function in the same command gets no entry.** If
   the unrecognised name appears earlier in the very command as
   `name() { … }`, it is a shell function, not a program — vouch reporting
   it as a program is a recorded defect (the function-name item in vouch's
   ROADMAP). An entry for that name would trust anything ever called by it.
   Tell the operator and record per rule 5.
5. **Anything recorded in the vouch repo states the defect in the
   abstract** — which code path is wrong and how to reproduce it from a
   fixture. Never the operator's actual command line, paths, program names,
   or what they were doing (vouch CLAUDE.md, the rule at the top). If no
   vouch checkout is present in the session, give the operator the defect
   text to carry there instead.
6. **MCP tools: read the DECLARED schema, never guess from the name.** An
   `mcp__server__tool` name is not a shell command — it has no `--help`.
   What fields it takes, and what any of them carry, come only from the
   harness's own listing of that tool (its declared parameters — via
   `ToolSearch` for a deferred tool, or the tool's own definition when
   already loaded), never from what the name suggests. A field called
   `code` still has to be confirmed, from the schema, before its language is
   a claim vouch can write down — this is CLAUDE.md §3 one layer up ("every
   entry in the knowledge file is a CLAIM, and must be true"): deciding a
   field carries code, or that a tool writes a path, is exactly that kind of
   claim, and a name is not where a checked claim comes from.
7. **Per tool, not per server, unless the operator says the words.**
   `vouch trust <mcp-name>` recognises exactly the one tool named — the
   tool-side twin of rule 2. `vouch trust --whole-server <server>` is
   available but must be said out loud, same as `--all-subcommands`: if the
   operator DOES say it, state plainly that it recognises every tool that
   server exposes, including ones never seen, with every one of their
   snippets unread unless the server entry itself declares them — and the
   still-asks proof in the MCP steps below becomes a different unknown
   server, not a sibling tool (there is no sibling left to ask).
8. **The `cwd_from_call` claim needs a verified yes, not a guess.** Any
   snippet or write-path declaration is asking, out loud, every time: does
   this tool run its snippet in the calling session's own working
   directory? Unless that is independently verified — the plugin's own
   docs or source say so, not an assumption — leave it unset (false).
   Unset/false is what keeps a relative write target inside the snippet
   asking instead of silently resolving against a directory nobody
   confirmed.
9. **Snippet declarations are not CLI-writable.** `vouch trust` writes only
   the recognition entry (`[[tool]]` with `match = […]` or `server = …`). A
   snippet or write-path declaration is added afterward by hand, under that
   SAME `[[tool]]` header — anchor on it, never insert above it. This is the
   same anchoring rule vouch's CLAUDE.md states for `[[program]]` (inserting
   above one has produced a duplicate header and a crashing binary three
   times); nothing about `[[tool]]` makes that failure less available. One
   accept covers both writes — show the whole entry, recognition and
   declaration together, before either one happens.

## Steps

Expect vouch's own gate to ask about your `vouch explain` and `vouch trust`
invocations — that is the gate working; answer its prompt.

1. Get the exact command from the prompt or the operator. If the prompt
   instead says `vouch stopped on: unmodeled_tool` and names
   `tool: mcp__server__tool`, this is an MCP tool call, not a shell
   command — skip to "MCP tools" below; the steps here assume something
   `vouch explain` can scan.
2. Run `vouch explain --cwd '<the directory the command ran in>' '<command>'`
   — for a PowerShell command,
   `vouch explain --cwd '<dir>' ps '<command>'`; bare explain scans as bash.
   Confirm it stops on `unmodeled_command` and note WHICH part is
   unrecognised (the prompt's per-item lines say). `--cwd` matters because a
   place rule — a trust or distrust zone, a guard override, a write scope, a
   scoped entry's `only_under` — is judged against where the command RUNS;
   without it explain judges from its own directory and can disagree with
   what the hook decided. Every run prints `judged from:`; read that line and
   check it is the place you meant.
3. Decide the narrowest entry: bare program (no verbs) or program + the one
   verb. A path-spelled head is recognised by its bare name — `vouch trust`
   normalises this itself and says so.

   **A flags-only run gets its own shape, `standalone_flags` — never the
   whole program.** If the command that triggered this is a program run with
   only flags (`cargo --version`, `python --help`), propose
   `standalone_flags` listing EXACTLY the flags seen in this run — not every
   flag the program supports, not a guess at what else might be safe. This
   carries the same verification obligation as the shipped-entry work
   (spec `2026-08-20-standalone-flags-design.md` §5): run the flag (and,
   if more than one is being listed together, run the full combination
   together too) and confirm it prints and exits rather than doing real
   work, dropping into a REPL, or reading standard input. State the claim
   being accepted, out loud, before the accept: "this asserts each listed
   flag alone does nothing" — dispatches no verb, evaluates no standard
   input, runs no file, writes nothing. A flag not run on this machine does
   not go in the list; say so and drop it rather than citing documentation
   for a shipped claim.

   The entry this writes: `subcommands = []` (explicitly empty — no verb
   coverage, standalone runs only), `case_sensitive_flags = true` (stated
   out loud, either value — the key requires it), `standalone_flags =
   [...]` naming exactly the run-verified flags. If the program already has
   a verb the operator uses (`vouch trust prog build --version`), the
   middle state is what gets written instead: `subcommands = ["build"]`
   plus `standalone_flags = ["--version"]` — verbs and standalone runs both
   covered, nothing wider.

   If the program is already described but was run with only flags and
   `standalone_flags` genuinely cannot describe it (a flag doing real work,
   or the operator wants coverage beyond what was run), say that plainly
   before proposing anything wider — the whole-CLI entry is available but
   covers verbs a scoped entry deliberately excludes.
4. Tell the operator, in one line per entry, exactly what it would trust
   ("recognise the `pull` operation of `frob` and nothing else — guards and
   write rules still apply"). Ask for an accept. Stop here without one.
5. On accept, run `vouch trust <program> [<verb>]`. It must print
   `verified: an entry now recognises …` — if it instead reports the entry
   did not fire and was removed again, that is a vouch defect: report it to
   the operator and record it per rule 5. One case where the undo is CORRECT
   and not a defect: the operator already has a place-scoped entry for this
   same name, so the appended second entry made the whole file refuse to
   load (rule 2a). Check `my-knowledge.toml` for the name before calling it
   a defect, and widen the existing entry's `only_under` instead.
6. Prove both directions (`--cwd` and the `ps` selector again, exactly as in
   step 2):
   - `vouch explain --cwd '<dir>' '<the original command>'` — must no longer
     stop on `unmodeled_command`.
   - `vouch explain --cwd '<dir>' '<a neighbouring command that must still
     ask>'` — for a verb-scoped entry, the same program with a DIFFERENT
     verb; for a new program or an all-subcommands entry, any other unknown
     program. Must still ask. A too-broad entry shows up here and must be
     reported, not shrugged at — with one alternative to rule out first: if
     the operator has a **trust zone** (`run.trust_all_under`) covering this
     directory, the neighbour is recognised BY THE ZONE and would allow with
     or without the new entry. The allow's own reason says which
     (`run.trust_all_under` and the glob that matched, versus the entry). Re-run
     the neighbour from a directory outside the zone before calling the entry
     too broad.
7. Report both results to the operator, quoting the two verdicts.

## MCP tools

An `unmodeled_tool` prompt is answered the same way as an unmodeled
command — narrowest entry, no write without accept, proof both directions —
but the mechanics differ: there is no `vouch explain` for a tool call itself
(it only scans bash/PowerShell text), the CLI write and the snippet write
land in the same file as two separate edits, the hand-edit gets its own
integrity check before anything is proved (a broken file and a correctly
asking snippet are indistinguishable from outside otherwise), and the proof
runs against the extracted snippet TEXT, not the tool call.

1. Get the exact tool name from the prompt (`tool: mcp__server__tool`) and
   its DECLARED schema — the harness's own listing of that tool's input
   fields (`ToolSearch` for a deferred tool; the tool's own definition when
   already loaded). Never infer a field's purpose from the tool's name
   (rule 6). If the schema is not available in this session, say so and
   stop — do not propose a snippet without having read it.
2. Decide the narrowest entry from the schema, not from what the tool
   probably does:
   - Nothing in the schema carries code that gets run, or a path that gets
     written → simple recognition only: `match = ["mcp__server__tool"]`,
     no snippet.
   - A field's schema shows it holds a script that gets executed →
     propose `[[tool.snippet]]`. `field` is the schema's own path into
     the input — dotted through nested objects, `[]` for an array step,
     exactly as the schema nests it, never invented (a key literally
     containing `.` or `[]` cannot be expressed; say so rather than
     approximate it). The language is either a fixed `language` (the tool
     only ever runs one) or `language_from` + `language_values` reading a
     sibling field the schema names — every value on the right must be one
     of `bash`, `powershell`, `python`, `javascript`; a name outside that
     set is not a legitimate value, whatever the schema calls it.
   - A field's schema shows it holds a path the tool writes to → propose
     `write_path_field` naming it. (No `vouch explain` route exists to
     prove this one today — say that in step 7 rather than skipping it
     silently.)
   - Ask the `cwd_from_call` question out loud, every time (rule 8), and
     default it false unless independently verified.
3. Tell the operator, in full, what BOTH writes will contain: the
   recognition entry `vouch trust` will write, and — if a declaration was
   proposed — the exact `[[tool.snippet]]` or `write_path_field` block the
   skill will hand-edit in afterward, with the `cwd_from_call` answer
   stated plainly. One accept covers both (rule 9). Stop here without one.
4. On accept, run `vouch trust <mcp-name>` — or, only if the operator said
   the words, `vouch trust --whole-server <server>` (rule 7). It must print
   `verified: an entry now recognises …` (or, for a server,
   `verified: a server entry now recognises every tool … exposes`); if it
   instead reports the entry did not fire and was undone, that is a vouch
   defect — report it per rule 5.
5. If a snippet or write-path declaration was proposed and accepted, add it
   now: first keep the file's bytes exactly as they are right after step 4
   — `vouch trust` already verified that content, and it is what step 6
   restores if this edit goes wrong. Then edit `my-knowledge.toml` by hand,
   anchoring the `[[tool.snippet]]` sub-table (or the `write_path_field`
   line) ON the `[[tool]]` header `vouch trust` just wrote — never inserted
   above it (rule 9). Show the diff as confirmation of what was written;
   this is not a fresh ask, the accept in step 3 already covers it.
6. Check the hand-edit didn't break the file it lives in, before trusting
   anything step 7 reports. `my-knowledge.toml` is refused WHOLE on a parse
   failure (`knowledge::load_files`) — every operator entry in it drops
   silently, including the recognition entry just verified in step 4 — and
   for a `write_path_field` or a `python`/`javascript` snippet, step 7 below
   has no way to tell "correctly asking" from "the file failed to load, so
   everything asks"; they look identical from outside. So: run one cheap,
   already-recognised command — `vouch explain 'ls -la'` — and read the
   WHOLE output. A refused `my-knowledge.toml` adds a loud gap banner after
   the decision on every invocation, unconditionally ("your own additions
   in my-knowledge.toml are not in effect …") — so the requirement is NO
   such banner anywhere in the output. Banner present → the edit broke the
   file: write back the bytes kept in step 5, tell the operator the
   hand-edit failed and why, and stop — do not continue to step 7 on a file
   that isn't loading.
7. Prove both directions for a snippet declaration:
   - `bash` or `powershell` snippet: pick one snippet text that should be
     recognised and one that should ask, and route each through
     `vouch explain <lang> '<text>'` (`explain bash …` / `explain ps …`) —
     the extracted TEXT, never the tool call, same mechanism as command
     step 6. The allow-shaped one must not stop on `unmodeled_command`; the
     ask-shaped one must still ask.
   - `python` snippet: there IS a scanner (M1.4 landed 2026-08-09), so the
     snippet is read and decided exactly as a bash one is — it does NOT
     simply ask naming the language, and reporting that it does would be a
     fabricated result. What is missing is only the `vouch explain`
     selector: the verb takes `bash`/`sh` and `ps`/`powershell` and
     nothing else, so there is no way to route the extracted TEXT through
     it by hand. Say that plainly — the declaration is proven by the
     recognition verdict in step 4 plus the absence of a gap banner in
     step 6, and the snippet's own decision is not provable here.
   - `javascript` snippet: there is no scanner and no `vouch explain`
     selector — every such snippet asks today, naming the language. That
     is expected, not provable through `vouch explain`; say so rather than
     fabricating a proof.
   - `write_path_field`: no `vouch explain` route exists for a write-target
     decision today — say that plainly instead of skipping the step.
   - The tool entry itself (recognition) needed no separate proof here —
     that is what `vouch trust`'s `verified:` line in step 4 already means.
8. Report every result to the operator: the recognition verdict from step 4,
   and, for anything declared, the step 7 verdicts (including any "not
   provable this way" statements) — never silently drop the ones that
   couldn't be proven.

## Working from the journal instead of one pasted prompt

The higher-yield input is not a single prompt: it is the journal, which
records what vouch decided whether or not anyone saw a prompt — including
every ask suppressed while an auto mode was on. `vouch doctor` prints the
undescribed names by frequency, and the journal itself groups them:

```
python - <<'PY'
import json, collections, re
p = r"<state dir>/journal.jsonl"   # journal::state_dir(), the temp vouch dir by default
names = collections.Counter()
for line in open(p, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line: continue
    r = json.loads(line)
    if r.get("verdict") != "ask": continue
    if "unmodeled_command" not in (r.get("reason") or "").split("\n")[0]: continue
    for m in re.findall(r"every operation of `([^`]+)`", r.get("reason", "")):
        names[m] += 1
for n, c in names.most_common(20): print(f"{c:5d}  {n}")
PY
```

Three rules that only apply to the bulk case, and the first two are the ones
that matter:

1. **A frequency count is not a reason to describe something.** §3 still
   binds every entry: a program that builds, installs, deploys or renders is
   left unknown ON PURPOSE, however often it asks. On 2026-08-19 the top two
   names in a day's traffic were a container tool and a toolchain installer
   — both correctly undescribed, and describing them because they were noisy
   would have been the §0 mistake in miniature.
2. **Check the roadmap before minting entries.** A cluster of names often has
   a structural fix already queued, and hand-written entries would be work
   the queue plans to delete. In the same measurement, most of the volume was
   python method names whose receiver vouch cannot yet track — which is a
   named roadmap item, not thirty entries waiting to be typed.
3. What the count IS good for: telling the operator the price of a gap, and
   ordering the queue. Report it as a number beside the roadmap row it
   belongs to.
