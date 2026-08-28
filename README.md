# vouch

A permission gate for Claude Code and Codex. It runs as a `PreToolUse` hook:
every tool call the host exposes is parsed, judged against declared knowledge
of what programs do, and answered before it runs.

Claude Code supports vouch's native allow / ask / deny response. Codex does
not currently support `ask` from `PreToolUse`, so vouch blocks the first
attempt and routes the human decision through Codex's native approval prompt
for a local MCP broker. An approved broker call grants one exact retry. An
allow emits nothing to Codex, leaving its native sandbox and approval policy
fully authoritative.

The judging is not pattern matching on the text of a command. vouch has three
scanners (bash, PowerShell, python) and walks what the command actually does:
which program runs, from which directory, what it writes and where, what it
hands to another interpreter, and which parts of it could not be read at all.
A line with several commands in it gets the strictest answer any one of them
earns.

The decision set has a fourth member, `abstain` — emit nothing and let the
harness's own rules decide. It is deliberately unreachable while vouch is
gating a tool call: saying nothing is not neutrality, it is the permissive case
wearing a different hat. Anything vouch cannot read prompts instead.

## The complaint it answers

Permission prompts that you cannot turn off train you to approve without
reading. So: **every prompt vouch raises names the setting that turns it off.**
A prompt with no named setting is a bug in vouch, whatever else is true about
it.

One exception is deliberate. The protected paths — vouch's own `config.toml`
and the hook registration in Claude's `settings.json` or Codex's `hooks.json`
— always prompt, and no
`write.allow_paths` entry can open one however broadly it is written. The
protected list is checked first and wins. That list is itself the setting, and
the prompt says so: removing a line from `[protected] paths` removes the
protection. A prompt that claimed to be unsettable while being settable would
be worse than one that admits where its off-switch is.

## Why an allow-list

A command is allowed because **everything in it is recognised**, not because
nothing recognised was found.

The difference is in how each kind of tool fails. A deny-list's error mode is
silent: when it misses something, a miss looks exactly like "nothing to
report", and you get no signal at all. An allow-list's error mode is a prompt
you can see, read, and switch off by name. That is the whole trade — more
prompts up front, in exchange for the failures being visible.

So: an unknown program asks. An unknown subcommand of a known program asks.
Code vouch could not parse asks, rather than being called probably fine. An
unrecognised harness tool asks, because emitting no decision would leave the
harness deciding alone, which is the permissive case wearing a different hat.

This project got that wrong once, and the reversal is worth stating plainly.
The original design said absence of knowledge must never be the permissive
case. Measuring the cost — with almost no knowledge written yet, "unrecognised
asks" would have prompted on 96.4% of real recorded commands — the setting was
flipped to allow unmodelled commands, and a principle was written afterwards to
justify it. That number was not a reason to abandon the invariant; it was a
measurement of how much knowledge was missing. Every hole later found by
review was that one decision. The default is back, and the knowledge file is
where the cost gets paid down.

## How a decision happens

For each command the scanners find, in plain words:

1. **Recognition.** Is there an entry describing this program, and does it
   cover this subcommand? Recognition is per command, not per program name:
   `kubectl get pods` and `kubectl delete pod` are different amounts of trust
   and are settable separately. Recognising a program claims only that vouch
   knows what it is — never that it is harmless.
2. **Guards.** Named effects declared in the knowledge — the shipped file
   declares the common ones (recursive deletion, history rewrite, process
   control, privilege escalation, and the rest), and you add or override your
   own. Every rule says where it came from, and the prompt prints it as a
   `rule source:` line: `declared`, `requested` if someone asked for it, or
   `inferred` if it is a guess, which it then says out loud. A guard asks every
   time on purpose, and approving one never creates a rule.
3. **Constructs.** Things vouch could not see through — a here-document it was
   not given, a command whose text is computed at run time, a snippet in a
   language it has no scanner for. Each is named, and each has its own setting.
4. **Place.** Where the command runs: the hook's directory, advanced by the
   `cd` walk and by run-directory flags such as `git -C <dir>`. Trust and
   distrust zones, and guard overrides scoped to a tree, are decided from that.
5. **Writes.** Where a write would land, resolved through quoting, variables
   assigned on the same line, and relative paths. The protected list is checked
   first; then the write walls (`ask_paths`, `deny_paths`); then the allow
   rules.

Then the answer, with its reason and the setting behind it. Here is a real one,
from a command that names no program vouch has been told about:

```
$ vouch explain --cwd 'C:/Users/dev/project' 'frobnicate --now'
judged from: C:/Users/dev/project
ASK
vouch stopped on: unmodeled_command
  no description of: frobnicate
  what that means: vouch has no entry that covers it
  to recognise one, use the vouch-trust skill — it proposes the narrowest entry,
  shows exactly what that entry would trust, writes it only on your accept (it
  drives `vouch trust`, whose usage `vouch trust` alone prints), and proves it
  fires. The narrowest entries here:
    frobnicate — an entry would recognise every operation of `frobnicate` — or,
    narrower, exactly this flags-only shape: `subcommands = []` with
    `standalone_flags = ["--now"]` and `case_sensitive_flags` stated
  to stop checking for unknown programs entirely, set
  lang.bash.constructs.unmodeled_command = "allow" — that allows every program
  vouch has never heard of, not just this one
```

A guard ask has the same shape and ends the same way — `setting:
guards.delete_recursive (currently "ask")` — so the way out is always on the
screen, next to what it would cost.

## The three files

All three live in `~/.config/vouch/`.

| File | What it is | Who writes it |
|---|---|---|
| `knowledge.toml` | What programs and harness tools are and do: `ls` reads, `rm -r` deletes recursively, `git` takes `-C` with a value. Every entry is a claim that must be true | Ships in the release bundle; from source, `scripts/install-knowledge.sh --force` replaces it wholesale. Your own entries do not belong here |
| `my-knowledge.toml` | Your own descriptions, laid over the shipped ones piece by piece: what you set wins, what you leave unset keeps what ships | You, or `vouch trust` on your explicit accept. Nothing overwrites it |
| `config.toml` | What you have told vouch to do: guard actions, construct actions per language, trust and distrust zones, write rules, the protected list | You. `vouch review --accept` is the only command that writes this file, and only on that accept |

Every key in the first two and every setting in the third is documented in
[`docs/reference/reference.md`](docs/reference/reference.md), which is generated
by `vouch schema config --write` from the same structs the loaders read — so it
cannot describe a shape vouch would refuse. `vouch.example.toml` is a working
`config.toml` to start from. Both binaries and `knowledge.toml` are version-gated
against each other: a mismatched pair refuses loudly rather than deciding
half-blind, so they move together.

## Install

Three pieces make a working install, and they arrive differently:

- **The gate** — `vouch`, `vouch-codex-broker`, and `knowledge.toml`, from one commit.
- **The wiring** — Claude uses four entries in `~/.claude/settings.json`;
  Codex uses two in `~/.codex/hooks.json` plus the local approval broker.
  Hook documents are always saved by a human; see below.
- **The procedures** — the skills, including `vouch-setup`, which walks a
  machine through the rest.

### Claude Code plugin

The repository is its own single-plugin marketplace:

```
claude plugin marketplace add <owner>/vouch
claude plugin install vouch@vouch
```

Then run `/vouch:setup`. That skill surveys the machine, replays that machine's
own recorded session history against a candidate config so you can see what
would actually fire before accepting anything, and writes nothing without an
explicit accept per change.

The plugin carries the skills and the `/vouch:setup`, `/vouch:update`, and
`/vouch:status` commands. It deliberately
does not carry the hooks: the live gate must not move when a plugin cache
refreshes, and hook registration is a human save whatever ships.

Keeping it current is a step someone has to run — a new version in the
marketplace moves nothing by itself, because the plugin cache is keyed by the
version installed:

```
claude plugin update vouch
```

then restart Claude Code.

That updates the procedures only. `/vouch:status` reports what is installed —
binary, knowledge, and plugin versions against the newest release — and writes
nothing. The gate — both binaries and
`knowledge.toml` — updates through `/vouch:update`: it compares the installed
version against the newest release, downloads the platform bundle, verifies it
against `SHA256SUMS` before unpacking, installs binaries and knowledge
together, and re-probes, all on an explicit accept. Run both update halves
when a release lands, so the skills and the binary they describe move in step.

### Codex plugin

The same repository is a Codex marketplace:

```
codex plugin marketplace add <owner>/vouch
codex plugin add vouch@vouch
```

Start a new Codex thread and run `$vouch:vouch-setup`; updating an installed
gate later is `$vouch:vouch-update`, and checking without moving anything is
`$vouch:vouch-status`. The plugin carries the
same procedures as Claude Code; it deliberately carries neither live hooks nor
an executable, so plugin refreshes cannot silently replace the gate.

### The from-source path

Prerequisites: Claude Code or Codex, and a Rust toolchain at or above the floor
`Cargo.toml` names in `rust-version`.

```
git clone https://github.com/<owner>/vouch
cd vouch
cargo build --release && scripts/install-binaries.sh && scripts/install-knowledge.sh
cp vouch.example.toml ~/.config/vouch/config.toml
scripts/install-skill.sh
```

That copy matters: with no `config.toml` at all, nothing has been allowed, so
every command asks and every prompt carries a banner saying why. The example
file is a working starting point — the binary's own message points at it.
`/vouch:setup` builds one from your machine's evidence instead, if you took the
plugin path.

Then generate the hook wiring, which no agent writes for you.

For Claude Code:

```
mkdir -p ~/.local/state/vouch
~/.config/vouch/bin/vouch install > ~/.local/state/vouch/claude-settings.json
```

`vouch install` reads your existing `~/.claude/settings.json`, merges in four
hook entries pointing at the binary's own path, and prints the merged document
— it writes nothing. Read the file it produced, then move it into place
yourself. Two reasons this is a human step and stays one. The program that
gates an agent's tool calls is not a file to let that agent rewrite, so vouch
prints and you save; `src/install.rs` records the same reasoning. And the
printed document is your *entire* settings file, which can carry credentials in
MCP server headers — so it belongs in an editor, never in a chat transcript or
a captured command output. If you want to inspect what changed locally without
opening the whole settings file, `vouch install --print` narrows the document
to the hooks-only view; redirect that form to private scratch too.

The four events, and why each is registered:

| Event | For |
|---|---|
| `PreToolUse` | the decision — this is the gate |
| `PostToolUse` | recording that it ran |
| `PostToolUseFailure` | recording that it errored or was interrupted |
| `PermissionDenied` | recording that you refused it |

The last three decide nothing. They exist so `vouch review` draws its
candidates from what actually happened rather than from absent signals.

For Codex, choose the shell Codex uses on this machine:

```
mkdir -p ~/.local/state/vouch
~/.config/vouch/bin/vouch install --host codex --shell powershell \
  > ~/.local/state/vouch/codex-hooks.json
# or: --shell bash
codex mcp add vouch_approval -- ~/.config/vouch/bin/vouch-codex-broker
```

Review the private `codex-hooks.json`, then save it as `~/.codex/hooks.json`. Codex gets
`PreToolUse` for decisions and `PostToolUse` for outcomes. The broker is what
turns an approved native MCP prompt into one exact retry; it stores hashes and
a short reason category, never raw command text or session IDs. Keep
`approval_policy = "on-request"` and `approvals_reviewer = "user"` at the top
level, and add `default_tools_approval_mode = "prompt"` inside the existing
`[mcp_servers.vouch_approval]` section. That native MCP prompt is the human
decision: denying it leaves the Ask blocked, while approving it lets the broker
validate the pending request and mint the bound one-use grant. There is no
second, nested elicitation.

To observe Codex while leaving `approvals_reviewer = "auto_review"` and the
native policy in charge, use passive shadow instead:

```
~/.config/vouch/bin/vouch install --host codex --shell powershell \
  --shadow --state-dir ~/.local/state/vouch \
  > ~/.local/state/vouch/codex-hooks.json
# or: --shell bash
```

This route needs no vouch approval broker. `PreToolUse` evaluates and appends a
`host = "codex"`, `mode = "shadow"` row while emitting nothing; `PostToolUse`
appends the matching host-attributed outcome. The explicit absolute state
directory keeps both rows in one durable journal even when Codex starts in a
different repository. New outcomes correlate by host plus tool-use id, so a
Codex id cannot attach to a Claude row.

Codex hooks cover shell commands, `apply_patch`, MCP tools, and most local
function tools. Hosted tools and some specialized paths can bypass the local
hook path, so vouch is a guardrail over observed calls, not a replacement for
the native sandbox.

Add `--shadow` to register vouch beside a gate you
are still running: it evaluates and journals every call in full and emits no
decision, so you can measure what it would have done before it does anything.

### One delivery route per machine

Use the plugin route on a machine that *consumes* vouch, and
`scripts/install-skill.sh` on a machine that *develops* it. Not both. The
plugin cache is version-keyed and updates only when someone runs the update
command, so a machine on both routes can end up holding two different texts of
the same skill under two different names.

### Releases

Version numbers and `CHANGELOG.md` are generated from structured `feat`/`fix`
entries recorded in each release-bearing commit. The private subject summarizes
the changeset; one nested entry names each independently visible public outcome.
Each release lands as one reviewed change, and the public-mirror tag that
follows triggers the build workflow to attach the binaries.

The mirror publisher scans the configured Git identity and the exact candidate
message, metadata, paths, patch, and files before it pushes a review branch.
After review, `--land` rescans that branch and fast-forwards mirror master to
the same commit; the forge merge button is not used because it creates a new,
unscanned object. `--verify` also audits published author, committer, and tagger
identities before `--tag` can start a release build.

`gh release download` fetches a per-platform archive holding both binaries,
`knowledge.toml`, and `vouch.example.toml` from a single commit, laid out to
match where they are installed.

## Commands

The harness calls `vouch --hook`, which reads hook JSON on standard input.
Everything else is for you:

| Command | What it does |
|---|---|
| `vouch explain '<cmd>'` | Decides a command now and prints the verdict and the whole reason, without running it. Says which directory it judged from; `--cwd <dir>` sets that directory |
| `vouch why` | The last recorded decision — verdict, reason, mode — then re-decides that same command under the current config, so you can see whether the two disagree. `vouch why '<cmd>'` decides that command instead |
| `vouch trust <program> [<verb>…]` | Writes a recognition entry to `my-knowledge.toml`; running it is the explicit accept. Verbs are named one by one, `--all-subcommands` covers a whole program, `--whole-server` a whole MCP server — the wide ones have to be said out loud |
| `vouch doctor` | What vouch could not read or describe: place rules that can never fire, `my-knowledge.toml` lines the merge discarded, commands it could not parse, programs it has no description of, and undeclared options on directory-changing programs, by count and by spelling |
| `vouch review [--accept <name>]` | Rule candidates drawn from recorded outcomes, each with the counts behind it, including the ones it will not propose and why. Prints only; `--accept` is the one thing that writes, and it never proposes a guard |
| `vouch import [file]` | Translates a cc-allow config to standard output and lists on standard error what did not translate. Writes nothing |
| `vouch install [--host claude\|codex] [--shell bash\|powershell] [--state-dir <absolute>] [--shadow] [--print]` | Prints the selected host's merged hook document for redirecting and saving. Codex requires an explicit shell; `--state-dir` is Codex-only and makes decision/outcome journaling durable. Live Codex notes include the broker route; passive `--shadow` notes leave the native reviewer unchanged and require no broker. `--print` narrows output to the hooks-only view. Writes nothing |
| `vouch schema <config\|knowledge> [--write]` | Prints the JSON Schema generated from the structs the loaders actually read; `--write` regenerates the committed schemas and the reference page |

## What will not move, and how mature this is

Four invariants are not up for negotiation, because each one is what makes the
rest worth trusting:

1. **Nothing is ever written to a config or knowledge file automatically.**
   Rules change on an explicit accept, and no other way.
2. **An approval is never a policy.** Approving a guard prompt lets one command
   through; it does not create a rule. That is why guards ask every time.
3. **A guard never hides where it came from.** The shipped knowledge declares
   the common effects, and a number of those rules are inferred rather than
   asked for — so every prompt names which, and deciding that a shape is
   dangerous stays your call. Where something is a write *channel* rather than
   a write, vouch reports it and lets you decide.
4. **Absence of knowledge is not permission.** The one exception is a trust
   zone, which you have to write out loud in your own config, and which grants
   recognition only — guards and write rules still apply to whatever runs there.

Maturity, plainly: this is one operator's tool on one machine. Its knowledge
file, its defaults, and its measurements all come from that machine's own
recorded history, so a second machine will find gaps — that is what
`vouch doctor` and `/vouch:setup` are for, and an unrecognised program is a
prompt to be closed by describing it, not a bug. Releases build for Windows
(x86-64), Linux (x86-64) and Apple silicon macOS; there is no Intel macOS
build.

Licensed under the WTFPL — see [LICENSE](LICENSE).

## Developing vouch

This repository carries the product: everything needed to use, build, and
release vouch. Development itself — the ordered roadmap, the approved
designs, the process docs, and the measurements over real recorded traffic —
lives in a private companion repository, because vouch's method is measuring
against real machine history and that history never leaves the machine that
produced it.

Two things to know before running anything here:

- **The committed test corpus is hand-authored and invented**, so a fresh
  clone is green: `cargo test --release` runs the full property suite over
  it. The measurement tests that need real recorded history skip when it is
  absent rather than falling back — a count over invented commands would be
  a fabricated number.
- **Nothing personal or secret goes in this repository.** The development
  side enforces that with git hooks and a six-place history audit before
  anything is published here.
