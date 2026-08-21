# vouch

A permission gate for Claude Code. It runs as a `PreToolUse` hook: every tool
call the agent is about to make is parsed, judged against declared knowledge of
what programs do, and answered — allow, ask, or deny — before it runs.

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
and the hook registration in `settings.json` — always prompt, and no
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
| `knowledge.toml` | What programs and harness tools are and do: `ls` reads, `rm -r` deletes recursively, `git` takes `-C` with a value. Every entry is a claim that must be true | Ships with vouch. `scripts/install-knowledge.sh --force` replaces it wholesale, so your own entries do not belong here |
| `my-knowledge.toml` | Your own descriptions, laid over the shipped ones piece by piece: what you set wins, what you leave unset keeps what ships | You, or `vouch trust` on your explicit accept. Nothing overwrites it |
| `config.toml` | What you have told vouch to do: guard actions, construct actions per language, trust and distrust zones, write rules, the protected list | You. `vouch review --accept` is the only command that writes this file, and only on that accept |

Every key in the first two and every setting in the third is documented in
[`docs/reference/reference.md`](docs/reference/reference.md), which is generated
by `vouch schema config --write` from the same structs the loaders read — so it
cannot describe a shape vouch would refuse. `vouch.example.toml` is a working
`config.toml` to start from. The binary and `knowledge.toml` are version-gated
against each other: a mismatched pair refuses loudly rather than deciding
half-blind, so they move together.

## Install

**Access.** This repository is private, so every path below needs authenticated
access to it. `claude plugin marketplace add` authenticates with the machine's
existing GitHub credential state — a logged-in `gh` with access to the
repository is enough, for the plugin path and for downloading release assets
alike.

Three pieces make a working install, and they arrive differently:

- **The gate** — the `vouch` binary and its `knowledge.toml`, from one commit.
- **The wiring** — four hook entries in `~/.claude/settings.json`. Always saved
  by a human; see below.
- **The procedures** — the skills, including `vouch-setup`, which walks a
  machine through the rest.

### The plugin path

The repository is its own single-plugin marketplace:

```
claude plugin marketplace add <owner>/vouch
claude plugin install vouch@vouch
```

Then run `/vouch:setup`. That skill surveys the machine, replays that machine's
own recorded session history against a candidate config so you can see what
would actually fire before accepting anything, and writes nothing without an
explicit accept per change.

The plugin carries the skills and the `/vouch:setup` command. It deliberately
does not carry the hooks: the live gate must not move when a plugin cache
refreshes, and hook registration is a human save whatever ships.

Keeping it current is a step someone has to run — a new version in the
marketplace moves nothing by itself, because the plugin cache is keyed by the
version installed:

```
claude plugin update vouch
```

then restart Claude Code.

### The from-source path

Prerequisites: Claude Code, and a Rust toolchain at or above the floor
`Cargo.toml` names in `rust-version`.

```
git clone https://github.com/<owner>/vouch
cd vouch
cargo build --release
scripts/install-knowledge.sh
cp vouch.example.toml ~/.config/vouch/config.toml
scripts/install-skill.sh
```

That copy matters: with no `config.toml` at all, nothing has been allowed, so
every command asks and every prompt carries a banner saying why. The example
file is a working starting point — the binary's own message points at it.
`/vouch:setup` builds one from your machine's evidence instead, if you took the
plugin path.

Then the hook wiring, which no agent writes for you:

```
target/release/vouch install > vouch-settings.json
```

`vouch install` reads your existing `~/.claude/settings.json`, merges in four
hook entries pointing at the binary's own path, and prints the merged document
— it writes nothing. Read the file it produced, then move it into place
yourself. Two reasons this is a human step and stays one. The program that
gates an agent's tool calls is not a file to let that agent rewrite, so vouch
prints and you save; `src/install.rs` records the same reasoning. And the
printed document is your *entire* settings file, which can carry credentials in
MCP server headers — so it belongs in an editor, never in a chat transcript or
a captured command output. If you want to look at what changed without
displaying the whole settings file, `vouch install --print` shows the
hooks-only view instead — safe to paste anywhere, since it carries no MCP
content.

The four events, and why each is registered:

| Event | For |
|---|---|
| `PreToolUse` | the decision — this is the gate |
| `PostToolUse` | recording that it ran |
| `PostToolUseFailure` | recording that it errored or was interrupted |
| `PermissionDenied` | recording that you refused it |

The last three decide nothing. They exist so `vouch review` draws its
candidates from what actually happened rather than from absent signals.

Add `--shadow` (`vouch install --shadow`) to register vouch beside a gate you
are still running: it evaluates and journals every call in full and emits no
decision, so you can measure what it would have done before it does anything.

### One delivery route per machine

Use the plugin route on a machine that *consumes* vouch, and
`scripts/install-skill.sh` on a machine that *develops* it. Not both. The
plugin cache is version-keyed and updates only when someone runs the update
command, so a machine on both routes can end up holding two different texts of
the same skill under two different names.

### Releases

There is no tagged release yet, so today the binary is built from source.
When there is one, `gh release download` fetches a per-platform archive holding
the binary, `knowledge.toml`, and `vouch.example.toml` from a single commit,
laid out to match where they are installed.

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
| `vouch install [--shadow] [--print]` | Bare form prints your `settings.json` with the four hook entries merged in, for redirecting to a file and saving. `--print` narrows that to the hooks-only view — safe to display, since it carries no MCP/server content. Writes nothing |
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
