# vouch config and knowledge reference

Generated from the structs vouch actually reads — `Raw` in `src/config.rs` for `config.toml`, and `Knowledge` in `src/guards.rs` for `knowledge.toml` and `my-knowledge.toml` — so this page can never describe a shape either loader does not actually accept.

Do not hand-edit this file. Regenerate it with `vouch schema config --write` (or `vouch schema knowledge --write` — either one writes the complete set), then review the diff.

## config.toml

`config.toml` (`~/.config/vouch/config.toml`): what the operator has told
vouch to do. Anything not named here resolves to `ask` — absence of a
setting must never become permission.

### Top level

| Field | Type | Default | Description |
|---|---|---|---|
| `guards` | map of string to Action | (none) | What commands DO, written as `[guards]`. Shared across every language: a guard fires the same way whichever scanner recognised the command that tripped it. Every key must be one of vouch's known guard names (`bypass_enforcement`, `confidential_output`, `delete_recursive`, `grant_execute`, `history_rewrite`, `publish_outward`, `process_control`, `privilege_escalation`, `disk_or_system`, `in_place_edit`, `local_state_write`, `remote_execution`); an unset guard always resolves to `ask`. |
| `lang` | map of string to LangConfig | (none) | Every language section, written as `[lang.<name>]` — `bash`, `powershell`, and `python` ship with vouch. One map, so a new scanner needs no new key here. |
| `protected` | ProtectedSection | (none) | `[protected]`: paths no `allow_paths` entry can ever open. |
| `run` | RunSection | (none) | `[run]`: run-place zones, executable-place program trust, and place-scoped guard overrides. |
| `shadow` | ShadowSection (optional) | (none) | `[shadow]`: mode-keyed shadow (design 2026-08-16). |
| `tools` | map of string to Action | (none) | Per-tool actions, written as `[tools]`. vouch used to say NOTHING about any tool it had no scanner for — 46.5% of recorded tool calls — which is the same "unknown means allowed" inversion as unmodelled programs, one level up. Naming a FIRST tool here makes this section govern every tool, not only the one named; see `Config::tool_decision`. |
| `version` | integer (optional) | (unset) | Accepted as a top-level key but not yet consumed; reserved for future versioning of the config format. |
| `write` | FileConfig | (none) | `[write]`: what vouch does about a write it can see, and where it is allowed to land. |

### `Action`

What vouch does about a construct, a guard, or a program: let the command
through, stop and ask the operator, or refuse it outright.

- `allow` — Let it through with no prompt.
- `ask` — Stop and show the operator what was recognised, before it runs.
- `deny` — Refuse it outright, with no prompt.

### `FileConfig`

The `[write]` table: what vouch does about a write it can see, and where
it is allowed to land.

| Field | Type | Default | Description |
|---|---|---|---|
| `allow_paths` | array of string | [] | Trees a write may land under with no prompt. Checked only after the write wall (`ask_paths`/`deny_paths`) has already let it through. |
| `ask_paths` | array of string | [] | Write wall: a write aimed under one of these trees always asks. No `allow_paths` entry, however broadly written, can open a tree named here. |
| `default` | Action | (none) | Verdict for a write whose destination is not covered by any of the lists below. |
| `deny_paths` | array of string | [] | Write wall: a write aimed under one of these trees is refused outright, with no prompt. Checked before `ask_paths`. |
| `scope` | array of WriteScope | (none) | Per-program write scopes, written as `[[write.scope]]`. |

### `GuardOverride`

A place-scoped guard override (`[[run.guards]]`): under one of `under`'s
trees, each named guard takes the action given here instead of its global
`[guards]` action. A looser override applies only where vouch can PROVE
the command ran in the tree. A stricter one restricts instead, so it
applies wherever any directory the command could be running in is under
the tree, and wherever vouch cannot place the command at all; it stands
down only when every possible directory is known and none is under it.

| Field | Type | Default | Description |
|---|---|---|---|
| `under` | array of string | (required) | The trees this override applies under. Each entry is a path or a `path/**` glob. |

### `LangConfig`

Settings for one language: `[lang.bash]`, `[lang.powershell]`,
`[lang.python]` — one shape for every scanner, looked up by name.

| Field | Type | Default | Description |
|---|---|---|---|
| `constructs` | map of string to Action | (none) | Per-construct verdicts, written as `[lang.<name>.constructs]`. A construct with no entry here defaults to `ask`, never to `default` above — absence of a setting must never become permission. |
| `default` | Action | (none) | Verdict when nothing this language's scanner recognised objected. Never applies to a construct — an unset construct always resolves to `ask`, whatever this says. |
| `wrap_depth` | integer (optional) | (unset) | How many layers of wrapper nesting are scanned before a deeper nest trips `wrap_depth_exceeded` and asks. `None` means the operator has not set it, so the built-in cap (4) applies. Read by the engine's wrapper walk, not by this file. |

### `ProgramLocationTrust`

One `[[run.trust_program]]` entry: recognise a path-spelled shell program
only when its existing canonical file is under one of `under`'s trees AND
its logical filename follows one of `name_patterns`' exact/prefix
conventions. This recognises the whole matching program, not one verb, and
never searches PATH. Recognition only; guards and write rules still apply.

| Field | Type | Default | Description |
|---|---|---|---|
| `name_patterns` | array of string | (required) | Logical executable names, either exact or a non-empty literal prefix followed by one terminal `*`. The platform `.exe` suffix is removed before matching; path separators and `*` alone are refused. |
| `under` | array of string | (required) | Exact executable paths or executable trees ending in `/**`. `~` and `$PROJECT_ROOT` expand at decision time. Unlike every other `under` key, this names where the PROGRAM FILE lives, not where it runs. |

### `ProtectedSection`

The `[protected]` table: paths no `allow_paths` entry can ever open,
however broadly it is written. Checked before every allow rule, by
identity rather than by folder.

| Field | Type | Default | Description |
|---|---|---|---|
| `paths` | array of string | [] | The protected paths themselves — vouch's own config and the hook registration, by default. This list IS the setting: removing a path from it is the only way to unprotect that path. |

### `RunSection`

The `[run]` table: run-place trust and distrust zones, executable-place
program trust, and place-scoped guard overrides.

| Field | Type | Default | Description |
|---|---|---|---|
| `guards` | array of GuardOverride | (none) | Place-scoped guard overrides, written as `[[run.guards]]`. |
| `trust_all_under` | array of string (optional) | (unset) | Trust zone: any command run from under one of these trees is recognised, whatever it is — recognition only, guards and write rules still apply. `None` means absent (fine); a written empty list is refused at load, since it can never apply. It grants, so it needs every directory the command could be running in proven inside one of these trees: one member vouch cannot place, or one that is outside, recognises nothing. |
| `trust_nothing_under` | array of string (optional) | (unset) | Distrust zone: no command run from under one of these trees is recognised, whatever it is — even a program a knowledge entry describes. Refused when written empty, same as the grants above: a written empty list can only be a mistake. It restricts, so it applies wherever any directory the command could be running in is under it, and wherever vouch cannot place the command at all; it stands down only when every possible directory is known and none is under it. |
| `trust_program` | array of ProgramLocationTrust | (none) | Program-location trust rules, written as `[[run.trust_program]]`. Both an existing canonical executable location and a logical filename convention must match; bare names and uncertainty grant nothing. |

### `ShadowSection`

`[shadow]`: stand down from gating while the harness reports a named
permission mode. vouch still evaluates and journals every call; what
would prompt is not emitted. An ALLOW is never suppressed.

| Field | Type | Default | Description |
|---|---|---|---|
| `modes` | array of string (optional) | (unset) | Which permission modes stand vouch down. The six documented spellings only; a written empty list refuses. |
| `stand_down` | StandDown (optional) | (none) | The three-state toggle. `Option` so the missing-key refusal can name the three values instead of serde's bare missing-field error; `validate` refuses `None`, so it is always `Some` in a loaded config. |

### `StandDown`

The `[shadow]` three-state toggle (mode-keyed shadow, design 2026-08-16):
what standing down suppresses. Required when the section is present —
the feature's own switch is never defaulted.

- `keep-deny` — Stand down, but what BLOCKS still blocks: a deny, and the protection
asks (the protected list, the ask_paths wall).
- `full` — Stand down every prompt and every block; only allows are emitted.
- `off` — Never stand down — the same as the section being absent.

### `WriteScope`

One `[[write.scope]]` entry: this program's own writes may land only
under `only_under` — judged against the write's resolved target, not the
whole command line.

| Field | Type | Default | Description |
|---|---|---|---|
| `only_under` | array of string | (required) | The trees this program's writes may land under. A write outside all of them asks, and `write.allow_paths` is not consulted for a scoped program. |
| `programs` | array of string | (required) | Which programs this scope restricts. Each entry is 1-3 tokens: the program name, optionally a subcommand, and optionally that subcommand's own second word (`"git worktree add"`). If a stated verb word is unreadable, the scope is unprovable and asks; it neither grants one entry by file order nor falls through to a later scope or wider global allowance. |

## knowledge.toml / my-knowledge.toml

`knowledge.toml` (what ships with vouch) and `my-knowledge.toml` (the
operator's own additions) both parse into this same shape: what programs
and harness tools ARE and DO. The operator's file is laid over the
shipped one, entry by entry, by name.

### Top level

| Field | Type | Default | Description |
|---|---|---|---|
| `env_name` | array of EnvName | (none) | One entry per environment-variable name the shell itself consults, written as `[[env_name]]`. |
| `program` | array of Program | (none) | One entry per described program, written as `[[program]]`. |
| `tool` | array of Tool | (none) | One entry per described harness tool (or whole MCP server), written as `[[tool]]`. |
| `version` | integer (optional) | (unset) | The schema version the file was written against. `None` means the file predates this key. Enforced in `knowledge::read_one`, and ONLY for the shipped file: a `None` here or a value below `knowledge::KNOWLEDGE_SCHEMA_VERSION` refuses the whole shipped load (spec §7, rev 3/4) rather than running blind on fields it never wrote. `my-knowledge.toml` parses into this same struct but is never checked against this field — operator files predate every schema change by design. |

### `Action`

What vouch does about a construct, a guard, or a program: let the command
through, stop and ask the operator, or refuse it outright.

- `allow` — Let it through with no prompt.
- `ask` — Stop and show the operator what was recognised, before it runs.
- `deny` — Refuse it outright, with no prompt.

### `EnvName`

An environment-variable name the SHELL ITSELF reads — not data the
command happens to be handed, but a name that changes which program a
later word resolves to, or what code the shell runs before the command
on the line (M2.120).

The distinction this kind exists to make: `LC_ALL=C sort f` sets
something `sort` reads, and vouch's description of `sort` still holds.
`PATH=<dir> ls` sets something the SHELL reads, and the `ls` that runs
is whatever sits in that directory — vouch's description of `ls` is then
a description of a program that is not running. Only names listed here
are read that way; every other assignment stays inert, which is what
keeps the ordinary case quiet.

| Field | Type | Default | Description |
|---|---|---|---|
| `effect` | string | "" | What the shell does with it, from the closed set validated at load:   "lookup"  — it decides which program a name resolves to, so the               command that runs may not be the one described               (`rebound_name`)   "startup" — it names code the shell runs before the command on the               line, which vouch has not read (`evaluated_input`) |
| `languages` | array of string | [] | Which scanner's lines this claim is true for, same meaning as a `[[program]]`'s. Empty means every language. |
| `name` | string | "" | The variable's name. Matched the way the PLATFORM matches it: exactly under bash, where `path=x` sets an ordinary variable and changes nothing, and case-insensitively under PowerShell, where `$env:Path` and `$env:PATH` are the same variable (both verified by running). |

### `HereWrite`

"With this shape and no destination named, this program writes into the
directory it is RUN from" — the write-side twin of `changes_dir` silence
(M2.129). `tar -xf a.tar` puts the archive's members in the run place,
`curl -O <url>` puts the URL's basename there, and vouch derived no
destination at all for either, so the commonest download-and-extract
spellings went unjudged while their explicit twins asked.

The claim is conditional because these programs only do it in some
shapes. All three conditions are ANDed, and validation requires at least
one of them to be set — an entry claiming a program ALWAYS writes where
it stands, unconditionally, is one this key has no way to be right about.

| Field | Type | Default | Description |
|---|---|---|---|
| `operands` | integer (optional) | (unset) | The exact number of operands the claim needs, when arity is what decides. `ln -s <target>` with ONE operand creates the link where it stands, under the target's basename (verified by running); with two, the second operand names the link and `writes = "last_arg"` already derives it. |
| `subcommand` | string (optional) | (unset) | The subcommand this claim is about, when the program has verbs. Unset means the claim is about the program however it is called. |
| `unless_flags` | array of string | [] | None of these may be present. Two different populations, both of which make the claim false: a flag that names the destination explicitly (`tar -C`, `unzip -d`), and a flag that makes the program write nothing at all (`unzip -l`, which lists).  **Not the same field as `Rule::unless_flags`, despite the name.** This one matches in ANY position and also suppresses on a flag that merely COULD be hiding in an unreadable token, because suppressing a derived write is the cautious direction here. The rule's veto is first-argument, exact-spelling, and suppresses only on a flag it can SEE, because there the cautious direction is to keep asking. |
| `when_flags` | array of string | [] | At least one of these flags must be present. Empty means the shape needs no flag — `unzip a.zip` and a bare `wget <url>` both extract or download where they stand with nothing switched on. |

### `Program`

One `[[program]]` entry: what a program IS and DOES. `knowledge.toml`
ships these for programs vouch describes out of the box;
`my-knowledge.toml` adds the operator's own, laid over the shipped set by
name.

| Field | Type | Default | Description |
|---|---|---|---|
| `all_subcommands` | boolean | false | Claims every subcommand, in an entry that would otherwise read as adding to a scoped one.  `subcommands` and `subcommand_paths` widen and never narrow, so a file cannot go from scoped coverage to all operations by leaving both keys out — that would make an omission permissive. Saying it out loud is the same rule as `vouch trust --all-subcommands` (§2). |
| `arg_names` | array of string | [] | This program's own positional parameters, named in call order — `["file", "mode"]` for python's `open`. What `writes = "arg_<N>"` and `wraps = "arg_<N>"` count positions against, and what `writes_only_with_file_mode` looks a `"mode"` position up in. For a method-shaped call the receiver fills position 0 and takes no name of its own, so names start at position 1.  Non-empty replaces on merge, like `value_options` — the operator's own list is a full replacement of the shipped one, not a field-by-field lay. |
| `args_from_input` | boolean | false | This program APPENDS arguments it reads from a channel the command line never names — `xargs` takes them from its standard input or from a file, and what it appends decides what the command it runs acts ON (M2.116). Rule 5 of any wrapper walk — "every remaining token is the wrapped command's arguments" — is simply untrue here, so the wrapped command's recorded arguments are not a faithful record of what it will be given, and every claim that depends on reading them fails closed. |
| `callback_args` | array of string | [] | This program's own parameters that it INVOKES as functions. An occupant carrying no callable mark — a subscript, a call result, a starred argument, or a `**` unpack that could be filling one — is unread and could still be a function at runtime, so it asks through the generic `callback_argument` construct. A marked occupant is judged instead: a literal lambda (`CallableArg::Inline`) raises neither construct, since its body was already scanned where it appears; a resolved reference (`CallableArg::Named`) is judged as its own call, with no arguments and unknown order (`by_reference_invocations`) — vouch sees THAT the reference exists, not what this program itself will pass it, so the outcome is whatever that reference's own entry produces; and a reference vouch could not NAME at all, or one whose entry carries a claim that call cannot evaluate without arguments, asks through `callable_argument` (`unresolved_callback_argument`). Because the real invocation is never observed directly, this entry's own general claims (pure read, no writes) say nothing about what a marked occupant does — that occupant is judged independently, through whichever path above applies, rather than inherited from this entry (task 2b, M2.86 and M2.89: `json.load(f, object_hook=whatever)` hands `object_hook` a function `json.load` calls itself, with arguments the scanner never sees, while `map(str, xs)` hands `map` a harmless, fully-described reference and allows). A positional callback slot must ALSO be named in `arg_names`, at its real position, so the existing keyword fold maps both spellings onto one check; a keyword-only one is legitimately absent from `arg_names`. Every name uses the shared ASCII parameter grammar: a letter or `_` first, then letters, digits, or `_`.  Non-empty replaces on merge, like `arg_names`. |
| `case_sensitive_flags` | boolean (optional) | (unset) | Whether `write_flags` must match case exactly.  PowerShell parameter names are case-insensitive, so `-Path` is declared lowercase and matched loosely. Unix flags are NOT: `tar -C` is the destination directory while `tar -c` means create, and matching them loosely would record the token after `-c` as a written path.  `None` means the entry did not say. That differs from `Some(false)` once two files describe the same program: unset means "keep what the other file said", and only an entry that spells it out changes it. |
| `changes_dir` | string (optional) | (unset) | The dir-change kind: what the walk can KNOW about where the shell goes after this program runs. One of `"no"`, `"stated"`, `"stack"`, `"unstated"` — a closed set, checked in `knowledge::validate`.  `"no"` exists so an operator can RETRACT a shipped claim: without it, a false "this moves the shell" has no operator-side fix.  `None` means the entry did not say. That differs from `Some("no")` once two files describe the same program: unset means "keep what the other file said", and only an entry that spells it out changes it — the same rule `case_sensitive_flags` follows. |
| `dest_dir_flags` | array of string | [] | Options that consume the following token AND that token is the destination the SHELL moves to for everything after this command — sibling of `run_dir_flags` (where THIS command runs) but for where the shell goes next. |
| `evaluates_input` | string | "" | This program runs text it obtains at execution time, so the thing that actually runs is not in the command vouch was given — unless vouch can prove it IS: a here-document on the same command, consumed and scanned, satisfies the "stdin" claim, because then the code is in the command after all.   "always" — e.g. Invoke-Expression, whatever its argument turns out to be   "stdin"  — a shell with no script and no -c snippet is reading code              from its standard input, as in `curl … \| bash` |
| `flag_prefix` | array of string | [] | How this program spells flags. cmd.exe uses `/s`, not `-s`; without this its flags read as paths and its paths read as flags, so both the guard rules and the written-path list come out wrong.  A list, because one name can belong to two languages: `del /s` is cmd, `del -Recurse` is the PowerShell alias for Remove-Item. Empty means "-". |
| `here_write` | array of HereWrite | (none) | Shapes in which this program writes into the directory it runs from without naming a destination, written as `[[program.here_write]]`. |
| `languages` | array of string | [] | Which scanned languages this entry applies to: values from `"bash"`, `"powershell"` — the scanners this field scopes entries against (`src/shell.rs`, `src/powershell.rs`). Python is a third scanner but is not a value here: a python snippet is scoped through the `python:` match prefix on the entry's own name, not through this field. Empty means every language, which is what every entry meant before this field existed.  A claim can be true in one language and false in the other: `chdir` is a `Set-Location` alias in PowerShell and is not a bash builtin at all. |
| `leading_args` | integer (optional) | (unset) | For `wraps = "rest"`: how many leading DATA positionals this wrapper consumes before the wrapped command's head. `timeout` takes exactly one (the duration), `chrt` one (the priority); every other rest wrapper takes none.  Replaces the duration heuristic the rest arm used to run (a token that looked like `5`/`30s`/`1.5h` was skipped wherever it appeared, for every rest wrapper). That guess read `env 5 rm -rf d` and `nice 30s rm` the same way it read `timeout 5 rm`, and it could not skip a leading positional that did not look like a duration — `timeout --signal TERM 5 sleep 1` among them. A count declared per program says the same thing without guessing at the token's shape.  `None` means the entry did not say (reads as 0). Same `Option` merge rule as `case_sensitive_flags`: unset keeps whatever the other file already claimed. |
| `match` | array of string | (required) | The program's own name(s), compared bare (no directory, no `.exe`) and case-insensitively. `python:`-prefixed names describe a python callable instead of a shell program. |
| `named_positional` | string (optional) | (unset) | For `writes = "named"`'s POSITIONAL FALLBACK only — never consulted when a `write_flags` member actually matched. Which positional names the destination when none did: `"first"` or `"last"` (the default).  PowerShell's `Set-Content [-Path] <string[]> [-Value] <Object[]>` puts the destination FIRST and the written CONTENT second, while `Copy-Item <source> <destination>` puts the destination LAST — one program-wide fallback that always picked "last" read `Set-Content f x` as writing to `x`, when `f` is the file that gets `x` written into it (M2.128).  `None` means the entry did not say (reads as "last"). Same `Option` merge rule as `case_sensitive_flags`: unset keeps whatever the other file already claimed. |
| `no_value_options` | array of string | [] | Options that take NO following token — needed so a destination walk does not mistake the option itself for a positional argument, or the token after it for the option's value. |
| `only_under` | array of string (optional) | (unset) | Place-scoped recognition: this entry is trusted only when the command runs under one of these globs. For the OPERATOR's own programs only — `knowledge::validate_place_scopes` refuses it on a name the shipped knowledge already describes, and refuses a scoped name split across more than one of the operator's own entries, so the overlay never has to decide what "unset means keep" means for a field that in practice never collides (spec 2026-08-06 §Refused shapes).  `None` means the entry did not say — same `Option` merge rule as `changes_dir` and `case_sensitive_flags`. Read by `recognises_at` for the verdict, and by `place_scopes` for the prompt that has to name an entry the run place put out of reach. |
| `produces` | array of string (optional) | (unset) | Origin tags this call's return value is known to produce. Tags are policy vocabulary declared by knowledge, not a closed set in code. A call that occupies one of this entry's declared `callback_args` withholds these tags because the callback may customize the result. `None` means this entry is silent; `Some([])` explicitly retracts a shipped producer claim during an overlay. |
| `rebinds_name_flags` | array of string | [] | Flags in which this program BINDS a name to something else — `hash -p <path> <name>` installs `<path>` under `<name>` in the shell's own lookup table, so a later `<name>` on the line runs that path (verified by running). The name-side twin of `[[env_name]]`'s `"lookup"` effect: there a variable the shell reads is assigned, here a program is told to change the table directly. Raises `rebound_name`. |
| `receiver_from` | array of string (optional) | (unset) | Origin tags required of a method call's receiver before any claim on this entry applies. `None` leaves the entry unconditional; `Some([])` explicitly removes a shipped receiver gate during an overlay. |
| `remote_dest` | boolean | false | This program's destination may be on ANOTHER MACHINE — `scp f host:d`, `rsync a host:/b`. A `[user@]host:path` destination from such an entry is not a local file, so the local path rules have nothing to say about it and it is skipped rather than judged.  Per ENTRY, never globally (M2.131.4): the same `host:path` shape written for `cp` is a local file with a colon in its name — on NTFS, an alternate data stream of the file before the colon — and skipping it there means a real write goes unjudged. |
| `rule` | array of Rule | (none) | Guard-tripping shapes for this program, written as `[[program.rule]]`. |
| `run_dir_flags` | array of string | [] | Options that consume the following token AND that token is the directory the command runs in — a flag whose value is the directory the command runs in, declared per program in the knowledge file. A subset of `value_options` — every run-dir flag also has to be in that list, or its value would be mistaken for the subcommand.  Matched by exact token equality, never case-folded (§7): `-c` is a value option (config), not `-C` (run directory). |
| `runs_file` | string | "" | This program EXECUTES a file named on its own command line, and vouch has not read that file — `bash s.sh`, `python s.py`. Written as `"arg_<N>"`, counting the program's own OPERANDS (tokens left after this entry's flag vocabulary is walked), so `arg_0` is "the first thing that is not one of my flags or a flag's value".  Distinct from `evaluates_input`, which covers the case where the code arrives on standard input and is therefore not on the line at all. Here the code's LOCATION is on the line and its CONTENT is not, which is the same blindness and the same construct (`evaluated_input`); reading the named file in order to allow it is deliberately out of scope (spec §9.1, ROADMAP M2.133).  A wrap arm that already consumed this line wins: `bash -c '<code>'` puts the code IN the command, so the operand after `-c` is a script vouch has read, not one it has not. |
| `runs_file_flags` | array of string | [] | Flags whose VALUE names code this program will run without vouch having read it — python's `-m <module>`, which names a module by import path rather than by file path. The flag half of `runs_file`, the way `write_flags` is the flag half of `writes`. |
| `snippet_args` | array of SnippetArgs (optional) | (none) | Indexed argument vectors a parsed snippet receives from this program's own invocation. The scanner reports only structure; this knowledge claim connects that structure to the enclosing program's arguments.  `None` means this entry is silent. `Some([])` explicitly retracts an overlaid claim; a non-empty list replaces it whole. |
| `standalone_flags` | array of string | [] | Flags this entry vouches for ALONE: a run whose every argument is one of these (whole-token, unquoted view, the entry's case rule) is a standalone run — covered by the entry, and read as evaluating no standard input. The claim per flag: given only listed flags, the program performs the flag's own action and stops. Verified by running each flag, per name and case — each alone and once all together — before it is written. |
| `sub_write` | array of SubWrite | (none) | Write targets that depend on the SUBCOMMAND, not on the program.  `git` writes wherever `clone`, `init` and `worktree add` are told to, and nowhere for `status` or `log`. A single `writes` for the whole program cannot say that. |
| `subcommand_paths` | array of array of string (optional) | (unset) | Exact positional command paths this entry recognises.  Each non-empty inner vector is matched from the first positional word under this entry's flag grammar. `[["mcp", "get"]]` recognises that operation without recognising `mcp add` or another sibling. Either this key or `subcommands` being present makes the entry scoped; both absent still means whole-program coverage. When both are present their scopes are unioned. |
| `subcommands` | array of string (optional) | (unset) | Which subcommands this entry recognises.  Three states (spec 2026-08-20 §3): the key ABSENT (`None`) covers the whole program — every run; a non-empty list covers those verbs, plus standalone runs when `standalone_flags` is present; an explicitly EMPTY list covers no verb at all — only standalone runs, and the loader refuses that spelling without a non-empty `standalone_flags` (an entry that can never recognise anything reads as installed protection and is worse than none). |
| `value_options` | array of string | [] | Options that consume the following token. Needed to find the subcommand. |
| `wrap_exec_flags` | array of string | [] | For `wraps = "after_exec"`: the flags after which the wrapped command begins. `find` spells four of them — `-exec`, `-execdir`, `-ok`, `-okdir` — and the walk expands EVERY occurrence, not just the first.  Was two hardcoded literals in the wrap arm, which is a program name in `src/` (§10: no program or tool names in code) and which left `-ok`/`-okdir` — the confirming twins of the two that were listed — running unjudged. |
| `wrap_exec_terminators` | array of string | [] | For `wraps = "after_exec"`: the tokens that END the wrapped command. `find` accepts `;` (usually written `\;` so the shell does not eat it) and `+`. A declared exec flag whose command reaches the end of the argument list without meeting one of these raises `wrap_unlocated`: the layers vouch was told exist were never found. |
| `wrap_flags` | array of string | [] | For `wraps = "after_flag"`: the flags whose value is the wrapped snippet. |
| `wrap_head_flags` | array of string | [] | For `wraps = "start_process"`: the flags whose VALUE names the program this entry starts, rather than carrying an ordinary value — `Start-Process -FilePath <program>`. A subset of `value_options` (checked in `knowledge::validate`), the same relationship `run_dir_flags` has: the flag has to be known to consume its value, or the walk would read that value as a positional.  Without this the program is only ever the first positional, and the flag spelling of the same command reached the end of the arguments with no positional found — which the arm then read as "this wrapped nothing" while the argument list sat in the command unjudged. |
| `wrap_join` | boolean (optional) | (unset) | Whether this program's wrapped snippet spreads over every token after the flag, rather than being one token: `cmd /c echo hi there` hands the shell three tokens as one command line, while python's own `-c` takes exactly the next token as the whole program and leaves the rest as the script's own argv. `true` rejoins the remaining tokens into one snippet; unset or `false` reads only the flag's own value.  `None` means the entry did not say. Same `Option` merge rule as `case_sensitive_flags`: unset keeps whatever the other file already claimed. |
| `wrap_lang` | string | "" | Which language the wrapped snippet is written in: one of the scanner languages (`bash`, `powershell`, `python`, `javascript`), or `opaque` (a language vouch has no parser for at all) or `cmd` (cmd.exe batch — not bash, so it is scanned no more than any other unscannable language) — a closed set, checked in `knowledge::validate`. A snippet in `opaque`, `cmd`, or any other unscannable language still asks (`unreadable_language`, spec 2026-08-14 §5.2) rather than passing unread.  Required for the three arms that scan TEXT (`wraps` = `"after_c"`, `"after_flag"`, or `"arg_<N>"`) — leaving it unset there used to fall back to silently scanning the snippet as bash, which is exactly the laundering this field exists to prevent. Not required for the arms that build a command rather than scan text (`"rest"`, `"after_exec"`, `"start_process"`). |
| `wraps` | string | "" | How this program runs ANOTHER command: "rest", "after_c", "after_exec", "after_flag", or "arg_<N>" naming one numbered positional argument as the wrapped snippet (see `arg_names`). |
| `write_flags` | array of string | [] | For `writes = "named"` and `"flags_only"`: the parameters whose value is the written path. |
| `writes` | string | "" | Which arguments this program writes to: "last_arg", "all_args", "of_prefix", "named", "flags_only", or "arg_<N>" naming one numbered positional argument (see `arg_names`). Empty means it is not known to write anything. |
| `writes_only_with_file_mode` | boolean (optional) | (unset) | A `writes = "arg_<N>"` claim only writes when this call's OWN "mode" argument says so — python's `open(file, mode)` shape, where a read-mode call touches nothing on disk. `true` needs a `"mode"` position to test: `arg_names` must name one, checked in `knowledge::validate`. The direction runs one way only — an entry may name `"mode"` in `arg_names` without setting this (a chmod-shaped entry whose mode is an integer, never a write predicate).  `None` means the entry did not say. Same `Option` merge rule as `case_sensitive_flags`: unset keeps whatever the other file already claimed. |
| `writes_via_handle` | string (optional) | (unset) | This ENTRY's claim: at the named position ("arg_<N>", receiver = 0) or keyword-only parameter (the same ASCII identifier grammar `callback_args` uses), the call writes through a file object already judged where it was minted — so the engine extracts NO write target from this call itself; the value is documentary, and validation checks only its spelling and its exclusivity with the other write claims.  This field does not itself prove the named value is a handle. A receiver-shaped entry whose claim depends on that fact pairs it with `receiver_from`; the shipped `.write`/`.writelines` entry requires a receiver carrying `file_handle`, so an ElementTree or other unknown same-named receiver gets no applicable claim and asks. Direct calls such as `json.dump` and `print` name their explicit handle parameter instead and need no receiver gate.  `None` means the entry did not say. Same `Option` merge rule as `writes_only_with_file_mode`. |

### `Rule`

One `[[program.rule]]`: the shape that trips a guard. A rule fires when
the command matches every non-empty condition it names; an empty list
condition matches nothing (never "anything"), so a rule with no
conditions at all fires only via `always`.

| Field | Type | Default | Description |
|---|---|---|---|
| `always` | boolean | false | Fires on every invocation of the program, with no other condition needed. |
| `any_arg_exact` | array of string | [] | Fires when any argument equals one of these exactly. |
| `any_arg_prefix` | array of string | [] | Fires when any argument starts with one of these. |
| `any_flag` | array of string | [] | Fires when any flag on the command is one of these. |
| `grants_execute` | boolean | false | This command hands another program permission to run — e.g. `chmod +x`. Trips `grant_execute` on its own, independent of the other conditions. |
| `guard` | string | (required) | The guard this rule trips — one of vouch's known guard names (`confidential_output`, `delete_recursive`, `grant_execute`, `history_rewrite`, `publish_outward`, `process_control`, `privilege_escalation`, `disk_or_system`, `in_place_edit`, `local_state_write`, `remote_execution`). |
| `source` | string | "" | Where this rule came from: `declared` (the operator's own config), `requested` (they asked for it), or `inferred` (a guess). Surfaced in the prompt so the operator always knows whose judgement they are seeing. |
| `sub_arg_0_in` | array of string | [] | Fires when the subcommand's own first argument is one of these. |
| `subcommand_in` | array of string | [] | Fires when the command's subcommand is one of these. |
| `unless_flags` | array of string | [] | Does NOT fire when the command's FIRST argument is exactly one of these — the veto, checked before every other condition including `always`.  Exists because a program can have one spelling that does not do the thing its guard is about, and the positive conditions cannot say so: `kill -0 <pid>` sends no signal at all, it asks the kernel whether the process exists. Without a veto the choice is a guard that asks on a liveness check or no guard at all, and both are wrong.  **First argument, spelled exactly, and nothing else.** Both halves of that were learned by getting it wrong: an any-position reading allowed `kill -9 -0` (a later `-0` is a PID, and a negative PID is a process GROUP), and an attached-value reading allowed `kill -09`, which bash delivers as SIGKILL. A veto that fails to fire leaves the guard firing, so narrow is the safe direction here; an entry that needs an any-position veto should ask for its own key and say why.  Vetoes only on a flag vouch can SEE. A spelling it cannot read leaves the guard firing — the opposite of `here_write`'s `unless_flags`, which suppresses a derived write and therefore also suppresses on a flag that merely COULD be hiding in an unreadable token. |

### `SnippetArgs`

One indexed argument vector a parsed snippet receives from its enclosing
program invocation.

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | (required) | Dotted expression the language scanner reports structurally. |
| `source_at` | integer (optional) | (unset) | Index occupied by the syntax that selected the snippet, when exposed. |
| `trailing_from` | integer | (required) | Index occupied by the first outer argument after the snippet source. |

### `SubWrite`

A write target that depends on the SUBCOMMAND, not on the program as a
whole — `git` writes wherever `clone`, `init` and `worktree add` are
told to, and nowhere for `status` or `log`.

| Field | Type | Default | Description |
|---|---|---|---|
| `min_positional` | integer | 0 | How many non-flag arguments must follow the subcommand before one of them is a destination. `git clone <url>` writes to a directory named after the URL — unknowable — so it needs two. |
| `subcommand` | string | (required) | The subcommand this applies to, e.g. "clone". |
| `takes` | string | "" | Which of those arguments is the destination: "last" (the default) or "first".  `git clone <url> <dir>` puts it last, but `git worktree add <dir> [<commit-ish>]` puts it FIRST — taking the last recorded `HEAD` as a written path, which is a commit, not a directory. |
| `then` | string | "" | A second word that must follow it, e.g. "add" for `worktree add`. |

### `Tool`

A harness tool vouch has no scanner for, and what is claimed about it.

| Field | Type | Default | Description |
|---|---|---|---|
| `action` | Action (optional) | (none) | What to do about it. Unset means allow: being listed at all is the recognition claim.  "ask" is the interesting case. It says vouch knows exactly what this tool is and is stopping anyway — a different sentence from "vouch has never heard of this", and the prompt says which. |
| `cwd_from_call` | boolean (optional) | (unset) | This tool executes its snippet (or writes its path) in the calling session's own working directory. Only when true does a relative target get resolved against the hook's cwd; absent or false leaves it unresolvable, which asks (fail closed). |
| `match` | array of string | [] | Optional, unlike `Program::match_names` — a `server` entry (spec 2026-08-05 §Schema) names no individual tool at all, and without `default` here `deny_unknown_fields` would refuse it with "missing field `match`" before `knowledge::validate_tool` ever got to say why a match-less, server-less entry is wrong. |
| `server` | string (optional) | (unset) | A whole-server grant, said out loud (spec 2026-08-05 §Schema): matches `<server>__<tool>` for every tool that server exposes, instead of one tool by name. Mutually exclusive with a non-empty `match` — checked in `knowledge::validate_tool`. |
| `snippet` | array of ToolSnippet (optional) | (none) | Which named `tool_input` fields carry a script vouch should decide on. `None` means "keep what the shipped entry declares" — the same `Option` merge rule every other per-entry claim in this file follows. `Some(vec![])` is a load error (`knowledge::validate_tool`): there is no legitimate "explicitly no snippets" spelling, because that reading would let one silent my-knowledge line turn off snippet inspection for a shipped entry it only meant to add a `source` to. The actual off-switch is `tools.<name>` in config. |
| `source` | string | "" | Why this tool is described. Shown in `vouch doctor` and in the prompt, and it is the claim someone has to stand behind. |
| `write_path` | array of ToolWritePath (optional) | (none) | Structured write declarations. This is a list so one tool can carry multiple independent path-bearing fields; every declaration is evaluated and the worst result governs the call. |
| `write_path_field` | string (optional) | (unset) | The `tool_input` field whose value is the path this tool writes. What `Write` and `Edit` were hardcoded to do. |

### `ToolSnippet`

One declared snippet of a `[[tool]]` entry: a named `tool_input` field
that carries a script vouch should decide on, and how to learn which
language it is written in.

| Field | Type | Default | Description |
|---|---|---|---|
| `field` | string | (required) | A stated path into `tool_input`: dotted steps descend objects, `[]` maps over an array (`commands[].command`). No wildcards, no globs. |
| `language` | string (optional) | (unset) | A fixed snippet language. Exactly one of this and `language_from` — checked in `knowledge::validate_tool`, which also checks this value is in the closed `knowledge::snippet_languages()` set. |
| `language_from` | string (optional) | (unset) | Read a sibling `tool_input` field and translate its value through `language_values`. Exactly one of this and `language`. |
| `language_values` | map of string to string (optional) | (unset) | The translation table for `language_from`: the value read from the sibling field, on the left, maps to a `knowledge::snippet_languages()` name on the right — every right-hand value is checked against that closed set at load. |

### `ToolWritePath`

One tool-input field that names one or more paths the tool writes.

| Field | Type | Default | Description |
|---|---|---|---|
| `field` | string | (required) |  |
| `format` | ToolWritePathFormat | (none) |  |

### `ToolWritePathFormat`

How a declared tool-input field names writes.

- `scalar` — The field is one path string, equivalent to the legacy
`write_path_field` shorthand.
- `apply_patch` — The field is an OpenAI `apply_patch` envelope. Every add, update,
delete, and move path in the envelope is decided; worst wins.

