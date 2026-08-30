//! Guards: what a command *does*, not what it is called.
//!
//! There are NO command names in this file. The knowledge lives in
//! `knowledge.toml` as data; this module implements a small fixed vocabulary of
//! predicates and evaluates the data against a parsed command.
//!
//! A guard hit asks by default and is never proposable as a standing rule.
//! Approving one instance must never become policy.
//!
//! Matching is on parsed head + argv, never raw text, so `git -C /repo push
//! --force`, `git push -f`, and `git -c x=y push --force` are one thing.

use crate::knowledge::Entry;
use crate::shell::Cmd;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashSet;

pub const KNOWN_GUARDS: &[&str] = &[
    "confidential_output",
    "delete_recursive",
    "grant_execute",
    "history_rewrite",
    "publish_outward",
    "process_control",
    "privilege_escalation",
    "disk_or_system",
    "in_place_edit",
    "local_state_write",
    "remote_execution",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub guard: String,
    pub source: String,
    pub detail: String,
    /// The token that made this rule's verb criterion indeterminate. Such a
    /// hit is decided by the language's `unread_verb` construct, not by the
    /// guard action: unread syntax is a promptable limit, not proof of the
    /// guarded effect.
    pub unread_verb: Option<String>,
}

/// One `[[program.rule]]`: the shape that trips a guard. A rule fires when
/// the command matches every non-empty condition it names; an empty list
/// condition matches nothing (never "anything"), so a rule with no
/// conditions at all fires only via `always`.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The guard this rule trips — one of vouch's known guard names
    /// (`confidential_output`, `delete_recursive`, `grant_execute`, `history_rewrite`,
    /// `publish_outward`, `process_control`, `privilege_escalation`,
    /// `disk_or_system`, `in_place_edit`, `local_state_write`,
    /// `remote_execution`).
    pub guard: String,
    /// Where this rule came from: `declared` (the operator's own config),
    /// `requested` (they asked for it), or `inferred` (a guess). Surfaced in
    /// the prompt so the operator always knows whose judgement they are
    /// seeing.
    #[serde(default)]
    pub source: String,
    /// Fires when the command's subcommand is one of these.
    #[serde(default)]
    pub subcommand_in: Vec<String>,
    /// Fires when the subcommand's own first argument is one of these.
    #[serde(default)]
    pub sub_arg_0_in: Vec<String>,
    /// Fires when any flag on the command is one of these.
    #[serde(default)]
    pub any_flag: Vec<String>,
    /// Does NOT fire when the command's FIRST argument is exactly one of
    /// these — the veto, checked before every other condition including
    /// `always`.
    ///
    /// Exists because a program can have one spelling that does not do the
    /// thing its guard is about, and the positive conditions cannot say so:
    /// `kill -0 <pid>` sends no signal at all, it asks the kernel whether the
    /// process exists. Without a veto the choice is a guard that asks on a
    /// liveness check or no guard at all, and both are wrong.
    ///
    /// **First argument, spelled exactly, and nothing else.** Both halves of
    /// that were learned by getting it wrong: an any-position reading allowed
    /// `kill -9 -0` (a later `-0` is a PID, and a negative PID is a process
    /// GROUP), and an attached-value reading allowed `kill -09`, which bash
    /// delivers as SIGKILL. A veto that fails to fire leaves the guard
    /// firing, so narrow is the safe direction here; an entry that needs an
    /// any-position veto should ask for its own key and say why.
    ///
    /// Vetoes only on a flag vouch can SEE. A spelling it cannot read leaves
    /// the guard firing — the opposite of `here_write`'s `unless_flags`,
    /// which suppresses a derived write and therefore also suppresses on a
    /// flag that merely COULD be hiding in an unreadable token.
    #[serde(default)]
    pub unless_flags: Vec<String>,
    /// Fires when any argument equals one of these exactly.
    #[serde(default)]
    pub any_arg_exact: Vec<String>,
    /// Fires when any argument starts with one of these.
    #[serde(default)]
    pub any_arg_prefix: Vec<String>,
    /// This command hands another program permission to run — e.g. `chmod
    /// +x`. Trips `grant_execute` on its own, independent of the other
    /// conditions.
    #[serde(default)]
    pub grants_execute: bool,
    /// Fires on every invocation of the program, with no other condition
    /// needed.
    #[serde(default)]
    pub always: bool,
}

/// One indexed argument vector a parsed snippet receives from its enclosing
/// program invocation.
#[derive(Debug, Deserialize, Clone, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnippetArgs {
    /// Dotted expression the language scanner reports structurally.
    pub name: String,
    /// Index occupied by the syntax that selected the snippet, when exposed.
    #[serde(default)]
    pub source_at: Option<usize>,
    /// Index occupied by the first outer argument after the snippet source.
    pub trailing_from: usize,
}

/// One `[[program]]` entry: what a program IS and DOES. `knowledge.toml`
/// ships these for programs vouch describes out of the box;
/// `my-knowledge.toml` adds the operator's own, laid over the shipped set by
/// name.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// The program's own name(s), compared bare (no directory, no `.exe`)
    /// and case-insensitively. `python:`-prefixed names describe a python
    /// callable instead of a shell program.
    #[serde(rename = "match")]
    pub match_names: Vec<String>,
    /// Options that consume the following token. Needed to find the subcommand.
    #[serde(default)]
    pub value_options: Vec<String>,
    /// Options that consume the following token AND that token is the
    /// directory the command runs in — a flag whose value is the directory
    /// the command runs in, declared per program in the knowledge file. A
    /// subset of `value_options` — every run-dir flag also has to be in that
    /// list, or its value would be mistaken for the subcommand.
    ///
    /// Matched by exact token equality, never case-folded (§7): `-c` is a
    /// value option (config), not `-C` (run directory).
    #[serde(default)]
    pub run_dir_flags: Vec<String>,
    /// Options that take NO following token — needed so a destination walk
    /// does not mistake the option itself for a positional argument, or the
    /// token after it for the option's value.
    #[serde(default)]
    pub no_value_options: Vec<String>,
    /// Which arguments this program writes to: "last_arg", "all_args",
    /// "of_prefix", "named", "flags_only", or "arg_<N>" naming one numbered
    /// positional argument (see `arg_names`). Empty means it is not known to
    /// write anything.
    #[serde(default)]
    pub writes: String,
    /// How this program runs ANOTHER command: "rest", "after_c", "after_exec",
    /// "after_flag", or "arg_<N>" naming one numbered positional argument as
    /// the wrapped snippet (see `arg_names`).
    #[serde(default)]
    pub wraps: String,
    /// For `writes = "named"` and `"flags_only"`: the parameters whose value is
    /// the written path.
    #[serde(default)]
    pub write_flags: Vec<String>,
    /// Whether `write_flags` must match case exactly.
    ///
    /// PowerShell parameter names are case-insensitive, so `-Path` is declared
    /// lowercase and matched loosely. Unix flags are NOT: `tar -C` is the
    /// destination directory while `tar -c` means create, and matching them
    /// loosely would record the token after `-c` as a written path.
    ///
    /// `None` means the entry did not say. That differs from `Some(false)` once
    /// two files describe the same program: unset means "keep what the other
    /// file said", and only an entry that spells it out changes it.
    #[serde(default)]
    pub case_sensitive_flags: Option<bool>,
    /// For `wraps = "after_flag"`: the flags whose value is the wrapped snippet.
    #[serde(default)]
    pub wrap_flags: Vec<String>,
    /// Which language the wrapped snippet is written in: one of the scanner
    /// languages (`bash`, `powershell`, `python`, `javascript`), or `opaque`
    /// (a language vouch has no parser for at all) or `cmd` (cmd.exe batch —
    /// not bash, so it is scanned no more than any other unscannable
    /// language) — a closed set, checked in `knowledge::validate`. A
    /// snippet in `opaque`, `cmd`, or any other unscannable language still
    /// asks (`unreadable_language`, spec 2026-08-14 §5.2) rather than
    /// passing unread.
    ///
    /// Required for the three arms that scan TEXT (`wraps` = `"after_c"`,
    /// `"after_flag"`, or `"arg_<N>"`) — leaving it unset there used to fall
    /// back to silently scanning the snippet as bash, which is exactly the
    /// laundering this field exists to prevent. Not required for the arms
    /// that build a command rather than scan text (`"rest"`, `"after_exec"`,
    /// `"start_process"`).
    #[serde(default)]
    pub wrap_lang: String,
    /// Indexed argument vectors a parsed snippet receives from this program's
    /// own invocation. The scanner reports only structure; this knowledge
    /// claim connects that structure to the enclosing program's arguments.
    ///
    /// `None` means this entry is silent. `Some([])` explicitly retracts an
    /// overlaid claim; a non-empty list replaces it whole.
    #[serde(default)]
    pub snippet_args: Option<Vec<SnippetArgs>>,
    /// How this program spells flags. cmd.exe uses `/s`, not `-s`; without this
    /// its flags read as paths and its paths read as flags, so both the guard
    /// rules and the written-path list come out wrong.
    ///
    /// A list, because one name can belong to two languages: `del /s` is cmd,
    /// `del -Recurse` is the PowerShell alias for Remove-Item. Empty means "-".
    #[serde(default)]
    pub flag_prefix: Vec<String>,
    /// This program runs text it obtains at execution time, so the thing that
    /// actually runs is not in the command vouch was given — unless vouch can
    /// prove it IS: a here-document on the same command, consumed and scanned,
    /// satisfies the "stdin" claim, because then the code is in the command
    /// after all.
    ///   "always" — e.g. Invoke-Expression, whatever its argument turns out to be
    ///   "stdin"  — a shell with no script and no -c snippet is reading code
    ///              from its standard input, as in `curl … | bash`
    #[serde(default)]
    pub evaluates_input: String,
    /// This program EXECUTES a file named on its own command line, and vouch
    /// has not read that file — `bash s.sh`, `python s.py`. Written as
    /// `"arg_<N>"`, counting the program's own OPERANDS (tokens left after
    /// this entry's flag vocabulary is walked), so `arg_0` is "the first
    /// thing that is not one of my flags or a flag's value".
    ///
    /// Distinct from `evaluates_input`, which covers the case where the code
    /// arrives on standard input and is therefore not on the line at all.
    /// Here the code's LOCATION is on the line and its CONTENT is not, which
    /// is the same blindness and the same construct (`evaluated_input`);
    /// reading the named file in order to allow it is deliberately out of
    /// scope (spec §9.1, ROADMAP M2.133).
    ///
    /// A wrap arm that already consumed this line wins: `bash -c '<code>'`
    /// puts the code IN the command, so the operand after `-c` is a script
    /// vouch has read, not one it has not.
    #[serde(default)]
    pub runs_file: String,
    /// Flags whose VALUE names code this program will run without vouch
    /// having read it — python's `-m <module>`, which names a module by
    /// import path rather than by file path. The flag half of `runs_file`,
    /// the way `write_flags` is the flag half of `writes`.
    #[serde(default)]
    pub runs_file_flags: Vec<String>,
    /// Flags in which this program BINDS a name to something else — `hash -p
    /// <path> <name>` installs `<path>` under `<name>` in the shell's own
    /// lookup table, so a later `<name>` on the line runs that path
    /// (verified by running). The name-side twin of `[[env_name]]`'s
    /// `"lookup"` effect: there a variable the shell reads is assigned, here
    /// a program is told to change the table directly. Raises
    /// `rebound_name`.
    #[serde(default)]
    pub rebinds_name_flags: Vec<String>,
    /// This program APPENDS arguments it reads from a channel the command
    /// line never names — `xargs` takes them from its standard input or from
    /// a file, and what it appends decides what the command it runs acts ON
    /// (M2.116). Rule 5 of any wrapper walk — "every remaining token is the
    /// wrapped command's arguments" — is simply untrue here, so the wrapped
    /// command's recorded arguments are not a faithful record of what it will
    /// be given, and every claim that depends on reading them fails closed.
    #[serde(default)]
    pub args_from_input: bool,
    /// Shapes in which this program writes into the directory it runs from
    /// without naming a destination, written as `[[program.here_write]]`.
    #[serde(default)]
    pub here_write: Vec<HereWrite>,
    /// This program's destination may be on ANOTHER MACHINE — `scp f
    /// host:d`, `rsync a host:/b`. A `[user@]host:path` destination from
    /// such an entry is not a local file, so the local path rules have
    /// nothing to say about it and it is skipped rather than judged.
    ///
    /// Per ENTRY, never globally (M2.131.4): the same `host:path` shape
    /// written for `cp` is a local file with a colon in its name — on NTFS,
    /// an alternate data stream of the file before the colon — and skipping
    /// it there means a real write goes unjudged.
    #[serde(default)]
    pub remote_dest: bool,
    /// Guard-tripping shapes for this program, written as `[[program.rule]]`.
    #[serde(default)]
    pub rule: Vec<Rule>,
    /// Write targets that depend on the SUBCOMMAND, not on the program.
    ///
    /// `git` writes wherever `clone`, `init` and `worktree add` are told to,
    /// and nowhere for `status` or `log`. A single `writes` for the whole
    /// program cannot say that.
    #[serde(default)]
    pub sub_write: Vec<SubWrite>,
    /// Which subcommands this entry recognises.
    ///
    /// Three states (spec 2026-08-20 §3): the key ABSENT (`None`) covers the
    /// whole program — every run; a non-empty list covers those verbs, plus
    /// standalone runs when `standalone_flags` is present; an explicitly
    /// EMPTY list covers no verb at all — only standalone runs, and the
    /// loader refuses that spelling without a non-empty `standalone_flags`
    /// (an entry that can never recognise anything reads as installed
    /// protection and is worse than none).
    #[serde(default)]
    pub subcommands: Option<Vec<String>>,
    /// Exact positional command paths this entry recognises.
    ///
    /// Each non-empty inner vector is matched from the first positional word
    /// under this entry's flag grammar. `[["mcp", "get"]]` recognises that
    /// operation without recognising `mcp add` or another sibling. Either
    /// this key or `subcommands` being present makes the entry scoped; both
    /// absent still means whole-program coverage. When both are present their
    /// scopes are unioned.
    #[serde(default)]
    pub subcommand_paths: Option<Vec<Vec<String>>>,
    /// Flags this entry vouches for ALONE: a run whose every argument is one
    /// of these (whole-token, unquoted view, the entry's case rule) is a
    /// standalone run — covered by the entry, and read as evaluating no
    /// standard input. The claim per flag: given only listed flags, the
    /// program performs the flag's own action and stops. Verified by
    /// running each flag, per name and case — each alone and once all
    /// together — before it is written.
    #[serde(default)]
    pub standalone_flags: Vec<String>,
    /// Claims every subcommand, in an entry that would otherwise read as adding
    /// to a scoped one.
    ///
    /// `subcommands` and `subcommand_paths` widen and never narrow, so a file
    /// cannot go from scoped coverage to all operations by leaving both keys
    /// out — that would make an omission permissive. Saying it out loud is
    /// the same rule as `vouch trust --all-subcommands` (§2).
    #[serde(default)]
    pub all_subcommands: bool,
    /// The dir-change kind: what the walk can KNOW about where the shell goes
    /// after this program runs. One of `"no"`, `"stated"`, `"stack"`,
    /// `"unstated"` — a closed set, checked in `knowledge::validate`.
    ///
    /// `"no"` exists so an operator can RETRACT a shipped claim: without it, a
    /// false "this moves the shell" has no operator-side fix.
    ///
    /// `None` means the entry did not say. That differs from `Some("no")` once
    /// two files describe the same program: unset means "keep what the other
    /// file said", and only an entry that spells it out changes it — the same
    /// rule `case_sensitive_flags` follows.
    #[serde(default)]
    pub changes_dir: Option<String>,
    /// Which scanned languages this entry applies to: values from `"bash"`,
    /// `"powershell"` — the scanners this field scopes entries against
    /// (`src/shell.rs`, `src/powershell.rs`). Python is a third scanner but
    /// is not a value here: a python snippet is scoped through the
    /// `python:` match prefix on the entry's own name, not through this
    /// field. Empty means every language, which is what every entry meant
    /// before this field existed.
    ///
    /// A claim can be true in one language and false in the other: `chdir` is
    /// a `Set-Location` alias in PowerShell and is not a bash builtin at all.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Options that consume the following token AND that token is the
    /// destination the SHELL moves to for everything after this command —
    /// sibling of `run_dir_flags` (where THIS command runs) but for where the
    /// shell goes next.
    #[serde(default)]
    pub dest_dir_flags: Vec<String>,
    /// Place-scoped recognition: this entry is trusted only when the command
    /// runs under one of these globs. For the OPERATOR's own programs only —
    /// `knowledge::validate_place_scopes` refuses it on a name the shipped
    /// knowledge already describes, and refuses a scoped name split across
    /// more than one of the operator's own entries, so the overlay never has
    /// to decide what "unset means keep" means for a field that in practice
    /// never collides (spec 2026-08-06 §Refused shapes).
    ///
    /// `None` means the entry did not say — same `Option` merge rule as
    /// `changes_dir` and `case_sensitive_flags`. Read by `recognises_at` for
    /// the verdict, and by `place_scopes` for the prompt that has to name an
    /// entry the run place put out of reach.
    #[serde(default)]
    pub only_under: Option<Vec<String>>,
    /// This program's own positional parameters, named in call order —
    /// `["file", "mode"]` for python's `open`. What `writes = "arg_<N>"` and
    /// `wraps = "arg_<N>"` count positions against, and what
    /// `writes_only_with_file_mode` looks a `"mode"` position up in. For a
    /// method-shaped call the receiver fills position 0 and takes no name of
    /// its own, so names start at position 1.
    ///
    /// Non-empty replaces on merge, like `value_options` — the operator's own
    /// list is a full replacement of the shipped one, not a field-by-field
    /// lay.
    #[serde(default)]
    pub arg_names: Vec<String>,
    /// This program's own parameters that it INVOKES as functions. An
    /// occupant carrying no callable mark — a subscript, a call result, a
    /// starred argument, or a `**` unpack that could be filling one — is
    /// unread and could still be a function at runtime, so it asks through
    /// the generic `callback_argument` construct. A marked occupant is
    /// judged instead: a literal lambda (`CallableArg::Inline`) raises
    /// neither construct, since its body was already scanned where it
    /// appears; a resolved reference (`CallableArg::Named`) is judged as
    /// its own call, with no arguments and unknown order
    /// (`by_reference_invocations`) — vouch sees THAT the reference exists,
    /// not what this program itself will pass it, so the outcome is
    /// whatever that reference's own entry produces; and a reference vouch
    /// could not NAME at all, or one whose entry carries a claim that call
    /// cannot evaluate without arguments, asks through `callable_argument`
    /// (`unresolved_callback_argument`). Because the real invocation is
    /// never observed directly, this entry's own general claims (pure
    /// read, no writes) say nothing about what a marked occupant does —
    /// that occupant is judged independently, through whichever path above
    /// applies, rather than inherited from this entry (task 2b, M2.86 and
    /// M2.89: `json.load(f, object_hook=whatever)` hands `object_hook` a
    /// function `json.load` calls itself, with arguments the scanner never
    /// sees, while `map(str, xs)` hands `map` a harmless, fully-described
    /// reference and allows). A positional callback slot must ALSO be
    /// named in `arg_names`, at its real position, so the existing keyword
    /// fold maps both spellings onto one check; a keyword-only one is
    /// legitimately absent from `arg_names`. Every name uses the shared
    /// ASCII parameter grammar: a letter or `_` first, then letters,
    /// digits, or `_`.
    ///
    /// Non-empty replaces on merge, like `arg_names`.
    #[serde(default)]
    pub callback_args: Vec<String>,
    /// Origin tags this call's return value is known to produce. Tags are
    /// policy vocabulary declared by knowledge, not a closed set in code.
    /// A call that occupies one of this entry's declared `callback_args`
    /// withholds these tags because the callback may customize the result.
    /// `None` means this entry is silent; `Some([])` explicitly retracts a
    /// shipped producer claim during an overlay.
    #[serde(default)]
    pub produces: Option<Vec<String>>,
    /// Origin tags required of a method call's receiver before any claim on
    /// this entry applies. `None` leaves the entry unconditional; `Some([])`
    /// explicitly removes a shipped receiver gate during an overlay.
    #[serde(default)]
    pub receiver_from: Option<Vec<String>>,
    /// A `writes = "arg_<N>"` claim only writes when this call's OWN "mode"
    /// argument says so — python's `open(file, mode)` shape, where a
    /// read-mode call touches nothing on disk. `true` needs a `"mode"`
    /// position to test: `arg_names` must name one, checked in
    /// `knowledge::validate`. The direction runs one way only — an entry may
    /// name `"mode"` in `arg_names` without setting this (a chmod-shaped
    /// entry whose mode is an integer, never a write predicate).
    ///
    /// `None` means the entry did not say. Same `Option` merge rule as
    /// `case_sensitive_flags`: unset keeps whatever the other file already
    /// claimed.
    #[serde(default)]
    pub writes_only_with_file_mode: Option<bool>,
    /// This ENTRY's claim: at the named position ("arg_<N>", receiver = 0)
    /// or keyword-only parameter (the same ASCII identifier grammar
    /// `callback_args` uses), the call writes
    /// through a file object already judged where it was minted — so the
    /// engine extracts NO write target from this call itself; the value is
    /// documentary, and validation checks only its spelling and its
    /// exclusivity with the other write claims.
    ///
    /// This field does not itself prove the named value is a handle. A
    /// receiver-shaped entry whose claim depends on that fact pairs it with
    /// `receiver_from`; the shipped `.write`/`.writelines` entry requires a
    /// receiver carrying `file_handle`, so an ElementTree or other unknown
    /// same-named receiver gets no applicable claim and asks. Direct calls
    /// such as `json.dump` and `print` name their explicit handle parameter
    /// instead and need no receiver gate.
    ///
    /// `None` means the entry did not say. Same `Option` merge rule as
    /// `writes_only_with_file_mode`.
    #[serde(default)]
    pub writes_via_handle: Option<String>,
    /// Whether this program's wrapped snippet spreads over every token after
    /// the flag, rather than being one token: `cmd /c echo hi there` hands
    /// the shell three tokens as one command line, while python's own `-c`
    /// takes exactly the next token as the whole program and leaves the rest
    /// as the script's own argv. `true` rejoins the remaining tokens into one
    /// snippet; unset or `false` reads only the flag's own value.
    ///
    /// `None` means the entry did not say. Same `Option` merge rule as
    /// `case_sensitive_flags`: unset keeps whatever the other file already
    /// claimed.
    #[serde(default)]
    pub wrap_join: Option<bool>,
    /// For `wraps = "rest"`: how many leading DATA positionals this wrapper
    /// consumes before the wrapped command's head. `timeout` takes exactly
    /// one (the duration), `chrt` one (the priority); every other rest
    /// wrapper takes none.
    ///
    /// Replaces the duration heuristic the rest arm used to run (a token
    /// that looked like `5`/`30s`/`1.5h` was skipped wherever it appeared,
    /// for every rest wrapper). That guess read `env 5 rm -rf d` and
    /// `nice 30s rm` the same way it read `timeout 5 rm`, and it could not
    /// skip a leading positional that did not look like a duration —
    /// `timeout --signal TERM 5 sleep 1` among them. A count declared per
    /// program says the same thing without guessing at the token's shape.
    ///
    /// `None` means the entry did not say (reads as 0). Same `Option` merge
    /// rule as `case_sensitive_flags`: unset keeps whatever the other file
    /// already claimed.
    #[serde(default)]
    pub leading_args: Option<usize>,
    /// For `wraps = "start_process"`: the flags whose VALUE names the program
    /// this entry starts, rather than carrying an ordinary value —
    /// `Start-Process -FilePath <program>`. A subset of `value_options`
    /// (checked in `knowledge::validate`), the same relationship
    /// `run_dir_flags` has: the flag has to be known to consume its value, or
    /// the walk would read that value as a positional.
    ///
    /// Without this the program is only ever the first positional, and the
    /// flag spelling of the same command reached the end of the arguments
    /// with no positional found — which the arm then read as "this wrapped
    /// nothing" while the argument list sat in the command unjudged.
    #[serde(default)]
    pub wrap_head_flags: Vec<String>,
    /// For `wraps = "after_exec"`: the flags after which the wrapped command
    /// begins. `find` spells four of them — `-exec`, `-execdir`, `-ok`,
    /// `-okdir` — and the walk expands EVERY occurrence, not just the first.
    ///
    /// Was two hardcoded literals in the wrap arm, which is a program name
    /// in `src/` (§10: no program or tool names in code) and which left
    /// `-ok`/`-okdir` — the confirming twins of the two that were listed —
    /// running unjudged.
    #[serde(default)]
    pub wrap_exec_flags: Vec<String>,
    /// For `wraps = "after_exec"`: the tokens that END the wrapped command.
    /// `find` accepts `;` (usually written `\;` so the shell does not eat
    /// it) and `+`. A declared exec flag whose command reaches the end of
    /// the argument list without meeting one of these raises
    /// `wrap_unlocated`: the layers vouch was told exist were never found.
    #[serde(default)]
    pub wrap_exec_terminators: Vec<String>,
    /// For `writes = "named"`'s POSITIONAL FALLBACK only — never consulted
    /// when a `write_flags` member actually matched. Which positional names
    /// the destination when none did: `"first"` or `"last"` (the default).
    ///
    /// PowerShell's `Set-Content [-Path] <string[]> [-Value] <Object[]>`
    /// puts the destination FIRST and the written CONTENT second, while
    /// `Copy-Item <source> <destination>` puts the destination LAST — one
    /// program-wide fallback that always picked "last" read `Set-Content f
    /// x` as writing to `x`, when `f` is the file that gets `x` written into
    /// it (M2.128).
    ///
    /// `None` means the entry did not say (reads as "last"). Same `Option`
    /// merge rule as `case_sensitive_flags`: unset keeps whatever the other
    /// file already claimed.
    #[serde(default)]
    pub named_positional: Option<String>,
}

/// A write target that depends on the SUBCOMMAND, not on the program as a
/// whole — `git` writes wherever `clone`, `init` and `worktree add` are
/// told to, and nowhere for `status` or `log`.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubWrite {
    /// The subcommand this applies to, e.g. "clone".
    pub subcommand: String,
    /// A second word that must follow it, e.g. "add" for `worktree add`.
    #[serde(default)]
    pub then: String,
    /// How many non-flag arguments must follow the subcommand before one of
    /// them is a destination. `git clone <url>` writes to a directory named
    /// after the URL — unknowable — so it needs two.
    #[serde(default)]
    pub min_positional: usize,
    /// Which of those arguments is the destination: "last" (the default) or
    /// "first".
    ///
    /// `git clone <url> <dir>` puts it last, but `git worktree add <dir>
    /// [<commit-ish>]` puts it FIRST — taking the last recorded `HEAD` as a
    /// written path, which is a commit, not a directory.
    #[serde(default)]
    pub takes: String,
}

/// One declared snippet of a `[[tool]]` entry: a named `tool_input` field
/// that carries a script vouch should decide on, and how to learn which
/// language it is written in.
#[derive(Debug, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolSnippet {
    /// A stated path into `tool_input`: dotted steps descend objects, `[]`
    /// maps over an array (`commands[].command`). No wildcards, no globs.
    pub field: String,
    /// A fixed snippet language. Exactly one of this and `language_from` —
    /// checked in `knowledge::validate_tool`, which also checks this value
    /// is in the closed `knowledge::snippet_languages()` set.
    #[serde(default)]
    pub language: Option<String>,
    /// Read a sibling `tool_input` field and translate its value through
    /// `language_values`. Exactly one of this and `language`.
    #[serde(default)]
    pub language_from: Option<String>,
    /// The translation table for `language_from`: the value read from the
    /// sibling field, on the left, maps to a `knowledge::snippet_languages()`
    /// name on the right — every right-hand value is checked against that
    /// closed set at load.
    #[serde(default)]
    pub language_values: Option<std::collections::BTreeMap<String, String>>,
}

/// How a declared tool-input field names writes.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolWritePathFormat {
    /// The field is one path string, equivalent to the legacy
    /// `write_path_field` shorthand.
    #[default]
    Scalar,
    /// The field is an OpenAI `apply_patch` envelope. Every add, update,
    /// delete, and move path in the envelope is decided; worst wins.
    ApplyPatch,
}

/// One tool-input field that names one or more paths the tool writes.
#[derive(Debug, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolWritePath {
    pub field: String,
    #[serde(default)]
    pub format: ToolWritePathFormat,
}

/// "With this shape and no destination named, this program writes into the
/// directory it is RUN from" — the write-side twin of `changes_dir` silence
/// (M2.129). `tar -xf a.tar` puts the archive's members in the run place,
/// `curl -O <url>` puts the URL's basename there, and vouch derived no
/// destination at all for either, so the commonest download-and-extract
/// spellings went unjudged while their explicit twins asked.
///
/// The claim is conditional because these programs only do it in some
/// shapes. All three conditions are ANDed, and validation requires at least
/// one of them to be set — an entry claiming a program ALWAYS writes where
/// it stands, unconditionally, is one this key has no way to be right about.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HereWrite {
    /// At least one of these flags must be present. Empty means the shape
    /// needs no flag — `unzip a.zip` and a bare `wget <url>` both extract or
    /// download where they stand with nothing switched on.
    #[serde(default)]
    pub when_flags: Vec<String>,
    /// None of these may be present. Two different populations, both of
    /// which make the claim false: a flag that names the destination
    /// explicitly (`tar -C`, `unzip -d`), and a flag that makes the program
    /// write nothing at all (`unzip -l`, which lists).
    ///
    /// **Not the same field as `Rule::unless_flags`, despite the name.** This
    /// one matches in ANY position and also suppresses on a flag that merely
    /// COULD be hiding in an unreadable token, because suppressing a derived
    /// write is the cautious direction here. The rule's veto is
    /// first-argument, exact-spelling, and suppresses only on a flag it can
    /// SEE, because there the cautious direction is to keep asking.
    #[serde(default)]
    pub unless_flags: Vec<String>,
    /// The subcommand this claim is about, when the program has verbs.
    /// Unset means the claim is about the program however it is called.
    #[serde(default)]
    pub subcommand: Option<String>,
    /// The exact number of operands the claim needs, when arity is what
    /// decides. `ln -s <target>` with ONE operand creates the link where it
    /// stands, under the target's basename (verified by running); with two,
    /// the second operand names the link and `writes = "last_arg"` already
    /// derives it.
    #[serde(default)]
    pub operands: Option<usize>,
}

/// An environment-variable name the SHELL ITSELF reads — not data the
/// command happens to be handed, but a name that changes which program a
/// later word resolves to, or what code the shell runs before the command
/// on the line (M2.120).
///
/// The distinction this kind exists to make: `LC_ALL=C sort f` sets
/// something `sort` reads, and vouch's description of `sort` still holds.
/// `PATH=<dir> ls` sets something the SHELL reads, and the `ls` that runs
/// is whatever sits in that directory — vouch's description of `ls` is then
/// a description of a program that is not running. Only names listed here
/// are read that way; every other assignment stays inert, which is what
/// keeps the ordinary case quiet.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvName {
    /// The variable's name. Matched the way the PLATFORM matches it: exactly
    /// under bash, where `path=x` sets an ordinary variable and changes
    /// nothing, and case-insensitively under PowerShell, where `$env:Path`
    /// and `$env:PATH` are the same variable (both verified by running).
    #[serde(default)]
    pub name: String,
    /// Which scanner's lines this claim is true for, same meaning as a
    /// `[[program]]`'s. Empty means every language.
    #[serde(default)]
    pub languages: Vec<String>,
    /// What the shell does with it, from the closed set validated at load:
    ///   "lookup"  — it decides which program a name resolves to, so the
    ///               command that runs may not be the one described
    ///               (`rebound_name`)
    ///   "startup" — it names code the shell runs before the command on the
    ///               line, which vouch has not read (`evaluated_input`)
    #[serde(default)]
    pub effect: String,
}

/// A harness tool vouch has no scanner for, and what is claimed about it.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// Optional, unlike `Program::match_names` — a `server` entry (spec
    /// 2026-08-05 §Schema) names no individual tool at all, and without
    /// `default` here `deny_unknown_fields` would refuse it with "missing
    /// field `match`" before `knowledge::validate_tool` ever got to say why a
    /// match-less, server-less entry is wrong.
    #[serde(rename = "match", default)]
    pub match_names: Vec<String>,
    /// Why this tool is described. Shown in `vouch doctor` and in the prompt,
    /// and it is the claim someone has to stand behind.
    #[serde(default)]
    pub source: String,
    /// What to do about it. Unset means allow: being listed at all is the
    /// recognition claim.
    ///
    /// "ask" is the interesting case. It says vouch knows exactly what this
    /// tool is and is stopping anyway — a different sentence from "vouch has
    /// never heard of this", and the prompt says which.
    #[serde(default)]
    pub action: Option<crate::config::Action>,
    /// Which named `tool_input` fields carry a script vouch should decide on.
    /// `None` means "keep what the shipped entry declares" — the same
    /// `Option` merge rule every other per-entry claim in this file follows.
    /// `Some(vec![])` is a load error (`knowledge::validate_tool`): there is
    /// no legitimate "explicitly no snippets" spelling, because that reading
    /// would let one silent my-knowledge line turn off snippet inspection for
    /// a shipped entry it only meant to add a `source` to. The actual
    /// off-switch is `tools.<name>` in config.
    #[serde(default)]
    pub snippet: Option<Vec<ToolSnippet>>,
    /// The `tool_input` field whose value is the path this tool writes. What
    /// `Write` and `Edit` were hardcoded to do.
    #[serde(default)]
    pub write_path_field: Option<String>,
    /// Structured write declarations. This is a list so one tool can carry
    /// multiple independent path-bearing fields; every declaration is
    /// evaluated and the worst result governs the call.
    #[serde(default)]
    pub write_path: Option<Vec<ToolWritePath>>,
    /// This tool executes its snippet (or writes its path) in the calling
    /// session's own working directory. Only when true does a relative
    /// target get resolved against the hook's cwd; absent or false leaves it
    /// unresolvable, which asks (fail closed).
    #[serde(default)]
    pub cwd_from_call: Option<bool>,
    /// A whole-server grant, said out loud (spec 2026-08-05 §Schema): matches
    /// `<server>__<tool>` for every tool that server exposes, instead of one
    /// tool by name. Mutually exclusive with a non-empty `match` — checked in
    /// `knowledge::validate_tool`.
    #[serde(default)]
    pub server: Option<String>,
    /// The merge identity for a `server` entry — never read from the file,
    /// never written to one. A `server` entry names no individual tool, so
    /// `match_names` is empty and `knowledge::overlay_all`'s per-name
    /// coverage tracking has nothing to key on; without a name of its own a
    /// server entry is either dropped by the merge outright or collides with
    /// every other name-less entry. Set once, in `load`, to
    /// `["server:<server>"]` — a spelling no real tool name can collide with,
    /// since real tool names never contain `:`. Match entries never set this;
    /// `knowledge::Entry for Tool` reads and writes `match_names` for those,
    /// exactly as before this field existed.
    #[serde(skip)]
    pub merge_names: Vec<String>,
}

/// `knowledge.toml` (what ships with vouch) and `my-knowledge.toml` (the
/// operator's own additions) both parse into this same shape: what programs
/// and harness tools ARE and DO. The operator's file is laid over the
/// shipped one, entry by entry, by name.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "knowledge.toml / my-knowledge.toml")]
pub struct Knowledge {
    /// The schema version the file was written against. `None` means the
    /// file predates this key. Enforced in `knowledge::read_one`, and ONLY
    /// for the shipped file: a `None` here or a value below
    /// `knowledge::KNOWLEDGE_SCHEMA_VERSION` refuses the whole shipped load
    /// (spec §7, rev 3/4) rather than running blind on fields it never
    /// wrote. `my-knowledge.toml` parses into this same struct but is never
    /// checked against this field — operator files predate every schema
    /// change by design.
    #[serde(default)]
    pub version: Option<u32>,
    /// One entry per described program, written as `[[program]]`.
    #[serde(default)]
    pub program: Vec<Program>,
    /// One entry per described harness tool (or whole MCP server), written
    /// as `[[tool]]`.
    #[serde(default)]
    pub tool: Vec<Tool>,
    /// One entry per environment-variable name the shell itself consults,
    /// written as `[[env_name]]`.
    #[serde(default)]
    pub env_name: Vec<EnvName>,
}

/// The JSON Schema for `knowledge.toml` / `my-knowledge.toml`, generated from
/// `Knowledge` — the same struct both files deserialize into, so the schema
/// can never describe a shape the loader does not actually accept.
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Knowledge)
}

/// The entry describing this tool, if any. Later entries win, so the operator's
/// file overrides the shipped one for the names it repeats.
pub fn tool_entry<'a>(kb: &'a Knowledge, tool: &str) -> Option<&'a Tool> {
    kb.tool.iter().rev().find(|t| t.match_names.iter().any(|n| n == tool))
}

/// The `server` entry covering this tool, if any (spec 2026-08-05 §Server
/// entry). A server entry matches `<server>__<tail>` where `<tail>` is
/// non-empty and contains no further `__`. That constraint is the whole
/// reason `server = "mcp"` matches nothing — every real tool name's
/// remainder after `mcp__` carries a `__` of its own — so the forbidden
/// every-server glob is inexpressible rather than merely discouraged.
///
/// Later entries win, exactly as `tool_entry`'s do.
///
/// An entry carrying BOTH `server` and a non-empty `match` is ignored here.
/// `knowledge::validate_tool` refuses that combination when a file is loaded
/// for real, so it cannot exist in production — but `guards::load` alone
/// does not validate, and the merge already treats any entry with a `server`
/// as a server entry (`knowledge::Entry for Tool` keys it by `merge_names`,
/// not by `match`). Matching such a hybrid by server here as well would let
/// this lookup disagree with the identity the merge used.
pub fn server_entry_for<'a>(kb: &'a Knowledge, tool: &str) -> Option<&'a Tool> {
    kb.tool.iter().rev().find(|t| {
        if !t.match_names.is_empty() {
            return false;
        }
        let Some(server) = t.server.as_deref().filter(|s| !s.is_empty()) else {
            return false;
        };
        match tool.strip_prefix(server).and_then(|rest| rest.strip_prefix("__")) {
            Some(tail) => !tail.is_empty() && !tail.contains("__"),
            None => false,
        }
    })
}

/// The entry that describes this tool: its own `match` entry if there is one,
/// else the `server` entry covering it. An exact entry beats a server entry
/// for recognition whatever the file order (spec §Server entry rule 4) — a
/// server grant is the fallback for the tools nobody described one by one,
/// never an override of the ones somebody did.
///
/// Named for both halves rather than `entry_for`, which already exists in
/// this file and answers the same question for PROGRAMS.
pub fn tool_or_server_entry<'a>(kb: &'a Knowledge, tool: &str) -> Option<&'a Tool> {
    tool_entry(kb, tool).or_else(|| server_entry_for(kb, tool))
}

/// The one language every snippet this tool's entry declares is written in,
/// when there is exactly one. `language_from` never qualifies — its language
/// depends on a sibling field of the original call, which is not knowable
/// from the entry alone, so guessing it would be inventing a fact (CLAUDE.md
/// §1). Used only as a fallback for a journal row written before
/// `journal::Record.lang` existed (Task 9): `Bash` and `PowerShell` qualify
/// today because each declares one snippet with a fixed `language`, but
/// nothing here names either — any entry shaped the same way qualifies.
pub fn fixed_snippet_lang<'a>(kb: &'a Knowledge, tool: &str) -> Option<&'a str> {
    let snippets = tool_or_server_entry(kb, tool)?.snippet.as_ref()?;
    let mut langs = snippets.iter().map(|p| p.language.as_deref());
    let first = langs.next().flatten()?;
    langs.all(|l| l == Some(first)).then_some(first)
}

/// The language to read a journal row's `cmd` as. `rec.lang` is authoritative
/// whenever the row carries one — every row Task 9 journals through
/// `journal::records_from_snippets` does. A lang-less row is one written
/// before that field existed, and falls back to [`fixed_snippet_lang`];
/// anything that still resolves to nothing (no entry, or the entry's
/// snippets don't share one fixed language) is left unknown rather than
/// guessed, and callers skip the row — the same thing `doctor` already did
/// for a tool with no scanner.
pub fn record_lang(kb: &Knowledge, rec: &crate::journal::Record) -> Option<String> {
    if !rec.lang.is_empty() {
        return Some(rec.lang.clone());
    }
    fixed_snippet_lang(kb, &rec.tool).map(str::to_string)
}

pub fn load(text: &str) -> Result<Knowledge, String> {
    let mut kb: Knowledge = toml::from_str(text).map_err(|e| e.to_string())?;
    normalise(&mut kb);
    // Only `wrap_lang`'s two claims, not the whole of `knowledge::validate`:
    // this function deliberately skips full validation everywhere else,
    // relied on by test fixtures that construct shapes the real
    // `load_files` path refuses (`[[tool]] snippet = []`, an operator's
    // partial overlay entry). The M2.125 pair table names this one gap as
    // refused "via `guards::load`" itself, so it alone runs here.
    crate::knowledge::validate_wrap_lang(&kb)?;
    Ok(kb)
}

/// Post-parse normalisation, run once here so both `knowledge::read_one` and
/// every test that calls `load` directly see the same result — the single
/// choke point both paths share.
///
/// Currently one job: give every `server` entry a merge identity
/// (`Tool::merge_names`) that `knowledge::overlay_all`'s per-name coverage
/// tracking can key on. A `server` entry's own `match` is empty by
/// definition, so without this it has no name at all to be found, split, or
/// overlaid by.
fn normalise(kb: &mut Knowledge) {
    for t in &mut kb.tool {
        if let Some(server) = &t.server {
            t.merge_names = vec![format!("server:{server}")];
        }
    }
}

static LOADED: std::sync::OnceLock<crate::knowledge::Loaded> = std::sync::OnceLock::new();

fn loaded() -> &'static crate::knowledge::Loaded {
    LOADED.get_or_init(|| {
        let home =
            std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default().replace('\\', "/");
        crate::knowledge::load_files(
            &crate::knowledge::knowledge_path(&home),
            &crate::knowledge::my_knowledge_path(&home),
        )
    })
}

/// What the gate decides with: the descriptions that ship, combined with the
/// operator's own. Resolved once per process.
pub fn in_effect() -> &'static Knowledge {
    &loaded().kb
}

/// Files vouch could not use. Empty is the normal case.
pub fn gaps() -> &'static [crate::knowledge::Gap] {
    &loaded().gaps
}

/// Sentences about operator recognition-scope spellings the merge silently
/// discarded (`knowledge::narrowing_noops`) — never a gap, since nothing
/// failed to load. Empty is the normal case. Printed by `doctor`, not by the
/// per-command prompt path.
pub fn notes() -> &'static [String] {
    &loaded().notes
}

fn base(head: &str) -> String {
    // Backslash is a path separator to fold only for the one shape where
    // that is unambiguous: a Windows-rooted path (`C:\...`, `C:/...`, or a
    // `\\host\share` UNC form) — the powershell/cmd spelling of an
    // executable's own path. Everywhere else, a backslash reaching here is
    // an ordinary character, never a separator: bash's own escape handling
    // (`shell::unescape_unquoted`, T10) already resolves an escaped
    // backslash in an unquoted word before `head` is ever built, so a bare
    // `\` surviving into a POSIX-style name means the shell would run it
    // literally, and folding it to `/` here read `who\ami` as a directory
    // named `who` (M2.121).
    let windows_rooted = {
        let b = head.as_bytes();
        (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
            || head.starts_with("\\\\")
    };
    let h = if windows_rooted {
        head.replace('\\', "/")
    } else {
        head.to_string()
    };
    let last = h.rsplit('/').next().unwrap_or(&h);
    // ASCII-only: full-Unicode lowercasing folds characters the shell and
    // the filesystem keep distinct (the Kelvin sign onto ASCII `k`,
    // measured live on NTFS) — vouch must keep them distinct too (M2.121).
    last.trim_end_matches(".exe").to_ascii_lowercase()
}

/// The program name with any path and `.exe` removed, lowercased.
///
/// The same normalisation the knowledge file matches on, exposed so callers
/// outside this module compare names the same way rather than inventing a
/// second, slightly different rule.
pub fn base_name(head: &str) -> String {
    base(head)
}

/// True when a token is a flag for a program that spells flags with `/`.
///
/// `/s` is a flag; `/mnt/c/work` is a path. Nothing in the syntax distinguishes
/// them, so the test is shape: a short run of characters with no further path
/// separator in it. A cmd.exe switch is one or two letters, never a path.
fn is_slash_flag(a: &str) -> bool {
    match a.strip_prefix('/') {
        Some(rest) => {
            !rest.is_empty()
                && rest.len() <= 3
                && !rest.contains('/')
                && !rest.contains('\\')
                && rest.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// How a program spells flags. Empty in the knowledge file means "-".
fn prefixes(declared: &[String]) -> Vec<&str> {
    crate::flags::effective_prefixes(declared)
}

/// True when a token is a flag for this program, given how it spells flags.
fn is_flag(a: &str, declared: &[String]) -> bool {
    prefixes(declared).iter().any(|p| match *p {
        "/" => is_slash_flag(a),
        _ => a.starts_with('-') && a.len() > 1,
    })
}

/// What the argument walk found at the command's verb position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// A readable verb at this argument position.
    At(usize),
    /// No positional token exists.
    None,
    /// A token made the position or value unknowable. `fallback` preserves
    /// the old scan boundary for consumers such as run-dir discovery that
    /// must still inspect flags before the possible verb.
    Unreadable { token: String, fallback: usize },
}

fn token_is_unreadable(cmd: &Cmd, index: usize, lang: &str) -> bool {
    if cmd.unread_args.contains(&index) {
        return true;
    }
    let Some(token) = cmd.args.get(index) else {
        return false;
    };
    match lang {
        "python" => false,
        "powershell" => carries_expansion(token),
        _ => token.contains(['\'', '"']) || carries_expansion(token),
    }
}

/// Locate and read the verb with one vector walk. An undescribed or refused
/// flag before the first positional makes the result unreadable rather than
/// silently treating its possible value as the verb.
pub fn resolve_verb(cmd: &Cmd, vocab: &crate::flags::Vocab, lang: &str) -> Verb {
    let mut walk = crate::flags::ArgWalk::new(vocab);
    let mut skip_next = false;
    let mut uncertainty: Option<String> = None;
    for (i, a) in cmd.args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        match walk.next(a) {
            crate::flags::Class::NotFlag => {
                if let Some(token) = uncertainty {
                    return Verb::Unreadable { token, fallback: i };
                }
                if token_is_unreadable(cmd, i, lang) {
                    return Verb::Unreadable { token: a.clone(), fallback: i };
                }
                return Verb::At(i);
            }
            crate::flags::Class::EndOfOptions => {}
            crate::flags::Class::Value { attached: None, .. } => skip_next = true,
            crate::flags::Class::Value { attached: Some(_), .. } => {}
            crate::flags::Class::Bool { .. } => {}
            crate::flags::Class::Undescribed { token } | crate::flags::Class::RefusedAbbrev { token, .. } => {
                if uncertainty.is_none() {
                    uncertainty = Some(token);
                }
            }
        }
    }
    match uncertainty {
        Some(token) => Verb::Unreadable { token, fallback: cmd.args.len() },
        None => Verb::None,
    }
}

/// Index into `cmd.args` of the subcommand under the compatibility reading.
/// New decision-bearing consumers use `resolve_verb` directly so they must
/// state what `Unreadable` means. This wrapper remains for boundary-only and
/// public callers, preserving the old fallback index.
///
/// `subcommand()` is defined on top of this so the two can never disagree
/// about which token that is.
///
/// Reads the shared flag primitive (`crate::flags`), not a hardcoded `-`
/// check (task 7): a `flag_prefix = ["/"]` entry's own flags are now
/// honoured rather than silently treated as positionals, and an
/// attached-value token (`--depth=1`, PowerShell `-c:v`) is read as ONE
/// self-contained token — consuming nothing further — rather than the
/// migration blindly skipping whatever token follows it, which would shift
/// the subcommand one position too far. `--` ends flag classification for
/// the rest of the vector (§4.1.4): the first token after it is read as the
/// subcommand candidate whatever shape it has, the same as `walk_post_
/// subcommand` already does past the subcommand itself.
pub fn subcommand_index(cmd: &Cmd, vocab: &crate::flags::Vocab) -> Option<usize> {
    match resolve_verb(cmd, vocab, "bash") {
        Verb::At(i) => Some(i),
        Verb::None => None,
        Verb::Unreadable { fallback, .. } => Some(fallback),
    }
}

fn subcommand<'a>(cmd: &'a Cmd, vocab: &crate::flags::Vocab, lang: &str) -> Option<&'a str> {
    match resolve_verb(cmd, vocab, lang) {
        Verb::At(i) => cmd.args.get(i).map(String::as_str),
        Verb::None | Verb::Unreadable { .. } => None,
    }
}

/// The verb this occurrence names under THIS entry's own vocabulary — what
/// every standalone question anchors on, and the one lookup they must all
/// read. A caller asking two of those questions about the same (entry,
/// occurrence) pair builds it once and hands the same answer to both, so the
/// two can never end up reading different grammars for the same tokens.
fn entry_subcommand<'a>(p: &Program, cmd: &'a Cmd, lang: &str) -> Option<&'a str> {
    subcommand(cmd, &crate::flags::vocab_for(p, wrap_abbrev(p)), lang)
}

/// Whether one of this entry's exact positional command paths matches.
///
/// This is a recognition grant, so every ambiguity before a complete match is
/// strict: an unread word, undescribed flag, refused abbreviation, or missing
/// value grants nothing. Once a declared path is complete, later flags and
/// operands belong to that already-named operation and cannot turn it into a
/// sibling path.
fn entry_subcommand_path_matches(p: &Program, cmd: &Cmd, lang: &str) -> bool {
    let Some(paths) = &p.subcommand_paths else {
        return false;
    };
    if paths.is_empty() {
        return false;
    }

    let vocab = crate::flags::vocab_for(p, wrap_abbrev(p));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let mut candidates: Vec<&Vec<String>> = paths.iter().collect();
    let mut word_index = 0usize;
    let mut skip_next = false;

    for (arg_index, arg) in cmd.args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        match walk.next(arg) {
            crate::flags::Class::NotFlag => {
                if token_is_unreadable(cmd, arg_index, lang) {
                    return false;
                }
                candidates.retain(|path| {
                    path.get(word_index)
                        .is_some_and(|word| word.eq_ignore_ascii_case(arg))
                });
                if candidates.is_empty() {
                    return false;
                }
                word_index += 1;
                if candidates.iter().any(|path| path.len() == word_index) {
                    return true;
                }
            }
            crate::flags::Class::EndOfOptions => {}
            crate::flags::Class::Value { attached: None, .. } => skip_next = true,
            crate::flags::Class::Value {
                attached: Some(_), ..
            }
            | crate::flags::Class::Bool { .. } => {}
            crate::flags::Class::Undescribed { .. } | crate::flags::Class::RefusedAbbrev { .. } => {
                return false
            }
        }
    }
    false
}

/// Whether this occurrence is a standalone run of `p` (spec 2026-08-20 §2):
/// no subcommand under the entry's own vocabulary, a non-empty argument
/// vector whose EVERY token is a whole-token member of the entry's
/// `standalone_flags` — compared on the unquoted view, under the entry's
/// stated case rule, with no cluster, abbreviation, or attached-value
/// reading — and a record nothing can append to (`eligible`: the engine's
/// fold of the occurrence's completeness and its not-under-an-
/// appending-wrapper bit; a caller that BUILT the argument list itself
/// passes true, because a hand-assembled record drops nothing).
///
/// `sub` is that subcommand, already looked up: `entry_subcommand(p, cmd)`
/// and nothing else, since "no verb under this entry's grammar" is condition
/// one and a union-derived verb would answer a different question.
///
/// Deliberately STRICTER than the shared flag primitive's classification.
/// That primitive answers "is this a flag of this program"; membership here
/// answers "is this one of the flags the entry vouches for ALONE", and the
/// loose reading would let two individually-vouched letters compose into a
/// spelling nobody verified.
fn standalone_run(p: &Program, cmd: &Cmd, sub: Option<&str>, eligible: bool) -> bool {
    if !eligible || cmd.args.is_empty() || p.standalone_flags.is_empty() || sub.is_some() {
        return false;
    }
    let case_sensitive = p.case_sensitive_flags.unwrap_or(false);
    cmd.args.iter().all(|a| declares(&p.standalone_flags, crate::paths::unquote(a), case_sensitive))
}

/// What `standalone_hint` found: the flags-only ask that remains may name
/// `standalone_flags` as the setting that would quiet it. `pair_no_value_options`
/// is true when the entry also needs the `no_value_options` pairing named
/// beside it, because the entry runs a file (`runs_file`/`runs_file_flags`)
/// and Task 4's membership rule binds the overlay to that pairing there.
pub struct StandaloneHint {
    pub pair_no_value_options: bool,
}

/// Whether the flags-only off-switch sentence may name `standalone_flags`
/// for this run of this entry: flags-only under the entry's vocabulary,
/// and every token a member the LOADER would accept — the ask must never
/// teach an edit the loader refuses. Carries whether the taught edit also
/// needs the `no_value_options` pairing (the entry runs a file, so Task
/// 4's membership rule binds it).
///
/// `sub` is the verb under this entry's own vocabulary, already looked up —
/// `entry_subcommand(prog, cmd)`, the same value `standalone_run` is given,
/// so the ask and the recognition it explains read one grammar.
fn standalone_hint(prog: &Program, cmd: &Cmd, sub: Option<&str>, eligible: bool) -> Option<StandaloneHint> {
    // `eligible` is the same per-occurrence fold recognition reads: on an
    // incomplete or appended-to record the ask stands WHATEVER the operator
    // writes, so teaching the key there would be a false promise.
    if !eligible || cmd.args.is_empty() || sub.is_some() {
        return None;
    }
    let prefixes = prefixes(&prog.flag_prefix);
    let refused = |t: &str| {
        crate::knowledge::member_shape_ok(&prefixes, t).is_err()
            || crate::knowledge::in_refused_vocab(prog, t).is_some()
    };
    if cmd.args.iter().any(|a| refused(crate::paths::unquote(a))) {
        return None;
    }
    Some(StandaloneHint { pair_no_value_options: !prog.runs_file.is_empty() || !prog.runs_file_flags.is_empty() })
}

/// The verb this command names, per the knowledge file's grammar for the
/// program — the same token every rule and every destination walk anchors on.
///
/// Exposed because a prompt that says which argument vouch could not classify
/// has to say which verb it was reading at the time, and working that out with
/// a second, slightly different rule ("the first argument without a dash")
/// picks a value option's VALUE the moment one is present.
///
/// The flag vocabulary is unioned across every same-name entry in the
/// requested language, exactly as `run_dir` and `written_paths` do. This
/// compatibility wrapper uses Bash; decision-bearing callers use
/// `subcommand_of_in` and state their language explicitly.
pub fn subcommand_of<'a>(kb: &Knowledge, cmd: &'a Cmd) -> Option<&'a str> {
    subcommand_of_in(kb, cmd, "bash")
}

/// A command's first verb word after the language-scoped walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbWord {
    Absent,
    Word(String),
    Unknown(String),
}

pub fn verb_of_in(kb: &Knowledge, cmd: &Cmd, lang: &str) -> VerbWord {
    let owned = verb_vocab(kb, cmd, lang);
    match resolve_verb(cmd, &owned.as_vocab(), lang) {
        Verb::At(i) => VerbWord::Word(cmd.args[i].clone()),
        Verb::None => VerbWord::Absent,
        Verb::Unreadable { token, .. } => VerbWord::Unknown(token),
    }
}

/// Language-aware form used by the decision pipeline.
pub fn subcommand_of_in<'a>(kb: &Knowledge, cmd: &'a Cmd, lang: &str) -> Option<&'a str> {
    let owned = verb_vocab(kb, cmd, lang);
    subcommand(cmd, &owned.as_vocab(), lang)
}

struct OwnedVerbVocab {
    value_options: Vec<String>,
    no_value_options: Vec<String>,
    flag_prefix: Vec<String>,
    case_sensitive: bool,
    colon_attach: bool,
}

impl OwnedVerbVocab {
    fn as_vocab(&self) -> crate::flags::Vocab<'_> {
        crate::flags::Vocab {
            value_options: &self.value_options,
            no_value_options: &self.no_value_options,
            flag_prefix: &self.flag_prefix,
            case_sensitive: self.case_sensitive,
            abbreviation: if self.case_sensitive {
                crate::flags::Abbrev::Refuse
            } else {
                crate::flags::Abbrev::Accept
            },
            colon_attach: self.colon_attach,
        }
    }
}

/// One language-scoped grammar for locating a name's verb. Empty entry fields
/// contribute nothing; non-empty claims combine, and the loader refuses the
/// cross-entry contradictions that cannot be combined truthfully.
fn verb_vocab(kb: &Knowledge, cmd: &Cmd, lang: &str) -> OwnedVerbVocab {
    let mut value_options: Vec<String> = Vec::new();
    let mut no_value_options: Vec<String> = Vec::new();
    let mut flag_prefix: Vec<String> = Vec::new();
    let mut case_sensitive: Option<bool> = None;
    for prog in entries_for_cmd(kb, cmd, lang) {
        for value in &prog.value_options {
            if !value_options.contains(value) {
                value_options.push(value.clone());
            }
        }
        for flag in &prog.no_value_options {
            if !no_value_options.contains(flag) {
                no_value_options.push(flag.clone());
            }
        }
        for prefix in crate::flags::effective_prefixes(&prog.flag_prefix) {
            let prefix = prefix.to_string();
            if !flag_prefix.contains(&prefix) {
                flag_prefix.push(prefix);
            }
        }
        if let Some(stated) = prog.case_sensitive_flags {
            case_sensitive.get_or_insert(stated);
        }
    }
    OwnedVerbVocab {
        value_options,
        no_value_options,
        flag_prefix,
        case_sensitive: case_sensitive.unwrap_or(false),
        colon_attach: lang == "powershell",
    }
}

/// WHERE a verb's second word is looked for: the first positional after the
/// subcommand.
///
/// One definition, so `sub_write.then` (`git worktree add <dir>` — the
/// destination walk) and a three-token `[[write.scope]]` entry (`programs =
/// ["git worktree add"]` — the rule that scopes it) cannot end up matching at
/// two different positions. A rule that located the word one way while the
/// walk it governs located it another would scope a different set of commands
/// than the writes it was written for.
fn then_word<'a>(positionals: &[&'a String]) -> Option<&'a str> {
    positionals.first().map(|s| s.as_str())
}

/// The second word of a command's verb — `add` in `git worktree add /x/wt` —
/// or why there is not one.
///
/// The last two cases are NOT interchangeable, and collapsing them was a real
/// hole: a `[[write.scope]]` entry that states a second word must not grant a
/// scope on a command whose verb has a DIFFERENT one, has none, or could not
/// be read. `SecondWord::Unknown` lets the decision pipeline take that last
/// case to `scope_unprovable` instead of selecting a scope by file order or
/// falling through to a wider write allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondWord {
    /// Nothing followed the subcommand: the verb is one word.
    Absent,
    /// The word, as the command wrote it.
    Word(String),
    /// Something after the subcommand could not be classified, so the order
    /// from that point on proves nothing — the same reason `written_paths`
    /// refuses to guess a destination there. Carries the offending token, for
    /// the prompt to name.
    Unknown(String),
}

/// This command's second verb word, per the knowledge file's grammar.
///
/// Located exactly where `sub_write.then` is matched (`then_word` above), so
/// the rule that scopes a write and the walk that finds it read the same
/// position.
pub fn then_of(kb: &Knowledge, cmd: &Cmd) -> SecondWord {
    then_of_in(kb, cmd, "bash")
}

/// Language-aware form used by the decision pipeline.
pub fn then_of_in(kb: &Knowledge, cmd: &Cmd, lang: &str) -> SecondWord {
    let owned = verb_vocab(kb, cmd, lang);
    let sub_idx = match resolve_verb(cmd, &owned.as_vocab(), lang) {
        Verb::At(i) => i,
        Verb::None => return SecondWord::Absent,
        Verb::Unreadable { token, .. } => return SecondWord::Unknown(token),
    };
    let (positionals, unknowable) = walk_post_subcommand(&cmd.args[sub_idx + 1..], &owned.as_vocab());
    if let Some(tok) = unknowable.first() {
        return SecondWord::Unknown(tok.clone());
    }
    if let Some(w) = then_word(&positionals) {
        return SecondWord::Word(w.to_string());
    }
    SecondWord::Absent
}

/// Where a run-dir flag put the command, or why it couldn't be resolved.
///
/// `Absent` means no run-dir flag was seen — most commands run in the
/// harness's own working directory, which is the engine's problem, not this
/// module's. `Unresolvable` carries the human-readable cause so a later
/// caller can put it straight into a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunDir {
    Absent,
    Dir(String),
    Unresolvable(&'static str),
}

/// The directory a run-dir flag sends this command to run in, per the
/// knowledge file — a flag whose value is the directory the command runs in,
/// declared per program in the knowledge file. The raw token value is
/// returned unresolved — turning it into an absolute path against `cd`
/// state, variables, etc. is the engine's job (§8).
///
/// Only tokens BEFORE the subcommand count, and only tokens that are not
/// themselves the consumed VALUE of some other `value_options` flag — a
/// run-dir flag token can appear as another flag's value without meaning
/// anything. After the subcommand, the same token can belong to the
/// subcommand and mean something else entirely — which is why the scan
/// stops at the boundary. Matching is exact token equality, never
/// case-folded (§7).
///
/// `run_dir_flags` and `value_options` are unioned across every entry whose
/// match list contains this head — the same rule `written_paths` follows, so
/// two entries for the same program can never disagree about what its flags
/// mean.
pub fn run_dir(kb: &Knowledge, cmd: &Cmd) -> RunDir {
    run_dir_with_flag_in(kb, cmd, "bash").0
}

/// The same walk, and the flag token that named the directory.
///
/// A verdict that silently depended on a run-dir flag would repeat the defect
/// class this whole design fixes, so the prompt shows what it resolved against
/// and where that came from — which needs the token, not just its value. One
/// walk, so the flag reported can never be a different one from the flag used.
///
/// Reads the shared flag primitive (`crate::flags`), not exact-string
/// equality (task 7): `git -C/tmp init` (short-attached, no space) used to
/// be silently invisible to this walk — not matched as `-C`, not matched as
/// any OTHER value_options flag either, just skipped as an unrecognised
/// token, so a run-dir the operator's own command line stated was silently
/// treated as absent. `spells`/`classify` read the same attached and
/// abbreviated shapes every other derivation consumer does.
///
/// The vocabulary is built directly, never through `vocab_for` (spec
/// §4.1.6, a HARD invariant, not a default to weaken): run-dir matching
/// stays case-sensitive ALWAYS, whatever the entry declares or leaves
/// unset — git's `value_options` carries both `-C` (run dir) and `-c`
/// (config), and folding them together would misread `git -c
/// core.pager=less log` as naming a run directory. `vocab_for` reads the
/// entry's OWN `case_sensitive_flags`, which is exactly the thing this
/// vocabulary must never defer to (pinned by
/// `matching_is_exact_never_case_folded`, guards_test.rs, whose fixture
/// declares no `case_sensitive_flags` at all). Abbreviation is refused
/// unconditionally for the same reason: a case-sensitive vocabulary is
/// exactly the shape spec §4.1.7 refuses it for, and this one is
/// case-sensitive by construction, not by an entry's declaration that could
/// be missing. `run_dir_flags` is folded into the SAME value_options list
/// classification reads — `classify` has one "consumes a following or
/// attached value" list to search — and rule membership (is this token's
/// canonical flag a run-dir flag, or some OTHER value-taking one) is
/// decided AFTER classification, by checking which of the two declared
/// lists the canonical name actually came from.
pub fn run_dir_with_flag(kb: &Knowledge, cmd: &Cmd) -> (RunDir, Option<String>) {
    run_dir_with_flag_in(kb, cmd, "bash")
}

pub fn run_dir_with_flag_in(kb: &Knowledge, cmd: &Cmd, lang: &str) -> (RunDir, Option<String>) {
    let mut run_dir_flags: Vec<String> = Vec::new();
    let owned = verb_vocab(kb, cmd, lang);
    for prog in entries_for_cmd(kb, cmd, lang) {
        run_dir_flags.extend(prog.run_dir_flags.iter().cloned());
    }
    let merged_value_options: Vec<String> =
        run_dir_flags.iter().cloned().chain(owned.value_options.iter().cloned()).collect();
    let vocab = crate::flags::Vocab {
        value_options: &merged_value_options,
        no_value_options: &owned.no_value_options,
        flag_prefix: &owned.flag_prefix,
        case_sensitive: true,
        abbreviation: crate::flags::Abbrev::Refuse,
        colon_attach: owned.colon_attach,
    };
    let end = match resolve_verb(cmd, &vocab, lang) {
        Verb::At(i) => i,
        Verb::None => cmd.args.len(),
        Verb::Unreadable { fallback, .. } => fallback,
    };
    let mut found: Option<(String, String)> = None;
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    // A token consumed as some OTHER flag's value is never itself a run-dir
    // flag candidate — `-x -C` with `-x` in value_options means `-C` here is
    // `-x`'s value, not a run-dir flag. `skip_next` carries that state across
    // iterations exactly the way `subcommand_index` does, so the two can
    // never disagree about which tokens are "spoken for".
    let mut skip_next = false;
    let mut i = 0;
    while i < end {
        let a = cmd.args[i].as_str();
        if skip_next {
            skip_next = false;
            i += 1;
            continue;
        }
        match walk.next(a) {
            crate::flags::Class::Value { flag, attached: Some(v) } => {
                // An attached value is a self-contained token — nothing
                // further to consume, whichever list `flag` came from.
                if run_dir_flags.iter().any(|f| f == &flag) {
                    if found.is_some() {
                        return (RunDir::Unresolvable("two run-dir flags"), None);
                    }
                    found = Some((flag, v));
                }
                i += 1;
            }
            crate::flags::Class::Value { flag, attached: None } => {
                if run_dir_flags.iter().any(|f| f == &flag) {
                    match cmd.args.get(i + 1) {
                        Some(v) if i + 1 < end => {
                            if found.is_some() {
                                return (RunDir::Unresolvable("two run-dir flags"), None);
                            }
                            found = Some((flag, v.clone()));
                            skip_next = true;
                            i += 1;
                        }
                        _ => return (RunDir::Unresolvable("run-dir flag with no value"), None),
                    }
                } else {
                    // Rule 2's shape: this OTHER value-taking flag's bare
                    // value is consumed and never itself a run-dir candidate.
                    skip_next = true;
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    match found {
        Some((f, d)) => (RunDir::Dir(d), Some(f)),
        None => (RunDir::Absent, None),
    }
}

enum WordRead<'a> {
    Word(&'a str),
    Absent,
    Unreadable(String),
}

fn sub_arg_0<'a>(cmd: &'a Cmd, vocab: &crate::flags::Vocab, lang: &str, verb: &Verb) -> WordRead<'a> {
    let start = match verb {
        Verb::At(i) => i + 1,
        Verb::None => return WordRead::Absent,
        Verb::Unreadable { token, .. } => return WordRead::Unreadable(token.clone()),
    };
    let mut walk = crate::flags::ArgWalk::new(vocab);
    let mut skip_next = false;
    for (offset, a) in cmd.args[start..].iter().enumerate() {
        let index = start + offset;
        if skip_next {
            skip_next = false;
            continue;
        }
        match walk.next(a) {
            crate::flags::Class::NotFlag => {
                return if token_is_unreadable(cmd, index, lang) {
                    WordRead::Unreadable(a.clone())
                } else {
                    WordRead::Word(a)
                };
            }
            crate::flags::Class::EndOfOptions => {}
            crate::flags::Class::Value { attached: None, .. } => skip_next = true,
            crate::flags::Class::Value { attached: Some(_), .. } | crate::flags::Class::Bool { .. } => {}
            crate::flags::Class::Undescribed { token } | crate::flags::Class::RefusedAbbrev { token, .. } => {
                return WordRead::Unreadable(token);
            }
        }
    }
    WordRead::Absent
}

/// Named predicate: a chmod-style mode that adds an execute bit.
fn grants_execute(args: &[String]) -> bool {
    args.iter().any(|a| {
        if a.contains("+x") || a.contains("+X") {
            return true;
        }
        let digits: Vec<char> = a.chars().collect();
        !digits.is_empty()
            && digits.iter().all(|c| c.is_ascii_digit())
            && digits.iter().any(|c| matches!(c, '1' | '3' | '5' | '7'))
    })
}

/// Whether any of `flags` is spelled on this command, as a FLAG rather than
/// as an operand that happens to look like one.
///
/// `flags::spells` is asked, per token, whether that token names one of the
/// targets — the same unquoting, attached-form, cluster, and
/// per-entry-case handling every other consumer gets, rather than a raw-token,
/// force-lowercased comparison (M2.119: `git push "--force"` was invisible to
/// the rule that fires on `--force`, because unquoting never reached it). The
/// walk goes through `flags::ArgWalk` so a literal `--` ends flag
/// classification for the rest of the vector, honouring §4.1.4 — `prog -- -x`
/// names an operand and matches nothing.
fn any_flag_spelled(flags: &[String], cmd: &Cmd, vocab: &crate::flags::Vocab) -> bool {
    let mut walk = crate::flags::ArgWalk::new(vocab);
    let mut ended = false;
    cmd.args.iter().any(|a| {
        let class = walk.next(a);
        if ended || class == crate::flags::Class::EndOfOptions {
            ended = true;
            return false;
        }
        flags.iter().any(|f| matches!(crate::flags::spells(f, a, vocab), crate::flags::Spell::Yes(_)))
    })
}

/// Whether this command's FIRST argument is exactly one of `flags`.
///
/// The veto's own reading, deliberately narrower than `any_flag_spelled` in
/// two ways, each closing a shape that was allowed when the veto shared that
/// function:
///
/// 1. **Exact spelling only** — a TOKEN comparison, not `flags::spells`. An
///    entry that declares no flag vocabulary makes every short flag look
///    attachable, so `-09` read as `-0` carrying the value `9` and stood the
///    guard down on what bash delivers as SIGKILL (measured: a spawned
///    process ended with wait status 137). `Spell::Yes(None)` is not enough
///    either: under `Abbrev::Accept` an accepted abbreviation returns it, and
///    a fully-described short cluster returns it too — so declaring this
///    program's real no-value flags, which is a TRUE §3 statement and the
///    obvious next improvement to the entry, would silently re-open the hole.
///    The veto's safety must not depend on an entry staying vocabulary-less,
///    so it compares the unquoted token itself, honouring the entry's own
///    `case_sensitive_flags`.
/// 2. **First argument only.** In `kill` only the leading token is a signal
///    specification; a later `-0` is a PID, and a negative PID is a process
///    GROUP. Reading it as the veto allowed `kill -9 -0`, which signals the
///    caller's own group — broader than the plain kill the guard exists for.
///
/// Narrow on purpose, and the narrowness is the safe direction: a veto that
/// fails to fire leaves the guard firing, which asks. An entry needing an
/// any-position veto should say so with its own key and its own reason,
/// rather than widening this one.
fn veto_flag_spelled(flags: &[String], cmd: &Cmd, prog: &Program) -> bool {
    let Some(first) = cmd.args.first() else {
        return false;
    };
    let tok = crate::paths::unquote(first);
    let exact = |f: &String| {
        if prog.case_sensitive_flags.unwrap_or(false) {
            *f == tok
        } else {
            f.eq_ignore_ascii_case(&tok)
        }
    };
    flags.iter().any(exact)
}

/// True when every criterion this rule states holds for `cmd`.
///
/// Order, and it is load-bearing: the VETO (`unless_flags`) is consulted
/// first, before `always` and before every criterion — a rule that fires on
/// every invocation is exactly the one that needs a way to name the
/// invocation it must not fire on. Then `always` matches unconditionally.
/// Then each stated criterion, all of which must hold.
///
/// Public so the enumeration test can ask "does THIS rule match?" per rule.
/// `check()`'s hits cannot answer that: `(guard, source)` pairs are not unique
/// across rules (several shipped git rules share `("history_rewrite", "inferred")`).
///
/// `any_flag`, `subcommand_in`, `sub_arg_0_in` and the veto all read the
/// shared flag primitive (`crate::flags`) through the SAME vocabulary, built
/// once below — `subcommand_index` needs one too, and building it per
/// criterion would risk two criteria disagreeing about where the verb is.
/// Abbreviation follows the entry's derivation policy: accepted for a
/// case-insensitive grammar and refused for a case-sensitive one. This is
/// why the veto does NOT share `any_flag_spelled`: an accepted abbreviation
/// or attached value widens a positive condition safely and a veto unsafely
/// (see `veto_flag_spelled`).
struct RuleMatch {
    matched: bool,
    unread_verb: Option<String>,
}

fn rule_match_in(rule: &Rule, cmd: &Cmd, prog: &Program, lang: &str) -> RuleMatch {
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    // The veto comes first, and before `always` in particular: a rule that
    // fires on every invocation is exactly the one that needs a way to name
    // the invocation it must not fire on.
    if !rule.unless_flags.is_empty() && veto_flag_spelled(&rule.unless_flags, cmd, prog) {
        return RuleMatch { matched: false, unread_verb: None };
    }
    if rule.always {
        return RuleMatch { matched: true, unread_verb: None };
    }

    let verb = resolve_verb(cmd, &vocab, lang);
    let mut unread_verb: Option<String> = None;

    if !rule.subcommand_in.is_empty() {
        match &verb {
            Verb::At(i) if rule.subcommand_in.iter().any(|x| x == &cmd.args[*i]) => {}
            Verb::Unreadable { token, .. } => unread_verb = Some(token.clone()),
            _ => return RuleMatch { matched: false, unread_verb: None },
        }
    }
    if !rule.sub_arg_0_in.is_empty() {
        match sub_arg_0(cmd, &vocab, lang, &verb) {
            WordRead::Word(s) if rule.sub_arg_0_in.iter().any(|x| x == s) => {}
            WordRead::Unreadable(token) => {
                if unread_verb.is_none() {
                    unread_verb = Some(token);
                }
            }
            _ => return RuleMatch { matched: false, unread_verb: None },
        }
    }
    if !rule.any_flag.is_empty() && !any_flag_spelled(&rule.any_flag, cmd, &vocab) {
        return RuleMatch { matched: false, unread_verb: None };
    }
    if !rule.any_arg_exact.is_empty()
        && !rule.any_arg_exact.iter().any(|x| cmd.args.iter().any(|a| crate::paths::unquote(a) == x))
    {
        return RuleMatch { matched: false, unread_verb: None };
    }
    if !rule.any_arg_prefix.is_empty()
        && !rule.any_arg_prefix.iter().any(|p| cmd.args.iter().any(|a| crate::paths::unquote(a).starts_with(p)))
    {
        return RuleMatch { matched: false, unread_verb: None };
    }
    if rule.grants_execute && !grants_execute(&cmd.args) {
        return RuleMatch { matched: false, unread_verb: None };
    }
    // A rule with no conditions at all would match everything; refuse it.
    let matched = rule.subcommand_in.len()
        + rule.sub_arg_0_in.len()
        + rule.any_flag.len()
        + rule.any_arg_exact.len()
        + rule.any_arg_prefix.len()
        > 0
        || rule.grants_execute;
    RuleMatch { matched, unread_verb: matched.then_some(unread_verb).flatten() }
}

pub fn rule_matches(rule: &Rule, cmd: &Cmd, prog: &Program) -> bool {
    rule_match_in(rule, cmd, prog, "bash").matched
}

pub fn check(kb: &Knowledge, cmd: &Cmd) -> Vec<Hit> {
    check_in(kb, cmd, "bash")
}

pub fn check_in(kb: &Knowledge, cmd: &Cmd, lang: &str) -> Vec<Hit> {
    let head = base(&cmd.head);
    let mut hits = Vec::new();
    for prog in entries_for_cmd(kb, cmd, lang) {
        for rule in &prog.rule {
            let outcome = rule_match_in(rule, cmd, prog, lang);
            if outcome.matched {
                hits.push(Hit {
                    guard: rule.guard.clone(),
                    source: rule.source.clone(),
                    detail: format!("{} {}", head, cmd.args.join(" ")).chars().take(200).collect(),
                    unread_verb: outcome.unread_verb,
                });
            }
        }
    }
    hits
}

/// True when this command's own arguments show no explicit script source: no
/// positional argument, and no lone `-`/`-s` — meaning code has to arrive on
/// standard input. Shared by `evaluates_input`'s `"stdin"` arm and
/// `heredoc_feeds`, which both have to recognise exactly this shape (a
/// script path or a `-c` snippet means the code IS in the command, already
/// scanned as a wrapper, so the heredoc or the pipe feeding stdin is not what
/// runs).
///
/// Public because the standalone-run suppression of `evaluates_input`'s
/// `"stdin"` arm is decided BESIDE this predicate rather than inside it: this
/// answers only "do the arguments name a script source", which stays true of
/// a flags-only run, and the entry's own `standalone_flags` claim is what
/// says the flag prints and exits.
pub fn reads_stdin(cmd: &Cmd) -> bool {
    let has_source = cmd.args.iter().any(|a| {
        let l = a.to_lowercase();
        !a.starts_with('-') || l == "-c" || l == "-s" || a == "-"
    });
    if !has_source {
        return true;
    }
    // `sh -s` and `bash -` both read the script from stdin.
    cmd.args.iter().any(|a| a == "-s" || a == "-" || a.eq_ignore_ascii_case("-s"))
}

/// True when this command runs text obtained at execution time, plus the
/// matched entry's own declared snippet language, when it named one.
///
/// `curl … | bash` hands vouch a `bash` with no script to read, and the code it
/// will run does not exist yet. That is not a judgement about the command; it
/// is the honest statement that vouch cannot see what runs, which is exactly
/// what a construct is for.
///
/// The `wrap_lang` alongside the bool is what lets the CONSUMING entry's own
/// language key the resulting construct (channel 3, engine.rs): a `python`
/// entry that declares `evaluates_input` keys its ask as
/// `lang.python.constructs.evaluated_input`, not the host command's, so a
/// host-language allow of the same construct name does not silently cover
/// it. `None` when the matched entry never named one — the caller falls back
/// to the host language.
///
/// `holds_input` is what the judgement decided for THIS occurrence: vouch has
/// the text of its standard input, so an entry claiming it runs code from
/// standard input has nothing left to warn about.
///
/// The gate sits INSIDE the match arm rather than before the loop, and that
/// placement is load-bearing: one name can match both a `"stdin"` entry and an
/// `"always"` entry — same-name duplicates are a normal merge outcome, and an
/// operator overlay can produce that pair — and only gating in the arm lets a
/// suppressed stdin arm fall through to the always entry, which still fires. An
/// early return before the loop would skip it and wrongly allow.
pub fn evaluates_input(
    kb: &Knowledge,
    cmd: &Cmd,
    holds_input: bool,
    standalone_eligible: bool,
) -> (bool, Option<String>, Option<StandaloneHint>) {
    evaluates_input_in(kb, cmd, "bash", holds_input, standalone_eligible)
}

pub fn evaluates_input_in(
    kb: &Knowledge,
    cmd: &Cmd,
    lang: &str,
    holds_input: bool,
    standalone_eligible: bool,
) -> (bool, Option<String>, Option<StandaloneHint>) {
    for prog in entries_for_cmd(kb, cmd, lang) {
        let wrap_lang = (!prog.wrap_lang.is_empty()).then(|| prog.wrap_lang.clone());
        match prog.evaluates_input.as_str() {
            // Untouched by the flag on purpose: an always-entry runs computed
            // text whatever its standard input holds, so no here-document can
            // satisfy that claim.
            "always" => return (true, wrap_lang, None),
            // The standalone stand-down (spec 2026-08-20 §2 effect 2): a run
            // of only listed flags does its own thing and stops, so there is
            // no code left for standard input to supply — the same shape a
            // heredoc attached to this SAME command still gets judged
            // through, because the locator above answers a different
            // question and does not consult `standalone_flags` at all.
            //
            // Standing down leaves the body empty rather than returning, so
            // this entry falls through to the next one exactly as an unmatched
            // arm did: a name can carry both a `"stdin"` entry and an
            // `"always"` one, and the always entry still has to fire.
            "stdin" if !holds_input && reads_stdin(cmd) => {
                // One lookup, both questions: whether this stands down, and —
                // when it does not — the off-switch sentence saying what would
                // have made it.
                let sub = entry_subcommand(prog, cmd, lang);
                if !standalone_run(prog, cmd, sub, standalone_eligible) {
                    let hint = standalone_hint(prog, cmd, sub, standalone_eligible);
                    return (true, wrap_lang, hint);
                }
            }
            _ => {}
        }
    }
    (false, None, None)
}

/// Whether a token APPENDED to this command — from the channel an
/// `args_from_input` wrapper feeds it — could change the answer vouch would
/// otherwise give (M2.116, spec §3.3's enumeration).
///
/// True in three cases, and the list is deliberately exhaustive rather than
/// "anything that looks risky":
///
///   1. The entry claims a WRITE of any kind. An appended token is exactly
///      what such a claim reads to find its destination, so a command with
///      none recorded has an unresolvable destination rather than no
///      destination — the difference this whole changeset is about.
///   2. The entry carries a guard rule with ANY condition an appended token
///      could satisfy: a flag, an exact or prefix argument match, or a
///      subcommand/sub-argument condition (a verb can arrive from the
///      channel as readily as a path can).
///   3. The entry hands arguments onward — it runs a file named at an
///      operand position, or it wraps a command. "No wrap flag present"
///      must not read as "wraps nothing" when the tokens that would carry
///      one have not arrived yet.
///
/// Everything else answers false, and that is what keeps `xargs echo` quiet:
/// an entry claiming no write, no rule and no hand-off says the same thing
/// however many arguments it is given.
pub fn appended_args_could_change_the_answer(kb: &Knowledge, cmd: &Cmd, lang: &str) -> bool {
    entries_for_cmd(kb, cmd, lang).any(|prog| {
        let claims_write = !prog.writes.is_empty() || !prog.write_flags.is_empty() || !prog.sub_write.is_empty();
        let rule_could_match = prog.rule.iter().any(|r| {
            !r.any_flag.is_empty()
                || !r.any_arg_exact.is_empty()
                || !r.any_arg_prefix.is_empty()
                || !r.subcommand_in.is_empty()
                || !r.sub_arg_0_in.is_empty()
                // A mode token that grants execute is as appendable as any
                // other argument: found by the task review, which measured a
                // channel-fed mode change allowing while the inline spelling
                // asked. `always` is deliberately absent — such a rule fires
                // whatever the arguments are, so the command already asks and
                // nothing here could change that.
                || r.grants_execute
        });
        let hands_on = !prog.runs_file.is_empty() || !prog.runs_file_flags.is_empty() || !prog.wraps.is_empty();
        claims_write || rule_could_match || hands_on
    })
}

/// The first declared `[[env_name]]` among `names`, with what the shell does
/// with it (M2.120). `names` is a list of variable names this text assigns —
/// a command's own prefix words, or the same-line assignments the scan
/// recorded; both channels ask the same question of the same list.
///
/// Scoped by language exactly as a `[[program]]` is: an entry naming no
/// language speaks for every one, `BASH_ENV` speaks only for bash. Names the
/// file does not list return `None` and stay inert, which is the whole reason
/// the shipped list is short and measured rather than guessed at.
pub fn env_name_effect<'a>(kb: &'a Knowledge, names: &[String], lang: &str) -> Option<(&'a str, &'a str)> {
    // Case matters in bash — `path=x` sets an ordinary variable and changes
    // nothing — and does NOT on Windows, where `$env:Path` and `$env:PATH`
    // are one variable (verified by running: setting one spelling and reading
    // the other returns the value). An exact match in both places would let
    // the ordinary PowerShell spelling through, so the comparison follows the
    // platform rather than being uniform for tidiness.
    let fold = lang == "powershell";
    names.iter().find_map(|n| {
        kb.env_name
            .iter()
            .filter(|e| e.languages.is_empty() || e.languages.iter().any(|l| l == lang))
            .find(|e| {
                if fold {
                    e.name.eq_ignore_ascii_case(n)
                } else {
                    e.name == *n
                }
            })
            .map(|e| (e.name.as_str(), e.effect.as_str()))
    })
}

/// The `rebinds_name_flags` spelling this command carries, if any — the
/// program-side half of the same rebinding `[[env_name]]`'s `"lookup"` names
/// (M2.113). Matched through the shared primitive, so an attached or
/// abbreviated spelling is read exactly as the guard rules read one.
pub fn rebinds_a_name<'a>(kb: &'a Knowledge, cmd: &Cmd, lang: &str) -> Option<&'a str> {
    let mut first = None;
    let mut scoped = None;
    for program in entries_for_cmd(kb, cmd, lang) {
        if first.is_none() {
            first = Some(program);
        }
        if !program.languages.is_empty() {
            scoped = Some(program);
            break;
        }
    }
    let prog = scoped.or(first)?;
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    prog.rebinds_name_flags.iter().find_map(|f| {
        cmd.args
            .iter()
            .any(|raw| matches!(crate::flags::spells(f, raw, &vocab), crate::flags::Spell::Yes(_)))
            .then_some(f.as_str())
    })
}

/// A file this command hands an interpreter to RUN — named on the line while
/// its contents are not (M2.118). The `runs_file` half of the blindness
/// `evaluates_input` covers for standard input.
///
/// True when the entry's declared operand position is occupied, when a
/// declared `runs_file_flags` flag carries its value (python's `-m <module>`,
/// which names code by import path rather than by file path), or when the
/// walk could not say WHERE that operand is. That last case is fail-closed on
/// purpose: an undescribed flag ahead of the position means the token vouch
/// would look at is not necessarily the token the program will read, and a
/// guess in either direction is a guess about what runs.
///
/// False when this entry's own wrap arm already consumed the line: `bash -c
/// '<code>'` puts the code IN the command, so the operand after `-c` is text
/// vouch has scanned rather than a file it has not read. Checked by SPELLING
/// through the shared primitive, clustered forms included (`bash -lc
/// '<code>'`) — these shells declare `-c` as a switch, so the wrap letter can
/// sit anywhere in a cluster.
/// The `Option<String>` is the consuming entry's own declared snippet
/// language, and it is returned for the same reason `evaluates_input` returns
/// it: the file python will run is python, so the ask belongs in python's
/// construct table, not in the table of whatever shell happened to type the
/// line. Keying every one of these under the host language is the recorded
/// defect M2.79, and it would also make the same program's two blindnesses —
/// `curl … | python` and `python s.py` — name two different off-switches.
pub fn runs_file_positional(kb: &Knowledge, cmd: &Cmd) -> (bool, Option<String>) {
    let head = base(&cmd.head);
    for prog in &kb.program {
        if !receiver_gate_holds(kb, prog, &cmd.receiver_origin) {
            continue;
        }
        if !prog.match_names.iter().any(|n| n.to_ascii_lowercase() == head) {
            continue;
        }
        if prog.runs_file.is_empty() && prog.runs_file_flags.is_empty() {
            continue;
        }
        if runs_file_in(prog, &cmd.args) {
            return (true, (!prog.wrap_lang.is_empty()).then(|| prog.wrap_lang.clone()));
        }
    }
    (false, None)
}

fn runs_file_in(prog: &Program, args: &[String]) -> bool {
    let want = prog.runs_file.strip_prefix("arg_").and_then(|n| n.parse::<usize>().ok());
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let mut skip_next = false;
    let mut options_ended = false;
    let mut operand = 0usize;
    for raw in args {
        // A token already spoken for as a flag's value is not itself an
        // operand, and must not be fed to the walk either — its text could be
        // `--`, which would end an option scan that never started.
        if skip_next {
            skip_next = false;
            continue;
        }
        let class = walk.next(raw);
        if class == crate::flags::Class::EndOfOptions {
            options_ended = true;
        }
        // Only while this program is still reading FLAGS. After the
        // end-of-options marker every token is an operand, so a file whose
        // NAME happens to spell the wrap flag is a script, not a snippet
        // flag: `python -- -c` runs a file called `-c`, verified by running
        // it. Testing the spelling regardless of the walk's state read that
        // as "the wrap arm owns this line" and allowed the file unread.
        if !options_ended {
            for f in &prog.wrap_flags {
                if matches!(crate::flags::spells(f, raw, &vocab), crate::flags::Spell::Yes(_))
                    || matches!(cluster_switch(prog, f, raw), ClusterHit::Yes)
                {
                    return false;
                }
                if matches!(cluster_switch(prog, f, raw), ClusterHit::Unreadable) {
                    return true;
                }
            }
        }
        match class {
            crate::flags::Class::Value { ref flag, ref attached } => {
                if prog.runs_file_flags.iter().any(|f| f == flag) {
                    return true;
                }
                if attached.is_none() {
                    skip_next = true;
                }
            }
            crate::flags::Class::Undescribed { .. } | crate::flags::Class::RefusedAbbrev { .. } => return true,
            crate::flags::Class::NotFlag => {
                // A lone `-` is the standard-input spelling in every shell
                // this key describes, never a filename — `evaluates_input`
                // owns that shape and already answers for it. When this same
                // entry declares a snippet argument layout, everything after
                // the explicit source belongs to that trailing vector rather
                // than becoming the script-file operand.
                if raw == "-" {
                    if prog.snippet_args.as_ref().is_some_and(|declarations| !declarations.is_empty()) {
                        return false;
                    }
                    continue;
                }
                if want == Some(operand) {
                    return true;
                }
                operand += 1;
            }
            crate::flags::Class::Bool { .. } | crate::flags::Class::EndOfOptions => {}
        }
    }
    false
}

/// Whether `cmd` matches an entry declaring `callback_args` AND hands one of
/// those declared slots something vouch has not already judged some other
/// way — the entry's other claims (no writes, no rules) hold only when this
/// is false; when it is true, the call hands the described function
/// something it will invoke, and that something never appears as its own
/// scanned event (task 2b, M2.86).
///
/// A slot resolved to a `CallableArg` (M2.89) — `Named`, `Inline`, or
/// `Unresolved` alike — is excluded from every rule below, not because it is
/// known safe but because it is already judged specifically: `Named`
/// through `by_reference_invocations`, `Unresolved` through
/// `unresolved_callback_argument`, and `Inline` through the calls its own
/// lambda body already emitted where it was scanned. Spec
/// §5.2 requires the two to be mutually exclusive PER SLOT — this generic
/// construct and that specific judgement are one slot's two outcomes, never
/// two competing asks for the same occupant. Testing for absence from
/// `effective.callable` / `cmd.callable_args` is the one check that reads
/// all three variants the same way, since folding tags the raw index the
/// same regardless of which variant occupies it.
///
/// Checked three ways, any one of which trips it:
///   1. a slot named in `callback_args` is ALSO named in `arg_names` (a
///      positional callback), the keyword-folded call occupies that
///      position — folding first means `f(object_hook=g)` and a
///      hypothetical positional spelling are read identically — AND that
///      folded occupant is a position the scanner could not read at all
///      (`effective.unread`) and was NOT resolved to a callable reference of
///      any kind (`effective.callable`, M2.92). Occupancy alone used to be
///      enough, which meant `re.sub('a', 'b', s)` asked about a function on
///      the strength of a replacement STRING sitting in the slot `repl`
///      names — `'b'` occupies the position but is never a callable, and
///      narrowing to unread-and-not-callable fixed that without reopening
///      the earlier hazard this same rule once had: an unread occupant —
///      `cbs[0]`, a subscript; `d["cb"]`, likewise; `*rest`, a starred
///      spread — still trips this, because a subscript or a call result can
///      evaluate to a function exactly as easily as `os.remove` can, and
///      treating "unmarked" as "not a callable" for a position the scanner
///      never read at all would be absence of evidence serving as evidence
///      of absence — precisely the inversion CLAUDE.md §1 and §6.3 exist to
///      prevent. What changed is narrower than that: a position the scanner
///      DID mark as a callable reference (M2.89, any variant) is no longer
///      ALSO counted here, because that position already has its own
///      specific judgement elsewhere (see above). `effective.unread` and
///      `effective.callable` are both FOLDED, for the same reason: a
///      keyword and a positional spelling of the same slot must read
///      identically.
///   2. a callback slot has no positional form at all (legitimately absent
///      from `arg_names` — most of json.load's callback parameters are
///      keyword-only), so it never reaches `effective_args`'s output; an
///      unfolded `name=value` token in the RAW call is checked directly,
///      and requires that same raw index to be marked unread
///      (`cmd.unread_args`) and NOT marked callable (`cmd.callable_args`) —
///      the raw index space, not the folded one rule 1 reads (getting the
///      two backwards is the M2.95(b) hazard). A plain string keyword
///      value — read, and read as not callable — still does not trip this.
///   3. a nameless keyword-unpacking marker (`**opts`) is present ANYWHERE
///      in the RAW call — `f(**opts)` alone, with no other argument at all,
///      is ordinary Python and could be carrying any keyword the call never
///      names, including a declared slot, so this cannot be scoped to a
///      position the way rule 1 is, and — unlike rules 1 and 2 — it is not
///      narrowed to a marked callable either: an unpack's contents are
///      never individually scanned, so there is no per-key mark to read,
///      and treating the absence of one as "not a callable" would infer
///      absence from silence, the exact defect class CLAUDE.md §6.3 exists
///      to prevent.
///
///      Round 1 of this fix tried to scope it to "past every position
///      `arg_names` accounts for" (a marker at position 0 read as "the
///      ordinary data argument", not a possible unpack) — needed then
///      because `**opts` and an unresolvable positional value pushed the
///      IDENTICAL token and could not be told apart. That positional
///      boundary reasoning is gone: `**opts` now pushes its own token,
///      `python::UNPACK_MARKER` (M2.78's fix, applied here), distinct from
///      `python::MARKER`'s ordinary "value I could not read" — so
///      `json.load(sys.stdin)` (an unresolvable attribute access, still
///      `MARKER`) and `json.load(**opts)` (now `UNPACK_MARKER`) are
///      distinguishable at the token level, and this rule can check the
///      unpack token directly instead of inferring its presence from where
///      a shared token landed.
pub fn callback_argument_used(kb: &Knowledge, cmd: &Cmd) -> bool {
    let head = base(&cmd.head);
    for prog in &kb.program {
        if !receiver_gate_holds(kb, prog, &cmd.receiver_origin) {
            continue;
        }
        if prog.callback_args.is_empty() {
            continue;
        }
        if !prog.match_names.iter().any(|n| n.to_ascii_lowercase() == head) {
            continue;
        }
        let effective = effective_args(prog, cmd);
        // `eff_position_occupied`, not a bare `.is_some()` (task 2b fix
        // round 4): a slot the call never addressed at all can still show
        // up occupying `eff` if a LATER position was folded, which must
        // not read as "this callback slot was used." `effective.callable`
        // and `effective.unread` are both the FOLDED position space
        // (M2.92) — read alongside `eff_position_occupied`, not against
        // `cmd.callable_args`/`cmd.unread_args`'s raw indices, which is
        // what rule 2 below reads instead. An unread-and-not-callable
        // occupant trips this exactly like the old callable-or-unread test
        // did for an unread one: vouch cannot say a function is absent from
        // a position it never read. A position already marked callable
        // (M2.89, any `CallableArg` variant) does NOT trip this — spec
        // §5.2's per-slot exclusivity: that position already has its own
        // specific judgement elsewhere (see the doc comment above).
        if callback_arg_positions(prog, effective.base_offset).iter().any(|&p| {
            eff_position_occupied(&effective.values, &effective.padding, p)
                && effective.unread.contains(&p)
                && !effective.callable.contains(&p)
        }) {
            return true;
        }
        if cmd.args.iter().enumerate().any(|(i, a)| {
            cmd.keyword_args.contains(&i)
                && cmd.unread_args.contains(&i)
                && !cmd.callable_args.contains_key(&i)
                && a.split_once('=').is_some_and(|(name, _)| {
                    prog.callback_args.iter().any(|c| c == name)
                })
        }) {
            return true;
        }
        if has_unpack_arg(cmd) {
            return true;
        }
    }
    false
}

/// One resolved callable argument, judged as its own invocation (M2.89).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByReference {
    /// The referenced head, already prefixed (`python:os.remove`).
    pub head: String,
    /// The synthetic command judged for it: same head, no arguments, no
    /// receiver claim of its own beyond what the reference carried. It
    /// joins no ordered pass — see `by_reference_invocations`'s own doc
    /// comment.
    pub cmd: Cmd,
    /// Set when the matched entry — receiver-gated against the reference's
    /// own origin, the same way the slot check above it is (task 4 review
    /// I2) — carries a claim this argument-less invocation cannot evaluate:
    /// a rule with conditions that need arguments, an unmodeled head, a
    /// directory move, a wrap, a run-file, evaluated input, or a write
    /// through an already-open handle (task 4 review Q1/C2/C3). Names the
    /// specific claim so the prompt can say what it is, rather than a fixed
    /// sentence that was true for only one of these.
    pub unevaluable: Option<String>,
    /// True only when `unevaluable` is the rule-with-conditions claim — the
    /// one case where a guard genuinely sits on the entry and only its
    /// conditions could not be evaluated without arguments. Every other
    /// `unevaluable` claim (an unmodeled head, a directory move, a wrap, a
    /// run-file, evaluated input, a handle write) names something that is
    /// not a guard at all, so `construct_reason`'s "guards still apply"
    /// closing line would assert a guard that does not exist (task 4 review
    /// I4). Meaningless when `unevaluable` is `None`.
    pub unevaluable_guard_backed: bool,
}

/// Whether raw argument `raw_idx` of `cmd` is a POSITIONAL token, and if so,
/// which folded position `effective_args` would place it at.
///
/// Reproduces `effective_args`'s own first pass — push every non-keyword,
/// non-unpack-marker argument into `eff` in source order — while tracking
/// which push corresponds to `raw_idx`, since `effective_args` returns the
/// folded array but not this mapping. Deliberately does NOT take a `base`
/// offset: `eff`'s indexing already begins at a method call's own receiver
/// (pushed like any other non-keyword argument), and `base` exists only to
/// translate `arg_names`' own position numbering into that same space — it
/// is never an offset on the raw push order itself. A keyword argument, or
/// one absent from this fold, returns `None`.
fn positional_fold_position(cmd: &Cmd, raw_idx: usize) -> Option<usize> {
    if cmd.keyword_args.contains(&raw_idx) {
        return None;
    }
    let mut pos = 0;
    for (i, a) in cmd.args.iter().enumerate() {
        if cmd.keyword_args.contains(&i) {
            continue;
        }
        if a == crate::python::UNPACK_MARKER && cmd.unread_args.contains(&i) {
            continue;
        }
        if i == raw_idx {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

/// Whether raw argument `raw_idx` of `cmd` occupies a slot `prog` declares
/// in its own `callback_args` — the SAME two rules `callback_argument_used`
/// checks (its own doc comment covers both in full), read per-argument
/// instead of as one whole-command boolean:
///
///   1. positional (or keyword-folded onto a positional slot named in both
///      `callback_args` and `arg_names`): fold `raw_idx` via
///      `positional_fold_position` and test the result against
///      `callback_arg_positions`.
///   2. keyword with no positional form in `arg_names` at all (legitimately
///      absent — most of a callback parameter's keyword-only spellings):
///      the raw token's own name, checked directly against
///      `prog.callback_args`. This also (harmlessly) matches a keyword
///      whose name IS in `arg_names`, which rule 1 would already have
///      caught via folding — `callback_argument_used` accepts the same
///      overlap because it only ever needs `true` once.
///
/// Rule 3 (`has_unpack_arg`, a nameless `**opts` that could be carrying a
/// declared slot invisibly) has nothing to contribute here: an unpack's
/// contents are never individually scanned, so there is no per-key
/// `CallableArg` mark hiding inside it for this function to report. That
/// possibility is what keeps `callback_argument_used` — a different
/// construct, `callback_argument`, for a different pass — asking about the
/// OUTER call's own claims; it is orthogonal to judging a MARKED reference
/// by itself.
fn in_declared_callback_slot(prog: &Program, cmd: &Cmd, raw_idx: usize) -> bool {
    if prog.callback_args.is_empty() {
        return false;
    }
    if cmd.keyword_args.contains(&raw_idx) {
        return cmd.args[raw_idx]
            .split_once('=')
            .is_some_and(|(name, _)| prog.callback_args.iter().any(|c| c == name));
    }
    let effective = effective_args(prog, cmd);
    let declared = callback_arg_positions(prog, effective.base_offset);
    positional_fold_position(cmd, raw_idx).is_some_and(|pos| declared.contains(&pos))
}

/// Every claim kind spec §5.2 enumerates for a matched entry, judged for a
/// by-reference call with no arguments. One variant per kind so
/// `claim_kind_unevaluable`'s `match` has no catch-all arm: adding a KIND
/// here without a matching arm fails to compile, which is what stops this
/// enumeration from silently going stale relative to itself (task 4 review
/// round 2, Finding A).
///
/// That is narrower than it first reads (task 4 review round 3, Finding 2).
/// It does NOT mean a new field on `Program` fails to compile here — nothing
/// ties `Program`'s field set to this enum's variant set, so adding a field
/// compiles cleanly whether or not a `ClaimKind` variant exists for it yet.
/// The guarantee is one step removed: once someone adds the variant (and a
/// `CLAIM_KINDS` entry, and a `claim_kind_unevaluable` arm) for a new
/// `Program` field, the compiler refuses to let that arm be forgotten
/// afterward — starting the chain is still a human's job; only closing a
/// chain already started is the compiler's. Making the first step
/// compiler-enforced too would need a proc macro deriving `ClaimKind` from
/// `Program`'s own field names, which is a bigger change than adding a field
/// is meant to be.
///
/// `RunsFile` merges `runs_file` and `runs_file_flags`, the one pair the
/// original chain already read together as a single claim.
#[derive(Clone, Copy)]
enum ClaimKind {
    Rule,
    ChangesDir,
    Wraps,
    RunsFile,
    EvaluatesInput,
    WritesViaHandle,
    ArgsFromInput,
    HereWrite,
    SubWrite,
    Writes,
    RemoteDest,
    RebindsNameFlags,
}

/// Priority order for `claim_kind_unevaluable`: the first six preserve the
/// exact order the original if/else-if chain checked them in (task 4 review
/// round 1); the six after close the gaps task 4 review round 2's Finding A
/// found — five kinds the chain never mentioned at all
/// (`args_from_input`, `here_write`, `sub_write`, `remote_dest`,
/// `rebinds_name_flags`), each independently provable via a scratch overlay
/// entry naming only that one field, plus `writes` named explicitly so the
/// match stays exhaustive. Order among the six new kinds is not
/// decision-bearing: `ArgsFromInput` is the only one of them that ever
/// returns `Some`, so it cannot tie against a sibling new kind on the same
/// entry.
const CLAIM_KINDS: [ClaimKind; 12] = [
    ClaimKind::Rule,
    ClaimKind::ChangesDir,
    ClaimKind::Wraps,
    ClaimKind::RunsFile,
    ClaimKind::EvaluatesInput,
    ClaimKind::WritesViaHandle,
    ClaimKind::ArgsFromInput,
    ClaimKind::HereWrite,
    ClaimKind::SubWrite,
    ClaimKind::Writes,
    ClaimKind::RemoteDest,
    ClaimKind::RebindsNameFlags,
];

/// One claim kind's judgement for a matched entry, given a by-reference call
/// with no arguments: `Some((reason, guard_backed))` when the kind cannot be
/// evaluated from a call this bare, `None` when it is either genuinely inert
/// here or produces its judgement somewhere else (documented per arm below).
fn claim_kind_unevaluable(kind: ClaimKind, p: &Program) -> Option<(String, bool)> {
    match kind {
        ClaimKind::Rule => {
            if p.rule.iter().any(|r| !r.always) {
                Some((
                    "a rule on this entry needs arguments this invocation does not have"
                        .to_string(),
                    true,
                ))
            } else {
                None
            }
        }
        ClaimKind::ChangesDir => {
            if p.changes_dir.as_deref().is_some_and(|d| d != "no") {
                Some((
                    "this entry moves the shell's working directory, and a by-reference call \
                     cannot be placed in the cd timeline"
                        .to_string(),
                    false,
                ))
            } else {
                None
            }
        }
        ClaimKind::Wraps => {
            if !p.wraps.is_empty() {
                Some((
                    "this entry runs another command or snippet vouch cannot see from a call \
                     with no arguments"
                        .to_string(),
                    false,
                ))
            } else {
                None
            }
        }
        ClaimKind::RunsFile => {
            if !p.runs_file.is_empty() || !p.runs_file_flags.is_empty() {
                Some(("this entry runs a file vouch has not read".to_string(), false))
            } else {
                None
            }
        }
        ClaimKind::EvaluatesInput => {
            if !p.evaluates_input.is_empty() {
                Some((
                    "this entry runs text vouch cannot see from a call with no arguments"
                        .to_string(),
                    false,
                ))
            } else {
                None
            }
        }
        ClaimKind::WritesViaHandle => {
            if p.writes_via_handle.is_some() {
                Some((
                    "this entry writes through an already-open file handle vouch cannot verify \
                     without the real call"
                        .to_string(),
                    false,
                ))
            } else {
                None
            }
        }
        // Verified against every real invocation of `args_from_input`
        // (engine.rs 1d4): there, this claim only speaks when paired with a
        // write/rule/wrap claim an appended token could change, because the
        // recorded command already carries a real, if partial, argument
        // list — `xargs echo` stays quiet because nothing about `echo`
        // depends on what arrives later. A by-reference call has no partial
        // list to fall back on; the record is not thinner, it is absent.
        // Gating this the same way would leave a bare `args_from_input =
        // true` entry (no other claim) allowed by reference, which is
        // exactly the shape task 4 review round 2's Finding A proved with a
        // scratch probe entry — so this arm asks unconditionally on the
        // claim alone.
        ClaimKind::ArgsFromInput => {
            if p.args_from_input {
                Some((
                    "this entry appends arguments it reads from a channel the call itself never \
                     names, and a call with no arguments cannot say what those would be"
                        .to_string(),
                    false,
                ))
            } else {
                None
            }
        }
        // `here_write` and `sub_write` are write claims, not this function's
        // to judge, on the same footing as the plain `writes` field just
        // below: their by-reference-safe destination (an unresolved
        // `python::MARKER` when a call this bare cannot rule the claim out)
        // is produced by `written_paths_in`, verified by reading its call
        // site (engine.rs Step 5.2) — which re-runs the `[[write.scope]]`
        // check over that output. Routing them through this function's
        // `callable_argument` text instead would skip that scope check
        // entirely, the exact regression class task 4 review C5 already
        // fixed once for plain `writes`.
        ClaimKind::HereWrite | ClaimKind::SubWrite | ClaimKind::Writes => None,
        // Verified against its one real call site (engine.rs 1d1, reading
        // `entry_for_cmd(..).remote_dest`): `remote_dest` only ever filters
        // an ALREADY-RESOLVED concrete path — `host:path` versus a local
        // file with a colon in its name — at the point a write target is
        // placed. A by-reference write resolves through `python::MARKER`
        // (this file's `written_paths_in`), which no `is_remote_spec` check
        // ever matches, so `remote_dest` has nothing to contribute to a
        // call this function ever judges.
        ClaimKind::RemoteDest => None,
        // Verified against its one call site (`rebinds_a_name`, called only
        // from engine.rs's 1d3 pass over `all_cmds`): isolation (spec §5.4)
        // never appends the synthetic by-reference command to that vector,
        // so this field cannot be reached from a by-reference call through
        // that pass. It is also vacuous even if it somehow were: the
        // synthetic command's `args` is always empty by construction, and
        // `rebinds_a_name` matches only against `cmd.args`.
        ClaimKind::RebindsNameFlags => None,
    }
}

/// The invocations a command makes by REFERENCE: each resolved callable
/// argument that occupies a slot the matched entry declares in
/// `callback_args`, judged as a call with no arguments and unknown order.
///
/// A marked argument is only ever judged as an invocation when it occupies
/// a DECLARED slot (`CallableArg`'s own doc comment) — without that
/// declaration vouch has no basis for saying a marked reference runs at
/// all. `datetime.datetime.now(timezone.utc)` marks `timezone.utc` (a bare
/// attribute) as a reference; judging it as an invocation would falsely
/// assert `now()` calls it (spec §5.2). `CallableArg::Inline` is already
/// scanned and judged where its body was emitted, and contributes nothing
/// of its own here; `CallableArg::Unresolved` raises its own construct
/// through `unresolved_callback_argument`, never a synthetic invocation —
/// there is no head to judge.
///
/// No arguments is the honest record — `map` will supply them from a list
/// vouch never sees. A write claim therefore resolves to an unnamed
/// destination (pass 1c's own unresolved-value handling, once judged) and a
/// claim this call cannot evaluate — a conditional rule, an unmodeled head,
/// a directory move, a wrap, a run-file, evaluated input, or a write
/// through an already-open handle — is named on `ByReference::unevaluable`
/// rather than quietly finding nothing (spec §5.2, task 4 review Q1/C2/C3).
pub fn by_reference_invocations(kb: &Knowledge, cmd: &Cmd) -> Vec<ByReference> {
    // Sorted by the argument's own position (task 4 review I1):
    // `cmd.callable_args` is a `HashMap`, so returning it in iteration
    // order would make which invocation wins a tied `worst` reason slot
    // depend on hash order rather than on the command.
    let mut indexed: Vec<(usize, &crate::syntax::CallableArg)> =
        cmd.callable_args.iter().map(|(&i, a)| (i, a)).collect();
    indexed.sort_by_key(|(i, _)| *i);
    let mut out = Vec::new();
    for (raw_idx, arg) in indexed {
        let crate::syntax::CallableArg::Named { head, receiver } = arg else { continue };
        let in_slot = entries_for_cmd(kb, cmd, "python")
            .into_iter()
            .any(|prog| in_declared_callback_slot(prog, cmd, raw_idx));
        if !in_slot {
            continue;
        }
        let full = format!("python:{head}");
        let synthetic =
            Cmd { head: full.clone(), receiver_origin: receiver.clone(), by_reference: true, ..Default::default() };
        // Receiver-gated (task 4 review I2): the same entry set the
        // reference itself would be judged against, not every same-named
        // entry regardless of what produced the receiver — `entries_for`
        // alone never applies `receiver_gate_holds`.
        let entries: Vec<&Program> = entries_for_cmd(kb, &synthetic, "python").collect();
        // `(reason, guard_backed)` — only the rule-with-conditions arm sets
        // `guard_backed`, since it is the only one of the twelve naming an
        // actual guard on the entry rather than a claim with no guard
        // behind it (task 4 review I4; `ByReference::unevaluable_guard_backed`).
        let found: Option<(String, bool)> = if entries.is_empty() {
            // C3: an unmodeled reference never reaches the ordinary
            // per-command unmodeled check — `by.cmd` is never appended to
            // `all_cmds` (isolation, spec §5.4) — so silence here would be
            // a silent allow of an unknown program (CLAUDE.md §1).
            Some((format!("vouch has no description of {full}"), false))
        } else {
            entries
                .iter()
                .find_map(|p| CLAIM_KINDS.iter().find_map(|k| claim_kind_unevaluable(*k, p)))
        };
        let (unevaluable, unevaluable_guard_backed) = match found {
            Some((reason, guard_backed)) => (Some(reason), guard_backed),
            None => (None, false),
        };
        out.push(ByReference {
            head: full,
            cmd: synthetic,
            unevaluable,
            unevaluable_guard_backed,
        });
    }
    out
}

/// Whether `cmd` hands over a callable-shaped reference vouch could not
/// resolve (`CallableArg::Unresolved`) in a slot the matched entry declares
/// in `callback_args` — the `Unresolved` twin of `by_reference_invocations`,
/// gated by the SAME `in_declared_callback_slot` rule (M2.89 Ruling A): an
/// unnameable reference outside a declared slot is no more an invocation
/// than a named one is.
pub fn unresolved_callback_argument(kb: &Knowledge, cmd: &Cmd) -> bool {
    cmd.callable_args.iter().any(|(&raw_idx, arg)| {
        matches!(arg, crate::syntax::CallableArg::Unresolved)
            && entries_for_cmd(kb, cmd, "python").into_iter().any(|prog| in_declared_callback_slot(prog, cmd, raw_idx))
    })
}

/// Whether a heredoc's body actually reaches the command it is attached to,
/// and if so, in what language — the predicate shared by the locator (inside
/// `expand_wrappers_with_sources`, to consume the body) and the engine (to
/// mark every heredoc the locator did NOT consume, at any depth).
///
/// `Some(language)` requires all three of the design's rules at once:
///   1. the matched entry declares `evaluates_input = "stdin"` — it is a
///      program known to read code from standard input at all;
///   2. `cmd` itself actually reads from stdin (`reads_stdin`) — a `-c`
///      snippet or a script path on the SAME command means the heredoc's
///      text is not what runs, even if the program could otherwise read
///      stdin;
///   3. the body reaches the consumer unmodified — a quoted delimiter
///      (`<<'EOF'`) always qualifies; an unquoted one only when the body
///      contains none of the characters shell expansion acts on (`$`, a
///      backtick), since otherwise the raw captured text is not what the
///      consumer actually sees.
///
/// Returns the ENTRY that matched alongside its own `wrap_lang` (possibly
/// empty — `scan_snippet` already treats an empty or unregistered language as
/// "fall back to bash", exactly like every other wrap arm).
///
/// The entry is part of the answer, not a convenience: whatever judges this
/// consumption downstream has to judge the entry that actually decided it. This
/// walk takes the FIRST name match, while the language-aware lookup orders
/// scoped entries ahead of unscoped ones — so a re-derived lookup can select a
/// different same-name entry, and a judgement resting on that one can rest on a
/// scan that never happened.
pub fn heredoc_feeds<'k>(
    kb: &'k Knowledge,
    cmd: &Cmd,
    heredoc: &crate::syntax::Heredoc,
) -> Option<(&'k Program, &'k str)> {
    let head = base(&cmd.head);
    for prog in &kb.program {
        if !receiver_gate_holds(kb, prog, &cmd.receiver_origin) {
            continue;
        }
        if !prog.match_names.iter().any(|n| n.to_ascii_lowercase() == head) {
            continue;
        }
        if prog.evaluates_input != "stdin" || !reads_stdin(cmd) {
            continue;
        }
        if !(heredoc.quoted_delimiter || !carries_expansion(&heredoc.body)) {
            continue;
        }
        return Some((prog, prog.wrap_lang.as_str()));
    }
    None
}

/// Whether shell expansion would act on this text before a consumer sees it.
///
/// One definition, three readers: the locator's unmodified-body rule above, the
/// stricter verbatim rule in `holds_input` (which adds the backslash the shell
/// also processes in an unquoted body), and the bash scanner's own
/// dynamic-value test. Refining what counts as expansion — `${` awareness,
/// quoting awareness — has to change one answer, not two that then disagree
/// about the same body.
pub fn carries_expansion(text: &str) -> bool {
    text.bytes().any(|b| b == b'$' || b == b'`')
}

/// Whether vouch HOLDS the text of this command's standard input — the five
/// rules of the 2026-08-11 input-source design.
///
/// `attached` is this command's own here-document records and `nth` selects the
/// DELIVERED one within it — the caller has already matched the resolved
/// `InputSource::Heredoc` identity against `attached[nth].id` before calling
/// this, so `nth` here is only a position into `attached`/`consumption`, never
/// compared against the identity itself. `consumption` is parallel to
/// `attached` — the locator's own verdict per record, so the sibling rule reads
/// what was already decided rather than deciding it a second time.
/// `entry` is the entry the locator actually consumed the delivered record
/// with, never a re-derived lookup.
///
/// Every rule that cannot be proven returns false, which keeps whatever ask the
/// command already had. There is no third answer.
#[allow(clippy::too_many_arguments)]
fn holds_input(
    cmd: &Cmd,
    args_complete: bool,
    args_from_input: bool,
    lang: &str,
    attached: &[&crate::syntax::Heredoc],
    consumption: &[Option<(&Program, &str)>],
    nth: usize,
    entry: &Program,
) -> bool {
    // A bounds guard, not one of the numbered rules: the sole caller takes `nth`
    // from an enumeration of this same slice, and rule 1 — that the resolved
    // input source names a here-document at all — is checked there.
    let Some(delivered) = attached.get(nth) else {
        return false;
    };
    // Rule 5: the recorded arguments must be a FAITHFUL record (an
    // argument-position process substitution is the program's real script and
    // pushes no token), and must name no source of their own. `reads_stdin`
    // treats `-c`, `-s` and a bare `-` as source spellings for every program
    // alike, so anything beyond a bare `-` is refused rather than interpreted —
    // per-program flag vocabulary is knowledge vouch does not have yet.
    if !args_complete {
        return false;
    }
    let declared_trailing = entry.snippet_args.as_ref().is_some_and(|declarations| !declarations.is_empty());
    let explicit_source = cmd.args.first().is_some_and(|arg| arg == "-");
    let accepted_source = cmd.args.is_empty()
        || (explicit_source && (cmd.args.len() == 1 || (declared_trailing && !args_from_input)));
    if !accepted_source {
        return false;
    }
    // Rule 2: the delivered body must reach the consumer VERBATIM. A quoted
    // delimiter always does. An unquoted one also has its backslashes processed
    // on delivery — pairs collapse, line continuations vanish — so a
    // backslash-bearing unquoted body can differ from what was scanned even
    // with no expansion character present.
    let verbatim =
        delivered.quoted_delimiter || (!carries_expansion(&delivered.body) && !delivered.body.contains('\\'));
    if !verbatim {
        return false;
    }
    // Rule 3: every OTHER record that also feeds standard input must have been
    // consumed — the shell delivers only the last of them, and the
    // unmodified-body test is per record, so a refused sibling at descriptor 0
    // can be exactly the body that runs. A sibling at another descriptor feeds
    // nothing and cannot be delivered, so it does not refuse.
    for (j, sibling) in attached.iter().enumerate() {
        if j == nth || sibling.fd != 0 {
            continue;
        }
        if consumption.get(j).map_or(true, |v| v.is_none()) {
            return false;
        }
    }
    // Rule 4: the CONSUMING entry must be in scope for this occurrence's own
    // language, and must declare a snippet language a scanner exists for. An
    // empty declared language is refused for the same reason an unregistered
    // one is: the scan falls back to bash, so a hold would rest on a reading
    // the entry never claimed.
    if !(entry.languages.is_empty() || entry.languages.iter().any(|l| l == lang)) {
        return false;
    }
    crate::syntax::scanner_for(&entry.wrap_lang).is_some()
}

/// Every entry matching `head` (`base_name` equality, case-insensitive) AND
/// scoped to `lang` — an entry's `languages` empty means every language,
/// exactly as it always has, so this filter is a no-op (matches whatever
/// `head` alone would) for every entry that never mentions `languages` at
/// all. `entry_for` picks the single best entry from this list for callers
/// that need exactly one; callers that must UNION claims across duplicate
/// shipped entries for the same name (`recognises`, below — the same "eight
/// names live in two shipped entries each" shape `knowledge::overlay_all`
/// documents) walk every one of them instead.
fn entries_for<'k>(kb: &'k Knowledge, head: &str, lang: &str) -> impl Iterator<Item = &'k Program> {
    let h = base(head);
    let lang = lang.to_string();
    kb.program.iter().filter(move |p| {
        p.match_names.iter().any(|n| n.to_ascii_lowercase() == h)
            && (p.languages.is_empty() || p.languages.iter().any(|l| l == &lang))
    })
}

/// Whether one structured origin carries a tag under the knowledge registry.
///
/// The scanner supplies only syntax facts. Calls acquire tags from matching
/// producer entries here, including the producer entry's own receiver gate,
/// so a method chain can propagate a claim without granting its first method
/// on an unknown value.
fn origin_has_tag(kb: &Knowledge, origin: &crate::syntax::ValueOrigin, tag: &str) -> bool {
    use crate::syntax::ValueOrigin;
    match origin {
        ValueOrigin::Unknown => false,
        ValueOrigin::Literal => tag == "data",
        ValueOrigin::Aggregate(members) => {
            !members.is_empty() && members.iter().all(|member| origin_has_tag(kb, member, tag))
        }
        ValueOrigin::Call { head, receiver, arguments } => {
            let unknown = ValueOrigin::Unknown;
            let receiver = receiver.as_deref().unwrap_or(&unknown);
            entries_for(kb, head, "python").any(|producer| {
                producer.produces.as_ref().is_some_and(|tags| tags.iter().any(|produced| produced == tag))
                    && receiver_gate_holds(kb, producer, receiver)
                    && !producer_callback_possible(producer, arguments)
            })
        }
    }
}

fn producer_callback_possible(program: &Program, arguments: &crate::syntax::CallArguments) -> bool {
    if program.callback_args.is_empty() {
        return false;
    }
    if arguments.keyword_unpack
        || arguments.keywords.iter().any(|name| program.callback_args.iter().any(|callback| callback == name))
    {
        return true;
    }
    program.callback_args.iter().any(|callback| {
        program
            .arg_names
            .iter()
            .position(|name| name == callback)
            .is_some_and(|position| arguments.positional > position || arguments.starred)
    })
}

/// Missing or explicitly empty is unconditional. A non-empty receiver gate
/// accepts when any declared tag is proven by the command's structured origin.
fn receiver_gate_holds(kb: &Knowledge, program: &Program, receiver: &crate::syntax::ValueOrigin) -> bool {
    program
        .receiver_from
        .as_ref()
        .map_or(true, |tags| tags.is_empty() || tags.iter().any(|tag| origin_has_tag(kb, receiver, tag)))
}

/// Every entry whose complete claim applies to this command occurrence.
fn entries_for_cmd<'k>(kb: &'k Knowledge, cmd: &Cmd, lang: &str) -> std::vec::IntoIter<&'k Program> {
    entries_for(kb, &cmd.head, lang)
        .filter(|program| receiver_gate_holds(kb, program, &cmd.receiver_origin))
        .collect::<Vec<_>>()
        .into_iter()
}

/// The ONE program-lookup primitive every language-aware caller goes
/// through: `base_name(head)` equality AND (`languages` empty or contains
/// `lang`) — spec 2026-07-31 §2.
///
/// More than one entry sharing a name is NORMAL, not a merge defect: the
/// shipped file already groups several names into two `[[program]]` entries
/// each (`sudo`, `doas`, `runas`, `find`, `dd`), and `overlay_all` can add
/// more of the same shape — an operator entry that only partially overlaps
/// one of those shipped entries by scope splits it, and if the SAME name
/// also lives in a second, untouched shipped entry, the merge legitimately
/// ends up with two same-name, same-scope entries side by side. This
/// function still has to return exactly one, by two rules in order:
/// 1. An entry actually SCOPED to `lang` beats an unscoped one: an unscoped
///    claim reads "everywhere", the weaker of the two once the caller is
///    asking about one specific language.
/// 2. Among entries tied on that (including a plain duplicate, per above),
///    the FIRST one in file order wins — arbitrary, but deterministic.
///    This is load-bearing, not a fallback: `dir_change_entry` (Task 6) reads
///    a SINGLE entry's `changes_dir` through this function, so which
///    duplicate answers has to be stable across runs, not whichever the
///    merge happened to push last. Pinned by
///    `entry_for_is_first_wins_for_a_merge_produced_duplicate` in
///    `tests/knowledge_merge_test.rs`.
///
/// Callers that must see EVERY claim for a name instead of picking one —
/// `recognises`, below, unioning recognition scopes across duplicate entries —
/// do not call this function at all; they walk `entries_for` directly.
pub fn entry_for<'k>(kb: &'k Knowledge, head: &str, lang: &str) -> Option<&'k Program> {
    // One pass: return the instant an entry actually scoped to `lang` is
    // found (rule 1), remembering only the very FIRST entry seen along the
    // way (rule 2) in case no scoped one ever turns up.
    let mut first: Option<&'k Program> = None;
    for p in entries_for(kb, head, lang) {
        if !p.languages.is_empty() {
            return Some(p);
        }
        if first.is_none() {
            first = Some(p);
        }
    }
    first
}

/// The single-entry selector for one command occurrence. It preserves
/// `entry_for`'s language-scope and file-order precedence after removing
/// entries whose receiver gates do not hold for this command.
pub fn entry_for_cmd<'k>(kb: &'k Knowledge, cmd: &Cmd, lang: &str) -> Option<&'k Program> {
    let mut first: Option<&'k Program> = None;
    for program in entries_for_cmd(kb, cmd, lang) {
        if !program.languages.is_empty() {
            return Some(program);
        }
        if first.is_none() {
            first = Some(program);
        }
    }
    first
}

/// True when the knowledge file has any entry for this program, scoped to
/// `lang`. `chdir` and `sl` are PowerShell-only claims: modelled on a
/// PowerShell line, unmodelled on a bash line, because in bash they are
/// either unrelated externals or nothing at all.
pub fn is_modeled(kb: &Knowledge, head: &str, lang: &str) -> bool {
    entry_for(kb, head, lang).is_some()
}

/// What `listable_standalone` found: the flags a fresh (or widened)
/// `standalone_flags` entry could truthfully list for this run.
/// `needs_case_key` is true when some same-name entry has not stated
/// `case_sensitive_flags`, so the offer names the key the post-merge check
/// will demand alongside it.
#[derive(Debug)]
pub struct ListableStandalone {
    pub flags: Vec<String>,
    pub needs_case_key: bool,
}

/// The flags a narrow entry could list for this run, when every argument
/// could be a `standalone_flags` member: flags-only under the UNION
/// vocabulary (the same computation `subcommand_of` uses), each token
/// passing the loader's member allowlist, and none sitting in a refused
/// vocabulary of ANY same-name entry in this language — the conservative
/// language-scoped union view, so the prompt never offers a member the
/// loader would then refuse.
///
/// `eligible` is the same per-occurrence fold every other standalone
/// question reads (`standalone_run`, `standalone_hint`): a record something
/// can still append to, or one the parser could not complete, is never
/// offered as a flags-only shape, whatever its tokens look like.
pub fn listable_standalone(kb: &Knowledge, cmd: &Cmd, eligible: bool) -> Option<ListableStandalone> {
    listable_standalone_in(kb, cmd, "bash", eligible)
}

fn listable_standalone_in(kb: &Knowledge, cmd: &Cmd, lang: &str, eligible: bool) -> Option<ListableStandalone> {
    if !eligible || cmd.args.is_empty() {
        return None;
    }
    // The union walk is built ONCE and both readings come off it: the verb
    // (what `subcommand_of` would rebuild from the same lists) and the flag
    // prefixes the member check needs.
    let owned = verb_vocab(kb, cmd, lang);
    if subcommand(cmd, &owned.as_vocab(), lang).is_some() {
        return None;
    }
    let flag_prefix = prefixes(&owned.flag_prefix);
    let same_name: Vec<&Program> = entries_for_cmd(kb, cmd, lang).collect();
    let mut flags: Vec<String> = Vec::new();
    for a in &cmd.args {
        let t = crate::paths::unquote(a);
        if crate::knowledge::member_shape_ok(&flag_prefix, t).is_err()
            || same_name.iter().any(|p| crate::knowledge::in_refused_vocab(p, t).is_some())
        {
            return None;
        }
        if !flags.iter().any(|f| f == t) {
            flags.push(t.to_string());
        }
    }
    let needs_case_key = same_name.iter().any(|p| p.case_sensitive_flags.is_none());
    Some(ListableStandalone { flags, needs_case_key })
}

/// The narrow-offer sentence for a flags-only run, in its two readings:
/// `modeled` (an entry for this name exists and scopes itself to verbs, so
/// the offer sits BESIDE its `subcommands`) or not (nothing describes the
/// name, so the whole-program entry is the alternative being narrowed from).
///
/// One function because two sites emit it — the per-run description below,
/// and the engine's union-collision arm, which regenerates the sentence after
/// two differing flag sets are united so the printed shape and the stored
/// marker agree. A test pins the exact text, so a second copy would be a
/// wording change that compiles, passes here, and fails there.
///
/// The caller decides which reading applies: the two sites answer "is this
/// name modeled" by different tests, and folding that choice in here would
/// change one of them.
pub fn standalone_offer_text(bare: &str, l: &ListableStandalone, modeled: bool) -> String {
    let flags = l.flags.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>().join(", ");
    if modeled {
        format!(
            "an entry could recognise exactly this flags-only shape: \
             `standalone_flags = [{flags}]` beside its `subcommands`{} — \
             covering runs of `{bare}` whose every argument is one of \
             those flags, and nothing else",
            if l.needs_case_key {
                ", with `case_sensitive_flags` stated on the entry"
            } else {
                ""
            }
        )
    } else {
        format!(
            "an entry would recognise every operation of `{bare}` — or, \
             narrower, exactly this flags-only shape: `subcommands = []` \
             with `standalone_flags = [{flags}]` and `case_sensitive_flags` \
             stated"
        )
    }
}

/// For every command the knowledge does not recognise: the name to show, and
/// what the NARROWEST entry covering it would trust — in words. The prompt
/// used to print one joined `vouch trust a b` command instead, which meant
/// "program a, subcommand b" and, four measured ways, did something other
/// than what the prompt was about (M2.12). A printed command cannot say what
/// it will trust; a sentence can.
///
/// The verb comes from `subcommand_of` — the SAME computation `recognises`
/// uses — so the sentence and the verdict cannot disagree about which token
/// is the subcommand. A fresh "first non-flag argument" pick here would name
/// a value-flag's VALUE as the verb the moment one is present. (One recorded
/// exception: a name carried by several entries with different
/// `value_options` can still split them — M2.53.)
///
/// `standalone_eligible` is forwarded to the recognition call below so that
/// this function and the verdict cannot disagree about whether a flags-only
/// run was covered — describing a command the engine recognised would print a
/// prompt about a thing that never asked.
pub fn unmodeled_descriptions(
    kb: &Knowledge,
    commands: &[Cmd],
    lang: &str,
    standalone_eligible: bool,
) -> Vec<(String, String, Option<ListableStandalone>)> {
    let mut out: Vec<(String, String, Option<ListableStandalone>)> = Vec::new();
    for c in commands {
        if c.head.is_empty() || recognises(kb, c, lang, standalone_eligible) {
            continue;
        }
        // The name an entry must carry, whatever the command was spelled like:
        // recognition compares bare names, so every description below is about
        // this one.
        let bare = base(&c.head);
        // What a flags-only run of this occurrence could list, if anything.
        // Computed ONCE and returned beside the sentence it shaped: the caller
        // needs the same marker to tell colliding populations apart, and a
        // second call there would be a second answer to one question.
        let narrow = listable_standalone_in(kb, c, lang, standalone_eligible);
        let (shown, desc) = if is_modeled(kb, &c.head, lang) {
            // Say WHICH part is unrecognised, or the prompt looks wrong to
            // anyone who just trusted this program.
            match subcommand_of_in(kb, c, lang) {
                Some(sub) => (
                    format!("{} {sub}", c.head),
                    format!("an entry would recognise the `{sub}` operation of `{bare}` and nothing else"),
                ),
                None if c.args.is_empty() => (
                    // A bare run names no operation at all, so nothing about
                    // it can be listed the way `standalone_flags` lists
                    // flags — the whole CLI is still the only writable entry.
                    c.head.clone(),
                    format!(
                        "a bare run (no arguments) cannot be described more narrowly \
                         — the only entry writable is the whole program, and that \
                         would include verbs a scoped entry deliberately excludes"
                    ),
                ),
                None => match &narrow {
                    Some(l) => (c.head.clone(), standalone_offer_text(&bare, l, true)),
                    None => (
                        c.head.clone(),
                        // Two populations reach this arm and the WHY must be
                        // true for each (delta-round catch): tokens that are
                        // not listable, vs a record eligibility disqualified
                        // (process substitution, an appending wrapper) where
                        // every RECORDED token is listable.
                        if standalone_eligible {
                            format!(
                                "the only entry writable for this run would recognise every \
                                 operation of `{bare}` — not every argument here is a flag \
                                 `standalone_flags` could list, and the whole-program entry \
                                 would include verbs a scoped entry deliberately excludes"
                            )
                        } else {
                            format!(
                                "the only entry writable for this run would recognise every \
                                 operation of `{bare}` — this run's recorded arguments are \
                                 not the complete story (something off the line supplies \
                                 more), so no flag list can vouch for it"
                            )
                        },
                    ),
                },
            }
        } else if bare == c.head.to_ascii_lowercase() {
            match &narrow {
                Some(l) => (c.head.clone(), standalone_offer_text(&bare, l, false)),
                None => (c.head.clone(), format!("an entry would recognise every operation of `{bare}`")),
            }
        } else {
            (
                c.head.clone(),
                format!(
                    "spelled with a directory or extension — recognition compares bare \
                     names, so an entry would name `{bare}` and cover every program \
                     invoked as `{bare}`"
                ),
            )
        };
        if !out.iter().any(|(n, _, _)| n == &shown) {
            out.push((shown, desc, narrow));
        }
    }
    out
}

/// The dir-change kind a program claims: what the walk can KNOW about where
/// the shell goes after it runs. Mirrors `Program::changes_dir`'s closed set
/// (spec 2026-07-31 §1) — parsed from that string in this ONE place, so
/// `engine::cd_timeline` never reads the raw string itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirChangeKind {
    /// Declared not to move the shell — an explicit retraction, not silence.
    No,
    /// The destination is stated in the command; the walk can read it.
    Stated,
    /// Stated when a plain directory argument is present; the bare swap
    /// form, `±n` rotates, and anything option-shaped walk a stack vouch
    /// never saw → unknown.
    Stack,
    /// Changes directory to somewhere never derivable from the command line
    /// → unknown, always.
    Unstated,
}

/// The dir-change kind for `head`, scoped to `lang`, PLUS the single entry it
/// was read from — one `entry_for` scan instead of the two `cd_timeline` used
/// to do (`dir_change_kind` followed by its own separate `entry_for` call) for
/// the exact same `(head, lang)`. `dir_change_kind`, just below, stays as a
/// thin wrapper over this for callers that only ever wanted the kind.
///
/// `None` covers both an `entry_for` miss and an entry that never mentions
/// `changes_dir`: neither is a claim that this program moves the shell, so a
/// membership test treats `None` and `Some((DirChangeKind::No, _))` alike —
/// `No` is kept as its own value so an operator's explicit retraction is
/// never confused with "nobody said" (spec §1).
fn dir_change_from_program(program: &Program) -> Option<(DirChangeKind, &Program)> {
    let p = program;
    let cd = p.changes_dir.as_deref()?;
    let kind = match cd {
        "no" => DirChangeKind::No,
        "stated" => DirChangeKind::Stated,
        "stack" => DirChangeKind::Stack,
        "unstated" => DirChangeKind::Unstated,
        // `knowledge::validate` rejects every other spelling before a shipped
        // or operator file ever loads (§1) — unreached in practice. `None`
        // ("not a mover") is the fail-quiet answer if it somehow is, rather
        // than a panic over a value this function does not police.
        _ => return None,
    };
    Some((kind, p))
}

pub fn dir_change_entry<'k>(kb: &'k Knowledge, head: &str, lang: &str) -> Option<(DirChangeKind, &'k Program)> {
    dir_change_from_program(entry_for(kb, head, lang)?)
}

/// Receiver-aware directory-change lookup for a concrete occurrence.
pub fn dir_change_entry_for_cmd<'k>(
    kb: &'k Knowledge,
    cmd: &Cmd,
    lang: &str,
) -> Option<(DirChangeKind, &'k Program)> {
    dir_change_from_program(entry_for_cmd(kb, cmd, lang)?)
}

/// Thin wrapper over `dir_change_entry`, just above, for callers that only
/// need the kind and not the entry it came from.
pub fn dir_change_kind(kb: &Knowledge, head: &str, lang: &str) -> Option<DirChangeKind> {
    Some(dir_change_entry(kb, head, lang)?.0)
}

/// True when this WHOLE command is recognised — the program AND, when the entry
/// scopes itself to particular subcommands or positional command paths, that
/// scope — for the language it was scanned as.
///
/// A CLI is not one operation. Recognising the name `kubectl` says nothing about
/// `kubectl delete` versus `kubectl get pods`, and treating the name as the
/// unit of trust is the blanket-allow this design exists to remove. An entry
/// with neither scope key covers the whole program, which is right for `ls`
/// and wrong for anything with verbs.
///
/// `standalone_eligible` is the one boolean per OCCURRENCE that the standalone
/// arm needs and that this function cannot derive: whether the recorded
/// argument list is a faithful record AND nothing off the line will append to
/// it. See `standalone_run`. A caller that assembled the arguments itself
/// passes `true`.
pub fn recognises(kb: &Knowledge, cmd: &Cmd, lang: &str, standalone_eligible: bool) -> bool {
    recognises_at(kb, cmd, lang, RecognitionPlace::nowhere(), standalone_eligible)
}

/// The three facts a place-scoped entry is judged against, carried together:
/// where the command runs, and the two roots its `only_under` globs expand
/// against.
///
/// One value rather than three positional parameters because two of them are
/// `Option<&str>` and the third a `&str` — a call site that transposed
/// `run_place` and `project_root`, or `home` and `lang`, would compile and
/// silently judge the wrong tree. The same reason `WalkOut` is a struct.
#[derive(Clone, Copy)]
pub struct RecognitionPlace<'a> {
    /// Where the command runs, or `None` when vouch cannot name it — in which
    /// case a place-scoped entry counts for nothing.
    pub dir: Option<&'a str>,
    /// What `~` expands to in a glob.
    pub home: &'a str,
    /// What `$PROJECT_ROOT` expands to, when there is one.
    pub project_root: Option<&'a str>,
}

impl RecognitionPlace<'_> {
    /// No place at all: what the place-less `recognises` asks with. The empty
    /// `home` never reaches an expansion, because a scoped entry is skipped
    /// before its globs are read when there is no directory to compare.
    pub fn nowhere() -> Self {
        RecognitionPlace { dir: None, home: "", project_root: None }
    }
}

/// The same question, asked about a command running in a KNOWN directory: an
/// entry carrying `only_under` counts only when `run_place` is a directory
/// under one of its globs (spec 2026-08-06 §Schema). Every other entry is
/// unaffected — a claim with no place on it was always a claim about
/// everywhere.
///
/// `run_place: None` means vouch cannot name where the command runs, and a
/// place-scoped entry then counts for NOTHING. That is the strict direction on
/// purpose: an entry saying "only under this tree" has made no claim at all
/// about a command whose tree is unknown, and absence of knowledge is never the
/// permissive case (CLAUDE.md §1). It is also what keeps `recognises` — which
/// delegates with no place — and this function agreeing wherever a caller uses
/// both: everything `recognises` accepts, `recognises_at` accepts too, so a
/// command this rejects is one `unmodeled_descriptions` will still describe.
///
/// `place.home` and `place.project_root` are what the globs expand against,
/// and are read only when a scoped entry is actually reached — so the empty
/// `home` the place-less delegate passes never reaches an expansion.
pub fn recognises_at(
    kb: &Knowledge,
    cmd: &Cmd,
    lang: &str,
    place: RecognitionPlace<'_>,
    standalone_eligible: bool,
) -> bool {
    !matches!(recognition_at(kb, cmd, lang, place, standalone_eligible), Recognised::No)
}

/// What recognised a command — the same walk `recognises_at` does, returning
/// WHICH kind of entry answered instead of only whether one did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recognised {
    /// No entry reached this command.
    No,
    /// An entry with no place on it: a claim about everywhere.
    Yes,
    /// A place-scoped entry, and the tree of its `only_under` that the run
    /// place matched — as WRITTEN, because that is the text a prompt names.
    AtPlace(String),
}

/// The recognition walk itself, told once.
///
/// The caller that has to SAY why a command was allowed needs the matched
/// tree, and asking a second function for it walked the entries again and
/// re-expanded the same globs — two answers to one question, which is how they
/// drift apart. One walk, one answer, and `recognises_at` above is the thin
/// boolean over it.
///
/// `standalone_eligible` reaches here as an EXPLICIT parameter rather than
/// being derived: this walk sees one `Cmd` and a `Cmd` cannot say whether the
/// list it carries is the whole list. See `standalone_run`.
pub fn recognition_at(
    kb: &Knowledge,
    cmd: &Cmd,
    lang: &str,
    place: RecognitionPlace<'_>,
    standalone_eligible: bool,
) -> Recognised {
    for p in entries_for_cmd(kb, cmd, lang) {
        let mut at_place: Option<&String> = None;
        if let Some(globs) = &p.only_under {
            let Some(dir) = place.dir else { continue };
            // A glob that cannot be expanded (`$PROJECT_ROOT` with no project
            // root) is not compared as raw text — it names no tree, so it
            // covers none. This is the GRANT direction: an entry that cannot
            // say where it applies grants nothing (spec §The one rule for
            // uncertainty). A rule that RESTRICTS reads the same failure the
            // other way round, in the engine.
            let Some(hit) = globs.iter().find(|g| {
                crate::paths::expand_pattern(g, place.home, place.project_root)
                    .is_some_and(|e| crate::paths::glob_match(&e, dir))
            }) else {
                continue;
            };
            at_place = Some(hit);
        }
        // Both scope keys absent covers the whole program. Once either is
        // present, first verbs, exact nested paths, and standalone runs are
        // the union. The standalone arm is the only way a fully empty scope
        // recognises anything, which is why the loader refuses that spelling
        // without a non-empty flag list (§3, §4).
        let covers = if p.subcommands.is_none() && p.subcommand_paths.is_none() {
            true
        } else {
            // The first-verb and standalone halves ask about the verb under
            // THIS entry's vocabulary, so that lookup runs once.
            let sub = entry_subcommand(p, cmd, lang);
            p.subcommands.as_ref().is_some_and(|subs| {
                !subs.is_empty()
                    && sub.is_some_and(|sub| subs.iter().any(|s| s.eq_ignore_ascii_case(sub)))
            }) || entry_subcommand_path_matches(p, cmd, lang)
                || standalone_run(p, cmd, sub, standalone_eligible)
        };
        if covers {
            return match at_place {
                Some(glob) => Recognised::AtPlace(glob.clone()),
                None => Recognised::Yes,
            };
        }
    }
    // Named by some entry, but every one of them scoped to other operations —
    // or to other places.
    Recognised::No
}

/// The `only_under` trees every entry naming this program carries, for this
/// language — as WRITTEN, unexpanded, in file order.
///
/// Empty means no entry for this name is place-scoped, which is the ordinary
/// case: it is how the engine tells "vouch has never heard of this program"
/// apart from "your entry for it does not reach where this command runs", two
/// prompts that must not say the same thing (spec 2026-08-06 §Every
/// place-derived verdict says so — the second names the existing entry and
/// must never suggest writing a fresh one, since a scoped name on a second
/// entry refuses the whole file).
///
/// It lives here, beside `recognises_at`, because `entries_for` — bare-name
/// equality plus the language scope — is the ONE program-lookup rule, and a
/// second copy of it in the engine would be a second answer to "which entries
/// name this program".
///
/// Unexpanded because the caller shows these to the operator: `~/scratch/**`
/// is what they would edit, and `expand_pattern` is what compares them.
pub fn place_scopes(kb: &Knowledge, head: &str, lang: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in entries_for(kb, head, lang) {
        for g in p.only_under.iter().flatten() {
            if !out.contains(g) {
                out.push(g.clone());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The wrapper walk's locators (spec §3.1, §3.2)
//
// Every arm below answers with one of three things and never with silence:
// the payload it LOCATED, a genuine "this invocation wraps nothing" (no
// declared wrap flag appears at all — a bare `bash`, a `find` with no
// `-exec`), or `Unlocated`, carrying the sentence the `wrap_unlocated`
// construct prints. The empty scan the arms used to return on a miss was
// indistinguishable from wrapping nothing, and that one ambiguity is the root
// of at least nine live wrong allows (M2.123).
// ---------------------------------------------------------------------------

/// What a locator found.
enum Payload {
    /// No declared wrap flag appears in these arguments at all — this
    /// invocation genuinely wraps nothing.
    Absent,
    /// The payload, the declared spelling that selected it, and every raw
    /// outer token after it. Keeping these together makes this locator the
    /// sole authority for both snippet extraction and snippet-argument joins.
    Found(LocatedSnippet),
    /// The entry declares a payload and the walk could not locate it. The
    /// string is the detail line the prompt carries.
    Unlocated(String),
}

/// One after-flag snippet and the enclosing argument context it exposes.
struct LocatedSnippet {
    /// Snippet text, already unquoted the way the interpreter receives it.
    source: String,
    /// The declared flag spelling, such as `-c`, which the interpreter exposes
    /// as the snippet source when a `snippet_args` claim maps it.
    source_spelling: String,
    /// Raw outer arguments after the snippet token. Resolution stays in the
    /// engine, so quotes and variable spellings are deliberately preserved.
    trailing: Vec<String>,
}

/// The abbreviation policy for a wrapper entry's own flag vocabulary
/// (spec §4.1.7): a case-insensitive entry is the PowerShell family, where an
/// unambiguous prefix is a real spelling; a case-sensitive unix entry refuses
/// one, loudly.
fn wrap_abbrev(prog: &Program) -> crate::flags::Abbrev {
    if prog.case_sensitive_flags.unwrap_or(false) {
        crate::flags::Abbrev::Refuse
    } else {
        crate::flags::Abbrev::Accept
    }
}

/// A clustered SWITCH spelling: does this single-dash cluster contain `flag`'s
/// letter, with every OTHER letter an independently declared no-value flag of
/// this entry?
///
/// This is the shells' binding, and only the shells': `-c` never consumes a
/// value there, so it may sit anywhere in the cluster and the letters around
/// it are just more switches. Verified by running on this machine —
/// `bash -lc 'echo x'` and `bash -cx 'echo x'` both run the string, with the
/// wrap letter last in one and first in the other.
///
/// A cluster containing the wrap letter with any OTHER letter undescribed is
/// `Unreadable`, never `No`: vouch was told this program wraps something,
/// the token in front of it says the wrap letter is present, and it cannot
/// parse the rest — which is exactly what `wrap_unlocated` is for.
enum ClusterHit {
    No,
    Yes,
    Unreadable,
}

fn cluster_switch(prog: &Program, flag: &str, raw: &str) -> ClusterHit {
    let s = crate::paths::unquote(raw);
    let (Some(letter), true) = (bare_short_letter(flag), is_cluster_vocabulary(prog) && is_short_cluster(s)) else {
        return ClusterHit::No;
    };
    let letters: Vec<char> = s[1..].chars().collect();
    let case_sensitive = prog.case_sensitive_flags.unwrap_or(false);
    if !letters.iter().any(|c| same_letter(*c, letter, case_sensitive)) {
        return ClusterHit::No;
    }
    let others_described = letters.iter().filter(|c| !same_letter(**c, letter, case_sensitive)).all(|c| {
        let short = format!("-{c}");
        declares(&prog.no_value_options, &short, case_sensitive)
    });
    if others_described {
        ClusterHit::Yes
    } else {
        ClusterHit::Unreadable
    }
}

/// A clustered VALUE spelling: `-Sc code` and `-Scx` for `-c`, where the
/// letters BEFORE the wrap letter are declared no-value switches and
/// everything AFTER it is the flag's attached value.
///
/// This is python's binding, and it is not the shells' — `python --help` says
/// `-c cmd` "terminates option list", so a letter following `c` in the same
/// token is the start of the command string rather than another switch.
/// `Some(None)` means the wrap letter was last and the value is the NEXT
/// token; `Some(Some(v))` means it was attached inside the cluster.
fn cluster_value(prog: &Program, flag: &str, raw: &str) -> Option<Option<String>> {
    let s = crate::paths::unquote(raw);
    let letter = bare_short_letter(flag)?;
    if !is_cluster_vocabulary(prog) || !is_short_cluster(s) {
        return None;
    }
    let case_sensitive = prog.case_sensitive_flags.unwrap_or(false);
    let letters: Vec<char> = s[1..].chars().collect();
    let at = letters.iter().position(|c| same_letter(*c, letter, case_sensitive))?;
    let before_described = letters[..at].iter().all(|c| {
        let short = format!("-{c}");
        declares(&prog.no_value_options, &short, case_sensitive)
    });
    if !before_described {
        return None;
    }
    let tail: String = letters[at + 1..].iter().collect();
    Some((!tail.is_empty()).then_some(tail))
}

/// Whether this entry's flags cluster at all.
///
/// Grouping several short flags behind one dash is the UNIX convention, and
/// `case_sensitive_flags = true` is precisely how this knowledge file marks a
/// unix flag vocabulary (CLAUDE.md §7). PowerShell spells its parameters as
/// single-dash LONG names — `-NoProfile`, `-Confirm` — which are the same
/// SHAPE as a cluster and are not one; reading them as clusters made every
/// PowerShell switch containing a wrap letter look like a grouping vouch
/// could not parse, which is a false ask on ordinary traffic.
fn is_cluster_vocabulary(prog: &Program) -> bool {
    prog.case_sensitive_flags.unwrap_or(false)
}

/// `-` plus exactly one further character → that character. Both cluster
/// readings key on this shape; a long flag never explodes.
fn bare_short_letter(flag: &str) -> Option<char> {
    let mut cs = flag.chars();
    match (cs.next(), cs.next(), cs.next()) {
        (Some('-'), Some(c), None) => Some(c),
        _ => None,
    }
}

/// A single-dash token with more than one letter after the dash — the only
/// shape either cluster reading applies to.
fn is_short_cluster(s: &str) -> bool {
    s.starts_with('-') && !s.starts_with("--") && s.chars().count() > 2
}

fn same_letter(a: char, b: char, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        a.eq_ignore_ascii_case(&b)
    }
}

fn declares(list: &[String], flag: &str, case_sensitive: bool) -> bool {
    list.iter().any(|d| {
        if case_sensitive {
            d == flag
        } else {
            d.eq_ignore_ascii_case(flag)
        }
    })
}

/// Finds the snippet a wrap flag carries, in every spelling the interpreter
/// itself accepts: separate (`-c <code>`), attached short (`-c<code>`),
/// long-with-equals (`--eval=<code>`), PowerShell's colon form, an accepted
/// abbreviation, and the clustered short form (`-Sc <code>`) the previous
/// text-prefix rule could not see at all.
///
/// Every one of those decisions is `crate::flags`' now, not this function's:
/// the private `same` closure and the two hand-rolled attachment shapes it
/// used to carry were one of the six divergent comparisons the shared
/// primitive replaced, and the one that misread `-Confirm` as `-C` with an
/// attached snippet.
///
/// The joined form (`wrap_join`) unquotes PER TOKEN and then joins, which is
/// what the interpreter receives: joining first and unquoting the result put
/// a statement separator back inside a quoted string and swallowed it
/// (M2.112).
///
/// `pub` so it is the ONE extraction rule: the `after_flag` wrap arm below
/// uses it, and so does the measurement in `corpus_shapes_test.rs` that
/// reconciles against it — two extractors quietly drifting apart is the
/// hole this closes.
pub fn after_flag_snippet(prog: &Program, args: &[String]) -> Option<String> {
    match locate_after_flag(prog, args) {
        Payload::Found(found) => Some(found.source),
        Payload::Absent | Payload::Unlocated(_) => None,
    }
}

fn locate_after_flag(prog: &Program, args: &[String]) -> Payload {
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let mut skip_next = false;
    for (i, raw) in args.iter().enumerate() {
        // A token already spoken for as some other flag's value is not itself
        // a candidate, and must not be fed to the walk either — its text
        // could be `--`, which would end option scanning that never started.
        if skip_next {
            skip_next = false;
            continue;
        }
        let class = walk.next(raw);
        if let crate::flags::Class::Value { attached: None, .. } = class {
            skip_next = true;
        }
        // After `--` nothing is this program's flag any more (spec §4.1.4).
        // This deliberately INVERTS the old over-read, which found `-c` after
        // a bare `--` by raw text: real python treats what follows as a
        // script filename, so scanning it as a snippet judged text the
        // interpreter never runs.
        if matches!(class, crate::flags::Class::NotFlag | crate::flags::Class::EndOfOptions) {
            continue;
        }
        for f in &prog.wrap_flags {
            match crate::flags::spells(f, raw, &vocab) {
                crate::flags::Spell::Yes(Some(v)) => {
                    return Payload::Found(LocatedSnippet {
                        source: crate::paths::unquote_snippet(&v),
                        source_spelling: f.clone(),
                        trailing: args[i + 1..].to_vec(),
                    });
                }
                crate::flags::Spell::Yes(None) => return payload_after(prog, args, i, f),
                crate::flags::Spell::RefusedAbbrev { declared } => {
                    return Payload::Unlocated(format!(
                        "`{raw}` reads as an abbreviation of `{declared}`, which this program's \
                         flags are matched exactly — vouch cannot tell whether the code it \
                         carries was meant to run"
                    ));
                }
                crate::flags::Spell::No => {}
            }
            match cluster_value(prog, f, raw) {
                Some(Some(v)) => {
                    return Payload::Found(LocatedSnippet {
                        source: crate::paths::unquote_snippet(&v),
                        source_spelling: f.clone(),
                        trailing: args[i + 1..].to_vec(),
                    });
                }
                Some(None) => return payload_after(prog, args, i, f),
                None => {}
            }
            if matches!(cluster_switch(prog, f, raw), ClusterHit::Unreadable) {
                return Payload::Unlocated(format!(
                    "`{raw}` groups `{f}` with a letter this entry does not describe, so vouch \
                     cannot tell where the code it carries begins"
                ));
            }
        }
    }
    Payload::Absent
}

/// The payload of a wrap flag that carried no attached value: the next token,
/// or — for an entry whose snippets genuinely spread over the rest of the
/// line (`wrap_join`) — every remaining token, each unquoted before they are
/// joined.
fn payload_after(prog: &Program, args: &[String], i: usize, flag: &str) -> Payload {
    let rest = &args[i + 1..];
    if rest.is_empty() {
        return Payload::Unlocated(format!(
            "`{flag}` is here with nothing after it, so the code it names is not in this command"
        ));
    }
    if prog.wrap_join == Some(true) {
        let joined: Vec<String> = rest.iter().map(|t| crate::paths::unquote_snippet(t)).collect();
        return Payload::Found(LocatedSnippet {
            source: joined.join(" "),
            source_spelling: flag.to_string(),
            trailing: Vec::new(),
        });
    }
    Payload::Found(LocatedSnippet {
        source: crate::paths::unquote_snippet(&rest[0]),
        source_spelling: flag.to_string(),
        trailing: rest[1..].to_vec(),
    })
}

/// What the `start_process` list locator found — the same three answers
/// `Payload` gives, over a LIST of tokens rather than one snippet of text.
enum ListPayload {
    Absent,
    Found(Vec<String>),
    Unlocated(String),
}

/// The arguments a `Start-Process`-shaped entry hands the program it starts:
/// the items of its declared list parameter.
///
/// The list flag is found ANYWHERE in the argument vector and in every
/// spelling `crate::flags` accepts, abbreviations included — an exact-token
/// search missed the abbreviated parameter names PowerShell itself resolves.
/// The list ENDS at the next token that is a declared parameter of THIS
/// entry: what follows the flag is data for the program being started, and
/// a dash-led item among it (`"-Command"`, `"-NoProfile"`, `"-File"`) is one
/// of that program's own flags, not the end of the list.
fn start_process_args(prog: &Program, args: &[String]) -> ListPayload {
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let mut skip_next = false;
    let mut at: Option<usize> = None;
    for (i, raw) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let class = walk.next(raw);
        if let crate::flags::Class::Value { attached: None, .. } = class {
            skip_next = true;
        }
        for f in &prog.wrap_flags {
            match crate::flags::spells(f, raw, &vocab) {
                crate::flags::Spell::Yes(Some(v)) => {
                    return ListPayload::Found(split_list(&v));
                }
                crate::flags::Spell::Yes(None) => {
                    at = Some(i);
                }
                crate::flags::Spell::RefusedAbbrev { declared } => {
                    return ListPayload::Unlocated(format!(
                        "`{raw}` reads as an abbreviation of `{declared}`, which this entry's \
                         flags are matched exactly — vouch cannot tell what is being started"
                    ));
                }
                crate::flags::Spell::No => {}
            }
        }
        if at.is_some() {
            break;
        }
    }
    let Some(at) = at else {
        return ListPayload::Absent;
    };
    let mut items: Vec<String> = Vec::new();
    for raw in &args[at + 1..] {
        // A PowerShell array expression rather than plain strings. vouch does
        // not evaluate PowerShell expressions, so the items are not in the
        // command in any form it can read — loud, not an empty list (§3.1).
        if crate::paths::unquote(raw).starts_with("@(") {
            return ListPayload::Unlocated(format!(
                "the argument list is a PowerShell array expression (`{raw}`…), whose items \
                 vouch cannot read"
            ));
        }
        if !matches!(
            crate::flags::classify(raw, &vocab),
            crate::flags::Class::NotFlag | crate::flags::Class::Undescribed { .. }
        ) {
            break;
        }
        items.extend(split_list(raw));
    }
    ListPayload::Found(items)
}

/// Which program a `Start-Process`-shaped entry starts.
///
/// Two spellings, and the flag one comes first because it is the one the
/// positional walk cannot see: `-FilePath pwsh` names the program through a
/// declared parameter, so the walk consumes `pwsh` as that flag's value and
/// reaches the end having seen no positional at all. `wrap_head_flags` is the
/// entry's claim that those flags name the program rather than carrying an
/// ordinary value.
///
/// Falls back to the first positional (`Start-Process pwsh -ArgumentList …`),
/// which is the same `operand_walk` every other operand-shaped arm uses — so
/// an undescribed flag in front of the program forks here too.
fn start_process_head(prog: &Program, args: &[String], fork: &mut ForkCursor) -> Option<String> {
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let mut skip_next = false;
    for (i, raw) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        let class = walk.next(raw);
        if let crate::flags::Class::Value { attached: None, .. } = class {
            skip_next = true;
        }
        for f in &prog.wrap_head_flags {
            match crate::flags::spells(f, raw, &vocab) {
                crate::flags::Spell::Yes(Some(v)) => return Some(crate::paths::unquote(&v).to_string()),
                crate::flags::Spell::Yes(None) => return args.get(i + 1).map(|v| crate::paths::unquote(v).to_string()),
                // Loud, like everywhere else: a refused abbreviation is not a
                // token that failed to be this flag, it is one vouch will not
                // guess about. Answering `None` here reaches the arm's
                // `wrap_unlocated`, which is the right sentence for it.
                crate::flags::Spell::RefusedAbbrev { .. } => return None,
                crate::flags::Spell::No => {}
            }
        }
    }
    let walk = operand_walk(prog, args, None, fork);
    if walk.unlocated.is_some() {
        return None;
    }
    walk.operand.map(|at| args[at].clone())
}

/// One `-ArgumentList` token into its items: the list is comma-separated and
/// each item may be quoted (`"-Command","Remove-Item …"`).
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',').map(|part| crate::paths::unquote(part.trim()).to_string()).filter(|p| !p.is_empty()).collect()
}

/// Every command an `after_exec` entry's declared flags introduce, plus a
/// detail line for each one whose terminator the walk never met.
///
/// EVERY occurrence, not just the first: `find d -exec echo x \; -exec rm -rf
/// d \;` runs two commands and only the first used to be judged. The flags
/// and the terminators both come from the entry (`wrap_exec_flags`,
/// `wrap_exec_terminators`) rather than from literals in this file.
fn after_exec_commands(prog: &Program, args: &[String]) -> (Vec<Cmd>, Vec<String>) {
    let case_sensitive = prog.case_sensitive_flags.unwrap_or(false);
    let mut found: Vec<Cmd> = Vec::new();
    let mut unlocated: Vec<String> = Vec::new();
    for (i, raw) in args.iter().enumerate() {
        let a = crate::paths::unquote(raw);
        if !declares(&prog.wrap_exec_flags, a, case_sensitive) {
            continue;
        }
        let rest: Vec<String> = args[i + 1..]
            .iter()
            .take_while(|t| !declares(&prog.wrap_exec_terminators, crate::paths::unquote(t), case_sensitive))
            .cloned()
            .collect();
        if rest.len() == args.len() - i - 1 {
            unlocated.push(format!(
                "`{a}` names a command that never reaches one of its terminators \
                 ({}), so vouch cannot tell where it ends",
                prog.wrap_exec_terminators.join(" ")
            ));
            continue;
        }
        match rest.split_first() {
            Some((h, rest_args)) => found.push(Cmd {
                head: h.clone(),
                args: rest_args.to_vec(),
                unread_args: Default::default(),
                keyword_args: Default::default(),
                callable_args: Default::default(),
                chain: None,
                prefix_assigns: vec![],
                receiver_origin: crate::syntax::ValueOrigin::Unknown,
                by_reference: false,
            }),
            None => unlocated.push(format!(
                "`{a}` is followed straight by its terminator, so vouch cannot tell what it \
                 was meant to run"
            )),
        }
    }
    (found, unlocated)
}

// ---------------------------------------------------------------------------
// The fork (spec §3.2): an undescribed flag makes the wrapped head ambiguous,
// and vouch judges BOTH readings rather than picking one.
// ---------------------------------------------------------------------------

/// One point where the walk could not tell which token the wrapped command
/// starts at, because a dash-led token in front of it is described by
/// neither of the entry's flag lists.
///
/// `factor` is how many readings the walk offered here — 2 for an ordinary
/// undescribed flag (it takes the next token as its value, or it takes none
/// and the next token is the command), 1 where the walk recorded a decision
/// point with no real choice in it. The engine enumerates the readings from
/// these and judges each one.
#[derive(Debug, Clone)]
pub struct ForkPoint {
    pub factor: usize,
    /// The undescribed token itself — what the prompt names.
    pub token: String,
    /// The program whose entry would describe it.
    pub program: String,
}

/// The choice vector ONE expansion pass runs under, and the fork points that
/// pass met.
///
/// Choices are consumed in visit order, so the same `picks` prefix always
/// selects the same readings: the walk is deterministic, and a pass that runs
/// past the end of `picks` takes reading 0 — the reading consistent with what
/// the entry's vocabulary actually says, since the vocabulary never claims
/// the undescribed flag takes a value. That makes the all-zero pass the one
/// whose reason speaks when every reading agrees (spec §3.2.2).
pub struct ForkCursor {
    picks: Vec<usize>,
    next: usize,
    points: Vec<ForkPoint>,
}

impl ForkCursor {
    pub fn new(picks: &[usize]) -> Self {
        Self { picks: picks.to_vec(), next: 0, points: Vec::new() }
    }

    /// Every fork point this pass met, in visit order.
    pub fn points(&self) -> &[ForkPoint] {
        &self.points
    }

    /// Record a decision point and answer which reading this pass takes.
    fn pick(&mut self, factor: usize, token: &str, program: &str) -> usize {
        let chosen = self.picks.get(self.next).copied().unwrap_or(0).min(factor.saturating_sub(1));
        self.points.push(ForkPoint { factor, token: token.to_string(), program: program.to_string() });
        self.next += 1;
        chosen
    }
}

/// Where the wrapped command's head sits in a rest wrapper's arguments, and
/// what the walk crossed to get there.
struct OperandWalk {
    /// Index in `args` of the first token the walk read as an operand — the
    /// wrapped head for `rest`, the script for `after_c`.
    operand: Option<usize>,
    /// Names bound by `NAME=value` prefix words the walk crossed.
    assigns: Vec<String>,
    /// Whether a declared wrap flag was seen (`after_c` only; the rest arm
    /// has no flag to look for).
    flag_seen: bool,
    /// Set when the walk could not say where the payload is.
    unlocated: Option<String>,
}

/// The one walk both operand-shaped arms share: cross this entry's own flags,
/// its declared leading data positionals, and any `NAME=value` prefix words,
/// and stop at the first token that is none of those.
///
/// `wrap_flag` is `Some` for `after_c`, where the payload is the first
/// OPERAND but only when the shell was actually told to read one — probed on
/// this machine: `bash -c -e 'echo x'` runs the string, so the script is not
/// `-c`'s own attached value.
///
/// An undescribed dash-led token forks (spec §3.2.2). Reading 0 treats it as
/// taking no value, which is what this entry's vocabulary implies by not
/// listing it; reading 1 treats the next token as its value. Both are judged
/// and the more restrictive verdict wins, so neither reading has to be right
/// for the answer to be safe.
fn operand_walk(prog: &Program, args: &[String], wrap_flag: Option<&[String]>, fork: &mut ForkCursor) -> OperandWalk {
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let name = prog.match_names.first().cloned().unwrap_or_default();
    let mut out = OperandWalk { operand: None, assigns: Vec::new(), flag_seen: false, unlocated: None };
    let mut leading = prog.leading_args.unwrap_or(0);
    let mut i = 0usize;
    while i < args.len() {
        let raw = args[i].as_str();
        let class = walk.next(raw);
        // A lone `-` is never a program name in any shell — it is `env`'s
        // "empty environment" spelling and, elsewhere, the standard-input
        // spelling. `crate::flags` reads it as `NotFlag` (nothing follows the
        // dash to match), so it would otherwise become the wrapped head.
        if raw == "-" {
            i += 1;
            continue;
        }
        if let Some(flags) = wrap_flag {
            for f in flags {
                let seen = matches!(crate::flags::spells(f, raw, &vocab), crate::flags::Spell::Yes(_))
                    || matches!(cluster_switch(prog, f, raw), ClusterHit::Yes);
                if seen {
                    out.flag_seen = true;
                }
                if matches!(cluster_switch(prog, f, raw), ClusterHit::Unreadable) {
                    out.unlocated = Some(format!(
                        "`{raw}` groups `{f}` with a letter `{name}`'s entry does not describe, \
                         so vouch cannot tell where the script begins"
                    ));
                    return out;
                }
            }
        }
        match class {
            crate::flags::Class::EndOfOptions => {}
            crate::flags::Class::Bool { .. } => {}
            crate::flags::Class::Value { attached: Some(_), .. } => {}
            crate::flags::Class::Value { attached: None, .. } => {
                if i + 1 >= args.len() {
                    out.unlocated = Some(format!(
                        "`{raw}` takes a value and there is nothing after it, so vouch cannot \
                         tell where `{name}`'s wrapped command begins"
                    ));
                    return out;
                }
                i += 1;
            }
            crate::flags::Class::Undescribed { .. } | crate::flags::Class::RefusedAbbrev { .. } => {
                if i + 1 >= args.len() {
                    // Nothing follows, so there is no reading in which a
                    // command begins — but the entry says this program wraps
                    // one, and the token in front of the gap is one vouch
                    // cannot read. Loud, not silent (spec §3.2 step 3).
                    out.unlocated = Some(format!(
                        "`{raw}` is not described for `{name}` and nothing follows it, so vouch \
                         cannot tell whether a command was wrapped at all"
                    ));
                    return out;
                }
                // Reading 0: the flag takes no value (what the vocabulary
                // implies). Reading 1: it takes the next token.
                if fork.pick(2, raw, &name) == 1 {
                    i += 1;
                }
            }
            crate::flags::Class::NotFlag => {
                // `FOO=1 cmd` — a prefix assignment, not the command.
                if raw.contains('=') {
                    if let Some((n, _)) = raw.split_once('=') {
                        let n = crate::paths::unquote(n);
                        if !n.is_empty() {
                            out.assigns.push(n.to_string());
                        }
                    }
                    i += 1;
                    continue;
                }
                // A declared leading DATA positional — `timeout`'s duration,
                // `chrt`'s priority. Replaces the duration-shaped guess.
                if leading > 0 {
                    leading -= 1;
                    i += 1;
                    continue;
                }
                out.operand = Some(i);
                return out;
            }
        }
        i += 1;
    }
    out
}

/// Scans a wrapped snippet in whatever language the entry declares, recording
/// its source text so the caller can also search it as a whole script rather
/// than as a bare list of program names. Extracted from the inline match the
/// `after_flag` arm used to run, so the `arg_<N>` arm can share it instead of
/// repeating the same three-way split.
///
/// Asks the registry (`syntax::scanner_for`) rather than hand-matching
/// language names: `"opaque"`, `"cmd"`, and any other name the registry does
/// not know (including the empty default an unset `wrap_lang` carries) are
/// all the SAME case — a language vouch has no parser for. The text is kept,
/// under its own real name, so the protected paths can still be searched for
/// inside it, but nothing else is claimed about it and it yields no
/// commands. This used to fall back to scanning the text as bash (M2.125) —
/// a silent laundering of unread code into "nothing objectionable found".
/// `scan_wrap_snippet`, the caller, is what turns this into the
/// `unreadable_language` construct rather than a silent miss.
///
/// `Ok` carries the commands found, plus that inner scan's OWN heredoc
/// records (so `go` can recurse into a heredoc nested inside this snippet —
/// without this, a heredoc inside a flag-carried or `-c` snippet vanishes at
/// the snippet boundary, both as a capture and as a marker). `Err((lang,
/// error))` when the registry has a scanner for this language but the text
/// did not parse — `lang` is the language actually scanned, so the reason it
/// drives names a setting that is really the decider.
fn scan_snippet(lang: &str, src: &str, srcs: &mut Vec<(String, String)>) -> Result<SnippetScan, (String, String)> {
    srcs.push((lang.to_string(), src.to_string()));
    let Some(scanner) = crate::syntax::scanner_for(lang) else {
        return Ok(SnippetScan::default());
    };
    scanner
        .scan(src)
        .map(|s| SnippetScan {
            cmds: s.commands,
            heredocs: s.heredocs,
            input_source: s.input_source,
            args_complete: s.args_complete,
            indexed_values: s.indexed_values,
            order: s.order,
            parsed: true,
        })
        .map_err(|e| (lang.to_string(), e))
}

/// What one snippet scan hands back to the wrapper walk: the commands it
/// found, plus the three per-command facts the walk has to carry across the
/// snippet boundary — the here-document records, and the two parallel arrays.
///
/// Every OTHER field of the inner scan is deliberately dropped here (the outer
/// text's own constructs, redirects and orders answer for the line), which is
/// exactly why these four have to be named: a Scan-parallel array that is not
/// in this struct does not survive the boundary, and the judgement that reads
/// it downstream would silently see nothing for every nested occurrence.
#[derive(Default)]
struct SnippetScan {
    cmds: Vec<Cmd>,
    heredocs: Vec<crate::syntax::Heredoc>,
    input_source: Vec<crate::syntax::InputSource>,
    args_complete: Vec<bool>,
    indexed_values: Vec<std::collections::HashMap<usize, crate::syntax::IndexedValueRef>>,
    order: Vec<crate::syntax::Order>,
    parsed: bool,
}

/// Connect scanner-reported indexed references to raw enclosing arguments
/// only when the program's knowledge entry declares that exact relationship.
/// The scanner remains context-free and the engine remains the sole resolver
/// of quotes, same-line assignments, and environment values.
fn join_snippet_args(
    prog: &Program,
    scan: &mut SnippetScan,
    source_spelling: Option<&str>,
    trailing: &[String],
    args_complete: bool,
    args_from_input: bool,
) {
    if !args_complete || args_from_input {
        return;
    }
    let Some(declarations) = prog.snippet_args.as_deref() else {
        return;
    };
    for (cmd_index, references) in scan.indexed_values.iter().enumerate() {
        let Some(cmd) = scan.cmds.get_mut(cmd_index) else {
            continue;
        };
        for (&arg_index, reference) in references {
            let Some(declaration) = declarations.iter().find(|declared| declared.name == reference.name) else {
                continue;
            };
            let value = if declaration.source_at == Some(reference.index) {
                source_spelling
            } else if reference.index >= declaration.trailing_from {
                trailing.get(reference.index - declaration.trailing_from).map(String::as_str)
            } else {
                None
            };
            let Some(value) = value else {
                continue;
            };
            let Some(argument) = cmd.args.get_mut(arg_index) else {
                continue;
            };
            if cmd.keyword_args.contains(&arg_index) {
                let Some((name, _)) = argument.split_once('=') else {
                    continue;
                };
                *argument = format!("{name}={value}");
            } else {
                *argument = value.to_string();
            }
            cmd.unread_args.remove(&arg_index);
        }
    }
}

/// Runs `scan_snippet` for one wrap site and reads back what it decided:
/// the commands found (empty, with the failure or the unreadable-language
/// construct recorded, on `Err` or on a language nothing can scan), the
/// language it actually used, and that inner scan's own heredoc records.
///
/// `scan_snippet` always pushes onto `srcs` before attempting the scan, in
/// both the `Ok` and `Err` paths, so `srcs.last()` is populated here
/// regardless of outcome — the `unwrap_or_else` fallback is defensive only,
/// never taken while that invariant holds.
///
/// A language the registry does not know (`opaque`, `cmd`, javascript, or a
/// value load-time validation should have refused) is pushed as
/// `unreadable_language` here rather than in `scan_snippet` — this is the
/// one place all three wrap sites share, so the construct lands the same way
/// whichever site raised it, and `scan_snippet` stays a pure "read this
/// text" function with no construct channel of its own.
///
/// Shared by the three sites below that hand a snippet to `scan_snippet` and
/// then need its answer folded back into `next_lang`/`inner_heredocs`: the
/// `after_flag` wrap arm, the `arg_<N>` wrap arm, and the heredoc locator —
/// they differ only in where the raw snippet text comes from.
fn scan_wrap_snippet(
    head: &str,
    wrap_lang: &str,
    src: &str,
    srcs: &mut Vec<(String, String)>,
    failures: &mut Vec<(String, String)>,
    constructs: &mut Vec<(String, String)>,
) -> (SnippetScan, String) {
    if crate::syntax::scanner_for(wrap_lang).is_none() {
        constructs.push((
            "unreadable_language".to_string(),
            format!(
                "`{head}` hands off a snippet in {wrap_lang}, a language vouch has no scanner \
                 for, so its contents were never read"
            ),
        ));
    }
    let result = scan_snippet(wrap_lang, src, srcs);
    let lang = srcs.last().map(|(l, _)| l.clone()).unwrap_or_else(|| wrap_lang.to_string());
    match result {
        Ok(scan) => (scan, lang),
        Err(e) => {
            failures.push(e);
            (SnippetScan::default(), lang)
        }
    }
}

/// Commands hidden inside wrapper programs, plus the originals.
///
/// `env rm -rf x` has head `env`; the real operation is in the arguments. Guards
/// match on head+argv, so without unwrapping, every wrapper is a way around
/// every guard. Recurses, with a depth cap so a pathological nest cannot hang
/// the gate. Keeps the built-in default cap (4) and drops the exceeded-depth
/// report — every caller of this three-argument form already ignores it.
///
/// No heredoc records: a bare command list carries no source text of its own
/// for the locator to find one attached to — callers that have a `Scan` (and
/// so a real `heredocs` list) use `expand_wrappers_with_sources` directly.
pub fn expand_wrappers(kb: &Knowledge, cmds: &[Cmd], lang: &str) -> Vec<Cmd> {
    expand_wrappers_with_sources(kb, cmds, &[], &[], &[], lang, &|_| 4).cmds
}

/// The same expansion, plus the LANGUAGE each expanded command is written in
/// and the raw source text of each wrapped snippet.
///
/// Guards only need the commands, but a snippet is a whole script: it can also
/// contain redirects and its own constructs. Returning the text lets the caller
/// scan it properly instead of seeing only the program names inside it.
///
/// A command unwrapped from `rest`/`after_exec` (`sudo rm -rf x`, `find -exec
/// rm {} ;`) is still written in whatever language the line around it was —
/// it never leaves the host syntax. A command that came out of a snippet in a
/// DIFFERENT language (`after_c`, `after_flag` — `bash -c "…"`, `powershell
/// -Command "…"`) carries THAT language instead, mirroring exactly the plang
/// each one pushes into `srcs`. Recognition and every per-program claim must
/// be looked up under this language, never the host's (spec §2): `sl` is a
/// dir-changer only in PowerShell, and a PowerShell snippet's `sl` on a bash
/// line has to be looked up as PowerShell or it silently stops being one.
///
/// `caps` resolves a language to how many layers of nesting are scanned
/// before recursion stops — the engine passes a closure reading the
/// operator's configured `lang.<name>.wrap_depth`, falling back to the
/// built-in default. A cap is a claim about how deep vouch actually looked,
/// so the returned fourth element names the LANGUAGE whose cap was reached
/// (first hit wins) rather than staying silent about it: the layers past the
/// cap are exactly the ones nothing scanned, so a caller that wants to keep
/// this from becoming a silent truncation folds `Some(lang)` into an ask
/// (M2.55).
///
/// What one wrapper expansion found. Named rather than a positional tuple
/// because two of its fields have the same type and only position told them
/// apart — the same reason `engine::Expanded` is a struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSite {
    /// Zero is the caller's command-line scope; successfully parsed snippets
    /// allocate child scopes in parent-before-child order.
    pub scope: usize,
    /// Scanner-supplied order inside this scope. `None` means wrapper
    /// expansion synthesized the occurrence and it only inherits its caller's
    /// position; that is not enough to make it a directory-mover event.
    pub local_order: Option<crate::syntax::Order>,
    /// True only when `local_order` came from the scanner for this exact
    /// occurrence. Synthesised wrapper commands inherit their caller's
    /// position for attribution, but that inherited position cannot prove a
    /// process-local directory change occurred in the caller's scope.
    pub scanner_order: bool,
}

pub struct ExpandedWrappers {
    /// Every occurrence: the top-level commands plus every command found
    /// inside a wrapper snippet or a consumed here-document body, in walk
    /// order.
    pub cmds: Vec<Cmd>,
    /// Parallel to `cmds`: parsed-snippet scope and local scanner order.
    pub execution_sites: Vec<ExecutionSite>,
    /// Parent command index for child scopes 1..N, in allocation order.
    pub scope_parents: Vec<usize>,
    /// Parallel to `cmds`: the language each occurrence was scanned under.
    pub langs: Vec<String>,
    /// Every `(language, source)` snippet the walk handed to a scanner.
    pub srcs: Vec<(String, String)>,
    /// The language whose nesting cap was reached, `None` if every layer was
    /// scanned (M2.55).
    pub wrap_depth_exceeded: Option<String>,
    /// Every `(lang, error)` a wrapped snippet failed to parse with (channel 1:
    /// a registry scanner exists for that language, but the text did not parse).
    pub parse_failures: Vec<(String, String)>,
    /// Parallel to `cmds`: whether vouch HOLDS the text of this occurrence's
    /// standard input — see `holds_input`. Read by the construct channel so a
    /// scanned body stops the ask that says the code is not in the command.
    pub holds_input: Vec<bool>,
    /// Parallel to `cmds`: whether this occurrence was produced by a wrapper
    /// that appends arguments from a channel the line never names
    /// (`args_from_input`). Its recorded arguments are therefore a partial
    /// record, and every judgement an appended token could change has to say
    /// so rather than answer from what it can see (M2.116).
    pub args_from_input: Vec<bool>,
    /// Parallel to `cmds`: whether this occurrence's recorded arguments are a
    /// faithful record of what the shell will pass — `Scan::args_complete`,
    /// carried across every wrapper boundary. A top-level occurrence takes
    /// the value the caller handed in; one unwrapped from a SNIPPET takes the
    /// inner scan's own; one unwrapped by a same-syntax token slice (`sudo`,
    /// `find -exec`, `Start-Process`) INHERITS the outer occurrence's, since
    /// its tokens are the outer command's tokens and no second scan produced
    /// them. Reading that last case as false instead would silently make
    /// every wrapper-nested spelling ineligible for the standalone arm.
    pub args_complete: Vec<bool>,
    /// Parallel to `cmds`: the directory a WRAPPER's own run-dir flag sent
    /// this occurrence to, unresolved. `env -C <dir> tar …` moves the inner
    /// `tar`, not just the `env` — the inner command carries no `-C` token of
    /// its own, so without this the place passes would judge it wherever the
    /// shell happened to be. `None` for a top-level command and for anything
    /// unwrapped by a wrapper with no run-dir flag on it.
    ///
    /// Innermost wins when wrappers nest: `env -C a env -C b cmd` places
    /// `cmd` at `b`. A relative inner value is then resolved by
    /// `engine::run_dir_place` against the line's own directory rather than
    /// against `a` — the composition of two nested relative run-dir flags is
    /// not modelled.
    pub inherited_run_dir: Vec<Option<String>>,
    /// Every `(key, detail)` construct the expansion walk itself raised —
    /// distinct from a command's or a snippet's own scanned constructs, and
    /// from `wrap_depth_exceeded` above (one cap-hit marker per line; this
    /// carries however many the walk found). The engine folds each pair
    /// through the same `construct_action_for`/`construct_reason` machinery
    /// as every other construct channel, attributed to the HOST language.
    ///
    /// Three producers live here: `wrap_unlocated` (an arm was told a
    /// payload exists and could not find it), `evaluated_input` (a wrap slot
    /// holds a marker, so the command string is known to exist and known to
    /// be unreadable), and `unreadable_language` (a located snippet — a wrap
    /// arm's payload or a consumed here-document — is in a language nothing
    /// can scan: `opaque`, `cmd`, or any other name outside the registry).
    pub constructs: Vec<(String, String)>,
}

/// Everything one `go` pass accumulates. A struct rather than eight more
/// `&mut` parameters: the recursion already carried fourteen, and four of
/// them had the same type, which is the shape where a mis-ordered call site
/// compiles and silently swaps two lists.
#[derive(Default)]
struct WalkOut {
    cmds: Vec<Cmd>,
    execution_sites: Vec<ExecutionSite>,
    scope_parents: Vec<usize>,
    langs: Vec<String>,
    holds: Vec<bool>,
    from_input: Vec<bool>,
    complete: Vec<bool>,
    inherited_run_dir: Vec<Option<String>>,
    srcs: Vec<(String, String)>,
    exceeded: Option<String>,
    failures: Vec<(String, String)>,
    constructs: Vec<(String, String)>,
}

#[allow(clippy::too_many_arguments)]
pub fn expand_wrappers_with_sources(
    kb: &Knowledge,
    cmds: &[Cmd],
    heredocs: &[crate::syntax::Heredoc],
    input_source: &[crate::syntax::InputSource],
    args_complete: &[bool],
    lang: &str,
    caps: &dyn Fn(&str) -> u8,
) -> ExpandedWrappers {
    expand_wrappers_forking(kb, cmds, heredocs, input_source, args_complete, lang, caps, &mut ForkCursor::new(&[]))
}

/// The same expansion, run under ONE reading of every ambiguous wrapper.
///
/// `fork` carries the choice vector in and the fork points it met back out.
/// A caller that hands over an empty vector gets the reading each entry's own
/// vocabulary implies — which is what every non-deciding caller wants, and
/// what `expand_wrappers_with_sources` above passes. The engine hands over a
/// real vector, once per reading, and judges each expansion separately (spec
/// §3.2.2): two readings that agree are that answer, and two that disagree
/// resolve to the more restrictive one.
#[allow(clippy::too_many_arguments)]
pub fn expand_wrappers_forking(
    kb: &Knowledge,
    cmds: &[Cmd],
    heredocs: &[crate::syntax::Heredoc],
    input_source: &[crate::syntax::InputSource],
    args_complete: &[bool],
    lang: &str,
    caps: &dyn Fn(&str) -> u8,
    fork: &mut ForkCursor,
) -> ExpandedWrappers {
    #[allow(clippy::too_many_arguments)]
    fn go(
        kb: &Knowledge,
        cmds: &[Cmd],
        heredocs: &[crate::syntax::Heredoc],
        input_source: &[crate::syntax::InputSource],
        args_complete: &[bool],
        lang: &str,
        scope: usize,
        orders: &[crate::syntax::Order],
        inherited_order: Option<&crate::syntax::Order>,
        depth: u8,
        caps: &dyn Fn(&str) -> u8,
        inherited: Option<&str>,
        // Whether the commands in `cmds` came from a wrapper that appends
        // arguments from a channel the line never names. Carried down the
        // recursion rather than recomputed, because it is a property of the
        // path that REACHED these commands, not of the commands themselves:
        // `echo f | xargs env prog` leaves `prog` just as un-recorded as
        // `xargs prog` does.
        from_input: bool,
        fork: &mut ForkCursor,
        out: &mut WalkOut,
    ) {
        // Reaching the cap is an ASK, never a silent truncation (M2.55): the
        // layers past it are exactly the ones nobody scanned. One event per
        // command — vouch is static and decides once, so only the FIRST
        // language to hit its own cap is kept.
        if depth > caps(lang) {
            if out.exceeded.is_none() {
                out.exceeded = Some(lang.to_string());
            }
            return;
        }
        for (i, cmd) in cmds.iter().enumerate() {
            // This occurrence's own facts, read positionally with a fail-closed
            // default: a short or absent array must degrade to asking, never to
            // reading a neighbour's answer. Hoisted above the pushes so the
            // completeness vector is filled in the same place as its siblings —
            // a parallel array populated somewhere else is the desync this
            // block's own comment warns about.
            let own_args_complete = args_complete.get(i).copied().unwrap_or(false);
            let own_order = orders.get(i).or(inherited_order).cloned();
            out.cmds.push(cmd.clone());
            out.execution_sites.push(ExecutionSite {
                scope,
                local_order: own_order.clone(),
                scanner_order: orders.get(i).is_some(),
            });
            out.langs.push(lang.to_string());
            // Pushed WITH the command, false for now, and back-patched by the
            // heredoc locator at the end of this iteration. The index has to be
            // captured here: the wrapper loop below pushes arbitrarily many
            // further commands, so appending at the locator would land the
            // judgement on someone else's occurrence — and a desynced parallel
            // array does not fail loudly, it silently misattributes.
            out.holds.push(false);
            out.from_input.push(from_input);
            out.complete.push(own_args_complete);
            out.inherited_run_dir.push(inherited.map(str::to_string));
            let self_idx = out.cmds.len() - 1;
            // Where a WRAPPER's own run-dir flag sends everything it wraps.
            // Read once per command rather than per matching entry, since the
            // flag is a property of the command line, not of one entry.
            let own_run_dir = match run_dir_with_flag_in(kb, cmd, lang) {
                (RunDir::Dir(d), _) => Some(d),
                _ => None,
            };
            let pass_down = own_run_dir.as_deref().or(inherited);
            // The same positional read with the same fail-closed default, for
            // the fact the synthesising wrap arms deliberately leave empty (an
            // unscanned here-document body is not this command's input).
            let own_source = input_source.get(i).cloned().unwrap_or(crate::syntax::InputSource::Unknown);
            let head = base(&cmd.head);
            for prog in &kb.program {
                if !receiver_gate_holds(kb, prog, &cmd.receiver_origin) {
                    continue;
                }
                // Name lookup only, not `entries_for` — that also filters by
                // language, which would add a language decision to wrapper
                // lookup this refactor must not make.
                if !prog.match_names.iter().any(|n| Program::same_name(n, &head)) {
                    continue;
                }
                // The language the WRAPPED snippet is written in — `lang`
                // (this command's own) unless the wrap crosses into another
                // scanner entirely, exactly where `srcs` gets its plang.
                let mut next_lang = lang.to_string();
                // What this wrap arm found, as ONE value: the commands plus the
                // three per-command facts that have to cross the snippet
                // boundary with them. Kept grouped rather than unpacked into
                // parallel locals — that unpacking is the hazard `SnippetScan`
                // exists to remove, and the next fact added to a scan would
                // otherwise need a new local in every arm.
                //
                // The three arms that SYNTHESISE a command rather than scanning
                // text leave the two INPUT facts empty on purpose:
                // `sudo python - <<'EOF'` attaches its here-document to `sudo`,
                // so the body is never scanned, and letting the unwrapped
                // `python -` inherit the wrapper's answer would suppress the one
                // ask that speaks for that shape.
                //
                // `args_complete` is the opposite case and those arms DO fill
                // it, with the outer occurrence's own value. Their tokens are
                // the outer command's tokens — a slice, not a fresh scan — so
                // whatever the parser dropped from the outer record is dropped
                // from theirs too, and whatever it kept it kept. Leaving it
                // empty would read as "incomplete" for every same-syntax
                // wrapper, which is not a fail-closed default here but a wrong
                // answer about a record nothing re-read.
                let inner: SnippetScan = match prog.wraps.as_str() {
                    "rest" => {
                        // The wrapped command starts at the first token that is
                        // not one of this entry's own flags, not one of its
                        // declared leading data positionals, and not a
                        // `NAME=value` prefix word. An undescribed dash-led
                        // token in front of it forks (spec §3.2.2) rather than
                        // being skipped on the guess that it takes no value.
                        let walk = operand_walk(prog, &cmd.args, None, fork);
                        match (walk.operand, walk.unlocated) {
                            (_, Some(detail)) => {
                                out.constructs.push(("wrap_unlocated".to_string(), detail));
                                SnippetScan::default()
                            }
                            (Some(at), None) => SnippetScan {
                                cmds: vec![Cmd {
                                    head: cmd.args[at].clone(),
                                    args: cmd.args[at + 1..].to_vec(),
                                    unread_args: Default::default(),
                                    keyword_args: Default::default(),
                                    callable_args: Default::default(),
                                    chain: None,
                                    // The env words this wrapper set for the
                                    // command it runs are that command's own
                                    // prefix assignments — `env FOO=1 prog` and
                                    // `FOO=1 prog` bind the same name.
                                    prefix_assigns: walk.assigns,
                                    receiver_origin: crate::syntax::ValueOrigin::Unknown,
                                    by_reference: false,
                                }],
                                args_complete: vec![own_args_complete],
                                ..SnippetScan::default()
                            },
                            (None, None) => SnippetScan::default(),
                        }
                    }
                    "after_c" => {
                        // A shell takes its script as the FIRST OPERAND after
                        // option parsing, not as `-c`'s own attached value —
                        // probed on this machine: `bash -c -e 'echo x'`,
                        // `bash -lc -x 'echo x'` and `bash -cx 'echo x'` all run
                        // the string. So the locator asks two separate
                        // questions: was the shell told to read a script, and
                        // where does the first operand sit.
                        let walk = operand_walk(prog, &cmd.args, Some(&prog.wrap_flags), fork);
                        match (walk.flag_seen, walk.operand, walk.unlocated) {
                            (_, _, Some(detail)) => {
                                out.constructs.push(("wrap_unlocated".to_string(), detail));
                                SnippetScan::default()
                            }
                            // No wrap flag at all: a bare shell, or one handed a
                            // script FILE. Genuinely wraps nothing here — the
                            // entry's `evaluates_input` claim speaks for the
                            // first and the file for the second.
                            (false, _, None) => SnippetScan::default(),
                            (true, None, None) => {
                                out.constructs.push((
                                    "wrap_unlocated".to_string(),
                                    format!(
                                        "`{}` was told to read a script and none of its arguments \
                                         is one, so the code it runs is not in this command",
                                        cmd.head
                                    ),
                                ));
                                SnippetScan::default()
                            }
                            (true, Some(at), None) => {
                                // The snippet is a whole script, carrying one
                                // layer of shell quoting the parser kept in the
                                // word value — `unquote_snippet` strips it and
                                // resolves the escapes that layer implies, the
                                // same rule `after_flag` uses below (one
                                // unescape rule, one place).
                                let inner_src = crate::paths::unquote_snippet(&cmd.args[at]);
                                next_lang = "bash".to_string();
                                match scan_snippet("bash", &inner_src, &mut out.srcs) {
                                    Ok(scan) => scan,
                                    Err(e) => {
                                        out.failures.push(e);
                                        SnippetScan::default()
                                    }
                                }
                            }
                        }
                    }
                    // One shell invoking another: `powershell -Command "..."`.
                    // The snippet is in a DIFFERENT language, so it must be
                    // scanned by that language's scanner or it is invisible.
                    "after_flag" => match locate_after_flag(prog, &cmd.args) {
                        Payload::Found(found) => {
                            let (mut scan, lang) = scan_wrap_snippet(
                                &cmd.head,
                                &prog.wrap_lang,
                                &found.source,
                                &mut out.srcs,
                                &mut out.failures,
                                &mut out.constructs,
                            );
                            join_snippet_args(
                                prog,
                                &mut scan,
                                Some(&found.source_spelling),
                                &found.trailing,
                                own_args_complete,
                                from_input,
                            );
                            next_lang = lang;
                            scan
                        }
                        Payload::Unlocated(detail) => {
                            out.constructs.push(("wrap_unlocated".to_string(), detail));
                            SnippetScan::default()
                        }
                        Payload::Absent => SnippetScan::default(),
                    },
                    // `python:os.system`/`.popen`-shaped calls: the wrapped
                    // snippet is one of THIS call's own arguments rather than
                    // a flag's value. A token still holding an unresolved
                    // marker — `python::MARKER` (an ordinary unresolvable
                    // value) or `python::UNPACK_MARKER` (a nameless `**`
                    // unpack, e.g. `os.system(**opts)`) — is not text vouch
                    // has. That is `evaluated_input` exactly: the command
                    // string is known to EXIST and known to be unreadable,
                    // which is not the same as an empty scan (M2.123).
                    s if s.starts_with("arg_") => {
                        match s.strip_prefix("arg_").and_then(|n| n.parse::<usize>().ok()).and_then(|i| cmd.args.get(i))
                        {
                            Some(v) if !is_unresolved_marker(v) => {
                                let (scan, lang) = scan_wrap_snippet(
                                    &cmd.head,
                                    &prog.wrap_lang,
                                    v,
                                    &mut out.srcs,
                                    &mut out.failures,
                                    &mut out.constructs,
                                );
                                next_lang = lang;
                                scan
                            }
                            Some(_) => {
                                out.constructs.push((
                                    "evaluated_input".to_string(),
                                    format!(
                                        "`{}` is handed a command string vouch could not read the \
                                     value of",
                                        cmd.head
                                    ),
                                ));
                                SnippetScan::default()
                            }
                            // The declared position is not there at all: the call
                            // wraps nothing, which is a fact about the call rather
                            // than a miss.
                            None => SnippetScan::default(),
                        }
                    }
                    // `Start-Process powershell -ArgumentList "-Command","…"`.
                    // The arguments are the list parameter's items and the
                    // program is either a declared head flag's value
                    // (`-FilePath pwsh`) or the first positional, so rebuild
                    // that command and let the normal expansion handle it —
                    // the powershell/cmd entries already know what to do
                    // with it.
                    //
                    // The LIST is asked for first, and it is what decides
                    // whether this invocation wraps anything at all. Asking
                    // for the program first (fix round 1) made a located list
                    // unreachable whenever the program was not a positional:
                    // the walk consumed `-FilePath`'s value as an ordinary
                    // flag value, found no operand, and the arm reported
                    // "wrapped nothing" while the declared wrap flag sat in
                    // the command with a payload in it. A located list vouch
                    // cannot attach a program to is `wrap_unlocated` — never
                    // wrapped-nothing, which is the one answer §3.1 says this
                    // arm must stop being able to give.
                    "start_process" => match start_process_args(prog, &cmd.args) {
                        ListPayload::Unlocated(detail) => {
                            out.constructs.push(("wrap_unlocated".to_string(), detail));
                            SnippetScan::default()
                        }
                        // No declared list parameter anywhere: this really is
                        // a `Start-Process` that hands its program nothing.
                        ListPayload::Absent => SnippetScan::default(),
                        ListPayload::Found(args) => {
                            match (start_process_head(prog, &cmd.args, fork), args.is_empty()) {
                                (Some(head), false) => SnippetScan {
                                    cmds: vec![Cmd {
                                        head,
                                        args,
                                        unread_args: Default::default(),
                                        keyword_args: Default::default(),
                                        callable_args: Default::default(),
                                        chain: None,
                                        prefix_assigns: vec![],
                                        receiver_origin: crate::syntax::ValueOrigin::Unknown,
                                        by_reference: false,
                                    }],
                                    args_complete: vec![own_args_complete],
                                    ..SnippetScan::default()
                                },
                                (None, _) => {
                                    out.constructs.push((
                                        "wrap_unlocated".to_string(),
                                        format!(
                                            "`{}` carries an argument list and vouch could not \
                                             tell which program it starts",
                                            cmd.head
                                        ),
                                    ));
                                    SnippetScan::default()
                                }
                                (Some(_), true) => {
                                    out.constructs.push((
                                        "wrap_unlocated".to_string(),
                                        format!(
                                            "`{}` names an argument list with no items vouch \
                                             could read",
                                            cmd.head
                                        ),
                                    ));
                                    SnippetScan::default()
                                }
                            }
                        }
                    },
                    "after_exec" => {
                        let (found, unlocated) = after_exec_commands(prog, &cmd.args);
                        for detail in unlocated {
                            out.constructs.push(("wrap_unlocated".to_string(), detail));
                        }
                        let complete = vec![own_args_complete; found.len()];
                        SnippetScan { cmds: found, args_complete: complete, ..SnippetScan::default() }
                    }
                    _ => SnippetScan::default(),
                };
                if !inner.cmds.is_empty() {
                    let (inner_scope, inner_orders, inherited_inner_order, inner_run_dir) =
                        if inner.parsed {
                            let child_scope = out.scope_parents.len() + 1;
                            out.scope_parents.push(self_idx);
                            // The child scope starts in this occurrence's run
                            // place. Reapplying that inherited directory to
                            // every command inside the child would erase a
                            // process-local directory change after it ran.
                            (child_scope, inner.order.as_slice(), None, None)
                        } else {
                            (scope, &[][..], own_order.as_ref(), pass_down)
                        };
                    go(
                        kb,
                        &inner.cmds,
                        &inner.heredocs,
                        &inner.input_source,
                        &inner.args_complete,
                        &next_lang,
                        inner_scope,
                        inner_orders,
                        inherited_inner_order,
                        depth + 1,
                        caps,
                        inner_run_dir,
                        from_input || prog.args_from_input,
                        fork,
                        out,
                    );
                }
            }
            // The heredoc locator. Lives HERE, inside the same recursion that
            // unwraps every other kind of wrapper, so a consumed body's
            // commands go through the identical judged path (recognition,
            // guards, writes — the engine's own snippet loop below never
            // merges commands, only constructs) and share the ONE depth
            // counter with every other snippet kind; a parse failure gets
            // channel 1 for free via `scan_snippet`/`failures`.
            //
            // Independent of the `for prog` loop above: `heredoc_feeds` does
            // its own entry lookup, so a command can be both a `wraps`-based
            // wrapper AND (separately) a heredoc consumer.
            //
            // Consumption is decided ONCE per attached record, here, and the
            // verdicts are what the judgement's sibling rule reads: asking
            // `heredoc_feeds` again per sibling would walk the knowledge a
            // second time for records this loop already judged, and would put a
            // second site in charge of "was this sibling consumed".
            let attached: Vec<&crate::syntax::Heredoc> = heredocs.iter().filter(|h| h.cmd_index == i).collect();
            let consumption: Vec<Option<(&Program, &str)>> =
                attached.iter().map(|h| heredoc_feeds(kb, cmd, h)).collect();
            for (nth, heredoc) in attached.iter().enumerate() {
                if let Some((entry, entry_lang)) = consumption[nth] {
                    let held = own_source == crate::syntax::InputSource::Heredoc(heredoc.id)
                        && holds_input(
                            cmd,
                            own_args_complete,
                            from_input,
                            lang,
                            &attached,
                            &consumption,
                            nth,
                            entry,
                        );
                    // Shares `scan_wrap_snippet` with the wrap arms above: an
                    // empty or unregistered `entry_lang` raises
                    // `unreadable_language` there, same as they do, so the
                    // language actually scanned is read back here too rather
                    // than re-derived.
                    let (mut scan, consumed_lang) = scan_wrap_snippet(
                        &cmd.head,
                        &entry_lang,
                        &heredoc.body,
                        &mut out.srcs,
                        &mut out.failures,
                        &mut out.constructs,
                    );
                    // The judgement, back-patched on EXACTLY the iteration whose
                    // record is the one the input source names — never on
                    // whichever sibling the loop happens to be on. Two
                    // here-documents can both be consumed while only the second
                    // is delivered, and the first can be verbatim while the
                    // second is not; judging on the loop variable would hold a
                    // command whose delivered text differs from the text that
                    // was scanned, with no other channel speaking.
                    //
                    // Compared by IDENTITY (`heredoc.id`), never by `nth`: `nth`
                    // is this record's position in `attached` — this command's
                    // own FILTERED list — while `own_source` was resolved
                    // against whichever list produced it, which for a record
                    // reached through a nested snippet is that snippet's own
                    // fresh `heredocs`, not `attached`. The two numbering
                    // schemes only ever coincided by accident (no preceding
                    // sibling); an id never has to coincide, because it is not
                    // a position in either list (M2.127).
                    if held {
                        out.holds[self_idx] = true;
                        let (source_spelling, trailing) = if cmd.args.first().is_some_and(|arg| arg == "-") {
                            (Some("-"), &cmd.args[1..])
                        } else {
                            (None, &[][..])
                        };
                        join_snippet_args(
                            entry,
                            &mut scan,
                            source_spelling,
                            trailing,
                            own_args_complete,
                            from_input,
                        );
                    }
                    if !scan.cmds.is_empty() {
                        let child_scope = out.scope_parents.len() + 1;
                        out.scope_parents.push(self_idx);
                        go(
                            kb,
                            &scan.cmds,
                            &scan.heredocs,
                            &scan.input_source,
                            &scan.args_complete,
                            &consumed_lang,
                            child_scope,
                            &scan.order,
                            None,
                            depth + 1,
                            caps,
                            None,
                            from_input,
                            fork,
                            out,
                        );
                    }
                }
            }
        }
    }
    let mut walked = WalkOut::default();
    go(
        kb,
        cmds,
        heredocs,
        input_source,
        args_complete,
        lang,
        0,
        &[],
        None,
        0,
        caps,
        None,
        false,
        fork,
        &mut walked,
    );
    ExpandedWrappers {
        cmds: walked.cmds,
        execution_sites: walked.execution_sites,
        scope_parents: walked.scope_parents,
        langs: walked.langs,
        srcs: walked.srcs,
        wrap_depth_exceeded: walked.exceeded,
        parse_failures: walked.failures,
        holds_input: walked.holds,
        args_from_input: walked.from_input,
        args_complete: walked.complete,
        inherited_run_dir: walked.inherited_run_dir,
        constructs: walked.constructs,
    }
}

/// What `written_paths` found, plus the two things a plain `Vec<String>`
/// could not say: that the destination IS the run directory, and that vouch
/// hit something it could not classify while walking for one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteTargets {
    /// Destination paths named explicitly in the command.
    pub paths: Vec<String>,
    /// A `sub_write.takes = "run_dir"` entry matched with zero positional
    /// destinations after it — the command writes wherever it runs, not to a
    /// path named in the command. Resolving that directory (the run-dir
    /// flag's value, cd state, or the hook's cwd) is the engine's job.
    pub run_dir_dest: bool,
    /// A token after a MATCHED sub_write subcommand that starts with this
    /// program's flag prefix and is named in neither `value_options` nor
    /// `no_value_options`. vouch cannot tell whether it consumes the token
    /// after it, so it cannot trust the positional count or order from that
    /// point on — the offending token is recorded here and no destination is
    /// guessed for that subcommand.
    pub unknowable: Vec<String>,
}

/// Whether any `[[program.here_write]]` claim on `prog` matches this command:
/// its flag conditions hold, its subcommand (if it names one) is the one
/// being run, and its operand count (if it names one) is what the command
/// has. Every condition an entry states must hold; conditions it leaves out
/// say nothing.
///
/// Flags are matched through the shared primitive, so an attached or
/// abbreviated spelling of `-C` counts as naming a destination exactly as
/// the write derivation counts it — a rule that read raw tokens here would
/// answer "no destination named" for `tar -xf a.tar -C./d` and claim the run
/// place for a command that states its own.
fn here_write_applies(prog: &Program, cmd: &Cmd, lang: &str, operands: &[&String]) -> bool {
    if prog.here_write.is_empty() {
        return false;
    }
    let vocab = crate::flags::vocab_for(prog, wrap_abbrev(prog));
    let present = |flags: &[String]| {
        flags.iter().any(|f| {
            cmd.args.iter().any(|raw| {
                matches!(crate::flags::spells(f, raw, &vocab), crate::flags::Spell::Yes(_))
                    || matches!(cluster_switch(prog, f, raw), ClusterHit::Yes)
                    || cluster_value(prog, f, raw).is_some()
            })
        })
    };
    // Tokens this entry's vocabulary cannot read at all. A mixed cluster is
    // the ordinary case here (`tar -xf`, where the last letter takes the
    // value), so their mere presence cannot withhold the claim — but one of
    // them may be HIDING an `unless_flag`, and that is the question the claim
    // depends on.
    let mut walk = crate::flags::ArgWalk::new(&vocab);
    let unreadable: Vec<&String> = cmd
        .args
        .iter()
        .filter(|raw| {
            matches!(
                walk.next(raw),
                crate::flags::Class::Undescribed { .. } | crate::flags::Class::RefusedAbbrev { .. }
            )
        })
        .collect();
    // Could an unreadable token be carrying this flag? For a bundled short
    // flag that is a letter test (`-qO-` carries `-O`), for a long flag a
    // prefix test. Case follows the entry's own rule (§7) — reading `-c` as
    // `-C` on a case-sensitive unix entry is the misread that rule exists
    // for. Deliberately generous: a false MAYBE only withholds a claim,
    // while a false NO would assert a write the command does not make.
    let could_hide = |flags: &[String]| {
        let cs = prog.case_sensitive_flags.unwrap_or(false);
        flags.iter().any(|f| {
            unreadable.iter().any(|raw| {
                let (t, f) = if cs {
                    ((*raw).clone(), f.clone())
                } else {
                    (raw.to_lowercase(), f.to_lowercase())
                };
                if f.starts_with("--") {
                    t.starts_with(&f)
                } else {
                    f.chars().nth(1).is_some_and(|c| t.trim_start_matches('-').contains(c))
                }
            })
        })
    };
    prog.here_write.iter().any(|hw| {
        let when_ok = hw.when_flags.is_empty() || present(&hw.when_flags);
        let unless_ok = !present(&hw.unless_flags) && !could_hide(&hw.unless_flags);
        let sub_ok = match &hw.subcommand {
            Some(want) => subcommand(cmd, &vocab, lang).is_some_and(|s| s == want),
            None => true,
        };
        let arity_ok = hw.operands.is_none_or(|n| operands.len() == n);
        when_ok && unless_ok && sub_ok && arity_ok
    })
}

/// Walk the tokens AFTER a matched sub_write subcommand (and, when `then` is
/// set, after that second word too): consume each `value_options` flag's
/// value, skip each `no_value_options` flag, collect everything else that
/// starts with a flag prefix as `unknowable`, and everything else again as a
/// positional.
///
/// The caller supplies the same language-scoped, name-wide vocabulary used
/// to locate the verb. `then_of_in` and `sub_write` therefore cannot disagree
/// because a flag claim lives on a sibling entry or because file order changed.
///
/// Reads the shared flag primitive (`crate::flags`), not a private
/// exact-string split (M2.128): `git clone url -C=/tmp /x` used to read
/// `-C=/tmp` as an undescribed token (the naive split only recognised `=` on
/// the flag's OWN spelling, never a short-attached or colon-attached form),
/// asking on a shape `spells` already knows how to classify. `ArgWalk`
/// carries the one thing a single-token classification cannot: whether `--`
/// has already ended flag scanning for the rest of the vector (§4.1.4) — a
/// token after `--` reads as a plain positional even if it is flag-shaped.
///
/// An attached-value token (`--depth=1`, one token) is self-contained when
/// its flag half — before the `=` — is described by either list: it consumes
/// nothing further and is neither a positional nor unknowable. An attached
/// value on an UNDESCRIBED flag is unknowable, fail-closed either way (the
/// alternative, treating it as a plain positional, would be a silent guess
/// about a shape vouch was never told about). A `Class::RefusedAbbrev`
/// candidate (under a case-sensitive name-wide grammar, spec §4.1.7) is
/// unknowable too, for the same reason: silently accepting or silently
/// dropping it would both be a guess this walk exists to refuse.
fn walk_post_subcommand<'a>(args: &'a [String], vocab: &crate::flags::Vocab) -> (Vec<&'a String>, Vec<String>) {
    let mut walk = crate::flags::ArgWalk::new(vocab);
    let mut positionals: Vec<&String> = Vec::new();
    let mut unknowable: Vec<String> = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        match walk.next(a) {
            crate::flags::Class::NotFlag => positionals.push(a),
            crate::flags::Class::EndOfOptions => {}
            crate::flags::Class::Value { attached: None, .. } => skip_next = true,
            crate::flags::Class::Value { attached: Some(_), .. } => {}
            crate::flags::Class::Bool { .. } => {}
            crate::flags::Class::Undescribed { token } => unknowable.push(token),
            crate::flags::Class::RefusedAbbrev { token, .. } => unknowable.push(token),
        }
    }
    (positionals, unknowable)
}

/// Rule 7 (spec §4): case-insensitive only when the entry says so; either way
/// this is EXACT-string comparison — a prefix never matches, and neither does
/// an attached form. `written_paths` and `engine::dir_change_candidates` both
/// used to carry their own identical copy of this before migrating onto the
/// shared flag primitive (tasks 6 and 7) — this whole-token comparison is
/// exactly the gap that migration closed (M2.128). What is left here is the
/// pre-primitive comparison itself, still read by
/// `examples/count_boundary_shapes.rs`'s own measurement of how many rows an
/// attached or abbreviated spelling would have newly matched.
pub fn flag_matches(list: &[String], token: &str, case_sensitive: bool) -> bool {
    list.iter().any(|f| {
        if case_sensitive {
            f == token
        } else {
            f.eq_ignore_ascii_case(token)
        }
    })
}

/// `sub_write.takes = "url_basename"`: the directory name a bare `git clone
/// <url>` creates, derived from the URL itself — its last `/`- or
/// `:`-segment with a trailing `.git` stripped. A URL that ends in a
/// separator right before `.git` (`.../repo/.git`) strips to an EMPTY last
/// segment — real git does not create a directory called nothing, it backs
/// up to the segment before (`repo`), so this walks backward through
/// segments until one survives the strip non-empty, rather than stopping at
/// the first (verified against git's own behaviour: reviewed 2026-08-06).
/// Returns `None` only when every segment strips to empty, which the caller
/// reads as "derive no destination" rather than guess.
fn url_basename(spec: &str) -> Option<String> {
    let s = spec.trim_end_matches('/');
    for seg in s.rsplit(['/', ':']) {
        let name = seg.strip_suffix(".git").unwrap_or(seg);
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
}

/// True when a python call's own head is method-shaped (`python:.chmod`,
/// receiver in position 0) rather than module- or builtin-shaped
/// (`python:os.chmod`, `python:open`) — the `:` language prefix is
/// immediately followed by a `.`.
///
/// Read per OCCURRENCE from `cmd.head`, never from the matched entry's
/// `match_names`: an entry can list both shapes at once (the shipped chmod
/// entry matches both `python:os.chmod` and `python:.chmod`), and only the
/// occurrence's own head says which shape THAT call actually took.
fn head_is_method_shaped(head: &str) -> bool {
    head.contains(":.")
}

/// Whether `a` is EITHER unresolved-value marker python.rs can push —
/// `MARKER` (an ordinary unresolvable value: an attribute access, a nested
/// call, an argument the walk could not name) or `UNPACK_MARKER` (a
/// nameless `**` keyword-unpack). Every site that only needs "is this text
/// I actually have, or a stand-in for something I don't" reads through this
/// rather than comparing against `MARKER` alone — comparing against `MARKER`
/// alone is only correct where the CALLER specifically means "an ordinary
/// unresolved value, as opposed to an unpack" (there is exactly one such
/// site: `guards::callback_argument_used`, which needs the unpack read
/// SEPARATELY, never folded into "unresolved value in general").
fn is_unresolved_marker(a: &str) -> bool {
    a == crate::python::MARKER || a == crate::python::UNPACK_MARKER
}

/// What `effective_args` pushes into a GAP — a position between two folded
/// positions that no token in the call ever addressed at all, positional or
/// keyword (task 2b fix round 4). Distinct from `python::MARKER` on
/// purpose: `MARKER` means "the call gave a value here and vouch could not
/// read it"; this means "the call never gave anything here at all" — the
/// two need different answers from `mode_says_write` (a genuinely ABSENT
/// mode is python's documented read default; an unreadable one cannot rule
/// out a write) and from `callback_argument_used`'s rule 1 (a genuinely
/// untouched callback slot must not read as occupied). Found live:
/// `open("f.txt", encoding="utf-8")` — a single-file text read, `mode`
/// never mentioned — used to correctly Allow via the genuinely-absent
/// reading; once `open`'s `arg_names` was extended to name `opener`
/// (needed to detect it positionally at all), folding `encoding` onto ITS
/// position padded straight through `mode`'s with the SAME marker an
/// unreadable value would leave, and the call started asking about a write
/// that was never there. This constant is guards.rs-internal — unlike
/// `MARKER`/`UNPACK_MARKER`, `src/python.rs`'s scanner never produces it;
/// it exists only inside this folding step.
///
/// Spelling, checked against `paths::expand_env_with`'s own grammar (task
/// 2b fix round 5): that function accepts `[A-Za-z0-9_]` as a `$NAME`
/// reference, so the first spelling tried here, `"$_"`, was a LEGAL
/// environment-variable name — a padded write-target position could expand
/// against the real process environment before the "still contains `$`"
/// fail-closed check downstream ever ran, verified live by the reviewer:
/// unset, the call asked (looked safe); set to an ordinary value, the
/// prompt named a fabricated, unrelated real path; set to a path inside an
/// allowed area, the call ALLOWED. A comma is not a name character in that
/// grammar (`is_name` there is `is_ascii_alphanumeric() || '_'`), so `$,`
/// is rejected at the first character after `$` exactly the way `$?` and
/// `$**` already are — same read as `$?`'s own doc comment: a value that
/// stops mattering, only spelled to evoke a skipped slot in a list rather
/// than an unresolved value or an unpacking.
///
/// That spelling argument is now BELT-AND-BRACES, and saying so is the
/// point (final review 2026-08-10, minor 3). Fix round 5 moved occupancy
/// onto the `padding` index set, so no occupancy check reads this text at
/// all; the environment-expansion hazard the paragraph above describes is
/// closed by the index tracking regardless of how the token is spelled.
/// One reader is left: `push_write_target` normalises this text to
/// `MARKER`, which matters only for the `named` / `flags_only` /
/// `of_prefix` write arms — they iterate `eff` directly and never consult
/// the index set, and no shipped python entry uses them. Keep the spelling
/// grammar-safe anyway: the two defences are deliberately independent, and
/// the second one existing is not a reason to weaken the first.
const PADDING_MARKER: &str = "$,";

/// Whether `eff[i]` is a REAL occupant — something a token in the call
/// actually addressed, whether resolved or not — as opposed to a gap
/// `effective_args` filled only to reach a LATER position. `None` (past the
/// end of `eff` entirely) and an index `effective_args` recorded in `padding`
/// both mean "nothing here"; only a genuine value, including the ordinary
/// unresolved marker, means "something here, unreadable or not."
///
/// Reads `padding` — the index set `effective_args` returns alongside `eff` —
/// rather than comparing `eff[i]` against `PADDING_MARKER`'s text (task 2b
/// fix round 5): seeing its own OWN doc comment for why a text comparison
/// is unsafe (a real argument can legally equal any fixed marker
/// spelling). `i` past the end of `padding`'s own range is simply absent
/// from the set, so `None` and a real, unpadded index both fall through to
/// the same `contains` check correctly.
fn eff_position_occupied(eff: &[String], padding: &HashSet<usize>, i: usize) -> bool {
    eff.get(i).is_some() && !padding.contains(&i)
}

/// Whether `v` is ANY internal sentinel `src/python.rs`'s scanner or this
/// module's own folding step can produce — `MARKER`, `UNPACK_MARKER`, or
/// `PADDING_MARKER` — as opposed to text a real command argument produced,
/// resolved or not.
fn is_any_internal_sentinel(v: &str) -> bool {
    is_unresolved_marker(v) || v == PADDING_MARKER
}

/// Whether a structurally unread `python::UNPACK_MARKER` in a call is a
/// nameless `**` unpack — shared by `callback_argument_used` (an unpack
/// anywhere could carry a declared callback slot) and `written_paths`'s
/// `arg_<N>` arm (it could supply `mode` invisibly). Identical readable
/// positional text is a literal, not syntax.
fn has_unpack_arg(cmd: &Cmd) -> bool {
    cmd.args.iter().enumerate().any(|(i, a)| {
        a == crate::python::UNPACK_MARKER && cmd.unread_args.contains(&i)
    })
}

/// The set of `eff`/`padding` indices a declared `callback_args` name maps
/// to, via `arg_names` and the method-receiver offset `base_off` — shared by
/// `written_paths` (to exclude these positions from write-target
/// extraction) and `callback_argument_used` (to test whether a call
/// occupies one). A name absent from `arg_names` (a keyword-only callback
/// parameter) contributes no position here, matching `arg_names`'s own doc
/// comment on `callback_args`.
fn callback_arg_positions(prog: &Program, base_off: usize) -> HashSet<usize> {
    prog.callback_args.iter().filter_map(|c| prog.arg_names.iter().position(|n| n == c)).map(|p| p + base_off).collect()
}

/// The one place a write-target CANDIDATE becomes a write target vouch will
/// actually report (task 2b fix round 5, the general backstop). Any
/// internal sentinel is normalised to `MARKER` — already proven safe
/// against `paths::expand_env_with`'s `$NAME` grammar (`?` is not a name
/// character, so the would-be reference is empty and never matches) —
/// rather than pushed as its own, possibly differently-spelled text.
///
/// This is deliberately a SEPARATE safeguard from getting each sentinel's
/// own spelling right (`PADDING_MARKER`'s doc comment above): a future
/// sentinel only has to be added to `is_any_internal_sentinel` to be
/// covered here, not independently proven grammar-safe at the point it is
/// introduced — the class stays closed even if a later spelling repeats
/// this round's mistake.
fn push_write_target(out: &mut WriteTargets, v: &str) {
    if is_any_internal_sentinel(v) {
        out.paths.push(crate::python::MARKER.to_string());
    } else {
        out.paths.push(v.to_string());
    }
}

/// Folds a python call's `name=value` keyword tokens onto the positional
/// slots `arg_names` claims for them, leaving every other token where it is.
///
/// A method-shaped call's own `args[0]` is always the receiver
/// (`src/python.rs`, Tasks 2-3) and takes no name of its own, so `arg_names`
/// position 0 names the call's SECOND token — `base` shifts every claimed
/// position by one for those calls, matching the doc comment on
/// `Program::arg_names` ("the receiver fills position 0 … names start at
/// position 1").
///
/// A keyword token whose name is not in `arg_names` is dropped rather than
/// kept in place: python itself never lets an unrecognised keyword argument
/// fill a positional slot, so treating it as one would misplace whatever
/// comes after it. An entry that declares no `arg_names` at all cannot make
/// that recognise-or-drop call for any name, so this returns the arguments
/// completely untouched — every non-python entry, none of which sets
/// `arg_names`, is unaffected by this function.
///
/// `Cmd::keyword_args` decides whether a `name=value` token came from keyword
/// syntax. The spelling alone never decides: a positional string can legally
/// be `"file=x"` or `"path=output"`, and folding either by text would replace
/// the real value with a different one. The Python scanner records keyword
/// positions out of band for the same reason it records unread positions out
/// of band; every other scanner leaves the set empty.
///
/// `MARKER` and `UNPACK_MARKER` part ways past that, though (task 2b fix
/// round 3): an ordinary unresolvable VALUE still has to OCCUPY a slot when
/// it falls through unfolded — `os.rename(compute(), "C:/work/x.txt")`
/// needs its first argument's marker to take position 0, or the second
/// argument reads as the destination one slot too early. A `**` unpack is
/// not a positional value at all, so it must NOT occupy a slot the same
/// way: doing so let the unpack's own token displace a real named-argument
/// fold and land in the prompt as if it were the real
/// argument — `open(file="C:/work/x.txt", **opts)` reported the literal
/// text `$**` as the write target instead of the path the operator
/// actually named, and a genuinely allowed destination could never resolve
/// as allowed for that shape. `UNPACK_MARKER` is therefore dropped here
/// rather than pushed — the ONLY per-token difference between the two
/// markers in this function.
///
/// Returns the folded array PLUS the set of indices that are pure PADDING
/// (task 2b fix round 5) — never addressed by any real token, positional
/// or keyword. Occupancy is tracked this way, by INDEX, rather than by
/// comparing a position's text against `PADDING_MARKER`, because a real
/// python string literal can legally equal ANY fixed marker spelling
/// (`open(f, "$,")` is ordinary Python), and a text comparison would then
/// misread a genuinely-given value as an untouched gap — verified live:
/// with only the text check, `open('C:/elsewhere/f.txt', '$,')` (a real,
/// if unusual, mode literal) ALLOWED, the same fail-open direction the
/// respelling in `PADDING_MARKER`'s own doc comment closed for the
/// environment-expansion path. Tracking the index instead makes the
/// property hold regardless of what any marker is spelled: nothing a
/// python literal can contain will ever be mistaken for "this position
/// was never addressed."
///
/// Also returns the method-receiver offset (`head_is_method_shaped`) it
/// derives from `head` internally — every caller needs that same offset
/// alongside `eff`/`padding` to translate an `arg_names` position into an
/// `eff` index, so it is computed once here rather than a second time at
/// each call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveArgs {
    pub values: Vec<String>,
    pub padding: HashSet<usize>,
    pub unread: HashSet<usize>,
    /// Folded positions holding a structurally observed callable reference.
    /// Folded, so a keyword and a positional spelling of the same slot read
    /// identically — the same reason `unread` is folded.
    pub callable: HashSet<usize>,
    pub base_offset: usize,
}

/// Arguments in the positions an entry's `arg_names` declares.
///
/// Python keyword tokens are folded onto their named positions while the
/// scanner's out-of-band readability and the fold's padding remain structural
/// index sets. A literal equal to an internal marker is therefore still
/// readable; an unread keyword value remains unread after it moves.
pub fn effective_args(prog: &Program, cmd: &Cmd) -> EffectiveArgs {
    let base = usize::from(head_is_method_shaped(&cmd.head));
    if prog.arg_names.is_empty() {
        return EffectiveArgs {
            values: cmd.args.clone(),
            padding: HashSet::new(),
            unread: cmd.unread_args.clone(),
            callable: cmd.callable_args.keys().copied().collect(),
            base_offset: base,
        };
    }
    let mut eff: Vec<String> = Vec::new();
    let mut unread: HashSet<usize> = HashSet::new();
    let mut callable: HashSet<usize> = HashSet::new();
    let mut folded: Vec<(usize, String, bool, bool)> = Vec::new();
    for (i, a) in cmd.args.iter().enumerate() {
        if cmd.keyword_args.contains(&i) {
            if let Some((name, value)) = a.split_once('=') {
                if let Some(p) = prog.arg_names.iter().position(|n| n == name) {
                    folded.push((
                        base + p,
                        value.to_string(),
                        cmd.unread_args.contains(&i),
                        cmd.callable_args.contains_key(&i),
                    ));
                }
            }
            continue;
        }
        if a == crate::python::UNPACK_MARKER && cmd.unread_args.contains(&i) {
            // A nameless keyword unpack is not a positional argument. The
            // structural unread bit distinguishes it from identical literal
            // text supplied positionally.
            continue;
        }
        if cmd.unread_args.contains(&i) {
            unread.insert(eff.len());
        }
        if cmd.callable_args.contains_key(&i) {
            callable.insert(eff.len());
        }
        eff.push(a.clone());
    }
    // Positions filled in claimed order, not source order: python places no
    // ordering requirement on keyword arguments, so `open(mode="w",
    // file="C:/t/x")` must fold identically to the declaration-order
    // spelling. `sort_by_key` is stable, so a real positional's "first
    // occupant wins" claim on a position (already in `eff` before this loop
    // runs) is unaffected either way.
    folded.sort_by_key(|(pos, ..)| *pos);
    let mut padding: HashSet<usize> = HashSet::new();
    for (pos, value, value_unread, value_callable) in folded {
        while eff.len() < pos {
            padding.insert(eff.len());
            eff.push(PADDING_MARKER.to_string()); // never addressed at all — see its own doc comment
        }
        if eff.len() == pos {
            if value_unread {
                unread.insert(pos);
            }
            if value_callable {
                callable.insert(pos);
            }
            eff.push(value); // first occupant wins
        }
    }
    EffectiveArgs {
        values: eff,
        padding,
        unread,
        callable,
        base_offset: base,
    }
}

/// Whether a `writes_only_with_file_mode` claim's own "mode" position says
/// this call writes.
///
/// Absent is python's documented default for `open` (a read); a recognised
/// read-only spelling (`"r"`, `"rb"`, …) is a read; anything else — a write
/// spelling, or a value vouch cannot read as a mode at all (an unresolved
/// name, an unrelated keyword value like an encoding) — is judged a possible
/// write, since a write cannot be ruled out (the same fail-closed floor as
/// an absent claimed position).
///
/// `has_unpack` (task 2b fix round 2, found by the `UNPACK_MARKER` sweep):
/// "absent" is trustworthy ONLY when nothing in the call could be supplying
/// mode invisibly. `open(**opts)` and `open(file="x", **opts)` both leave
/// `eff`'s mode position genuinely empty (nothing folded there — `**opts`
/// carries no name to fold BY, so the mode-shaped keyword `**opts` might be
/// unpacking, e.g. `mode="w"`, never reaches this function's ordinary
/// per-position check at all), and reading that as "the documented default"
/// was a live, verified silent write-bypass: `open(file="x", **opts)`
/// allowed unconditionally, whatever the unseen `mode` in `opts` actually
/// was. When an unpack is present, "absent" no longer means "genuinely
/// never given" — it means "vouch cannot tell", so this returns `true`
/// (cannot rule out a write) instead of the ordinary read default.
fn mode_says_write(prog: &Program, eff: &[String], padding: &HashSet<usize>, base: usize, has_unpack: bool) -> bool {
    // Validation (`knowledge::validate`) requires `arg_names` to contain
    // "mode" whenever `writes_only_with_file_mode = true` is set on a loaded
    // file; a caller that builds a `Program` without going through that
    // check gets the fail-safe reading — treat it as a possible write.
    let Some(p) = prog.arg_names.iter().position(|n| n == "mode") else {
        return true;
    };
    // A PADDED position (task 2b fix round 4) means the call never
    // addressed this position at all — read exactly like `None`, not like
    // an unreadable value. Without this, folding a LATER keyword
    // (`open("f.txt", encoding="utf-8")`) pads straight through mode's own
    // position, and a plain read call starts asking about a write.
    if !eff_position_occupied(eff, padding, base + p) {
        return has_unpack; // absent → a read, UNLESS an unpack could be supplying it invisibly
    }
    let v = &eff[base + p];
    let is_mode = !v.is_empty() && v.len() <= 4 && v.chars().all(|c| "rwaxbtU+".contains(c));
    if is_mode {
        v.chars().any(|c| "wax+".contains(c))
    } else {
        true // present but unreadable → a write cannot be ruled out
    }
}

/// Paths this command writes to, per the knowledge file. Empty when the program
/// is not declared to write, which is NOT a claim that it does not write —
/// only that vouch has no description of it. See `unmodeled_command`.
pub fn written_paths(kb: &Knowledge, cmd: &Cmd) -> WriteTargets {
    written_paths_in(kb, cmd, "bash")
}

pub fn written_paths_in(kb: &Knowledge, cmd: &Cmd, lang: &str) -> WriteTargets {
    let mut out = WriteTargets::default();
    let verb_grammar = verb_vocab(kb, cmd, lang);
    for prog in entries_for_cmd(kb, cmd, lang) {
        // Keyword arguments folded onto the positions `arg_names` claims for
        // them (a no-op for every entry that never sets `arg_names`, which is
        // every non-python entry) — every arm below reads this instead of
        // `cmd.args` directly, so folding is uniform across all of them.
        // `padding` is the companion index set a padded (never-addressed)
        // position lives in — see `eff_position_occupied`'s doc comment for
        // why occupancy is tracked by index rather than by comparing a
        // position's text against `PADDING_MARKER`.
        let effective = effective_args(prog, cmd);
        let eff = effective.values;
        let padding = effective.padding;
        let base_off = effective.base_offset;
        // A flag's VALUE is not a positional argument. Without this,
        // `truncate -s 0 <file>` records `0` as a written path, and the
        // positional fallback below can pick a flag's value as a destination.
        // Kept paired with its OWN position in `eff` (task 2b fix round 4):
        // "all_args"/"last_arg" need to skip a `callback_args`-declared
        // position by that same index — an invoked-function reference is
        // never a written path, and folding it in as one competes with
        // `callback_argument`'s own Ask for the "worst" slot, which can
        // mask a dead `callback_args` declaration (`shutil.move`'s
        // `copy_function`, resolved but unreadable as a path, was reported
        // as an "unresolved_path" write target instead of the invoked
        // parameter it actually is).
        let mut non_flags: Vec<(usize, &String)> = Vec::new();
        let mut skip_next = false;
        for (i, a) in eff.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }
            if is_flag(a, &prog.flag_prefix) {
                if prog.value_options.iter().any(|v| v == a) {
                    skip_next = true;
                }
                continue;
            }
            non_flags.push((i, a));
        }
        let callback_positions = callback_arg_positions(prog, base_off);
        // Excludes a declared callback position (never a path, whatever sits
        // there) AND a padded, never-addressed one (task 2b fix round 5 —
        // `eff_position_occupied`, not a bare index check: "skipped rather
        // than pushed as a write path" for BOTH `all_args` and `last_arg`,
        // the two arms that ever read this list).
        let non_flags_paths: Vec<&String> = non_flags
            .iter()
            .filter(|(i, _)| !callback_positions.contains(i) && eff_position_occupied(&eff, &padding, *i))
            .map(|(_, a)| *a)
            .collect();
        // "Writes where it stands": a declared shape whose destination is the
        // directory the command runs in (M2.129). Decided BEFORE the position
        // arms and winning over them, because for the shape it describes the
        // position arms derive the wrong thing rather than nothing: a
        // one-operand link creation has its TARGET last, and the link — the
        // file actually created — is in the run place under that target's
        // basename. Found by the task review: gating this on "the arms
        // derived nothing" made the claim unreachable for exactly the shape
        // it was added for.
        if here_write_applies(prog, cmd, lang, &non_flags_paths) {
            out.run_dir_dest = true;
            continue;
        } else if !prog.here_write.is_empty() && cmd.by_reference {
            // A by-reference call can never SATISFY a conditional
            // `here_write` entry's `when_flags`/`subcommand`/`operands` gate
            // — every one of those reads `cmd`/`non_flags_paths`, which are
            // empty by construction for the synthetic probe — so
            // `here_write_applies` above is deterministically false for any
            // conditional entry, not merely inapplicable to this call. An
            // unconditional entry (empty `when_flags`, no `subcommand`, no
            // `operands` or `operands = 0`) is already caught by the branch
            // above; this is only the conditional case, reported unresolved
            // rather than silently found to write nothing (task 4 review
            // round 2, Finding B). Gated on `cmd.by_reference`, not
            // `eff.is_empty()` — a genuinely bare REAL command (`sort` typed
            // with no arguments) also has an empty `eff` and must stay
            // silent here, unaffected by this fix (task 4 review round 3,
            // CRITICAL).
            push_write_target(&mut out, crate::python::MARKER);
            continue;
        }
        match prog.writes.as_str() {
            "last_arg" => {
                if let Some(last) = non_flags_paths.last() {
                    push_write_target(&mut out, last);
                } else if cmd.by_reference {
                    // A by-reference invocation, judged with no arguments
                    // (task 4 review C4), still claims a write here; report
                    // it as unresolved rather than silently finding nothing.
                    // An ordinary real invocation given only flags
                    // (`touch --help`) or genuinely bare (`sort` typed with
                    // no arguments) has `by_reference == false` and stays
                    // silent, exactly as before this fix (task 4 review
                    // round 3, CRITICAL: `eff.is_empty()` could not tell the
                    // two cases apart).
                    push_write_target(&mut out, crate::python::MARKER);
                }
            }
            "all_args" => {
                if !non_flags_paths.is_empty() {
                    for a in &non_flags_paths {
                        push_write_target(&mut out, a);
                    }
                } else if cmd.by_reference {
                    push_write_target(&mut out, crate::python::MARKER);
                }
            }
            // "named"       — the flag's value, with a positional fallback
            // "flags_only"  — the flag's value and nothing else
            //
            // `tar` and `unzip` need the second: their positional arguments are
            // the archive and the members to read, so a fallback would record
            // an input as a written path and prompt about it.
            //
            // Matched through `flags::spells`, not `flag_matches` (M2.128):
            // `flag_matches` is exact-string-only, so `--output=<path>`,
            // `-o<path>`, and PowerShell `-Path:<path>` all read as some
            // OTHER token — never the flag — and the destination inside them
            // was never derived at all. `spells` reads the same attached,
            // abbreviated, and case-per-entry shapes every other derivation
            // consumer does. An attached value (`Spell::Yes(Some(v))`) IS the
            // destination directly, with nothing left to consume; a bare
            // match (`Spell::Yes(None)`) still needs the next token, exactly
            // as before. Abbreviation policy is the derivation policy (spec
            // §4.1.7): `Accept` for a case-insensitive entry (every
            // PowerShell writer here), `Refuse` for a case-sensitive one (the
            // unix writers) — a refused candidate is loud, routed to the
            // existing `unknowable` named-ask channel rather than silently
            // matched or silently dropped.
            "named" | "flags_only" => {
                let abbrev = if prog.case_sensitive_flags.unwrap_or(false) {
                    crate::flags::Abbrev::Refuse
                } else {
                    crate::flags::Abbrev::Accept
                };
                let vocab = crate::flags::vocab_for(prog, abbrev);
                let mut take_next = false;
                let mut found = false;
                for a in &eff {
                    if take_next {
                        push_write_target(&mut out, a);
                        found = true;
                        take_next = false;
                        continue;
                    }
                    for f in &prog.write_flags {
                        match crate::flags::spells(f, a, &vocab) {
                            crate::flags::Spell::Yes(Some(v)) => {
                                push_write_target(&mut out, &v);
                                found = true;
                                break;
                            }
                            crate::flags::Spell::Yes(None) => {
                                take_next = true;
                                break;
                            }
                            crate::flags::Spell::RefusedAbbrev { .. } => {
                                out.unknowable.push(a.clone());
                                break;
                            }
                            crate::flags::Spell::No => {}
                        }
                    }
                }
                // Positional fallback: `Copy-Item a.txt C:/x/b.txt`. Which
                // positional is the destination is per-entry
                // (`named_positional`, M2.128): `Set-Content [-Path]
                // [-Value]` puts it first, `Copy-Item <src> <dest>` puts it
                // last — the default, when the entry does not say.
                if !found && prog.writes == "named" {
                    let pick = if prog.named_positional.as_deref() == Some("first") {
                        non_flags_paths.first()
                    } else {
                        non_flags_paths.last()
                    };
                    if let Some(p) = pick {
                        push_write_target(&mut out, p);
                        found = true;
                    }
                }
                // A by-reference call finds neither a flag's value nor a
                // positional fallback — `found` stays false and this arm
                // falls silent, exactly like `last_arg` and `all_args`
                // before their own fix (task 4 review round 2, Finding B).
                // Gated on `cmd.by_reference`, not `eff.is_empty()` or
                // `!found` alone: an ordinary real invocation that simply
                // omits its write flag (`tar -tf a.tar`, `"flags_only"`, no
                // positional fallback ever runs) — or is typed genuinely
                // bare (`sort` with no arguments) — has `by_reference ==
                // false` and must stay silent, unaffected by this fix (task
                // 4 review round 3, CRITICAL).
                if !found && cmd.by_reference {
                    push_write_target(&mut out, crate::python::MARKER);
                }
            }
            "of_prefix" => {
                for a in &eff {
                    if let Some(v) = a.strip_prefix("of=") {
                        push_write_target(&mut out, v);
                    }
                }
                // An empty `eff` never enters the loop above, so a
                // by-reference call finds nothing here either — gated on
                // `cmd.by_reference`, not `eff.is_empty()` (task 4 review
                // round 2, Finding B; round 3, CRITICAL) — same precedent as
                // `last_arg`/`all_args`. A genuinely bare real `dd` also has
                // an empty `eff` and must stay silent.
                if cmd.by_reference {
                    push_write_target(&mut out, crate::python::MARKER);
                }
            }
            // `writes = "arg_<N>"` names ONE numbered positional argument as
            // the written path — python's `open(file, mode)` shape, where
            // the write position is neither "last" nor "all" and varies by
            // function signature (see `arg_names`).
            s if s.starts_with("arg_") => {
                if let Some(i) = s.strip_prefix("arg_").and_then(|n| n.parse::<usize>().ok()) {
                    let has_unpack = has_unpack_arg(cmd);
                    let mode_blocks = prog.writes_only_with_file_mode == Some(true)
                        && !mode_says_write(prog, &eff, &padding, base_off, has_unpack);
                    if !mode_blocks {
                        // `eff_position_occupied`, not a bare `eff.get(i)`
                        // (task 2b fix round 5): a padded, never-addressed
                        // position reads exactly like a genuinely absent one
                        // — both are "unresolved", never the padding text
                        // itself.
                        let target = if !eff_position_occupied(&eff, &padding, i) {
                            crate::python::MARKER.to_string()
                        } else {
                            let v = &eff[i];
                            // A structurally marked but unfolded keyword never
                            // names a resolved position: with no `arg_names`
                            // to map it through, it is no more trustworthy
                            // than an absent one. Literal positional
                            // `name=value` text is not a keyword and remains
                            // the real target.
                            if prog.arg_names.is_empty() && cmd.keyword_args.contains(&i) {
                                crate::python::MARKER.to_string()
                            } else {
                                v.clone()
                            }
                        };
                        push_write_target(&mut out, &target);
                    }
                }
            }
            _ => {}
        }

        // Subcommand-scoped destinations: `git clone <url> <dir>` writes to
        // <dir>, `git status` writes nothing. The program-wide `writes` cannot
        // express that, so these are declared per subcommand.
        //
        // The anchor is the language-scoped verb grammar, never string equality — a flag's
        // VALUE that happens to equal the subcommand's own spelling
        // (`git -C init init foo`) must not be mistaken for it. The
        // vocabulary is the same name-wide grammar `then_of_in` reads, so the
        // scope and destination walks cannot anchor on different tokens.
        if !prog.sub_write.is_empty() {
            let sub_idx = match resolve_verb(cmd, &verb_grammar.as_vocab(), lang) {
                Verb::At(i) => Some(i),
                Verb::None => None,
                Verb::Unreadable { token, .. } => {
                    out.unknowable.push(token);
                    None
                }
            };
            if let Some(sub_idx) = sub_idx {
                for sw in &prog.sub_write {
                    if cmd.args[sub_idx] != sw.subcommand {
                        continue;
                    }
                    let (positionals, unk) = walk_post_subcommand(&cmd.args[sub_idx + 1..], &verb_grammar.as_vocab());
                    // Something after the subcommand could not be
                    // classified — vouch does not know whether it takes a
                    // value, so the positional count and ORDER from that
                    // point on are not trustworthy, and that includes
                    // whether `then`'s second word is even at the position
                    // this walk found it at. This has to run BEFORE the
                    // `then` filter below: an undescribed value-taking flag
                    // between the subcommand and the second word shifts the
                    // positional list, so a `then` mismatch does not prove
                    // the second word is absent — `git worktree --reason
                    // cleanup add /x/wt` must not fall through as if
                    // `worktree` had no `add`. Report the flag and guess no
                    // destination, rather than guess wrong either way.
                    if !unk.is_empty() {
                        out.unknowable.extend(unk);
                        continue;
                    }
                    let positionals: Vec<&String> = if sw.then.is_empty() {
                        positionals
                    } else {
                        match then_word(&positionals) {
                            Some(f) if f == sw.then => positionals[1..].to_vec(),
                            _ => continue,
                        }
                    };
                    if sw.takes == "run_dir" {
                        // Zero positionals: the destination IS the run
                        // directory. One or more: behaves as "first".
                        // `min_positional` is not consulted here — it
                        // exists to gate "last"/"first" ambiguity, not this
                        // shape.
                        match positionals.first() {
                            Some(p) => out.paths.push((*p).clone()),
                            None => out.run_dir_dest = true,
                        }
                        continue;
                    }
                    if sw.takes == "url_basename" {
                        // Fires only on the bare form: exactly one
                        // positional (the URL). Two positionals is the
                        // explicit-destination shape and belongs to the
                        // OTHER `clone` sub_write entry (min_positional =
                        // 2), matched by its own loop iteration — both run
                        // because clone has two disjoint sub_write entries
                        // sharing a merge key (recorded at Task 14).
                        if positionals.len() == 1 {
                            if let Some(mut name) = url_basename(positionals[0]) {
                                // `--bare`/`--mirror` (both consumed as
                                // no_value_options, so they never reach
                                // `positionals`) make git append `.git` to a
                                // DERIVED name — an explicit destination
                                // argument is used verbatim either way, so
                                // this only applies here, never in the
                                // min_positional = 2 arm above. The parent
                                // directory is unaffected either way (same
                                // tree, ask/allow does not change), but the
                                // printed name and the "add to
                                // write.allow_paths" remedy must say the
                                // directory git actually creates.
                                let bare = cmd.args[sub_idx + 1..].iter().any(|a| a == "--bare" || a == "--mirror");
                                if bare {
                                    name.push_str(".git");
                                }
                                out.paths.push(name);
                            }
                        }
                        continue;
                    }
                    if positionals.len() >= sw.min_positional.max(1) {
                        let pick = if sw.takes == "first" {
                            positionals.first()
                        } else {
                            positionals.last()
                        };
                        if let Some(p) = pick {
                            out.paths.push((*p).clone());
                        }
                    }
                }
            } else if cmd.by_reference {
                // `resolve_verb` reads `cmd.args`, empty by construction for
                // a by-reference call — `Verb::None`, so `sub_idx` is
                // `None` and the whole scoped-destination block above is
                // skipped with no judgement at all today, a silent allow of
                // a program that DOES declare a subcommand-scoped write
                // (task 4 review round 2, Finding B). Gated on
                // `cmd.by_reference`, not `eff.is_empty()` or merely
                // `sub_idx.is_none()`: an ordinary real command that is
                // simply flags-only (`git -C /path`) or genuinely bare
                // (`git` typed with no arguments at all) also resolves
                // `Verb::None`, has `by_reference == false`, and must keep
                // behaving exactly as before this fix — vouch does not know
                // this program's verb from a real, present argument list
                // either, but that is the ordinary "no subcommand
                // recognised" case, not this one (task 4 review round 3,
                // CRITICAL: `eff.is_empty()` flipped bare `git` from allow
                // to ask because it cannot distinguish the two).
                push_write_target(&mut out, crate::python::MARKER);
            }
        }
    }
    out
}

/// Every guard hit in the list, each carrying the INDEX of the command that
/// tripped it. Nothing is deduped.
///
/// Which command tripped a guard used to be a detail — one guard name, one
/// action, wherever it came from. A place-scoped override makes it the
/// question: the same guard tripped in two directories can resolve to two
/// different actions, and a list that has already collapsed them to one hit
/// has thrown away the only thing that tells them apart. The index is how the
/// caller gets back to that command's order, and from there to its place.
pub fn check_each(kb: &Knowledge, cmds: &[Cmd]) -> Vec<(usize, Hit)> {
    let langs = vec!["bash".to_string(); cmds.len()];
    check_each_in(kb, cmds, &langs)
}

/// Language-aware guard walk. The language list is command-parallel; a
/// missing entry refuses the language-specific reading by using an empty
/// language name, whose token rules are the conservative shell rules.
pub fn check_each_in(kb: &Knowledge, cmds: &[Cmd], langs: &[String]) -> Vec<(usize, Hit)> {
    let mut out: Vec<(usize, Hit)> = Vec::new();
    for (i, c) in cmds.iter().enumerate() {
        let lang = langs.get(i).map(String::as_str).unwrap_or("");
        for hit in check_in(kb, c, lang) {
            out.push((i, hit));
        }
    }
    out
}

/// The first hit of each distinct guard, in the order the guards first appear.
///
/// A thin wrapper over `check_each` that keeps this dedupe exactly as it was
/// for the callers that still want one hit per guard name and have no place to
/// resolve against.
pub fn check_all(kb: &Knowledge, cmds: &[Cmd]) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    for (_, hit) in check_each(kb, cmds) {
        if !out.iter().any(|h| h.guard == hit.guard) {
            out.push(hit);
        }
    }
    out
}
