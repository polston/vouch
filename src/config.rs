//! Configuration.
//!
//! One shape for every language. `[lang.bash]` and `[lang.powershell]` are the
//! same struct, looked up by name, so adding a language adds a config key and
//! nothing else — no new struct, no new accessor, no new code path.
//!
//! The rule that matters: anything with no explicit setting resolves to `Ask`,
//! never `Allow`. Absence of knowledge must never be the permissive case.
//!
//! The corollary, enforced by tests: every construct a scanner can name MUST be
//! settable here. A prompt with no setting behind it is the exact defect that
//! made the previous tool unfixable.

use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;

/// What vouch does about a construct, a guard, or a program: let the command
/// through, stop and ask the operator, or refuse it outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Let it through with no prompt.
    Allow,
    /// Stop and show the operator what was recognised, before it runs.
    Ask,
    /// Refuse it outright, with no prompt.
    Deny,
}

impl Default for Action {
    fn default() -> Self {
        Action::Ask
    }
}

/// The six permission-mode spellings the harness documents, exactly as
/// delivered in hook input. Closed on purpose: a typo in `[shadow].modes`
/// must refuse the config loudly, never silently fail to match (§1) — a
/// future harness mode needs a vouch update to be nameable, which is loud
/// and the correct cost.
pub const PERMISSION_MODES: [&str; 6] =
    ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"];

/// The `[shadow]` three-state toggle (mode-keyed shadow, design 2026-08-16):
/// what standing down suppresses. Required when the section is present —
/// the feature's own switch is never defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StandDown {
    /// Stand down, but what BLOCKS still blocks: a deny, and the protection
    /// asks (the protected list, the ask_paths wall).
    KeepDeny,
    /// Stand down every prompt and every block; only allows are emitted.
    Full,
    /// Never stand down — the same as the section being absent.
    Off,
}

/// `[shadow]`: stand down from gating while the harness reports a named
/// permission mode. vouch still evaluates and journals every call; what
/// would prompt is not emitted. An ALLOW is never suppressed.
#[derive(Debug, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShadowSection {
    /// The three-state toggle. `Option` so the missing-key refusal can name
    /// the three values instead of serde's bare missing-field error;
    /// `validate` refuses `None`, so it is always `Some` in a loaded config.
    #[serde(default)]
    pub stand_down: Option<StandDown>,
    /// Which permission modes stand vouch down. The six documented
    /// spellings only; a written empty list refuses.
    #[serde(default)]
    pub modes: Option<Vec<String>>,
}

/// Why `tool_decision` returned the action it did.
///
/// [review] The prompt used to compute "is this tool described" and "what do
/// I do about it" separately — the first from `guards::tool_entry`, the
/// second from `tool_action` — and asserted a fixed relationship between
/// them that only held for ONE of the paths `tool_action` can take. A tool
/// with no `action` in knowledge.toml (so `Allow` on its own) came back
/// `Ask` the instant the operator's `[tools]` section named any OTHER tool,
/// and the prompt still said "this is described in knowledge.toml and set to
/// ask there" — which knowledge.toml never said. This type carries the
/// reason OUT of the same decision that picked the action, so the two can
/// never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolReason {
    /// No `[[tool]]` entry names this tool at all.
    Unmodeled,
    /// An entry names it, and nothing in the operator's config overrides it:
    /// the entry's own `action` (or its absence, meaning allow) decided.
    Described,
    /// The operator's own `[tools]` section names this exact tool; that
    /// value decided, whatever knowledge.toml says.
    ConfigNamed,
    /// An entry names this tool, but the operator's `[tools]` section names
    /// at least one OTHER tool. Naming any tool makes that section govern
    /// EVERY tool (see `tool_decision`, below), so the shipped description
    /// is out of play — this tool asks because it is not named there, not
    /// because knowledge.toml said ask.
    ConfigGovernsOthers,
    /// There is no config file at all — not even one that names no tools.
    /// A materially different sentence from the other three: nothing has
    /// been allowed, because nothing has been said, full stop. The shipped
    /// description in knowledge.toml is not consulted for the verdict here,
    /// only for what the prompt can say the tool DOES.
    NoConfig,
}

fn default_ask() -> Action {
    Action::Ask
}

/// A place-scoped guard override (`[[run.guards]]`): under one of `under`'s
/// trees, each named guard takes the action given here instead of its global
/// `[guards]` action. A looser override applies only where vouch can PROVE
/// the command ran in the tree.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
pub struct GuardOverride {
    /// The trees this override applies under. Each entry is a path or a
    /// `path/**` glob.
    pub under: Vec<String>,
    /// Every key except `under`. Serde flatten cannot deny unknown keys, so
    /// guard-name validation happens in `validate` — which is better anyway:
    /// the error can say "not a known guard" instead of "unknown field".
    #[serde(flatten)]
    pub actions: std::collections::HashMap<String, Action>,
}

/// The `[run]` table: trust and distrust zones, and place-scoped guard
/// overrides.
#[derive(Debug, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunSection {
    /// Trust zone: any command run from under one of these trees is
    /// recognised, whatever it is — recognition only, guards and write
    /// rules still apply. `None` means absent (fine); a written empty list
    /// is refused at load, since it can never apply.
    #[serde(default)]
    pub trust_all_under: Option<Vec<String>>,
    /// Distrust zone: no command run from under one of these trees is
    /// recognised, whatever it is — even a program a knowledge entry
    /// describes. Refused when written empty, same as the grants above: a
    /// written empty list can only be a mistake.
    #[serde(default)]
    pub trust_nothing_under: Option<Vec<String>>,
    /// Place-scoped guard overrides, written as `[[run.guards]]`.
    #[serde(default, rename = "guards")]
    pub guard_overrides: Vec<GuardOverride>,
}

/// One `[[write.scope]]` entry: this program's own writes may land only
/// under `only_under` — judged against the write's resolved target, not the
/// whole command line.
#[derive(Debug, Deserialize, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteScope {
    /// Which programs this scope restricts. Each entry is 1-3 tokens: the
    /// program name, optionally a subcommand, and optionally that
    /// subcommand's own second word (`"git worktree add"`).
    pub programs: Vec<String>,
    /// The trees this program's writes may land under. A write outside all
    /// of them is judged as if this scope did not exist — falling through to
    /// the ordinary wall/allow_paths check.
    pub only_under: Vec<String>,
}

/// One `programs` entry split into the program, its verb, and the verb's
/// second word: `"git worktree add"` -> `("git", Some("worktree"),
/// Some("add"))`, `"git init"` -> `("git", Some("init"), None)`, `"git"` ->
/// `("git", None, None)`.
///
/// A fourth token is refused at load, so nothing downstream has to represent
/// one. The second word exists because it is a real verb in the knowledge
/// file's own grammar — `git worktree add` is modelled as `subcommand =
/// "worktree", then = "add"` — and the driving case for a write scope
/// (repository creation only under a scratch tree) cannot be written down
/// without it.
///
/// One definition, because `validate_scopes`, `WriteScope::names` and doctor's
/// shadow check must never disagree about which word is which — a second,
/// slightly different split is how a rule gets validated in one shape and
/// matched in another.
fn split_program(entry: &str) -> (&str, Option<&str>, Option<&str>) {
    let mut words = entry.split_whitespace();
    (words.next().unwrap_or(""), words.next(), words.next())
}

/// One entry's words folded for comparison — program, verb, second word — as
/// `validate_scopes` keys duplicates on and doctor compares widths by.
type ScopeWords = (String, Option<String>, Option<String>);

impl WriteScope {
    /// True when this scope entry names this command.
    ///
    /// Each word an entry states must match, and each word it omits matches
    /// anything: `"git"` covers every git operation, `"git worktree"` covers
    /// every worktree operation, `"git worktree add"` covers that one. Names
    /// fold case and drop any path and `.exe`, because that is how every other
    /// name comparison in vouch works (`guards::base_name`) —
    /// `C:/tools/Git.exe init` and `git init` are one program, and a scope
    /// that missed the first spelling would be a restriction that quietly
    /// stopped applying.
    ///
    /// The second word carries a third answer that the first cannot, and it
    /// decides the opposite way: a stated word meeting a word vouch COULD NOT
    /// READ claims the command. A scope restricts, so it applies until it is
    /// disproven, and an unreadable word disproves nothing — `git worktree
    /// --undescribedflag add C:/work/wt` must not walk out of a `git worktree
    /// add` scope on the strength of one flag nobody described. A stated word
    /// meeting a DIFFERENT word, or meeting none at all, does not claim: those
    /// are answers, and they say this is another operation.
    pub fn names(&self, head: &str, sub: Option<&str>, then: &crate::guards::SecondWord) -> bool {
        use crate::guards::SecondWord;
        let head = crate::guards::base_name(head);
        let stated_sub = |want: Option<&str>| match want {
            None => true,
            Some(w) => sub.is_some_and(|g| g.eq_ignore_ascii_case(w)),
        };
        let stated_then = |want: Option<&str>| match (want, then) {
            (None, _) => true,
            (Some(_), SecondWord::Unknown(_)) => true,
            (Some(w), SecondWord::Word(g)) => g.eq_ignore_ascii_case(w),
            (Some(_), SecondWord::Absent) => false,
        };
        self.programs.iter().any(|entry| {
            let (want_head, want_sub, want_then) = split_program(entry);
            crate::guards::base_name(want_head) == head
                && stated_sub(want_sub)
                && stated_then(want_then)
        })
    }
}

/// Settings for one language: `[lang.bash]`, `[lang.powershell]`,
/// `[lang.python]` — one shape for every scanner, looked up by name.
#[derive(Debug, Deserialize, Default, Clone, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LangConfig {
    /// Verdict when nothing this language's scanner recognised objected.
    /// Never applies to a construct — an unset construct always resolves to
    /// `ask`, whatever this says.
    #[serde(default = "default_ask")]
    pub default: Action,
    /// Per-construct verdicts, written as `[lang.<name>.constructs]`. A
    /// construct with no entry here defaults to `ask`, never to `default`
    /// above — absence of a setting must never become permission.
    #[serde(default)]
    pub constructs: HashMap<String, Action>,
    /// How many layers of wrapper nesting are scanned before a deeper nest
    /// trips `wrap_depth_exceeded` and asks. `None` means the operator has
    /// not set it, so the built-in cap (4) applies. Read by the engine's
    /// wrapper walk, not by this file.
    #[serde(default)]
    pub wrap_depth: Option<u8>,
}

/// The `[write]` table: what vouch does about a write it can see, and where
/// it is allowed to land.
#[derive(Debug, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// Verdict for a write whose destination is not covered by any of the
    /// lists below.
    #[serde(default = "default_ask")]
    pub default: Action,
    /// Trees a write may land under with no prompt. Checked only after the
    /// write wall (`ask_paths`/`deny_paths`) has already let it through.
    #[serde(default)]
    pub allow_paths: Vec<String>,
    /// Write wall: a write aimed under one of these trees always asks. No
    /// `allow_paths` entry, however broadly written, can open a tree named
    /// here.
    #[serde(default)]
    pub ask_paths: Vec<String>,
    /// Write wall: a write aimed under one of these trees is refused
    /// outright, with no prompt. Checked before `ask_paths`.
    #[serde(default)]
    pub deny_paths: Vec<String>,
    /// Per-program write scopes, written as `[[write.scope]]`.
    #[serde(default)]
    pub scope: Vec<WriteScope>,
}

/// The `[protected]` table: paths no `allow_paths` entry can ever open,
/// however broadly it is written. Checked before every allow rule, by
/// identity rather than by folder.
#[derive(Debug, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProtectedSection {
    /// The protected paths themselves — vouch's own config and the hook
    /// registration, by default. This list IS the setting: removing a path
    /// from it is the only way to unprotect that path.
    #[serde(default)]
    paths: Vec<String>,
}

/// `config.toml` (`~/.config/vouch/config.toml`): what the operator has told
/// vouch to do. Anything not named here resolves to `ask` — absence of a
/// setting must never become permission.
#[derive(Debug, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "config.toml")]
struct Raw {
    /// Accepted as a top-level key but not yet consumed; reserved for future
    /// versioning of the config format.
    #[allow(dead_code)]
    #[serde(default)]
    version: Option<i64>,
    /// Refusal detector, not a setting: the old top-level `[bash]` spelling.
    /// Its value is never read — `load` errors out the moment this is
    /// `Some`, pointing at `[lang.bash]` instead. No schema for its value
    /// exists (or is needed): the field exists only so the loader can tell
    /// the old spelling was used at all.
    #[serde(default)]
    #[schemars(skip)]
    bash: Option<toml::Value>,
    /// Refusal detector, not a setting: the old top-level `[powershell]`
    /// spelling. Same treatment as `bash`, above — `[lang.powershell]` is
    /// the current spelling.
    #[serde(default)]
    #[schemars(skip)]
    powershell: Option<toml::Value>,
    /// Every language section, written as `[lang.<name>]` — `bash`,
    /// `powershell`, and `python` ship with vouch. One map, so a new scanner
    /// needs no new key here.
    #[serde(default)]
    lang: HashMap<String, LangConfig>,
    /// What commands DO, written as `[guards]`. Shared across every
    /// language: a guard fires the same way whichever scanner recognised the
    /// command that tripped it. Every key must be one of vouch's known guard
    /// names (`delete_recursive`, `grant_execute`, `history_rewrite`,
    /// `publish_outward`, `process_control`, `privilege_escalation`,
    /// `disk_or_system`, `in_place_edit`, `remote_execution`); an unset guard
    /// always resolves to `ask`.
    #[serde(default)]
    guards: HashMap<String, Action>,
    /// `[run]`: trust/distrust zones and place-scoped guard overrides.
    #[serde(default)]
    run: RunSection,
    /// `[write]`: what vouch does about a write it can see, and where it is
    /// allowed to land.
    #[serde(default)]
    write: FileConfig,
    /// `[protected]`: paths no `allow_paths` entry can ever open.
    #[serde(default)]
    protected: ProtectedSection,
    /// Per-tool actions, written as `[tools]`. vouch used to say NOTHING
    /// about any tool it had no scanner for — 46.5% of recorded tool calls —
    /// which is the same "unknown means allowed" inversion as unmodelled
    /// programs, one level up. Naming a FIRST tool here makes this section
    /// govern every tool, not only the one named; see `Config::tool_decision`.
    #[serde(default)]
    tools: HashMap<String, Action>,
    /// `[shadow]`: mode-keyed shadow (design 2026-08-16).
    #[serde(default)]
    shadow: Option<ShadowSection>,
}

#[derive(Debug, Default)]
pub struct Config {
    pub langs: HashMap<String, LangConfig>,
    pub guards: HashMap<String, Action>,
    pub run: RunSection,
    pub write: FileConfig,
    pub protected: Vec<String>,
    pub tools: HashMap<String, Action>,
    pub shadow: Option<ShadowSection>,
    /// True only for `Config::nothing_configured()` — there is no config file
    /// on disk at all. Distinguishes that from a real, loaded config that
    /// simply names no tools yet (`tools` empty either way, so `tools` alone
    /// cannot tell the two apart). `load()` always sets this to `false`.
    pub no_config_file: bool,
}

impl Config {
    /// What vouch decides with when there is no config file.
    ///
    /// Not a default config — there deliberately is no such thing any more. It
    /// is the shape of "vouch has been told nothing": no language section, so
    /// every language default is Ask; no allow_paths, so no write is inside an
    /// allowed area; no protected paths, which costs nothing because everything
    /// asks anyway; and no tool is allowed, however knowledge.toml describes it.
    pub fn nothing_configured() -> Config {
        let mut c = Config::default();
        c.no_config_file = true;
        c
    }

    pub fn lang(&self, lang: &str) -> Option<&LangConfig> {
        self.langs.get(lang)
    }

    pub fn lang_default(&self, lang: &str) -> Action {
        self.langs.get(lang).map(|l| l.default).unwrap_or(Action::Ask)
    }

    /// The stand-down toggle in force: `Off` unless a `[shadow]` section
    /// arms one. `nothing_configured()` carries no section, so a missing or
    /// broken config can never stand down (design rule 1).
    pub fn stand_down(&self) -> StandDown {
        self.shadow.as_ref().and_then(|s| s.stand_down).unwrap_or(StandDown::Off)
    }

    /// Whether `[shadow].modes` lists this permission mode. An empty mode
    /// (old harness, a direct caller) matches nothing — fail-closed.
    pub fn stands_down_in(&self, permission_mode: &str) -> bool {
        !permission_mode.is_empty()
            && self
                .shadow
                .as_ref()
                .and_then(|s| s.modes.as_ref())
                .is_some_and(|m| m.iter().any(|x| x == permission_mode))
    }

    // [review] `tool_action`, the reason-dropped wrapper around
    // `tool_decision`, was here and nothing called it — not the binary, not a
    // test (same as `names_tool`, below). Deleted rather than threading a
    // `kb` parameter through code no caller exercises.

    /// The action for a harness tool, and WHY — see `ToolReason`. A caller
    /// that needs to explain the decision (the prompt does) uses this
    /// instead of re-deriving the reason from a second, independent check.
    ///
    /// `kb` is the knowledge in effect, passed in rather than read from the
    /// process-wide static — the shipped description this falls back to
    /// (`shipped_tool_action`) lives in `kb`, and a caller such as a test
    /// must be able to supply its own instead of whatever `guards::in_effect`
    /// resolved to for the whole process.
    pub fn tool_decision(&self, tool: &str, kb: &crate::guards::Knowledge) -> (Action, ToolReason) {
        if let Some(a) = self.tools.get(tool) {
            return (*a, ToolReason::ConfigNamed);
        }
        // No config file at all is not the same as a real config that merely
        // names no tools yet. The latter predates tool gating and may fall
        // back to the shipped recognition (below); the former means nothing
        // has been allowed — full stop, whatever knowledge.toml claims a tool
        // does. Checked before the empty-tools fallback so it always wins.
        if self.no_config_file {
            return (Action::Ask, ToolReason::NoConfig);
        }
        // A config written before tools were gated says nothing about them. That
        // is not the same as saying "ask about everything" — it is silence, and
        // filling silence with a flood of prompts is how a correct rule gets
        // switched off wholesale. So when a config names NO tools at all, the
        // shipped recognition applies; the moment it names any, it governs
        // completely and the shipped list is ignored.
        if self.names_no_tools() {
            let described = crate::guards::tool_or_server_entry(kb, tool).is_some();
            let reason = if described { ToolReason::Described } else { ToolReason::Unmodeled };
            return (shipped_tool_action(tool, kb), reason);
        }
        (Action::Ask, ToolReason::ConfigGovernsOthers)
    }

    /// True when the operator's `[tools]` section names nothing — the state
    /// in which shipped descriptions still govern, and in which naming a
    /// FIRST tool flips the section into governing every tool (see
    /// `tool_decision`). The prompt that suggests adding that first line
    /// must be able to say so (M2.12). `tools` is public; this exists so the
    /// call site says what the emptiness MEANS, not to grant access.
    pub fn names_no_tools(&self) -> bool {
        self.tools.is_empty()
    }

    // [review] `names_tool` was here and nothing called it — not the binary,
    // not a test. It answered "does the config name this tool", which is
    // exactly the second, independent check that `ToolReason` exists to
    // remove: a caller re-deriving why a decision happened instead of taking
    // the reason out of `tool_decision`, which is how the prompt came to
    // claim knowledge.toml had said something it never said. Deleted rather
    // than kept, so it cannot be picked up as the convenient-looking answer.

    /// Unset construct → Ask, never Allow.
    pub fn construct_action(&self, lang: &str, name: &str) -> Action {
        self.langs
            .get(lang)
            .and_then(|l| l.constructs.get(name))
            .copied()
            .unwrap_or(Action::Ask)
    }

    /// The action for a construct ONLY if the config actually names it.
    ///
    /// Lets a caller tell "the user set this" apart from "nothing was said", so
    /// a construct added after a config was written can fall back to a policy
    /// the user DID declare instead of to one vouch picked for them.
    pub fn named_construct_action(&self, lang: &str, name: &str) -> Option<Action> {
        self.langs
            .get(lang)
            .and_then(|l| l.constructs.get(name))
            .copied()
    }

    /// Unset guard → Ask. A guard describes what a command does, so an unset one
    /// must interrupt, never pass.
    pub fn guard_action(&self, name: &str) -> Action {
        self.guards.get(name).copied().unwrap_or(Action::Ask)
    }

    // --- convenience for existing call sites -------------------------------
    pub fn bash(&self) -> LangConfig {
        self.langs.get("bash").cloned().unwrap_or_default()
    }
}

/// The action for a harness tool when the config expresses no tool policy.
///
/// The names live in `knowledge.toml` as data, like every other name vouch
/// knows. There are no tool names in this file, for the same reason there are no
/// command names in `guards.rs`: a name in source is a rule that cannot be
/// changed, inspected, or overridden without a rebuild. `kb` is the knowledge
/// to read those names from — passed in, not read from the process-wide
/// static, so a caller can supply its own instead of whatever
/// `guards::in_effect` resolved to for the whole process.
///
/// The lookup is `guards::entry_for`, so a whole-server grant recognises the
/// tools it covers exactly as a per-tool entry does — otherwise a server
/// entry with nothing else in it would describe a tool that still asked as
/// though undescribed, and the operator's stated grant would do nothing.
pub fn shipped_tool_action(tool: &str, kb: &crate::guards::Knowledge) -> Action {
    match crate::guards::tool_or_server_entry(kb, tool) {
        Some(t) => t.action.unwrap_or(Action::Allow),
        None => Action::Ask,
    }
}

/// The JSON Schema for `config.toml`, generated from `Raw` — the same struct
/// `load` deserializes into, so the schema can never describe a shape the
/// loader does not actually accept. `Raw` stays private; the schema is the
/// only thing about its shape this module exposes to a caller outside it.
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Raw)
}

pub fn load(text: &str) -> Result<Config, String> {
    let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
    if raw.bash.is_some() || raw.powershell.is_some() {
        return Err(
            "config uses the old [bash]/[powershell] spelling; these sections are now \
             [lang.bash]/[lang.powershell] — same keys, new table name"
                .to_string(),
        );
    }
    let cfg = Config {
        langs: raw.lang,
        guards: raw.guards,
        run: raw.run,
        write: raw.write,
        protected: raw.protected.paths,
        tools: raw.tools,
        shadow: raw.shadow,
        no_config_file: false,
    };
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<(), String> {
    let known = |g: &str| crate::guards::KNOWN_GUARDS.contains(&g);
    for g in cfg.guards.keys() {
        if !known(g) {
            return Err(format!("[guards] names '{g}', which is not a known guard"));
        }
    }
    for o in &cfg.run.guard_overrides {
        if o.under.is_empty() {
            return Err("[[run.guards]] has an empty `under` list".into());
        }
        for g in o.actions.keys() {
            if !known(g) {
                return Err(format!("[[run.guards]] names '{g}', which is not a known guard"));
            }
        }
        if o.actions.is_empty() {
            return Err("[[run.guards]] sets no guard action".into());
        }
    }
    for (name, list) in [
        ("run.trust_all_under", &cfg.run.trust_all_under),
        ("run.trust_nothing_under", &cfg.run.trust_nothing_under),
    ] {
        if matches!(list, Some(v) if v.is_empty()) {
            return Err(format!("{name} is an empty list — a rule that can never apply; remove the line or fill it"));
        }
    }
    for s in &cfg.write.scope {
        if s.only_under.is_empty() {
            return Err("[[write.scope]] only_under is an empty list".into());
        }
        if s.programs.is_empty() {
            return Err("[[write.scope]] names no programs".into());
        }
    }
    // Exact contradictions (spec §Overlaps tier 1). Textual comparison after
    // case/separator folding — $PROJECT_ROOT aliasing is doctor's job, not
    // load's (expansion needs a machine context load does not have).
    let fold = |p: &String| p.replace('\\', "/").to_lowercase();
    let empty: Vec<String> = Vec::new();
    let opposing = [
        ("run.trust_all_under", cfg.run.trust_all_under.as_ref().unwrap_or(&empty),
         "run.trust_nothing_under", cfg.run.trust_nothing_under.as_ref().unwrap_or(&empty)),
        ("write.allow_paths", &cfg.write.allow_paths, "write.ask_paths", &cfg.write.ask_paths),
        ("write.allow_paths", &cfg.write.allow_paths, "write.deny_paths", &cfg.write.deny_paths),
    ];
    for (an, a, bn, b) in opposing {
        for pa in a.iter() {
            if b.iter().any(|pb| fold(pa) == fold(pb)) {
                return Err(format!(
                    "'{pa}' appears in both {an} and {bn} — the config says two opposite \
                     things about one tree; fix it (the vouch-reconcile skill guides this)"
                ));
            }
        }
    }
    // [shadow] — mode-keyed shadow. Every refusal is about the feature's own
    // switch, so nothing here may default silently (design, config rules 2-4).
    if let Some(s) = &cfg.shadow {
        let Some(toggle) = s.stand_down else {
            return Err("[shadow] has no stand_down — say which state you mean: \
                        \"keep-deny\", \"full\", or \"off\""
                .into());
        };
        if let Some(modes) = &s.modes {
            if modes.is_empty() {
                return Err("[shadow] modes is an empty list — a written empty list can \
                            only be a mistake; name the modes or remove the line"
                    .into());
            }
            for m in modes {
                if !PERMISSION_MODES.contains(&m.as_str()) {
                    // The list comes from the const the check itself reads, so
                    // the refusal can never name a set of spellings different
                    // from the one that decided it.
                    return Err(format!(
                        "[shadow] modes names '{m}', which is not a permission mode this \
                         vouch knows; the spellings: {}",
                        PERMISSION_MODES.join(", ")
                    ));
                }
            }
        } else if toggle != StandDown::Off {
            return Err("[shadow] stand_down is armed but no modes are named — list the \
                        modes that stand vouch down, or set stand_down = \"off\""
                .into());
        }
    }
    Ok(())
}

/// The `[[write.scope]]` checks that need the KNOWLEDGE, kept out of
/// `validate` because `load` has only the config text (spec §Validation and
/// version skew).
///
/// A two-token entry ("prog verb") can only work if vouch can locate the verb,
/// and locating it needs the program's argument grammar: `guards::subcommand_of`
/// takes the first token that is neither a flag nor a `value_options` flag's
/// VALUE, so with no `value_options` declared for the program it picks a
/// flag's value as often as it picks the verb. A rule that matches the wrong
/// token is a scope that silently governs the wrong writes, so it refuses at
/// load instead.
///
/// `kb` is passed in rather than read from `guards::in_effect()` for the same
/// reason `shipped_tool_action` takes it: the process-wide static is not the
/// knowledge every caller means.
pub fn validate_scopes(cfg: &Config, kb: &crate::guards::Knowledge) -> Result<(), String> {
    // Every (program, verb, second word) already named, with the entry that
    // named it. A second entry naming the same triple is refused: the engine
    // takes the FIRST rule that names a command, so the second one never judges
    // anything and swapping the two in the file changes the verdict. That is
    // the same defect as two my-knowledge entries for one name, and it gets the
    // same remedy — one entry carrying both trees (spec §Overlaps tier 1: a
    // config that says two things about one subject is refused by name).
    //
    // An entry that CONTAINS a longer one (`git` beside `git init`, or `git
    // worktree` beside `git worktree add`) is deliberately not refused here:
    // the wider rule still judges every other operation, so it is inert only
    // where the two meet. That is tier 2 — precedence making a rule partly
    // inert — and it belongs in doctor's overlap bucket, which lists what
    // shadows what.
    let mut seen: Vec<(ScopeWords, usize)> = Vec::new();
    for (i, s) in cfg.write.scope.iter().enumerate() {
        for entry in &s.programs {
            let (head, sub, then) = split_program(entry);
            if head.is_empty() {
                return Err("[[write.scope]] programs contains an empty name".into());
            }
            // A fourth word cannot mean anything: the knowledge file's grammar
            // names a verb and at most one word after it, so an entry with more
            // could never match and would sit in the config looking like a rule.
            if entry.split_whitespace().count() > 3 {
                return Err(format!(
                    "[[write.scope]] names '{entry}' — an entry is a program, optionally a verb, \
                     and optionally that verb's second word (\"git worktree add\"); nothing \
                     would ever match this one"
                ));
            }
            // Folded the way the engine matches, so a case-varied spelling of
            // the same program is caught as the duplicate it is.
            let fold = |w: Option<&str>| w.map(str::to_lowercase);
            let key = (crate::guards::base_name(head), fold(sub), fold(then));
            if let Some((_, first)) = seen.iter().find(|(k, _)| k == &key) {
                return Err(if *first == i {
                    format!("[[write.scope]] names '{entry}' twice in one programs list")
                } else {
                    format!(
                        "[[write.scope]] names '{entry}' in two entries — only the first would \
                         ever judge it, so the order of the file would decide the verdict; put \
                         both trees in ONE entry's only_under"
                    )
                });
            }
            seen.push((key, i));
            // A program alone needs no grammar. Naming a verb — or a verb and
            // its second word — means vouch has to LOCATE that verb in a
            // command, and locating it needs the program's argument grammar:
            // `subcommand_of` takes the first token that is neither a flag nor
            // a `value_options` flag's VALUE, so with no `value_options`
            // declared it picks a flag's value as often as it picks the verb.
            let Some(sub) = sub else { continue };
            // The same union `subcommand_of` reads, spelled the same way it
            // spells it — the knowledge's own name lowercased, compared to
            // `base_name` of the head. Empty means no entry describes the
            // grammar, which includes the case where no entry describes the
            // program at all.
            let head = crate::guards::base_name(head);
            let described = kb.program.iter().any(|p| {
                !p.value_options.is_empty()
                    && p.match_names.iter().any(|n| n.to_ascii_lowercase() == head)
            });
            if !described {
                return Err(format!(
                    "[[write.scope]] names '{entry}', but nothing describes {head}'s argument \
                     grammar (`value_options` in the knowledge), so vouch cannot tell which \
                     token is the '{sub}' verb — scope the program alone (\"{head}\"), or \
                     describe {head} in your my-knowledge file first"
                ));
            }
        }
    }
    Ok(())
}

/// `Action` ranked the same way `engine::rank` ranks it (Allow < Ask < Deny,
/// "worst wins"). Not shared with that function — it is private to
/// `engine.rs`, which is decision code, and a doctor-only change (this one)
/// must never have a reason to touch decision code (CLAUDE.md's baseline
/// discipline). If the two orders ever disagree, that is a bug in one of
/// them to fix directly, not a reason for a third copy.
fn action_rank(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

/// The action, as the config spells it — the word an operator would type.
/// Same convention as `engine::action_word` (private there, decision code —
/// see `action_rank`, above, for why this is a second copy on purpose rather
/// than a shared one). `{action:?}` would print `Allow`, the Rust variant
/// name, not `allow`, the TOML spelling; a doctor message telling an operator
/// what to type has to use the word they would actually type.
fn action_word(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Ask => "ask",
        Action::Deny => "deny",
    }
}

/// Place-scoped rules that can never fire because a wider or opposing rule
/// already answers first (spec 2026-08-06 §Overlaps tier 2). None of these
/// are refused at load — each line is a legal rule on its own, and only once
/// it is expanded against THIS machine's home and project root, alongside
/// every OTHER rule in the same config, does it turn out to be unreachable.
///
/// Five shapes, each a pattern (or override, or scope entry) sitting entirely
/// inside another rule that answers first:
///   1. a `run.trust_all_under` grant nested inside a `run.trust_nothing_under`
///      zone — the zone is checked first (spec §Precedence), so the grant can
///      never fire there.
///   2. a `write.allow_paths` entry nested inside a `write.deny_paths` wall —
///      the wall is checked first, so the entry can never allow there.
///   3. a loosening `[[run.guards]]` override (an action ranked BELOW the
///      guard's global action) whose `under` sits entirely inside a
///      `run.trust_nothing_under` zone — the zone forces at least `ask`
///      everywhere under it, capping whatever the override would loosen to.
///   4. a `write.ask_paths` entry nested inside a `write.deny_paths` wall —
///      legal at load (only exact opposing pairs refuse there; ask/deny may
///      overlap, and deny wins by being checked first), but an ask entry
///      entirely inside a deny wall can never ask, because deny answers
///      first every time.
///   5. a `[[write.scope]]` entry with an earlier, WIDER entry for the same
///      program — one that states strictly fewer words, all of which agree:
///      `"git"` before `"git init"`, or `"git worktree"` before `"git
///      worktree add"`. The engine takes the first `[[write.scope]]` entry
///      that names a command (see `engine.rs`'s
///      `cfg.write.scope.iter().find(...)`), so the wider entry, being
///      earlier, matches first and the narrower one never separately judges
///      the operation it names. One rule at every depth, not a case per depth.
///
/// Each finding names the inert line, what shadows it, and ends pointing at
/// the reconciliation skill — the same skill the exact-contradiction refusal
/// in `validate`, above, names.
pub fn inert_place_rules(cfg: &Config, home: &str, project_root: Option<&str>) -> Vec<String> {
    let root = |expanded: &str| expanded.strip_suffix("/**").unwrap_or(expanded).to_string();
    // Whether an INNER pattern's whole set sits inside an OUTER one. The two
    // sides are not symmetric: a `/**` outer names a tree, so anything at or
    // under its root is inside it; an outer with no `/**` names exactly ONE
    // path, so nothing is "inside" it except that identical path. [review]
    // The first version rooted both sides the same way and compared roots
    // with `starts_with`, which made an EXACT outer (`deny_paths =
    // ["C:/x/exact-file"]`) swallow a glob entirely below it
    // (`allow_paths = ["C:/x/exact-file/nested/**"]`) — "exact-file/nested"
    // starts with "exact-file/" as a STRING even though "exact-file" is a
    // single path with nothing under it, not a directory. `decide_file`
    // never treated it that way, so doctor was flagging a rule that still
    // fired.
    let contained = |inner_root: &str, outer_expanded: &str| {
        let inner = crate::paths::fold_case(inner_root);
        match outer_expanded.strip_suffix("/**") {
            Some(outer_root) => {
                let outer_root = crate::paths::fold_case(outer_root);
                inner == outer_root || inner.starts_with(&format!("{outer_root}/"))
            }
            // No `/**`: outer names one path, so only that exact path is
            // "inside" it — never a `starts_with` prefix match.
            None => inner == crate::paths::fold_case(outer_expanded),
        }
    };
    // Every pattern, expanded: the text as written, and its root (the
    // expanded form minus a trailing `/**`) — the root is what the INNER
    // side of `contained` compares, whatever the pattern's own shape.
    let expand_all = |patterns: &[String]| -> Vec<(String, String)> {
        patterns
            .iter()
            .filter_map(|p| crate::paths::expand_pattern(p, home, project_root).map(|e| (p.clone(), e)))
            .collect()
    };

    let mut out = Vec::new();

    // Every pattern of one list that sits entirely inside a pattern of
    // another, reported in the second list's own words. Four of the five
    // shapes below are exactly this scan and differ only in the sentence, so
    // it is written once: a fifth hand-rolled copy is how one of them ends up
    // rooting or comparing its two sides differently from the rest.
    let mut report = |inner: &[(String, String)],
                      outer: &[(String, String)],
                      msg: &dyn Fn(&str, &str) -> String| {
        for (i_written, i_expanded) in inner {
            let i_root = root(i_expanded);
            for (o_written, o_expanded) in outer {
                if contained(&i_root, o_expanded) {
                    out.push(msg(i_written, o_written));
                }
            }
        }
    };

    // Expanded once each: the same list is both an inner and an outer side
    // below, and expanding it per check would be the same work answered twice.
    // An absent list expands to nothing, which reports nothing — the same
    // result the `if let Some(..)` guards used to produce.
    let empty: Vec<String> = Vec::new();
    let trust = expand_all(cfg.run.trust_all_under.as_ref().unwrap_or(&empty));
    let distrust = expand_all(cfg.run.trust_nothing_under.as_ref().unwrap_or(&empty));
    let allow = expand_all(&cfg.write.allow_paths);
    let ask = expand_all(&cfg.write.ask_paths);
    let deny = expand_all(&cfg.write.deny_paths);

    // 1: run.trust_all_under inside run.trust_nothing_under.
    report(&trust, &distrust, &|t, d| {
        format!(
            "run.trust_all_under '{t}' is entirely inside run.trust_nothing_under \
             '{d}' — the distrust zone is checked first, so it can never grant \
             trust there; the vouch-reconcile skill guides fixing this"
        )
    });

    // 2: write.allow_paths inside write.deny_paths.
    report(&allow, &deny, &|a, d| {
        format!(
            "write.allow_paths '{a}' is entirely inside write.deny_paths '{d}' — \
             the wall is checked first, so it can never allow a write there; the \
             vouch-reconcile skill guides fixing this"
        )
    });

    // 4: write.ask_paths inside write.deny_paths. Legal at load (only exact
    // opposing pairs refuse there — ask/deny overlap is a normal, intentional
    // shape, and deny wins by being checked first), but a line entirely
    // swallowed by the wall can never ask.
    report(&ask, &deny, &|a, d| {
        format!(
            "write.ask_paths '{a}' is entirely inside write.deny_paths '{d}' — deny \
             is checked first, so it can never ask there; the vouch-reconcile skill \
             guides fixing this"
        )
    });

    // 6: write.allow_paths inside write.ask_paths. The mirror of check 2, with
    // ask in place of deny: `decide_file_for`'s wall loop checks `deny_paths`
    // then `ask_paths`, both before `allow_paths` is ever consulted (spec
    // §Precedence), so an allow entirely inside the ask wall is just as inert
    // as one inside the deny wall — found by the final whole-branch review of
    // the place-scoped-rules changeset, which named this as the one of the
    // spec's five overlap shapes this bucket had not implemented.
    report(&allow, &ask, &|a, k| {
        format!(
            "write.allow_paths '{a}' is entirely inside write.ask_paths '{k}' — \
             ask is checked first, so it can never allow a write there; the \
             vouch-reconcile skill guides fixing this"
        )
    });

    // 3: a loosening [[run.guards]] override inside a run.trust_nothing_under
    // zone. "Loosening" means the override sets a guard to an action ranked
    // below the guard's own global action (`resolve_guard_action`'s
    // grant-shaped branch) — a restricting override inside the same zone is
    // NOT inert, because the zone only guarantees `ask`, and a restriction to
    // `deny` still has an effect there.
    for o in &cfg.run.guard_overrides {
        let under = expand_all(&o.under);
        for (guard, &action) in &o.actions {
            if action_rank(action) >= action_rank(cfg.guard_action(guard)) {
                continue;
            }
            report(&under, &distrust, &|u, d| {
                format!(
                    "[[run.guards]] override under '{u}' loosens {guard} to \
                     {}, entirely inside run.trust_nothing_under '{d}' — that \
                     zone forces at least ask everywhere under it, so the override \
                     can never loosen anything there; the vouch-reconcile skill \
                     guides fixing this",
                    action_word(action)
                )
            });
        }
    }

    // 5: a write.scope entry shadowed by an earlier, WIDER one for the same
    // program — `git` before `git init`, and now `git worktree` before `git
    // worktree add`. Wider means the earlier entry states strictly fewer
    // words while every word it does state agrees, which is exactly when it
    // matches everything the later one would have. Only the EARLIEST such
    // entry is named — it is the one `engine.rs`'s `.find()` actually reaches
    // first, so it is the one that shadows, whatever else follows it.
    let words = |e: &str| -> ScopeWords {
        let (h, s, t) = split_program(e);
        (crate::guards::base_name(h), s.map(str::to_lowercase), t.map(str::to_lowercase))
    };
    for (j, s2) in cfg.write.scope.iter().enumerate() {
        for e2 in &s2.programs {
            let (head2, sub2, then2) = words(e2);
            // What the later entry exists to single out, in its own words:
            // "init", or "worktree add". A one-word entry states nothing a
            // wider entry could have omitted, so nothing can shadow it.
            let narrow = match (&sub2, &then2) {
                (Some(s), Some(t)) => format!("{s} {t}"),
                (Some(s), None) => s.clone(),
                _ => continue,
            };
            let shadow = cfg.write.scope[..j].iter().enumerate().find_map(|(i, s1)| {
                s1.programs.iter().find_map(|e1| {
                    let (head1, sub1, then1) = words(e1);
                    // Strictly fewer words, and the ones it has agree.
                    let wider = head1 == head2
                        && match (&sub1, &then1) {
                            (None, _) => true,
                            (Some(_), None) => sub1 == sub2 && then2.is_some(),
                            (Some(_), Some(_)) => false,
                        };
                    wider.then(|| (i + 1, e1.clone()))
                })
            });
            if let Some((entry_num, e1)) = shadow {
                out.push(format!(
                    "[[write.scope]] entry {entry_num} ('{e1}') comes before entry {} ('{e2}') \
                     for the same program — vouch matches the first entry that names a command, \
                     so the wider entry matches first and '{e2}' can never separately \
                     judge {narrow}; the vouch-reconcile skill guides fixing this",
                    j + 1
                ));
            }
        }
    }

    out
}
