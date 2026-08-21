//! Routing: turn one hook input into one decision.
//!
//! Moved out of `main.rs` (M2.5 task 5) so tests can drive the real dispatch
//! instead of re-implementing it. Knowledge is taken as a parameter instead of
//! read from the process-wide static, so a test can inject its own; `main.rs`
//! still passes `guards::in_effect()`.
//!
//! The order a tool call is decided in (M2.5 task 7, spec 2026-08-05
//! §Decision flow) — config is the decisions layer, knowledge is the
//! descriptions layer, and nothing below is allowed to reverse that:
//!
//!   1. The config names the tool → the config decides, both directions.
//!   2. The entry describing it (its own, else its server's) declares
//!      snippets and/or a write path → those are decided, worst wins, and
//!      the entry's `action` caps what they can reach.
//!   3. An entry with no declarations → recognition, through
//!      `Config::tool_decision`'s branches.
//!   4. No entry at all → the unmodeled-tool ask.
//!
//! Every hole in step 2 — a missing field, an unreadable language, an
//! unresolvable path — is an ASK naming what was missing. None of them fall
//! through to recognition: an allow-list that allows what it could not read
//! is not an allow-list (CLAUDE.md §1).

use crate::config::{Action, Config, ToolReason};
use crate::engine::{decide_command_at, decide_command_in_unknown_dir, decide_file};
use crate::guards::{Knowledge, Tool};
use crate::snippet::Extracted;
use crate::protocol::{Decision, HookInput, ToolInput};
use serde_json::{Map, Value};

/// One decision, and the snippets it was decided from.
pub struct RouteOutcome {
    pub decision: Decision,
    /// (text, language) actually decided — journaled per-snippet by Task 9.
    /// Populated whenever extraction succeeded, whatever the verdict: the
    /// journal records what vouch looked at, not only what it allowed.
    pub snippets: Vec<(String, String)>,
}

/// Walks up from `cwd` looking for a repository root.
pub fn project_root(cwd: &str) -> Option<String> {
    let mut dir = std::path::PathBuf::from(cwd.replace('\\', "/"));
    loop {
        if dir.join(".git").exists() {
            return Some(dir.to_string_lossy().replace('\\', "/"));
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn decide(cfg: &Config, kb: &Knowledge, home: &str, input: &HookInput) -> RouteOutcome {
    let root = project_root(&input.cwd);
    // Every tool call, Bash and PowerShell included, flows through the same
    // declared-snippet/write-path decision flow (M2.5 task 8): `Bash` and
    // `PowerShell` are `[[tool]]` entries declaring `command` as a bash or
    // powershell snippet field, and `Write`/`Edit`/`NotebookEdit` declare
    // their write-path field, all in `knowledge.toml`. Saying NOTHING for an
    // unrecognised tool here was the same inversion as unmodelled programs,
    // one level up: 46.5% of recorded tool calls used to get no decision at
    // all, so the harness decided alone and vouch could not even report that
    // it had abstained. An unrecognised tool asks, and the prompt names the
    // setting, like everything else.
    decide_tool(cfg, kb, home, input, root.as_deref(), &input.tool_name)
}

/// Steps 1-4 of the decision flow, for one tool call.
fn decide_tool(
    cfg: &Config,
    kb: &Knowledge,
    home: &str,
    input: &HookInput,
    root: Option<&str>,
    tool: &str,
) -> RouteOutcome {
    let server = crate::guards::server_entry_for(kb, tool);
    // Exact beats server for recognition, whatever the file order.
    let entry = crate::guards::tool_or_server_entry(kb, tool);
    let (action, why) = cfg.tool_decision(tool, kb);

    // 1. The config names this tool: it decides, both directions, before any
    //    snippet is read. This is the operator's off-switch for snippet
    //    inspection, and the one honest answer to "what setting turns this
    //    prompt off" — which is why the prompt that offers it says what it
    //    really grants.
    if why == ToolReason::ConfigNamed {
        return RouteOutcome {
            decision: undeclared(cfg, entry, tool, action, why),
            snippets: Vec::new(),
        };
    }

    // 2. Declarations decide. An entry that declares snippets or a write path
    //    is never "ungoverned" when the config names some OTHER tool: its
    //    snippet decision IS its governance, so it is exempt from
    //    `ConfigGovernsOthers`. Without that exemption, naming one MCP tool in
    //    config would flip every declared tool — every bash command on the
    //    machine, once Task 8 makes `Bash` an entry — to ask.
    let declared = entry.filter(|e| e.snippet.is_some() || e.write_path_field.is_some());
    let Some(declared) = declared else {
        // 3. and 4.: an entry with nothing declared, or no entry at all. The
        //    existing branches decide, UNCHANGED — the entry's own `action`
        //    has already been consulted there, by `shipped_tool_action`, and
        //    only in the branch where the shipped description is in play.
        //    Capping here would answer past the branch that decided: an entry
        //    set to deny would deny even when the config governing OTHER tools
        //    was what produced the ask, and even when there is no config file
        //    at all — the second of those printing "set tools.X = allow" about
        //    a file that does not exist. The cap belongs to the declared path,
        //    where there are snippet verdicts to cap.
        let decision = undeclared(cfg, entry, tool, action, why);
        // The one claim those branches cannot express: a whole-server stop
        // covers every tool the server exposes, and an exact entry claiming
        // bare recognition must not silently override it (spec §Server entry
        // rule 4). Confined to `Described`, the branch where the shipped
        // description is what decided — never over a config-driven verdict.
        // `Unmodeled` means no entry was found at all, so there is no server
        // entry to cap with either.
        let decision =
            if why == ToolReason::Described { cap(decision, server, tool) } else { decision };
        return RouteOutcome { decision, snippets: Vec::new() };
    };

    let (mut decision, snippets) = decide_declared(cfg, home, input, root, tool, declared);

    // The entry's own `action` caps the best verdict its declarations can
    // reach: "vouch knows what this is and stops anyway" has to keep meaning
    // that even when every snippet passed. A restrictive SERVER action caps
    // every tool of that server, exact entries included — a whole-server stop
    // means the whole server, and a more specific entry must not silently
    // override the operator's stated stop.
    decision = cap(decision, entry, tool);
    decision = cap(decision, server, tool);
    RouteOutcome { decision, snippets }
}

/// Decide one call on everything its entry declares. Every declaration is
/// evaluated and the worst verdict governs — they compose, they are not
/// alternatives.
fn decide_declared(
    cfg: &Config,
    home: &str,
    input: &HookInput,
    root: Option<&str>,
    tool: &str,
    entry: &Tool,
) -> (Decision, Vec<(String, String)>) {
    let fields = merged_fields(&input.tool_input);
    // Only when the entry CLAIMS the tool runs in the calling session's own
    // directory does the call's cwd reach the decision (spec §Schema rule 4).
    // Without the claim a relative target is genuinely unresolvable, and
    // guessing that it means the caller's directory would be inventing a fact
    // about someone else's server.
    // An empty cwd is no cwd. Composing against it produced `/notes/x.txt`
    // for a write path — a root-relative path the call never named — and the
    // engine reads it as "no directory" anyway, so the two would have
    // disagreed about the same call.
    let cwd = if entry.cwd_from_call == Some(true) {
        Some(input.cwd.as_str()).filter(|d| !d.is_empty())
    } else {
        None
    };

    let mut worst: Option<Decision> = None;
    let mut snippets = Vec::new();

    match entry.snippet.as_deref() {
        // `Some(vec![])` is a load error (`knowledge::validate_tool` refuses
        // the whole file), so this arm only fires for knowledge built by a
        // test calling `guards::load` directly. It asks anyway: the empty
        // list used to be FILTERED OUT here, which removed the declaration
        // instead of failing on it, and an entry declaring an empty snippet
        // BESIDE a write path that independently allowed then allowed the
        // call with the declaration silently unread — the one hole in step 2
        // that did not ask, against the module doc above saying every one of
        // them does.
        Some([]) => {
            worst = worse(
                worst,
                Decision::Ask(format!(
                    "vouch stopped on: snippet\n  \
                     tool: {tool}\n  \
                     this tool's entry declares a snippet list with nothing in it, so it names \
                     nothing for vouch to read and cannot say what this call does{}",
                    blanket(tool)
                )),
            );
        }
        Some(declared) => match crate::snippet::extract(declared, &fields) {
            Extracted::Ok(pairs) => {
                for (text, lang) in &pairs {
                    worst = worse(worst, decide_snippet(cfg, home, root, cwd, tool, text, lang));
                }
                snippets = pairs;
            }
            Extracted::Refused(what) => {
                worst = worse(
                    worst,
                    Decision::Ask(format!(
                        "vouch stopped on: snippet\n  \
                         tool: {tool}\n  \
                         {what}\n  \
                         vouch recognises this tool and knows which field carries its snippet, \
                         but that field could not be read, so it cannot say what this call \
                         does{}",
                        blanket(tool)
                    )),
                );
            }
        },
        None => {}
    }

    if let Some(field) = &entry.write_path_field {
        worst = worse(worst, decide_write_field(cfg, home, root, cwd, tool, field, &fields));
    }

    // Ask is the empty fold's identity (spec §Schema rule 5): a declaration
    // that produced nothing to decide on is a hole, not a pass.
    let decision = worst.unwrap_or_else(|| {
        Decision::Ask(format!(
            "vouch stopped on: snippet\n  \
             tool: {tool}\n  \
             this tool's entry declares what to inspect, but the call produced nothing to \
             decide on{}",
            blanket(tool)
        ))
    });
    (decision, snippets)
}

/// Why a snippet's relative destinations cannot be placed when its entry
/// makes no `cwd_from_call` claim. Reads as the tail of the engine's
/// "vouch cannot tell which directory this command's writes land in — …"
/// sentence, and names the line that would settle it, exactly as the
/// write-path prompt one level up does.
const NO_CWD_CLAIM: &str =
    "this tool's entry does not claim the tool runs in the calling session's directory, so \
     nothing says where a relative path starts (if the tool does run there, add \
     cwd_from_call = true to its entry in my-knowledge.toml — only if that is true of the tool)";

/// One extracted snippet text, in the language its declaration resolved to.
fn decide_snippet(
    cfg: &Config,
    home: &str,
    root: Option<&str>,
    cwd: Option<&str>,
    tool: &str,
    text: &str,
    lang: &str,
) -> Decision {
    // Ask the registry, not a hand-matched language list: a language with its
    // own scanner (bash, powershell, python, ...) is decided through the
    // engine exactly like a typed command; a language the registry has never
    // heard of (javascript, today) has nothing that can read it and asks
    // here, naming what it is missing.
    if crate::syntax::scanner_for(lang).is_none() {
        return unreadable_language(cfg, tool, lang);
    }
    // Guards, `[write]` rules, wrapper expansion, protected paths and
    // recognition all apply to the snippet exactly as they do to a typed
    // command — it is the same engine, on text that arrived by another
    // route.
    //
    // Which of the two entry points is the whole `cwd_from_call` claim (spec
    // 2026-08-05 §Schema rule 4). Without the claim there is no directory
    // this snippet's relative writes can be placed in, and "as written" is
    // not an answer — `decide_file` canonicalises a relative target against
    // the VOUCH PROCESS's own current directory, so the same call decided
    // from two different directories got two different verdicts, and one of
    // them was allow. Unresolvable is what it is, so unresolvable is what it
    // says.
    let decided = match cwd {
        Some(dir) => decide_command_at(cfg, lang, text, Some(home), root, Some(dir)),
        None => decide_command_in_unknown_dir(cfg, lang, text, Some(home), root, NO_CWD_CLAIM),
    };
    match decided {
        // The no-scanner arm returns Abstain, which renders as no output at
        // all and hands the call to the harness. It is unreachable from here
        // — the registry check above only lets a language THIS engine can
        // scan through, and load validation keeps a typo'd language name out
        // of the file entirely — so this arm exists to make sure that if the
        // two ever drift apart, the result is a prompt rather than a silent
        // pass.
        Decision::Abstain => unreadable_language(cfg, tool, lang),
        other => other,
    }
}

/// The path this tool says it writes, read from the same merged field map the
/// snippets came from.
fn decide_write_field(
    cfg: &Config,
    home: &str,
    root: Option<&str>,
    cwd: Option<&str>,
    tool: &str,
    field: &str,
    fields: &Map<String, Value>,
) -> Decision {
    let target = match fields.get(field) {
        Some(Value::String(s)) if !s.trim().is_empty() => s.replace('\\', "/"),
        // Naming which of the three it was, because they are three different
        // things to go and fix: a wrong field name in the entry, a call that
        // omitted it, a value that is not a path at all.
        found => {
            let what = match found {
                None => "this call sends no such field",
                Some(Value::String(_)) => "this call's value for it is empty",
                Some(_) => "this call's value for it is not a string",
            };
            return Decision::Ask(format!(
                "vouch stopped on: write path\n  \
                 tool: {tool}\n  \
                 field: {field}\n  \
                 this tool's entry says it writes the path named by that field, and {what}, so \
                 vouch cannot say which file it means{}",
                blanket(tool)
            ));
        }
    };
    if is_absolute(&target) {
        return decide_file(cfg, home, root, &target);
    }
    match cwd {
        Some(dir) => decide_file(
            cfg,
            home,
            root,
            &format!("{}/{}", dir.replace('\\', "/").trim_end_matches('/'), target),
        ),
        // Fail closed: the path is relative to a directory nobody stated.
        None => Decision::Ask(format!(
            "vouch stopped on: write path\n  \
             tool: {tool}\n  \
             field: {field}\n  \
             path: {target}\n  \
             the path is relative, and this tool's entry does not claim the tool writes in the \
             calling session's directory, so vouch cannot say which file it means\n  \
             if the tool does write there, add cwd_from_call = true to its entry in \
             my-knowledge.toml — only if that is true of the tool{}",
            blanket(tool)
        )),
    }
}

/// A snippet in a language vouch has no scanner for. It recognises the tool
/// and found the snippet; what it cannot do is read it (M1.4).
///
/// The command-path wrapper walk raises exactly this defect — a located
/// snippet in a language nothing can scan — as the `unreadable_language`
/// construct, settable per language at `lang.<lang>.constructs.<name>`
/// (spec 2026-08-14 §5.2). There is no HOST scan on the tool-call path the
/// way there is on the command path (a tool's snippet field is not text
/// found partway through scanning something else), so the language this
/// gates on is the snippet's own declared, unscannable one — but it is the
/// SAME setting either way: setting
/// `lang.javascript.constructs.unreadable_language = "allow"` allows every
/// javascript snippet from now on, in any tool AND in any wrapped shell
/// command alike. Unset defaults to Ask, same as
/// before this setting existed — this is a refinement of an already-correct
/// prompt, not a repair of one that lacked a setting (CLAUDE.md §5 was
/// already satisfied by the blanket `tools.<name>` switch below).
fn unreadable_language(cfg: &Config, tool: &str, lang: &str) -> Decision {
    let body = format!(
        "vouch stopped on: snippet language\n  \
         tool: {tool}\n  \
         language: {lang}\n  \
         construct: unreadable_language\n  \
         this tool's entry recognises the call and names the field carrying its snippet, but \
         vouch has no {lang} scanner yet, so it cannot say what this snippet does\n  \
         to allow every {lang} snippet from now on, in any tool, set \
         lang.{lang}.constructs.unreadable_language = \"allow\"{}",
        blanket(tool)
    );
    match cfg.construct_action(lang, "unreadable_language") {
        Action::Allow => {
            Decision::Allow(format!("lang.{lang}.constructs.unreadable_language = \"allow\""))
        }
        Action::Deny => Decision::Deny(body),
        Action::Ask => Decision::Ask(body),
    }
}

/// The one off-switch every snippet-side prompt names, and what it really
/// costs. `tools.<name> = "allow"` is not a rule about this call — it allows
/// every future call of the tool with nothing looked at — and a prompt that
/// offered it without saying so would be steering the operator into exactly
/// the blind grant snippet inspection exists to remove.
fn blanket(tool: &str) -> String {
    format!(
        "\n  to allow this tool from now on, set tools.{tool} = \"allow\"\n  \
         careful: that is a blanket grant — it allows EVERY call of this tool, snippet unseen"
    )
}

/// Raise `decision` to an entry's declared `action` when that action is
/// worse. An action never LOWERS a verdict: `action` unset (or `allow`) is a
/// recognition claim about the tool, never permission for whatever its
/// snippet turned out to contain.
///
/// Which sentence the prompt says is read off the entry itself — a `server`
/// entry stops the call for a different reason than the tool's own entry
/// does, and the operator is owed the one that is true.
fn cap(decision: Decision, entry: Option<&Tool>, tool: &str) -> Decision {
    let Some(e) = entry else { return decision };
    let Some(action) = e.action else { return decision };
    // `Action::Allow` ranks 0, so this returns for it without a special case:
    // no decision is ever worse than allow, and none is ever lowered to it.
    if rank(&decision) >= rank_of(action) {
        return decision;
    }
    let verb = match action {
        Action::Deny => "deny",
        _ => "ask",
    };
    let what = if e.source.is_empty() {
        "vouch has no description of what this tool does"
    } else {
        e.source.as_str()
    };
    let reason = match &e.server {
        Some(server) => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what that server is: {what}\n  \
             the entry for the whole server {server} is set to {verb}, and a whole-server stop \
             covers every tool the server exposes — including ones with an entry of their own\n  \
             to allow this one tool from now on, set tools.{tool} = \"allow\"\n  \
             that setting applies to EVERY use of this tool"
        ),
        None => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what it does: {what}\n  \
             this is described in knowledge.toml and set to {verb} there, so vouch is stopping \
             on purpose rather than because it does not recognise it — an entry set to {verb} \
             caps what its snippets can allow\n  \
             to allow it from now on, set tools.{tool} = \"allow\"\n  \
             that setting applies to EVERY use of this tool"
        ),
    };
    match action {
        Action::Deny => Decision::Deny(reason),
        _ => Decision::Ask(reason),
    }
}

/// How bad a decision is. Abstain ranks with Allow deliberately: it is not
/// reachable on the tool path, and ranking it lowest means a cap REPLACES it
/// rather than letting an emit-nothing stand if it ever became reachable.
fn rank(d: &Decision) -> u8 {
    match d {
        Decision::Allow(_) | Decision::Abstain => 0,
        Decision::Ask(_) => 1,
        Decision::Deny(_) => 2,
    }
}

fn rank_of(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Ask => 1,
        Action::Deny => 2,
    }
}

/// Worst wins. Equal ranks keep what was already there, so the reason the
/// operator reads comes from the first declaration that reached that verdict.
fn worse(current: Option<Decision>, next: Decision) -> Option<Decision> {
    match current {
        Some(c) if rank(&c) >= rank(&next) => Some(c),
        _ => Some(next),
    }
}

/// `extra` with the three typed fields put back. Serde's `flatten` only
/// receives the keys `ToolInput` did NOT consume, so without this a
/// declaration of `field = "command"` could never match anything — and Task 8
/// gives `Bash` exactly that declaration, so every bash call on the machine
/// would ask.
fn merged_fields(t: &ToolInput) -> Map<String, Value> {
    let mut fields = t.extra.clone();
    for (name, value) in [("command", &t.command), ("file_path", &t.file_path), ("url", &t.url)] {
        if let Some(v) = value {
            fields.insert(name.to_string(), Value::String(v.clone()));
        }
    }
    fields
}

/// A path that already says where it starts, in any spelling the resolver
/// downstream understands. `~` and `$` are included because expansion happens
/// after this, and prefixing either with a working directory would produce a
/// path that resolves to nothing.
fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('~')
        || path.starts_with('$')
        || (path.len() > 1 && path.as_bytes()[1] == b':')
}

/// The server segment of an MCP-routed tool NAME, if the name is shaped like
/// one: `mcp__<server>__<tail>`. This is a string-shape test on the incoming
/// name — every harness that routes calls through MCP spells them this way,
/// so recognising the shape recognises the harness's own naming convention,
/// not any particular program or tool (CLAUDE.md: no tool names in `src/`).
/// Mirrors the tail constraint `guards::server_entry_for` matches an actual
/// entry against, but this runs with no entry in hand at all — it only says
/// what the NAME looks like, which is why the unmodeled-tool prompt can use
/// it before any `[[tool]]` lookup has found anything.
///
/// `pub`, not module-private: `main.rs`'s `vouch trust` reuses this exact
/// shape test (Task 11) to decide whether an mcp-shaped name has a tool tail
/// to trust narrowly, or is only the server half and needs `--whole-server`
/// said out loud. Duplicating the split here a second time would let the two
/// callers' ideas of "shaped like a real tool" drift apart.
pub fn mcp_server_of(tool: &str) -> Option<&str> {
    let rest = tool.strip_prefix("mcp__")?;
    let (server, tail) = rest.split_once("__")?;
    (!server.is_empty() && !tail.is_empty()).then_some(server)
}

/// A tool with no declarations to decide on: the entry's own recognition, or
/// the absence of one, through `Config::tool_decision`'s branches.
fn undeclared(
    cfg: &Config,
    entry: Option<&Tool>,
    tool: &str,
    a: Action,
    why: ToolReason,
) -> Decision {
    // What the prompt can say this tool DOES — and, when the description came
    // from a whole-server grant, that it did. Without that clause the sentence
    // reads as though someone had described this tool one by one, and the
    // operator looking for the line that produced the prompt would not find
    // one (CLAUDE.md §5: the prompt names what turns it off, which means the
    // operator has to be able to FIND it).
    let described = entry.map(|t| match &t.server {
        Some(server) => format!("{} (from the entry for the whole server {server})", t.source),
        None => t.source.clone(),
    });
    // [review] This used to pick between two sentences based on
    // `described` alone, matching it against `a` as though the two
    // could only relate one way. They cannot be matched like that:
    // `described` says whether knowledge.toml has an entry; `why`
    // says which rule actually produced `a`, and those are
    // independent. A tool can be described AND ask for a reason that
    // has nothing to do with what knowledge.toml says — reported by
    // the reviewer, reproduced with `Read` (shipped, unset action, so
    // Allow) plus a config naming one unrelated tool: the decision
    // became Ask, and the old text still said "knowledge.toml ...
    // set to ask there", which was false. `why` is drawn from the
    // SAME computation that chose `a` (`Config::tool_decision`), so
    // the sentence and the verdict cannot drift apart again.
    let verb = match a {
        Action::Deny => "deny",
        _ => "ask",
    };
    let first_tool_warning = if cfg.names_no_tools() {
        "\n  careful: your config names no tools yet — the first tools.<Name> line makes \
         [tools] govern EVERY tool, so each tool it does not name will start asking. The \
         tools vouch currently recognises are the [[tool]] entries in knowledge.toml and \
         my-knowledge.toml — name each one you rely on in the same edit"
    } else {
        ""
    };
    let reason = match (&described, why) {
        (Some(what), ToolReason::ConfigGovernsOthers) => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what it does: {what}\n  \
             knowledge.toml describes this tool, but that is not what decided this: \
             your config's [tools] section names at least one OTHER tool, and naming \
             any tool makes that section govern EVERY tool — the shipped description \
             is out of play, so this one asks only because it is not named there\n  \
             to allow it, add tools.{tool} = \"allow\" to your config\n  \
             that setting applies to EVERY use of this tool"
        ),
        (Some(what), ToolReason::ConfigNamed) => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what it does: {what}\n  \
             knowledge.toml describes this tool, but your OWN config names it directly \
             (tools.{tool}) and that is what decided this, not knowledge.toml\n  \
             to allow it, set tools.{tool} = \"allow\""
        ),
        // No config file at all. Materially different from every case
        // above: those all presume a config exists and reason about
        // what IT says. Here nothing has been said, so nothing has
        // been allowed — whatever knowledge.toml happens to claim
        // about this tool is not what decided this, and the prompt
        // must not imply it was.
        (what, ToolReason::NoConfig) => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what it does: {}\n  \
             there is no vouch config file at all, so nothing has been allowed — not \
             even a tool knowledge.toml describes\n  \
             to allow it, create a config (`vouch import` writes a starting point) and \
             set tools.{tool} = \"allow\"\n  \
             that setting applies to EVERY use of this tool",
            what.as_deref().unwrap_or("vouch has no description of what this tool does")
        ),
        (Some(what), _) => format!(
            "vouch stopped on: tool\n  \
             tool: {tool}\n  \
             what it does: {what}\n  \
             this is described in knowledge.toml and set to {verb} there, so vouch \
             is stopping on purpose rather than because it does not recognise it\n  \
             to allow it from now on, set tools.{tool} = \"allow\"\n  \
             that setting applies to EVERY use of this tool{first_tool_warning}"
        ),
        // An MCP-shaped name gets a different first resort: recommend the
        // scoped per-tool entry before the blanket `tools.<name>` setting
        // even exists in the sentence (spec 2026-08-05 §Decision flow rule
        // 4). Non-MCP names keep the wording above, byte for byte — nothing
        // here is known about what THIS name is, only about the shape it is
        // spelled in.
        (None, _) => match mcp_server_of(tool) {
            Some(server) => format!(
                "vouch stopped on: unmodeled_tool\n  \
                 tool: {tool}\n  \
                 what that means: vouch has no scanner for this tool, so it cannot say \
                 what the call does\n  \
                 to recognise just this one, use the vouch-trust skill — it proposes the \
                 narrowest [[tool]] entry, shows exactly what it would trust, and writes \
                 it only on your accept\n  \
                 a `server = \"{server}\"` entry in knowledge.toml is the deliberate \
                 whole-server form instead — it recognises every tool the {server} server \
                 exposes at once, not just this one, so write that only if that is what \
                 you mean\n  \
                 to allow this one tool from now on, set tools.{tool} = \"allow\"\n  \
                 careful: that is a blanket grant — it allows EVERY call of this tool, \
                 snippet unseen{first_tool_warning}"
            ),
            None => format!(
                "vouch stopped on: unmodeled_tool\n  \
                 tool: {tool}\n  \
                 what that means: vouch has no scanner for this tool, so it cannot say \
                 what the call does\n  \
                 to allow this tool from now on, set tools.{tool} = \"allow\"\n  \
                 that setting applies to EVERY use of this tool{first_tool_warning}"
            ),
        },
    };
    match a {
        Action::Allow => Decision::Allow(format!("tools.{tool} = \"allow\"")),
        Action::Ask => Decision::Ask(reason),
        Action::Deny => Decision::Deny(reason),
    }
}
