use std::io::{BufRead, Read};
use vouch::config::{load, Config};
use vouch::journal;
use vouch::protocol::{parse_input, render_for, Decision, Host};
use vouch::route::project_root;

fn home() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default()
        .replace('\\', "/")
}

enum HookCall {
    Refused,
    Processed(Option<String>),
}

/// Decide one normalized hook document using the config already loaded by the
/// process. The ordinary hook path calls this once; the evidence replay path
/// calls it for each JSONL row so config/knowledge loading and process startup
/// are paid once per worker rather than once per recorded tool call.
fn run_hook_call(
    raw: &str,
    cfg: &Config,
    notice: Option<&str>,
    hook_options: &vouch::cli::HookOptions,
    state_dir: &std::path::Path,
    home_dir: &str,
) -> HookCall {
    let shadow = hook_options.shadow;
    let host = hook_options.host;
    let mut input = match parse_input(raw) {
        Ok(input) => input,
        Err(_) => return HookCall::Refused,
    };
    if host == Host::Codex
        && hook_options.shell == Some(vouch::cli::InstallShell::PowerShell)
        && input.tool_name == "Bash"
    {
        input.tool_name = "PowerShell".into();
    }

    // Terminal events report what actually happened. They never decide anything.
    if let Some(o) = vouch::outcome::Outcome::from_event(&input.hook_event_name) {
        let detail = if !input.reason.is_empty() {
            input.reason.clone()
        } else if input.is_interrupt {
            "interrupted".to_string()
        } else {
            input.error.clone()
        };
        let _ = journal::append_outcome(
            state_dir,
            &journal::OutcomeRecord {
                id: input.tool_use_id.clone(),
                outcome: o,
                detail: detail.clone(),
                host: host.as_str().into(),
            },
        );
        if host == Host::Codex {
            if let Ok(Some(original_id)) =
                vouch::approval::take_outcome_alias(state_dir, &input.tool_use_id)
            {
                let _ = journal::append_outcome(
                    state_dir,
                    &journal::OutcomeRecord {
                        id: original_id,
                        outcome: o,
                        detail: "outcome of the exact approved retry".into(),
                        host: host.as_str().into(),
                    },
                );
            }
        }
        return HookCall::Processed(None);
    }

    let outcome = vouch::route::decide(
        cfg,
        vouch::guards::in_effect(),
        home_dir,
        &input,
    );
    let mut decision = with_banner(outcome.decision, notice);

    // The emission step of mode-keyed shadow is computed before journalling,
    // because the rows' `mode` word depends on it.
    let (emit, mode) = if shadow {
        (false, "shadow")
    } else {
        let protection =
            matches!(&decision, Decision::Ask(r) if vouch::engine::is_protection_ask(r));
        vouch::protocol::stand_down_emission(
            cfg.stand_down(),
            cfg.stands_down_in(&input.permission_mode),
            &decision,
            protection,
        )
    };

    if host == Host::Codex && emit {
        if let Decision::Ask(reason) = &decision {
            let now = journal::now_epoch_secs().parse::<u64>().unwrap_or_default();
            decision = match vouch::approval::gate(state_dir, &input, reason, now) {
                Ok(vouch::approval::GateResult::Granted) => {
                    Decision::Allow("one-time human approval for this exact retry".into())
                }
                Ok(vouch::approval::GateResult::Pending { request_id }) => Decision::Ask(format!(
                    "{reason}\n  approval request: {request_id}\n  call mcp__vouch_approval__request_approval with that request_id, then retry this exact tool call once"
                )),
                Err(error) => Decision::Deny(format!(
                    "vouch could not create a one-time Codex approval request: {error}"
                )),
            };
        }
    }

    // A config-named allow short-circuits extraction, so it uses the single
    // record fallback. Snippet-bearing calls retain one record per snippet.
    if outcome.snippets.is_empty() {
        let rec = journal::record_from_host(host, &input, &decision, mode);
        let _ = journal::append(state_dir, &rec);
    } else {
        for rec in vouch::journal::records_from_snippets_host(
            host,
            &input,
            &decision,
            mode,
            &outcome.snippets,
        ) {
            let _ = journal::append(state_dir, &rec);
        }
    }

    if !emit {
        HookCall::Processed(None)
    } else {
        HookCall::Processed(render_for(host, &decision))
    }
}

/// The directory a manual verdict is judged from: `--cwd` when the caller gave
/// one, else the process's own working directory.
///
/// `--cwd` lets the operator ask "what would you say if this ran from THERE"
/// without actually being there. Absent it, the process's own directory is the
/// only honest stand-in. One definition, because `explain` and `why <command>`
/// both offer the flag and a second copy of the fallback could answer the same
/// question two ways.
fn judged_from(cwd: Option<String>) -> String {
    cwd.map(|d| d.replace('\\', "/")).unwrap_or_else(|| {
        std::env::current_dir()
            .map(|d| d.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
            .unwrap_or_default()
    })
}

fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("VOUCH_CONFIG") {
        return std::path::PathBuf::from(p);
    }
    vouch::knowledge::config_dir(&home()).join("config.toml")
}

/// The config, and what could not be read if anything.
///
/// A missing config file is not an error and not a reason to fall back to
/// settings the operator cannot see. It means nothing has been allowed, which
/// every prompt then says out loud.
fn load_config() -> (Config, Option<vouch::knowledge::Gap>) {
    use vouch::knowledge::GapKind;
    let path = config_path();
    let gap = |kind: GapKind, why: String| {
        Some(vouch::knowledge::Gap {
            path: vouch::knowledge::display_path(&path),
            why,
            source: vouch::knowledge::GapSource::Config,
            kind,
        })
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => match load(&text) {
            // The checks that need the KNOWLEDGE run here rather than inside
            // `load`, which has only the config text. This is the one shared
            // load site — the hook and every CLI verb come through it — so a
            // refusal reaches the operator whichever way they run vouch. A
            // library caller that builds a `Config` itself (a test, `vouch
            // explain`'s library twin) skips this by design: it supplies
            // its own knowledge, and validating against a static it never
            // chose would refuse configs that are fine for it.
            Ok(cfg) => match vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()) {
                Ok(()) => (cfg, None),
                Err(e) => (Config::nothing_configured(), gap(GapKind::Unusable, e)),
            },
            // On disk and unusable. NOT missing — the banner says so, and must
            // never offer to copy an example over a file that has content.
            Err(e) => (
                Config::nothing_configured(),
                gap(GapKind::Unusable, format!("could not be read: {e}")),
            ),
        },
        Err(e) => {
            // Failing to open is not the same as not being there: a directory,
            // or a file vouch is not allowed to read, is present and broken.
            let (kind, why) = if path.exists() {
                (GapKind::Unusable, format!("could not be opened ({e})"))
            } else {
                (GapKind::Missing, format!("not found ({e})"))
            };
            (Config::nothing_configured(), gap(kind, why))
        }
    }
}

/// What vouch could not read, appended to every prompt until it is fixed.
///
/// This is the difference between a fresh install and a broken one: both prompt
/// on everything, and only one of them is supposed to.
///
/// It goes AFTER the reason, never before. `vouch review` identifies what
/// stopped a command from the first line of the recorded reason, so a banner in
/// front of it makes every prompt on a fresh install invisible to review — the
/// exact machine that needs review most.
///
/// [review] One fixed sentence used to cover every gap. Reproduced: a valid
/// `knowledge.toml`, a broken `my-knowledge.toml` — verdict `allow` (it
/// recognised the command fine), and directly under it the banner claimed
/// vouch "recognises nothing", named the OPERATOR'S OWN path, and told them
/// to copy the shipped file over it. All three of those were false, and the
/// third would have destroyed their own additions. A broken install reading
/// identically to a differently-broken one is the exact failure this task
/// exists to prevent — so the wording below branches on which file the gap
/// is actually about.
fn banner(config_gap: Option<&vouch::knowledge::Gap>) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();

    for g in vouch::guards::gaps() {
        lines.push(gap_paragraph(g));
    }
    if let Some(g) = config_gap {
        lines.push(gap_paragraph(g));
    }

    if let Some(msg) = redirected_files() {
        lines.push(msg);
    }

    for (former, now) in moved_files() {
        if std::path::Path::new(&former).exists() && !std::path::Path::new(&now).exists() {
            lines.push(format!(
                "a vouch file is at a path vouch no longer reads.\n  \
                 found:  {former}\n  reads:  {now}\n  \
                 move it there. vouch will not move it for you — it never writes to your \
                 config on its own."
            ));
        }
    }

    if lines.is_empty() { None } else { Some(lines.join("\n\n")) }
}

/// The paragraph for one gap.
///
/// Two independent things decide the wording, and BOTH have been got wrong
/// here: which file it is (a `knowledge.toml` problem and a `my-knowledge.toml`
/// problem want opposite advice) and whether that file exists (a missing file
/// can be replaced with an example; a broken one must never be).
fn gap_paragraph(g: &vouch::knowledge::Gap) -> String {
    use vouch::knowledge::{GapKind, GapSource};
    match (g.source, g.kind) {
            (GapSource::Knowledge, GapKind::Missing) => format!(
                "vouch has no knowledge file, so it recognises nothing and will ask about \
                 every command until it has one.\n  \
                 looked for: {}\n  why: {}\n  \
                 put the descriptions there and this stops. `knowledge.toml` in the vouch \
                 repository is the file to copy.",
                g.path, g.why
            ),
            // [review] This case used to print the sentence above: "vouch has
            // no knowledge file", with a parse error naming a line of that
            // same file underneath it, and an instruction to copy over it.
            // The file is there and has content in it; saying it is absent is
            // false, and the advice destroys what is there.
            (GapSource::Knowledge, GapKind::Unusable) => format!(
                "vouch found its knowledge file and could not read it, so it recognises \
                 nothing and will ask about every command until that is fixed. The file is \
                 there — this is not a missing install.\n  \
                 file: {}\n  why: {}\n  \
                 fix the file at that path; the reason above points at what is wrong with \
                 it. Do NOT copy the repository's `knowledge.toml` over it before you have \
                 looked: that path has content in it now.",
                g.path, g.why
            ),
            // [review] Spec 2026-08-05 §Schema, version skew point 1: a
            // shipped file written for a newer schema than this binary
            // understands fails to PARSE (unknown keys, `deny_unknown_fields`)
            // before the version gate below ever gets a chance to run — so
            // without this arm it fell through to the ordinary Unusable
            // wording, "fix the file... do NOT copy the repository's
            // knowledge.toml over it", which sends the operator to edit a
            // file that is not broken. Their vouch binary is just old.
            (GapSource::Knowledge, GapKind::NewerThanBinary) => format!(
                "this knowledge file is newer than this vouch binary — update vouch. It names \
                 a schema version this binary does not understand, so vouch recognises \
                 nothing and will ask about every command until it is updated. The file \
                 itself is not the problem.\n  \
                 file: {}\n  why: {}\n  \
                 get a current vouch binary; do not edit this file to make it look older.",
                g.path, g.why
            ),
            (GapSource::Knowledge, GapKind::Empty) => format!(
                "vouch read its knowledge file and it describes nothing at all, so it \
                 recognises nothing and will ask about every command until it does. The \
                 file is there and it parses — it is just empty of descriptions.\n  \
                 file: {}\n  why: {}\n  \
                 the file has no `[[program]]` and no `[[tool]]` entries in it — either it \
                 was never filled in, or its contents were removed. `knowledge.toml` in the \
                 vouch repository is the file to copy.",
                g.path, g.why
            ),
            // [review] REFUSED is not ABSENT (spec §7, rev 4). Before this
            // arm existed, a shipped knowledge file that exists but refuses
            // to load fell through to the wildcard below and printed its
            // sentence — "vouch still recognises everything the shipped
            // knowledge describes" — directly under a gap saying the shipped
            // file just refused. Both cannot be true at once: if the shipped
            // base refused, vouch recognises NOTHING, this operator's overlay
            // included. This arm has to come before the wildcard, or the
            // wildcard would swallow it and print the false sentence again.
            (GapSource::MyKnowledge, GapKind::SetAside) => format!(
                "your own additions in my-knowledge.toml were never applied. The SHIPPED \
                 knowledge base failed to load, so there is nothing to lay them over — vouch \
                 recognises NOTHING right now, not even what the shipped file alone would \
                 have covered.\n  \
                 file: {}\n  why: {}\n  \
                 fix the SHIPPED knowledge file first; the gap above this one names it and \
                 why. Your own file is not the problem and does not need to change.",
                g.path, g.why
            ),
            // [review, final review Finding 1] The wildcard arm below prints
            // "vouch still recognises everything the shipped knowledge
            // describes" for every OTHER `GapSource::MyKnowledge` gap, which
            // is true there: `read_one` rejecting this file on its own leaves
            // `kb` as the shipped base alone (`load_files`'s `None => base`
            // arm). It is false for THIS gap — an ambiguous retraction fails
            // the whole combined load closed (`validate_retraction`), and
            // `load_files` returns `Knowledge::default()`, not the shipped
            // base. That is the same false-sentence shape `SetAside`, one arm
            // up, already exists to prevent — a broken-shipped-base gap used
            // to fall through this same wildcard and claim the overlay still
            // covered everything. This arm has to come before the wildcard,
            // or the wildcard swallows it and prints the false sentence again.
            (GapSource::MyKnowledge, GapKind::Ambiguous) => format!(
                "an entry in your my-knowledge.toml is ambiguous, and vouch will not guess \
                 which language it means — so nothing is in effect right now, not the \
                 shipped knowledge either, and every command will ask until it is fixed.\n  \
                 file: {}\n  why: {}\n  \
                 the reason above names the entry; say which language the retraction is \
                 actually about (`languages = [\"bash\"]` or `[\"powershell\"]`), or write \
                 one entry per language if it truly applies to both.",
                g.path, g.why
            ),
            // [review, final review Finding 2] This used to share the
            // `Ambiguous` arm above, whose closing sentence tells the
            // operator to add `languages = [...]` — a remedy that fixes none
            // of the three refusals `validate_place_scopes` reports (an
            // `only_under` on a name the shipped knowledge already
            // describes, a scoped name split across more than one entry, or
            // an empty `only_under` list). None of the three is a language
            // question, so the remedy has to come from the `why:` line
            // itself — it already names the entry and what is wrong with it
            // — rather than from a second sentence guessing at a fix.
            (GapSource::MyKnowledge, GapKind::PlaceScope) => format!(
                "an entry in your my-knowledge.toml declares a place scope (`only_under`) that \
                 can never apply — so nothing is in effect right now, not the shipped \
                 knowledge either, and every command will ask until it is fixed.\n  \
                 file: {}\n  why: {}\n  \
                 the reason above names the entry and exactly what is wrong with it; fix that \
                 (this is not a language question, so `languages = [...]` changes nothing here).",
                g.path, g.why
            ),
            // Spec 2026-08-20 §4. Unlike `SetAside`/`Ambiguous`/`PlaceScope`
            // above, the shipped knowledge is NOT what failed here and the
            // combined load is NOT thrown away — an operator entry merged
            // cleanly, on its own, but the MERGED shape (an operator overlay
            // can replace a vocabulary whole) failed one check that can only
            // be answered post-merge. This still has to come before the
            // wildcard below: its own sentence is true here in the same way
            // the wildcard's is, but names the specific set-aside reason
            // instead of the generic "fix the file" advice, which points at
            // the wrong half of the problem — the merged SHAPE, not a syntax
            // or field error in the file on its own.
            (GapSource::MyKnowledge, GapKind::MergedShape) => format!(
                "your own additions in my-knowledge.toml were set aside because a merged \
                 entry's shape is refused — vouch still recognises everything the shipped \
                 knowledge describes; only what YOU added is missing.\n  \
                 file: {}\n  why: {}\n  \
                 the reason above names the entry and the key; fix that in your own file \
                 (this is not a problem with the shipped knowledge).",
                g.path, g.why
            ),
            // my-knowledge.toml is never announced for being absent, so every
            // gap that reaches here is about a file that IS there.
            (GapSource::MyKnowledge, _) => format!(
                "your own additions in my-knowledge.toml are not in effect — vouch still \
                 recognises everything the shipped knowledge describes; only what YOU added \
                 to it is missing.\n  \
                 looked for: {}\n  why: {}\n  \
                 fix the file at that path (the error above should point at the line) — do \
                 NOT replace it with the shipped `knowledge.toml`; that is a different file \
                 and would throw your own additions away.",
                g.path, g.why
            ),
            // `SetAside`, `Ambiguous`, `PlaceScope` and `MergedShape` are only
            // ever constructed for `GapSource::MyKnowledge`, and
            // `NewerThanBinary` only ever for `GapSource::Knowledge` (all in
            // `load_files`/`read_one`). These combinations cannot occur; they
            // exist only so this match stays exhaustive if that ever
            // changes, and say so rather than rendering nothing if it does.
            (GapSource::Knowledge, GapKind::SetAside | GapKind::Ambiguous | GapKind::PlaceScope | GapKind::MergedShape)
            | (GapSource::Config, GapKind::SetAside | GapKind::Ambiguous | GapKind::NewerThanBinary | GapKind::PlaceScope | GapKind::MergedShape) => format!(
                "vouch has a gap it has no wording for ({:?}, {:?}) — this combination is \
                 not supposed to be reachable.\n  file: {}\n  why: {}",
                g.source, g.kind, g.path, g.why
            ),
            (GapSource::Config, GapKind::Missing) => format!(
                "vouch has no config file, so nothing has been allowed and every command \
                 asks.\n  \
                 looked for: {}\n  why: {}\n  \
                 `vouch.example.toml` is the file to copy — it ships in the release \
                 bundle beside this binary, and sits at the root of a repository checkout.",
                g.path, g.why
            ),
            // [review] The defect this branch exists for: a config with ONE
            // bad character printed the "no config file" headline above a
            // parse error pointing at line 2 of it, then told the operator to
            // copy the example over their own settings.
            (GapSource::Config, GapKind::Unusable | GapKind::Empty) => format!(
                "vouch found your config file and could not use it, so nothing has been \
                 allowed and every command asks. The file is there — this is not a fresh \
                 install.\n  \
                 file: {}\n  why: {}\n  \
                 fix the file at that path; the reason above says what is wrong with it. Do \
                 NOT copy `vouch.example.toml` over it: that path has your settings in it, \
                 and copying would throw them away.",
                g.path, g.why
            ),
    }
}

/// Says out loud that an environment variable, not `~/.config/vouch/`, is
/// deciding which files vouch reads — and that one of the two variables no
/// longer means what it used to.
///
/// [review] `VOUCH_KNOWLEDGE` meant THE OPERATOR'S OWN file before this
/// branch and means THE SHIPPED file after it. Nothing said so anywhere the
/// operator would see it. An operator who had it set and upgrades is pointing
/// vouch at their small personal file as if it were the whole shipped set;
/// reproduced with a file containing one `[[program]] match = ["rm"]` entry,
/// which made `rm -rf /` ALLOW, and `git push --force`, `sudo rm -rf /` and
/// `chmod +x` all fall through to the unmodelled-program prompt. No gap is
/// reported for any of it, because the file is there and it parses.
///
/// This changes no polarity and turns nothing off. It says which variable is
/// in play, what it points at, and how to stop it — which is what §5 asks of
/// anything that changes a decision.
fn redirected_files() -> Option<String> {
    let set: Vec<(&str, String, &str)> = [
        (
            vouch::knowledge::KNOWLEDGE_ENV,
            "the knowledge that SHIPS with vouch",
        ),
        (
            vouch::knowledge::MY_KNOWLEDGE_ENV,
            "your own additions",
        ),
    ]
    .iter()
    .filter_map(|(var, what)| std::env::var(var).ok().map(|v| (*var, v, *what)))
    .collect();
    if set.is_empty() {
        return None;
    }
    let dir = vouch::knowledge::display_path(&vouch::knowledge::config_dir(&home()));
    let mut msg = String::from(
        "vouch is not reading its own directory: an environment variable is telling it \
         which files to read.\n",
    );
    for (var, value, what) in &set {
        msg.push_str(&format!("  {var} = {value}\n    which vouch reads as: {what}\n"));
    }
    msg.push_str(&format!(
        "  {} used to mean YOUR OWN file and now means the shipped one. If it was set \
         before that change, vouch is reading your personal additions as though they were \
         the whole shipped set — everything the shipped file describes is then missing, \
         and nothing else reports it, because your file is there and parses fine.\n  \
         to turn this off, unset the variable(s) above; vouch then reads \
         {dir}/knowledge.toml and {dir}/my-knowledge.toml.",
        vouch::knowledge::KNOWLEDGE_ENV
    ));
    Some(msg)
}

/// Files that used to live loose in `~/.config` and now live in
/// `~/.config/vouch/`. Pairs of (where it was, where it is read from now).
///
/// [review] `dir.join(...)` appends the PLATFORM separator to a `/`-built
/// string, so the "reads:" side printed `.../vouch\config.toml` on Windows —
/// forward slashes throughout, then one backslash, which a shell pasting the
/// path unquoted silently eats. Both sides go through `display_path` so
/// nothing printed here can do that again.
fn moved_files() -> Vec<(String, String)> {
    let h = home();
    let dir = vouch::knowledge::config_dir(&h);
    vec![
        (
            vouch::knowledge::display_path(&vouch::knowledge::former_path(&h, "vouch.toml")),
            vouch::knowledge::display_path(&dir.join("config.toml")),
        ),
        (
            vouch::knowledge::display_path(&vouch::knowledge::former_path(&h, "vouch-knowledge.toml")),
            vouch::knowledge::display_path(&dir.join("my-knowledge.toml")),
        ),
    ]
}

/// Appends the banner. Abstain carries no text and is left alone.
fn with_banner(d: Decision, banner: Option<&str>) -> Decision {
    let Some(b) = banner else { return d };
    match d {
        Decision::Allow(r) => Decision::Allow(format!("{r}\n\n{b}")),
        Decision::Ask(r) => Decision::Ask(format!("{r}\n\n{b}")),
        Decision::Deny(r) => Decision::Deny(format!("{r}\n\n{b}")),
        Decision::Abstain => Decision::Abstain,
    }
}

fn print_decision(d: &Decision) {
    match d {
        Decision::Allow(r) => println!("ALLOW\n{r}"),
        Decision::Ask(r) => println!("ASK\n{r}"),
        Decision::Deny(r) => println!("DENY\n{r}"),
        Decision::Abstain => println!("ABSTAIN\n  vouch does not gate this; the harness decides."),
    }
}

/// The first lines of `my-knowledge.toml`, written only when the file is
/// created. Both halves of `vouch trust` write into the SAME file, so this is
/// shared rather than spelled twice: whichever half happened to create it
/// would otherwise decide what the file claims to hold.
const MY_KNOWLEDGE_HEADER: &str =
    "# Tools and programs you have vouched for. Written by `vouch trust`.\n\
     # This file ADDS to what ships with vouch; it does not replace it.\n";

/// The body of a TOML list: every item quoted the way TOML spells a string,
/// comma-joined. The entry templates write `key = [<this>]`, and how an item
/// is escaped is one rule, not one per template.
fn toml_list(items: &[String]) -> String {
    items.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")
}

/// `vouch trust` for an MCP-shaped name (spec 2026-08-05 §Server entry,
/// Decisions §1) — the tool half of the trust command. Split out of the
/// `"trust"` arm in `main` because it writes and verifies a completely
/// different entry shape (`[[tool]]`, not `[[program]]`) with its own
/// recognition check: `guards::recognises` is program-only, so a tool is
/// verified by reloading and asking `guards::tool_entry` /
/// `guards::server_entry_for` directly whether the entry as WRITTEN fires
/// (mirrors the program path's M2.14 write-reload-verify shape).
///
/// `whole_server = true` means the operator said `--whole-server` — the
/// `--all-subcommands` equivalent one level up (spec rule 5): `name` is
/// written verbatim as `server = "<name>"`, a grant covering every tool that
/// server exposes. Without it, `name` must already have a tool tail
/// (`route::mcp_server_of` — the same shape test the unmodeled-tool prompt
/// uses to decide whether to mention the server-entry form at all); a name
/// that is only the server half is refused, naming the flag, rather than
/// silently writing a `[[tool]] match` entry that can never fire (nothing is
/// ever called by the bare server spelling).
///
/// Exits the process; never returns — same control-flow shape every other
/// branch of the `"trust"` arm already uses.
fn cmd_trust_tool(name: &str, whole_server: bool) -> ! {
    // Refused before anything on disk is touched: a name this command cannot
    // write must not leave the config directory behind on its way to saying so.
    if !whole_server && vouch::route::mcp_server_of(name).is_none() {
        eprintln!(
            "`{name}` has no separate tool name after the server — there is nothing narrower \
             than the whole server to trust here.\n  \
             to trust exactly one tool, name it in full: vouch trust mcp__server__tool\n  \
             to trust every tool this server exposes, say so out loud: \
             vouch trust --whole-server {name}"
        );
        std::process::exit(1);
    }

    let path = vouch::knowledge::my_knowledge_path(&home());
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existed_before = path.exists();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let header = if existing.trim().is_empty() { MY_KNOWLEDGE_HEADER } else { "" };
    let stamp = vouch::journal::now_epoch_secs();
    let entry = if whole_server {
        format!(
            "\n# vouched for by you, {stamp}\n\
             # A whole-server grant, said out loud: recognises EVERY tool the {name:?} server\n\
             # exposes, including ones never seen yet. It makes no claim about what any of\n\
             # them do; guards and [write] rules still apply to whatever each is handed.\n\
             [[tool]]\nserver = {name:?}\nsource = \"you ran `vouch trust --whole-server`; \
             recognition only, for every tool this server exposes — guards and [write] rules \
             still apply to whatever it is handed\"\n"
        )
    } else {
        format!(
            "\n# vouched for by you, {stamp}\n\
             # Recognises this exact MCP tool and nothing else. It makes no claim about what\n\
             # the tool does; guards and [write] rules still apply to whatever it is handed.\n\
             [[tool]]\nmatch = [{name:?}]\nsource = \"you ran `vouch trust`; recognition \
             only — guards and [write] rules still apply to whatever it is handed\"\n"
        )
    };

    if let Err(e) = std::fs::write(&path, format!("{existing}{header}{entry}")) {
        // Exit 0 on a failed write, same as the program path: the failure is
        // reported, and nothing was described.
        eprintln!("could not write {}: {e}", vouch::knowledge::display_path(&path));
        std::process::exit(0);
    }
    println!("described: {name}");
    // Same reasoning as the program path (M2.14): the write is not the
    // deliverable, a live claim is. Reload exactly what vouch reads and ask
    // the real lookup, not a name-level check.
    let loaded = vouch::knowledge::load_files(&vouch::knowledge::knowledge_path(&home()), &path);
    let recognised = if whole_server {
        // No concrete tool name exists to probe with — `name` IS the server.
        // Synthesize one under it; `server_entry_for`'s match is a pure
        // string-shape test (server + "__" + non-empty, "__"-free tail), so
        // this genuinely proves the entry as written would cover a real tool
        // of that server, not merely that a `server` key with this value now
        // exists in the file.
        let probe = format!("{name}__vouch_trust_probe");
        vouch::guards::server_entry_for(&loaded.kb, &probe).is_some()
    } else {
        vouch::guards::tool_entry(&loaded.kb, name).is_some()
    };
    if !recognised {
        // Undo — but NOT the program path's unconditional write-back: that
        // mints a zero-byte file when none existed before this run (open
        // defect M2.54(3)). Remove what this run created; restore only what
        // was here before it. The undo and the word for it are chosen
        // together so they cannot come apart.
        let (undone, undo_desc) = if existed_before {
            (
                std::fs::write(&path, &existing).is_ok(),
                "restored to what it was before this run",
            )
        } else {
            (std::fs::remove_file(&path).is_ok(), "removed again")
        };
        // What became of the entry, said once — an undo that itself failed
        // leaves the operator holding the file, so it names the file.
        let undo_clause = if undone {
            format!("has been {undo_desc}")
        } else {
            format!(
                "could NOT be {undo_desc}. Please fix {} by hand",
                vouch::knowledge::display_path(&path)
            )
        };
        if loaded.gaps.is_empty() {
            eprintln!(
                "wrote the entry, checked it, and `{name}` is still not recognised — the \
                 entry does not fire, so it {undo_clause}. This is a vouch defect, not \
                 something you did wrong; please report it."
            );
        } else {
            eprintln!(
                "wrote the entry, but could not verify it: the knowledge vouch reads has \
                 problems of its own, and the entry {undo_clause} until those problems are \
                 fixed. The problems:"
            );
            for g in &loaded.gaps {
                eprintln!("{}", gap_paragraph(g));
            }
        }
        std::process::exit(1);
    }
    if whole_server {
        println!("verified: a server entry now recognises every tool `{name}` exposes");
    } else {
        println!("verified: an entry now recognises `{name}`");
    }
    println!("written to {}", vouch::knowledge::display_path(&path));
    std::process::exit(0);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cfg, config_gap) = load_config();
    // What vouch could not read, said on every prompt until it is fixed. A
    // fresh install and a broken one both prompt on everything; this is the
    // only thing that tells them apart from outside.
    let notice = banner(config_gap.as_ref());

    // `vouch explain [bash|ps] '<command>'` — answers "why am I being asked".
    if args.first().map(String::as_str) == Some("explain") {
        let target = match vouch::cli::parse_target(&args[1..]) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{e}");
                // The only non-zero exit in this binary. Everything else exits
                // 0 on purpose: in the PreToolUse protocol a non-zero exit
                // means "block, and show stderr to the model". `explain` is
                // never a hook, so a usage error is free to be a usage error.
                std::process::exit(2);
            }
        };
        if target.cmd.is_empty() {
            eprintln!("usage: vouch explain [--cwd <dir>] [bash|ps] '<command>'");
            std::process::exit(0);
        }
        // Saying which directory was used is not optional, whichever one it
        // was: a verdict with no stated location is a verdict about an
        // unstated place.
        let here = judged_from(target.cwd.clone());
        println!("judged from: {here}");
        let d = with_banner(
            vouch::engine::decide_command_at(
                &cfg, target.lang, &target.cmd, Some(&home()),
                project_root(".").as_deref(), Some(&here),
            ),
            notice.as_deref(),
        );
        print_decision(&d);
        std::process::exit(0);
    }

    // `vouch why` — explains the most recent journalled decision, or, given a
    // command, explains THAT one.
    //
    // Silently ignoring an argument was worse than rejecting it: asking why a
    // particular command prompted and being shown an unrelated verdict reads
    // as an answer, and it is not one.
    if args.first().map(String::as_str) == Some("why") {
        let target = match vouch::cli::parse_target(&args[1..]) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        if !target.cmd.is_empty() {
            let (lang, cmd, cwd) = (target.lang, target.cmd, target.cwd);
            let here = judged_from(cwd);
            println!("command: {cmd}");
            println!("judged from: {here}");
            let d = with_banner(
                vouch::engine::decide_command_at(
                    &cfg,
                    lang,
                    &cmd,
                    Some(&home()),
                    project_root(".").as_deref(),
                    Some(&here),
                ),
                notice.as_deref(),
            );
            print_decision(&d);
            std::process::exit(0);
        }
        match journal::last(&journal::state_dir()) {
            Some(rec) => {
                println!("last decision: {} on {}", rec.verdict.to_uppercase(), rec.tool);
                println!("command: {}", rec.cmd.chars().take(400).collect::<String>());
                if rec.reason.is_empty() {
                    println!("reason: (none recorded — vouch abstained)");
                } else {
                    println!("reason:\n{}", rec.reason);
                }
                println!("mode: {}", rec.mode);
                if !rec.permission_mode.is_empty() {
                    println!("permission mode: {}", rec.permission_mode);
                }
                // What was recorded is history. This is what the CURRENT
                // config says about the same command, judged from the
                // directory it actually ran in — the two are free to
                // disagree, and that disagreement is the point of asking.
                // `lang` is empty on a row journaled through the single-record
                // fallback (no snippet was ever extracted); `bash` is what
                // `parse_target` itself defaults to for the same reason.
                let lang = if rec.lang.is_empty() { "bash" } else { rec.lang.as_str() };
                let cwd = if rec.cwd.is_empty() { None } else { Some(rec.cwd.as_str()) };
                match cwd {
                    Some(dir) => print!("re-decided now, from {dir}: "),
                    None => println!("re-decided now (no directory was recorded)"),
                }
                let d = with_banner(
                    vouch::engine::decide_command_at(
                        &cfg, lang, &rec.cmd, Some(&home()),
                        project_root(".").as_deref(), cwd,
                    ),
                    notice.as_deref(),
                );
                print_decision(&d);
            }
            None => println!("no decisions recorded yet"),
        }
        std::process::exit(0);
    }

    // `vouch trust <program>…` — describe a program so an allow-list can work.
    //
    // An allow-list needs a cheap way to say "I vouch for this". Without one the
    // only options are hand-editing a file — which the user has said they will
    // never do — or turning the whole check off. Running this command IS the
    // explicit accept; nothing is ever written without it.
    if args.first().map(String::as_str) == Some("trust") {
        // Route every trailing token: vouch's own two control flags are
        // reserved before anything else, everything else spelled with a
        // leading `-` (single OR double dash — a single-dash flag used to
        // fall through into `words` and be minted as a bogus subcommand,
        // the M2.54 defect) is a candidate `standalone_flags` member, and
        // everything left is a plain word (the program name, a verb, or a
        // slash-spelled token, which is not flag-shaped here and stays a
        // word exactly as before).
        let mut flags_typed: Vec<String> = Vec::new();
        let mut words: Vec<String> = Vec::new();
        let (mut all, mut whole_server) = (false, false);
        for a in &args[1..] {
            // vouch's own control flags, reserved before routing: recorded
            // here rather than re-scanned afterwards, so one pass answers what
            // each token is.
            if a == "--all-subcommands" {
                all = true;
                continue;
            }
            if a == "--whole-server" {
                whole_server = true;
                continue;
            }
            if a.starts_with('-') {
                flags_typed.push(a.clone());
            } else {
                words.push(a.clone());
            }
        }
        // A control flag claims "recognise everything"; naming flags claims
        // "recognise only these narrow flags-only runs". Both said at once is
        // a contradiction, not a widening — refuse before anything is written
        // rather than silently letting one win.
        if (all || whole_server) && !flags_typed.is_empty() {
            eprintln!(
                "`{}` and naming flags ({}) contradict — one asks for everything, \
                 the other for the narrow flags-only entry. Say one or the other.",
                if all { "--all-subcommands" } else { "--whole-server" },
                flags_typed.join(", ")
            );
            std::process::exit(1);
        }
        if words.is_empty() {
            eprintln!("usage: vouch trust <program> [<subcommand>…]");
            eprintln!();
            eprintln!("  vouch trust kubectl get     recognises `kubectl get …` only");
            eprintln!("  vouch trust kubectl --all-subcommands");
            eprintln!("                               recognises every `kubectl` verb");
            eprintln!("  vouch trust ls               a program with no verbs");
            eprintln!();
            eprintln!("  vouch trust mcp__server__tool");
            eprintln!("                               recognises exactly that MCP tool");
            eprintln!("  vouch trust --whole-server mcp__server");
            eprintln!("                               recognises every tool that server exposes");
            eprintln!();
            eprintln!("  A CLI is not one operation. Trusting the name alone vouches for");
            eprintln!("  every verb it has, so subcommands are named explicitly unless you");
            eprintln!("  ask for all of them. The same is true one level up: naming a whole");
            eprintln!("  MCP server vouches for every tool it exposes, so that is written");
            eprintln!("  only when asked for by name.");
            // `display_path`, not `.display()`. `config_dir` builds a
            // `/`-joined string and `PathBuf::join` appends the PLATFORM
            // separator, so this printed `.../vouch\my-knowledge.toml` — and
            // pasted unquoted into bash, a backslash eats the next character.
            // `vouch trust` is the one command whose whole output is "here is
            // the file I wrote", so this was the worst place for it.
            eprintln!(
                "  writes to {}",
                vouch::knowledge::display_path(&vouch::knowledge::my_knowledge_path(&home()))
            );
            std::process::exit(0);
        }
        // MCP tool names are unbounded and shaped nothing like a program's:
        // exact, case-sensitive match, and a `[[tool]]` entry rather than
        // `[[program]]` (spec 2026-08-05 §Decisions 1, §Server entry). The
        // shape alone decides the routing — `base_name` lowercasing below is
        // for program names only, and must never touch one of these.
        if words[0].starts_with("mcp__") {
            cmd_trust_tool(&words[0], whole_server);
        }
        // Everything below writes a `[[program]]` entry, which has no server
        // to be whole. Falling through with the flag set wrote that entry
        // anyway and said nothing — the operator asked to recognise every
        // tool a server exposes and got a program described instead. Refused,
        // naming the flag, before anything is written.
        if whole_server {
            eprintln!(
                "`--whole-server` recognises every tool one MCP server exposes, and \
                 `{}` is not an MCP server name — those are spelled `mcp__<server>`.\n  \
                 to recognise this program, leave the flag off: vouch trust {}\n  \
                 to recognise every tool a server exposes: vouch trust --whole-server \
                 mcp__<server>",
                words[0], words[0]
            );
            std::process::exit(1);
        }
        let path = vouch::knowledge::my_knowledge_path(&home());
        let program = words[0].clone();
        // A name spelled with a directory or `.exe` would write an entry
        // recognition can never match: `entries_for` strips both and
        // lowercases before comparing (guards::base_name). Writing the raw
        // spelling was M2.12's first measured defect — the instruction ran,
        // wrote a rule, and nothing changed. Write the compared form, and
        // say so. A case-only difference is left as typed: match names are
        // compared case-insensitively, so rewriting it would change the
        // operator's file for zero effect.
        let bare = vouch::guards::base_name(&program);
        let program = if bare != program.to_ascii_lowercase() {
            println!(
                "note: `{program}` is spelled with a directory or extension — recognition \
                 compares bare program names, so the entry is written as `{bare}` and covers \
                 every program invoked as `{bare}`"
            );
            bare
        } else {
            program
        };
        let subs: Vec<String> = words[1..].to_vec();
        // A bad member (`--`, a charset violation, an attached-value
        // spelling) refuses HERE, before anything is written — not after a
        // failed verify-and-undo. `member_shape_ok` is the one definition of
        // "flag-shaped" shared with the per-file validator and the
        // prompt-side listability test, so this cannot drift from either.
        for f in &flags_typed {
            if let Err(why) = vouch::knowledge::member_shape_ok(&["-"], f) {
                eprintln!("`{f}` cannot be trusted as a standalone flag: {why}");
                std::process::exit(1);
            }
        }
        // The no-verbs whole-program note and BOTH existing templates fire
        // only when no flags were typed — a flags-carrying mint always uses
        // the narrow flags-only template below instead, whether or not it
        // also names subcommands.
        let entry = if flags_typed.is_empty() {
            if subs.is_empty() && !all {
                // Not a refusal — a program with no verbs is the normal case. But
                // say what is being vouched for, because "kubectl" and "kubectl
                // test" are very different amounts of trust.
                println!(
                    "note: recognising EVERY operation of `{program}`. To scope it, name the \
                     subcommands: vouch trust {program} <subcommand>…\n\
                     note: this entry is also read as claiming `{program}` does not change the \
                     shell's working directory. A dir-changing program needs `changes_dir` in the \
                     entry."
                );
            }
            if subs.is_empty() {
                format!(
                    "\n# vouched for by you, {}\n\
                     # Recognises every operation of this program. It makes no claim about\n\
                     # what it writes — guards and [write] rules still apply to it. It also\n\
                     # claims the program does not change the shell's working directory; if it\n\
                     # does, add `changes_dir` to this entry.\n\
                     [[program]]\nmatch = [{:?}]\nall_subcommands = true\n",
                    vouch::journal::now_epoch_secs(),
                    program
                )
            } else {
                let list = toml_list(&subs);
                format!(
                    "\n# vouched for by you, {}\n\
                     # Recognises ONLY these subcommands. Any other verb of this program\n\
                     # stays unknown. Guards and [write] rules still apply. It also claims\n\
                     # the program does not change the shell's working directory; if it\n\
                     # does, add `changes_dir` to this entry.\n\
                     [[program]]\nmatch = [{:?}]\nsubcommands = [{list}]\n",
                    vouch::journal::now_epoch_secs(),
                    program
                )
            }
        } else {
            // The scoped rule asks nothing of an entry with no `runs_file` —
            // `no_value_options` is deliberately absent here, so nobody
            // "helpfully" adds it to a template that does not need it.
            let flist = toml_list(&flags_typed);
            let subs_line = if subs.is_empty() {
                "subcommands = []".to_string()
            } else {
                format!("subcommands = [{}]", toml_list(&subs))
            };
            format!(
                "\n# vouched for by you, {}\n\
                 # Recognises {} runs whose EVERY argument is one of these flags.\n\
                 # The claim: each listed flag, alone, makes the program do that\n\
                 # flag's own action and stop - no verb, no reading stdin, no\n\
                 # writing. Guards and [write] rules still apply.\n\
                 [[program]]\nmatch = [{:?}]\n{subs_line}\ncase_sensitive_flags = true\nstandalone_flags = [{flist}]\n",
                vouch::journal::now_epoch_secs(),
                if subs.is_empty() { "ONLY" } else { "these subcommands, plus" },
                program
            )
        };
        let fresh = [&program];
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let header = if existing.trim().is_empty() { MY_KNOWLEDGE_HEADER } else { "" };
        match std::fs::write(&path, format!("{existing}{header}{entry}")) {
            Ok(()) => {
                for n in &fresh {
                    println!("described: {n}");
                }
                // The write is not the deliverable — a live claim is. Reload
                // exactly what vouch reads and check the entry as WRITTEN
                // covers the shape it was asked to cover. A name-level check
                // (is_modeled) would be vacuously true whenever the program
                // was already known; `recognises` on the program + verbs is
                // the per-command claim §2 defines. An entry that does not
                // fire must not stay in the file reading as if it did.
                let loaded = vouch::knowledge::load_files(
                    &vouch::knowledge::knowledge_path(&home()),
                    &path,
                );
                let probe = vouch::shell::Cmd {
                    head: program.clone(),
                    args: subs.clone(),
                    unread_args: Default::default(),
                    chain: None,
                    prefix_assigns: vec![],
                };
                let claimed = if subs.is_empty() {
                    program.clone()
                } else {
                    format!("{program} {}", subs.join(" "))
                };
                // The probe's argument list was built two statements above, so
                // it is a complete record by construction and nothing can
                // append to it (spec 2026-08-20 §2.4).
                //
                // A flags-carrying mint verifies its own flags probe always,
                // plus the bare verb probe when `subs` is also non-empty — a
                // `subcommands = []` entry does not cover a bare run, so the
                // OLD bare probe would wrongly fail there. With no flags
                // typed, this is exactly the existing single-probe check.
                let verified = if flags_typed.is_empty() {
                    vouch::guards::recognises(&loaded.kb, &probe, "bash", true)
                } else {
                    let flag_probe = vouch::shell::Cmd {
                        head: program.clone(),
                        args: flags_typed.clone(),
                        unread_args: Default::default(),
                        chain: None,
                        prefix_assigns: vec![],
                    };
                    vouch::guards::recognises(&loaded.kb, &flag_probe, "bash", true)
                        && (subs.is_empty()
                            || vouch::guards::recognises(&loaded.kb, &probe, "bash", true))
                };
                if verified {
                    println!("verified: an entry now recognises `{claimed}`");
                } else {
                    // Undo: restore the file to what it was before this run.
                    let restored = std::fs::write(&path, &existing).is_ok();
                    if loaded.gaps.is_empty() {
                        if restored {
                            eprintln!(
                                "wrote the entry, checked it, and `{claimed}` is still not \
                                 recognised — the entry does not fire, so it has been removed \
                                 again. This is a vouch defect, not something you did wrong; \
                                 please report it."
                            );
                        } else {
                            eprintln!(
                                "wrote the entry, checked it, and `{claimed}` is still not \
                                 recognised — the entry does not fire, so it could NOT be \
                                 removed. Please delete it from {} by hand. This is a vouch \
                                 defect, not something you did wrong; please report it.",
                                vouch::knowledge::display_path(&path)
                            );
                        }
                    } else {
                        // The check could not run against real knowledge — a
                        // refused shipped file (stale version) reads as
                        // nothing merged. That is the operator's setup, not a
                        // vouch defect, and the gaps say exactly what to fix.
                        if restored {
                            eprintln!(
                                "wrote the entry, but could not verify it: the knowledge vouch \
                                 reads has problems of its own, and the entry has been removed \
                                 again until they are fixed:"
                            );
                        } else {
                            eprintln!(
                                "wrote the entry, but could not verify it: the knowledge vouch \
                                 reads has problems of its own, and the entry could NOT be \
                                 removed. Please delete it from {} by hand until those problems \
                                 are fixed. The problems:",
                                vouch::knowledge::display_path(&path)
                            );
                        }
                        for g in &loaded.gaps {
                            eprintln!("{}", gap_paragraph(g));
                        }
                    }
                    std::process::exit(1);
                }
                println!("written to {}", vouch::knowledge::display_path(&path));
            }
            Err(e) => eprintln!("could not write {}: {e}", vouch::knowledge::display_path(&path)),
        }
        std::process::exit(0);
    }

    // `vouch doctor` — what vouch could not read or describe. These are vouch's
    // own gaps, surfaced so they get fixed instead of silently becoming prompts.
    if args.first().map(String::as_str) == Some("doctor") {
        // `vouch::engine::parse_undeclared_option_line` scrapes one line of a
        // recorded `journal::Record.reason` for the marker
        // `engine::undeclared_option_line` writes on a rule-4 ask — the two
        // are kept side by side in `engine.rs` so they cannot drift apart.
        // This is the whole of the third bucket below (spec 2026-07-31 §9.1)
        // — a fact already written into the journal at decision time, never
        // re-derived against current knowledge the way the other two
        // buckets are.

        // Fourth bucket (Task 11, spec 2026-08-06 §Overlaps tier 2): place
        // rules that can never fire because a wider or opposing rule in the
        // SAME config already answers first. Computed from the operator's
        // config alone — unlike every bucket below, it needs no journal
        // history at all, so it runs and prints ahead of the "no decisions
        // recorded yet" exit rather than behind it: a rule can be inert on
        // day one, before vouch has ever been asked to decide anything.
        // `cfg` is the one `main()` already loaded above (line 510) — every
        // other branch in this function reads that same binding by
        // reference, and doctor is no exception.
        let inert = vouch::config::inert_place_rules(&cfg, &home(), project_root(".").as_deref());
        if !inert.is_empty() {
            println!("place rules that can never fire ({}):", inert.len());
            for f in inert.iter().take(20) {
                println!("  {f}");
            }
            println!();
        }

        let program_findings = vouch::config::program_location_findings(
            &cfg,
            &home(),
            project_root(".").as_deref(),
        );
        if !program_findings.is_empty() {
            println!(
                "program-location rules needing attention ({}):",
                program_findings.len()
            );
            for finding in program_findings.iter().take(20) {
                println!("  {finding}");
            }
            println!();
        }

        // Fifth bucket, same reason the fourth runs ahead of the
        // empty-journal exit: `guards::notes()` is a fact about the
        // operator's OWN config alone (Task 4's `narrowing_noops`, a
        // `subcommands` spelling the merge silently discarded), not
        // something derived from journal history, so it belongs beside the
        // inert place rules and ahead of "no decisions recorded yet" too — a
        // fresh-state-dir run would otherwise never see it.
        let notes = vouch::guards::notes();
        if !notes.is_empty() {
            println!("my-knowledge lines the merge silently discarded ({}):", notes.len());
            for n in notes {
                println!("  {n}");
            }
            println!();
        }

        let dir = journal::state_dir();
        let recs = journal::all(&dir);
        if recs.is_empty() {
            println!("no decisions recorded yet ({})", dir.display());
            std::process::exit(0);
        }
        // Re-scan the recorded commands against the CURRENT knowledge rather
        // than scraping the reason text. Scraping only ever saw commands that
        // PROMPTED, so with `unmodeled_command = "allow"` — the shipped setting
        // until 2026-07-28 — doctor reported zero gaps across a thousand
        // decisions. The whole point of doctor is to surface gaps that are NOT
        // prompting, and that stays true whichever way the setting is set: an
        // operator who sets it back to "allow" needs this most.
        let kb = vouch::guards::in_effect();
        let mut unreadable: Vec<&journal::Record> = Vec::new();
        let mut unmodeled: std::collections::HashMap<String, usize> = Default::default();
        for r in &recs {
            // `r.lang` is authoritative for a row Task 9 journaled per
            // snippet; a row from before that field existed falls back to a
            // knowledge lookup (`fixed_snippet_lang`) instead of the old
            // hardcoded tool-name table. Either way, a tool with no readable
            // language is skipped, same as before.
            let lang = match vouch::guards::record_lang(kb, r) {
                Some(l) => l,
                None => continue,
            };
            let scanner = match vouch::syntax::scanner_for(&lang) {
                Some(s) => s,
                None => continue,
            };
            match scanner.scan(&r.cmd) {
                Err(_) => unreadable.push(r),
                Ok(scan) => {
                    // The doctor scan reports recognition gaps, not decisions,
                    // so it uses the built-in default depth rather than the
                    // operator's configured cap — same as `expand_wrappers`'s
                    // convenience form — and ignores whether that cap was hit.
                    let cmds = vouch::guards::expand_wrappers_with_sources(
                        kb,
                        &scan.commands,
                        &scan.heredocs,
                        &scan.input_source,
                        &scan.args_complete,
                        &lang,
                        &|_| 4,
                    )
                    .cmds;
                    let mut seen = std::collections::HashSet::new();
                    for c in &cmds {
                        if c.head.is_empty() || !seen.insert(c.head.clone()) {
                            continue;
                        }
                        if !vouch::guards::is_modeled(kb, &c.head, &lang) {
                            *unmodeled.entry(c.head.clone()).or_default() += 1;
                        }
                    }
                }
            }
        }
        println!("decisions recorded: {}", recs.len());
        println!("\ncommands vouch could NOT read ({}):", unreadable.len());
        for r in unreadable.iter().take(20) {
            println!("  {}", r.cmd.chars().take(140).collect::<String>());
        }
        if unreadable.is_empty() {
            println!("  (none)");
        }
        let mut um: Vec<_> = unmodeled.iter().collect();
        um.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        println!("\nprograms vouch has no description of ({}):", um.len());
        for (name, n) in um.iter().take(30) {
            println!("  {n:>5}  {name}");
        }
        if um.is_empty() {
            println!("  (none)");
        }
        // Third bucket (spec 2026-07-31 §9.1): undeclared-option asks on
        // dir-change entries, aggregated straight from recorded reasons.
        // Nothing here is re-scanned against today's knowledge — that is
        // what the two buckets above already do, and a rule-4 reason is a
        // historical fact rather than a claim to re-check. This is the one
        // instrument that can measure PowerShell noise: the corpus this repo
        // measures against is bash history, so no pre-build count bounds an
        // undeclared PowerShell common parameter, and the per-claim decision
        // of which ones to declare has no data to be made with otherwise.
        // Omitted entirely when nothing carries the marker, unlike the two
        // buckets above — every run has a definite answer for "unreadable"
        // and "unmodeled" (even if it is none), but most runs will never
        // have produced a rule-4 ask at all, and a header over an empty list
        // reads as a gap where there is none.
        let mut undeclared: std::collections::HashMap<(String, String), usize> = Default::default();
        for r in &recs {
            for line in r.reason.lines() {
                if let Some((head, flag)) = vouch::engine::parse_undeclared_option_line(line) {
                    *undeclared.entry((head.to_string(), flag.to_string())).or_default() += 1;
                }
            }
        }
        if !undeclared.is_empty() {
            let mut ud: Vec<_> = undeclared.iter().collect();
            ud.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
            println!("\nundeclared options on dir-changers, by spelling ({}):", ud.len());
            for ((head, flag), n) in ud {
                println!("  {n:>5}  {head} {flag}");
            }
        }
        // my-knowledge.toml, not knowledge.toml. The latter is the file that
        // ships, and `scripts/install-knowledge.sh --force` overwrites it —
        // so a description added there is lost on the next install. Nothing
        // overwrites my-knowledge.toml.
        println!(
            "\nadd any of these to my-knowledge.toml to describe what they do (no rebuild).\n\
             that is your own file and nothing overwrites it. knowledge.toml is the file that\n\
             ships with vouch, and `scripts/install-knowledge.sh --force` replaces it wholesale."
        );
        std::process::exit(0);
    }

    // `vouch review` — evidence-backed rule candidates. Writes NOTHING without
    // an explicit `--accept <name>`, and never proposes a guard at all.
    if args.first().map(String::as_str) == Some("review") {
        let recs = journal::all(&journal::state_dir());
        let cands = vouch::review::candidates(&recs);

        if let Some(pos) = args.iter().position(|a| a == "--accept") {
            let want = args.get(pos + 1).cloned().unwrap_or_default();
            let Some(c) = cands.iter().find(|c| c.name == want) else {
                eprintln!("no candidate named '{want}'");
                std::process::exit(0);
            };
            match vouch::review::apply(
                &std::fs::read_to_string(config_path()).unwrap_or_else(|_| "version = 1\n".into()),
                c,
            ) {
                Ok(new_text) => {
                    if let Some(parent) = config_path().parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(config_path(), new_text) {
                        Ok(()) => println!("accepted: {} = \"allow\" in [{}]", c.name, c.section),
                        Err(e) => eprintln!(
                            "could not write {}: {e}",
                            vouch::knowledge::display_path(&config_path())
                        ),
                    }
                }
                Err(e) => eprintln!("refused: {e}"),
            }
            std::process::exit(0);
        }

        if cands.is_empty() {
            println!("nothing to review yet — vouch has not asked you anything it could learn from");
            std::process::exit(0);
        }
        println!("candidates from real recorded outcomes:\n");
        for c in &cands {
            println!("  {}", c.name);
            println!(
                "    approved {} · refused {} · no answer recorded {} · {} session(s)",
                c.approved, c.denied, c.unknown, c.sessions
            );
            if c.proposable {
                println!("    would add:  [{}]  {} = \"allow\"", c.section, c.name);
                if c.approved == 0 {
                    println!(
                        "    NO EVIDENCE YET — {} prompt(s), none answered. Silence is not consent.",
                        c.unknown
                    );
                } else {
                    println!("    accept it:  vouch review --accept {}", c.name);
                }
            } else {
                let why = c
                    .blocked
                    .clone()
                    .unwrap_or_else(|| "not a settable key.".to_string());
                println!("    NOT PROPOSABLE — {why}");
                println!("    shown so you can see vouch is not hiding it.");
            }
            println!();
        }
        println!("nothing above has been written. Only --accept writes anything.");
        std::process::exit(0);
    }

    // `vouch import <cc-allow.toml>` — translate an existing config, and say
    // plainly what did not translate.
    if args.first().map(String::as_str) == Some("import") {
        let src = args.get(1).cloned().unwrap_or_else(|| {
            format!("{}/.config/cc-allow.toml", home())
        });
        let text = match std::fs::read_to_string(&src) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("cannot read {src}: {e}");
                std::process::exit(0);
            }
        };
        match vouch::import_cc::import(&text) {
            Ok(r) => {
                println!("{}", r.config);
                eprintln!("
# --- what did NOT translate ---");
                for n in &r.notes {
                    eprintln!("# - {n}");
                }
                eprintln!("#
# nothing was written. Redirect stdout to save (create the directory first):");
                eprintln!("#   mkdir -p ~/.config/vouch && vouch import > ~/.config/vouch/config.toml");
            }
            Err(e) => eprintln!("import failed: {e}"),
        }
        std::process::exit(0);
    }

    // `vouch install [--host ...] [--shell ...] [--state-dir ...] [--shadow]
    // [--print]` — emit
    // the selected host's hook registration. Bare Claude `install` prints
    // the full merged settings.json document, for
    // redirecting to a file. `--print` narrows that to the hooks-only view —
    // display-safe, since it carries no MCP/server content. Any other
    // argument is refused by `parse_install_args` before anything is read —
    // an unrecognised flag must never fall through to the bare-install form
    // and print more than was asked for.
    if args.first().map(String::as_str) == Some("install") {
        let options = match vouch::cli::parse_install_options(&args[1..]) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        let settings_path = match options.host {
            Host::Claude => std::path::PathBuf::from(home()).join(".claude/settings.json"),
            Host::Codex => std::path::PathBuf::from(home()).join(".codex/hooks.json"),
        };
        let existing = std::fs::read_to_string(&settings_path).unwrap_or_default();
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
            .unwrap_or_else(|_| "vouch".into());
        let planned = match options.host {
            Host::Claude => vouch::install::plan(&existing, &exe, options.shadow),
            Host::Codex => match options.state_dir.as_deref() {
                Some(state_dir) => vouch::install::plan_codex_with_state(
                    &existing,
                    &exe,
                    options.shell.expect("Codex shell was validated"),
                    options.shadow,
                    state_dir,
                ),
                None => vouch::install::plan_codex(
                    &existing,
                    &exe,
                    options.shell.expect("Codex shell was validated"),
                    options.shadow,
                ),
            },
        };
        match planned {
            Ok(p) => {
                println!(
                    "{}",
                    if options.hooks_only {
                        &p.hooks_view
                    } else {
                        &p.settings
                    }
                );
                eprintln!("
# --- what this changes ---");
                for n in &p.notes {
                    eprintln!("# - {n}");
                }
                if options.hooks_only {
                    eprintln!(
                        "# hooks view only - redirect the bare form to a file to save the whole document"
                    );
                }
                eprintln!("# target: {}", settings_path.display());
                eprintln!("# nothing was written.");
            }
            Err(e) => eprintln!("install failed: {e}"),
        }
        std::process::exit(0);
    }

    // `vouch schema <config|knowledge> [--write]` — the JSON Schema for
    // config.toml or knowledge.toml, generated from the same structs the
    // real loaders read. With no `--write` it prints the one schema named to
    // stdout, same convention as `import`/`install`: nothing is written.
    // `--write` regenerates the complete committed set — both schema files
    // and the combined human reference page — regardless of which target was
    // named, because the page documents both (see `cli::SchemaTarget`).
    if args.first().map(String::as_str) == Some("schema") {
        let (target, write) = match vouch::cli::parse_schema_args(&args[1..]) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        let docs = vouch::cli::generate_schema_docs();
        if !write {
            let json = match target {
                vouch::cli::SchemaTarget::Config => &docs.config_json,
                vouch::cli::SchemaTarget::Knowledge => &docs.knowledge_json,
            };
            println!("{json}");
            std::process::exit(0);
        }
        let files = [
            ("docs/reference/config-schema.json", &docs.config_json),
            ("docs/reference/knowledge-schema.json", &docs.knowledge_json),
            ("docs/reference/reference.md", &docs.reference_md),
        ];
        let mut failed = false;
        for (path, contents) in files {
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(path, contents) {
                Ok(()) => println!("wrote {path}"),
                Err(e) => {
                    eprintln!("could not write {path}: {e}");
                    failed = true;
                }
            }
        }
        std::process::exit(if failed { 1 } else { 0 });
    }

    // Anything that is not a hook invocation must never block on stdin.
    if args.is_empty()
        || !args
            .iter()
            .any(|a| matches!(a.as_str(), "--hook" | "--hook-batch"))
    {
        println!("vouch {}", env!("CARGO_PKG_VERSION"));
        println!("usage:");
        println!("  vouch --hook [--host claude|codex] [--shell bash|powershell] [--state-dir <absolute>] [--shadow]");
        println!("                            decide a tool call (reads hook JSON on stdin)");
        println!("  vouch --hook-batch       replay JSONL hook calls in one process (status JSONL out)");
        println!("  vouch explain '<cmd>'     what vouch decides, and why");
        println!("  vouch why '<cmd>'         the same, for a command already run");
        println!("  vouch why                 explain the last recorded decision");
        println!("  vouch doctor              list what vouch could not read or describe");
        println!("  vouch review [--accept X] evidence-backed rule candidates");
        println!("  vouch import [file]       translate a cc-allow config to stdout");
        println!("  vouch install [--host claude|codex] [--shell bash|powershell] [--state-dir <absolute>] [--shadow] [--print]");
        println!("                            print merged host hook wiring; writes nothing");
        println!("  vouch schema <config|knowledge> [--write]");
        println!("                            print (or regenerate) the reference docs");
        std::process::exit(0);
    }

    let hook_options = match vouch::cli::parse_hook_options(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let state_dir = hook_options
        .state_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(journal::state_dir);
    let home_dir = home();

    if hook_options.batch {
        let stdin = std::io::stdin();
        for (index, line) in stdin.lock().lines().enumerate() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    eprintln!("vouch: could not read batch hook input: {error}");
                    std::process::exit(2);
                }
            };
            let (status, emitted) = match run_hook_call(
                &line,
                &cfg,
                notice.as_deref(),
                &hook_options,
                &state_dir,
                &home_dir,
            ) {
                HookCall::Refused => ("refused", false),
                HookCall::Processed(output) => ("processed", output.is_some()),
            };
            println!(
                "{}",
                serde_json::json!({
                    "index": index,
                    "status": status,
                    "emitted": emitted,
                })
            );
        }
        std::process::exit(0);
    }

    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        std::process::exit(0);
    }
    if let HookCall::Processed(Some(output)) = run_hook_call(
        &raw,
        &cfg,
        notice.as_deref(),
        &hook_options,
        &state_dir,
        &home_dir,
    ) {
        println!("{output}");
    }
    std::process::exit(0);
}
