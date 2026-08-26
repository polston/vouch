//! Append-only record of what vouch decided and what actually happened.
//!
//! Rules:
//!   1. Journalling must never break a session. Callers ignore errors.
//!   2. `mode` says what vouch DID for the call: "live" (emitted its
//!      decision), "shadow" (the --shadow flag — not the live gate at all),
//!      or "stood-down" (mode-keyed shadow suppressed the emission). Any
//!      mode other than "live" is NEVER evidence that a human decided
//!      anything.
//!   3. Outcomes come from real harness events, never from the absence of one.
//!      A record with no terminal event stays `Unknown` and is evidence of
//!      nothing. See `outcome.rs` for why that matters.

use crate::outcome::Outcome;
use crate::protocol::{Decision, HookInput, Host};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Record {
    #[serde(default)]
    pub id: String,
    pub ts: String,
    pub session: String,
    pub tool: String,
    pub cmd: String,
    pub verdict: String,
    pub reason: String,
    pub mode: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default = "pending")]
    pub outcome: Outcome,
    /// The language `cmd` was decided in, when it came from a declared
    /// snippet (Task 9's `records_from_snippets`) — `"bash"`, `"powershell"`,
    /// or whatever `knowledge::snippet_languages()` names. Empty for a row
    /// journaled through `record_from`'s single-record fallback: a
    /// config-named short-circuit never extracted a snippet at all, so
    /// claiming a language for it would assert something vouch never looked
    /// at. `#[serde(default)]` reads an older journal, written before this
    /// field existed, the same way.
    #[serde(default)]
    pub lang: String,
    /// The harness-reported permission mode of the call this row records
    /// (`HookInput.permission_mode`). Empty on rows written before this
    /// field existed OR when the caller supplied no mode — the two are not
    /// distinguishable, by construction (the repo's own hook-probe scripts
    /// are such callers).
    #[serde(default)]
    pub permission_mode: String,
    /// Which host selected this hook adapter. Empty only on rows written
    /// before host attribution existed; the host is a CLI fact, never trusted
    /// from hook input.
    #[serde(default)]
    pub host: String,
}

/// Seconds since the epoch, as a string. No date library: the journal only
/// needs an orderable stamp, and a missing one made time-based analysis of the
/// shadow run impossible.
pub fn now_epoch_secs() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs().to_string(),
        Err(_) => String::new(),
    }
}

fn pending() -> Outcome {
    Outcome::Pending
}

/// A terminal event for a decision already recorded.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutcomeRecord {
    pub id: String,
    pub outcome: Outcome,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub host: String,
}

/// The verdict word and reason text every journal record carries, read off
/// one `Decision` the same way whether it becomes one record or several.
fn verdict_and_reason(d: &Decision) -> (&'static str, String) {
    match d {
        Decision::Allow(r) => ("allow", r.clone()),
        Decision::Ask(r) => ("ask", r.clone()),
        Decision::Deny(r) => ("deny", r.clone()),
        Decision::Abstain => ("abstain", String::new()),
    }
}

pub fn record_from(input: &HookInput, d: &Decision, mode: &str) -> Record {
    record_from_host(Host::Claude, input, d, mode)
}

pub fn record_from_host(host: Host, input: &HookInput, d: &Decision, mode: &str) -> Record {
    let (verdict, reason) = verdict_and_reason(d);
    let cmd = input
        .tool_input
        .command
        .clone()
        .or_else(|| input.tool_input.file_path.clone())
        .or_else(|| input.tool_input.url.clone())
        .unwrap_or_default();
    Record {
        id: input.tool_use_id.clone(),
        ts: now_epoch_secs(),
        session: input.session_id.clone(),
        tool: input.tool_name.clone(),
        cmd,
        verdict: verdict.to_string(),
        reason,
        mode: mode.to_string(),
        cwd: input.cwd.clone(),
        outcome: Outcome::Pending,
        lang: String::new(),
        permission_mode: input.permission_mode.clone(),
        host: host.as_str().into(),
    }
}

/// One `Record` per extracted snippet, sharing the call's `tool_use_id` and
/// everything else `record_from` would have put in a single record — `cmd`
/// is the snippet TEXT and `lang` is the language it was decided in. Nothing
/// is joined: a two-command batch call journals two rows a human (or
/// `review`, or `doctor`) can read independently.
///
/// Never called when `snippets` is empty. A config-named allow short-circuits
/// `route::decide_tool` before extraction ever runs (spec §Decision flow
/// step 1) — that tool journals through `record_from`'s single-record
/// fallback instead, with an empty `lang`, because the snippet was never
/// looked at and the journal must not pretend otherwise.
pub fn records_from_snippets(
    input: &HookInput,
    d: &Decision,
    mode: &str,
    snippets: &[(String, String)],
) -> Vec<Record> {
    records_from_snippets_host(Host::Claude, input, d, mode, snippets)
}

pub fn records_from_snippets_host(
    host: Host,
    input: &HookInput,
    d: &Decision,
    mode: &str,
    snippets: &[(String, String)],
) -> Vec<Record> {
    let (verdict, reason) = verdict_and_reason(d);
    snippets
        .iter()
        .map(|(text, lang)| Record {
            id: input.tool_use_id.clone(),
            ts: now_epoch_secs(),
            session: input.session_id.clone(),
            tool: input.tool_name.clone(),
            cmd: text.clone(),
            verdict: verdict.to_string(),
            reason: reason.clone(),
            mode: mode.to_string(),
            cwd: input.cwd.clone(),
            outcome: Outcome::Pending,
            lang: lang.clone(),
            permission_mode: input.permission_mode.clone(),
            host: host.as_str().into(),
        })
        .collect()
}

fn append_line(dir: &Path, file: &str, line: &str) -> std::io::Result<()> {
    create_dir_all(dir)?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(file))?;
    // ONE write, with the newline already in it.
    //
    // `writeln!` can issue several writes — the text and the newline
    // separately — so two hook processes appending at the same moment
    // interleave as `{A}{B}\n\n`. Two such lines were found in a real journal
    // of 1326. `read_lines` skips whatever will not parse, so the damage is
    // silent: a decision simply disappears from the evidence `review` uses.
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    f.write_all(buf.as_bytes())
}

pub fn append(dir: &Path, rec: &Record) -> std::io::Result<()> {
    append_line(
        dir,
        "journal.jsonl",
        &serde_json::to_string(rec).unwrap_or_default(),
    )
}

pub fn append_outcome(dir: &Path, rec: &OutcomeRecord) -> std::io::Result<()> {
    append_line(
        dir,
        "outcomes.jsonl",
        &serde_json::to_string(rec).unwrap_or_default(),
    )
}

pub fn state_dir() -> std::path::PathBuf {
    std::env::var("VOUCH_STATE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("vouch"))
}

fn read_lines<T: for<'de> Deserialize<'de>>(dir: &Path, file: &str) -> Vec<T> {
    let body = match std::fs::read_to_string(dir.join(file)) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Every decision, with its real outcome folded in.
///
/// A decision whose id never received a terminal event is `Unknown` — never
/// `Denied`, never `Executed`.
pub fn all(dir: &Path) -> Vec<Record> {
    let mut recs: Vec<Record> = read_lines(dir, "journal.jsonl");
    let outs: Vec<OutcomeRecord> = read_lines(dir, "outcomes.jsonl");
    let mut by_id: HashMap<(String, String), Outcome> = HashMap::new();
    for o in &outs {
        by_id.insert((o.host.clone(), o.id.clone()), o.outcome);
    }
    for r in &mut recs {
        r.outcome = by_id
            .get(&(r.host.clone(), r.id.clone()))
            .copied()
            .unwrap_or(Outcome::Unknown);
    }
    recs
}

pub fn last(dir: &Path) -> Option<Record> {
    all(dir).pop()
}
