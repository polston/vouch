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
    /// Execution count when duplicate runs are compacted. Defaults to 1.
    #[serde(default = "default_count", skip_serializing_if = "is_one")]
    pub count: usize,
    /// Whether this record represents synthetic test, benchmark, or probe traffic.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub measurement: bool,
}

pub fn is_measurement_session() -> bool {
    std::env::var_os("VOUCH_MEASUREMENT").is_some()
}

fn default_count() -> usize {
    1
}

fn is_one(c: &usize) -> bool {
    *c == 1
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
        count: 1,
        measurement: is_measurement_session(),
    }
}

pub fn record_unparseable(host: Host, raw: &str, d: &Decision) -> Record {
    let (verdict, reason) = verdict_and_reason(d);
    Record {
        id: String::new(),
        ts: now_epoch_secs(),
        session: String::new(),
        tool: "unparseable".into(),
        cmd: raw.chars().take(200).collect(),
        verdict: verdict.to_string(),
        reason,
        mode: "enforce".into(),
        cwd: String::new(),
        outcome: Outcome::Pending,
        lang: String::new(),
        permission_mode: String::new(),
        host: host.as_str().into(),
        count: 1,
        measurement: is_measurement_session(),
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
            count: 1,
            measurement: is_measurement_session(),
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
    tail_record(dir).or_else(|| all(dir).pop())
}

/// Configuration policy for journal rotation, retention caps, and historical deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalPolicy {
    /// Maximum total records retained after compaction and pruning. Default is 5,000.
    pub max_records: usize,
    /// Whether to collapse duplicate runs in historical records while aggregating counts.
    pub compact_duplicates: bool,
    /// Number of recent records to preserve un-compacted to protect active session tool_use_id pairing. Default is 1,000.
    pub preserve_recent: usize,
}

impl Default for JournalPolicy {
    fn default() -> Self {
        Self {
            max_records: 5000,
            compact_duplicates: true,
            preserve_recent: 1000,
        }
    }
}

/// Statistics reported after pruning and compaction.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompactionStats {
    pub original_count: usize,
    pub compacted_count: usize,
    pub pruned_count: usize,
    pub outcomes_retained: usize,
}

/// Pure in-memory compaction and bounded retention algorithm.
///
/// 1. Partitions records into historical and recent (last `preserve_recent` entries).
///    Recent entries are left completely untouched to preserve harness `tool_use_id` pairing.
/// 2. In historical records, duplicate runs sharing `(host, tool, lang, cmd, verdict, mode)`
///    are collapsed into their latest occurrence, aggregating execution counts.
/// 3. If combined records exceed `max_records`, oldest records are truncated.
pub fn compact_records(records: &[Record], policy: &JournalPolicy) -> (Vec<Record>, CompactionStats) {
    let original_count = records.len();
    if records.is_empty() {
        return (Vec::new(), CompactionStats::default());
    }

    let preserve_recent = policy.preserve_recent.min(records.len());
    let split_idx = records.len() - preserve_recent;
    let (historical, recent) = records.split_at(split_idx);

    let mut final_historical: Vec<Record> = Vec::new();
    if policy.compact_duplicates && !historical.is_empty() {
        // Collect latest instance of each signature, accumulating execution counts
        let mut latest_by_sig: HashMap<(String, String, String, String, String, String, bool), Record> = HashMap::new();
        for r in historical.iter().rev() {
            let key = (
                r.host.clone(),
                r.tool.clone(),
                r.lang.clone(),
                r.cmd.clone(),
                r.verdict.clone(),
                r.mode.clone(),
                r.measurement,
            );
            latest_by_sig
                .entry(key)
                .and_modify(|entry| {
                    entry.count = entry.count.saturating_add(r.count.max(1));
                })
                .or_insert_with(|| {
                    let mut rec = r.clone();
                    if rec.count == 0 {
                        rec.count = 1;
                    }
                    rec
                });
        }
        // Preserve relative chronological order of first-seen signatures from historical records
        let mut retained_keys = std::collections::HashSet::new();
        for r in historical {
            let key = (
                r.host.clone(),
                r.tool.clone(),
                r.lang.clone(),
                r.cmd.clone(),
                r.verdict.clone(),
                r.mode.clone(),
                r.measurement,
            );
            if retained_keys.insert(key.clone()) {
                if let Some(compacted_rec) = latest_by_sig.remove(&key) {
                    final_historical.push(compacted_rec);
                }
            }
        }
    } else {
        final_historical.extend_from_slice(historical);
    }

    let mut combined = final_historical;
    combined.extend_from_slice(recent);

    let compacted_count = combined.len();
    let mut pruned_count = 0;
    if combined.len() > policy.max_records {
        let excess = combined.len() - policy.max_records;
        pruned_count = excess;
        combined = combined.split_off(excess);
    }

    (
        combined,
        CompactionStats {
            original_count,
            compacted_count,
            pruned_count,
            outcomes_retained: 0,
        },
    )
}

/// Atomically compacts duplicate historical runs and prunes records exceeding the retention policy cap.
///
/// Also prunes orphaned `outcomes.jsonl` entries whose corresponding journal records have been pruned.
pub fn prune_and_compact(dir: &Path, policy: &JournalPolicy) -> std::io::Result<CompactionStats> {
    create_dir_all(dir)?;
    let recs: Vec<Record> = read_lines(dir, "journal.jsonl");
    if recs.is_empty() {
        return Ok(CompactionStats::default());
    }

    let (compacted_recs, mut stats) = compact_records(&recs, policy);

    // Filter outcomes to only retain those matching retained journal records
    let outcomes: Vec<OutcomeRecord> = read_lines(dir, "outcomes.jsonl");
    let active_ids: std::collections::HashSet<(String, String)> = compacted_recs
        .iter()
        .filter(|r| !r.id.is_empty())
        .map(|r| (r.host.clone(), r.id.clone()))
        .collect();
    let filtered_outcomes: Vec<OutcomeRecord> = outcomes
        .into_iter()
        .filter(|o| active_ids.contains(&(o.host.clone(), o.id.clone())))
        .collect();
    stats.outcomes_retained = filtered_outcomes.len();

    // Atomic write for journal.jsonl
    let tmp_journal = dir.join("journal.jsonl.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_journal)?;
        for r in &compacted_recs {
            let line = serde_json::to_string(r).unwrap_or_default();
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp_journal, dir.join("journal.jsonl"))?;

    // Atomic write for outcomes.jsonl
    let tmp_outcomes = dir.join("outcomes.jsonl.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_outcomes)?;
        for o in &filtered_outcomes {
            let line = serde_json::to_string(o).unwrap_or_default();
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp_outcomes, dir.join("outcomes.jsonl"))?;

    Ok(stats)
}

/// Reads the single most recent record directly from the end of `journal.jsonl`
/// without loading or parsing the entire historical file.
pub fn tail_record(dir: &Path) -> Option<Record> {
    use std::io::{Read, Seek, SeekFrom};
    let path = dir.join("journal.jsonl");
    let mut file = std::fs::File::open(&path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let read_size = std::cmp::min(len, 8192) as usize;
    file.seek(SeekFrom::End(-(read_size as i64))).ok()?;
    let mut buf = vec![0u8; read_size];
    file.read_exact(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let last_line = text.lines().rev().find(|l| !l.trim().is_empty())?;
    let mut rec: Record = serde_json::from_str(last_line).ok()?;

    if !rec.id.is_empty() {
        if let Ok(out_file) = std::fs::File::open(dir.join("outcomes.jsonl")) {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(out_file);
            for line in reader.lines().flatten() {
                if let Ok(o) = serde_json::from_str::<OutcomeRecord>(&line) {
                    if o.host == rec.host && o.id == rec.id {
                        rec.outcome = o.outcome;
                    }
                }
            }
        }
    }
    Some(rec)
}
