//! `vouch review` — turn recorded evidence into rule candidates.
//!
//! Hard invariant, stated by the user:
//!
//!   "If it's an unsafe operation, I'm gonna say yes because I want it done, but
//!    I don't want you to have the permission to do the fucked up thing every
//!    time... it SHOULD keep asking every single time."
//!
//! So:
//!   * A GUARD hit is never proposable. No amount of approving turns a guard
//!     into a standing rule. Guards are listed here only so the user can see
//!     they exist and see that vouch is not hiding them.
//!   * Only a decision vouch ASKED about, whose outcome is a real `Executed`
//!     event, counts as approval evidence. `Unknown` counts as nothing —
//!     silence is not consent.
//!   * Only `live` records count. `shadow` and `stood-down` rows (and any
//!     future mode word) are nothing: vouch did not act as the gate, so the
//!     user was never actually asked.
//!   * Nothing is written without an explicit `--accept <name>`.

use crate::journal::Record;
use crate::outcome::Outcome;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Candidate {
    /// The construct or guard name that caused the prompts.
    pub name: String,
    /// Config section it belongs to, e.g. "lang.bash.constructs".
    pub section: String,
    pub approved: usize,
    pub denied: usize,
    pub unknown: usize,
    pub sessions: usize,
    /// Guards can never become a rule.
    pub proposable: bool,
    /// Why it cannot be proposed, when it cannot. Shown in place of a rule so
    /// the entry is still visible rather than silently dropped.
    pub blocked: Option<String>,
    pub example: String,
}

impl Candidate {
    /// The exact line that would be written. Empty for non-proposable items.
    pub fn rule_line(&self) -> String {
        if !self.proposable {
            return String::new();
        }
        format!("[{}]\n{} = \"allow\"", self.section, self.name)
    }
}

/// Pulls the construct/guard name out of a reason string.
///
/// Scans every line rather than reading only the first. The reason now carries
/// a banner AFTER it when vouch could not read a file (§ the moved-file /
/// no-knowledge-file notice), and a future change that puts anything else in
/// front of the recorded reason must not silently empty `vouch review` again —
/// that is exactly the failure this scan exists to prevent.
fn stopped_on(reason: &str) -> Option<(String, bool)> {
    reason.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("vouch stopped on: ")?;
        if let Some(name) = rest.strip_suffix(" (guard)") {
            return Some((name.trim().to_string(), true));
        }
        Some((rest.trim().to_string(), false))
    })
}

/// True when `name` is a construct key the config can actually set, for
/// whichever language `rec`'s row was decided in.
fn is_settable_construct(rec: &Record, name: &str) -> bool {
    match record_lang(rec).as_deref().and_then(crate::syntax::scanner_for) {
        Some(s) => s.known_constructs().contains(&name),
        None => false,
    }
}

fn section_for(rec: &Record, is_guard: bool) -> String {
    if is_guard {
        return "guards".to_string();
    }
    match record_lang(rec) {
        Some(lang) => format!("lang.{lang}.constructs"),
        None => "write".to_string(),
    }
}

/// `rec.lang` when the row carries one, else the knowledge-lookup fallback
/// (`guards::record_lang`) for a journal written before that field existed.
/// A thin wrapper so the two functions above read the same way `doctor`
/// does, without each reaching for `guards::in_effect()` on its own.
fn record_lang(rec: &Record) -> Option<String> {
    crate::guards::record_lang(crate::guards::in_effect(), rec)
}

pub fn candidates(records: &[Record]) -> Vec<Candidate> {
    let mut acc: HashMap<String, Candidate> = HashMap::new();
    let mut sessions: HashMap<String, std::collections::HashSet<String>> = HashMap::new();

    for r in records {
        // vouch must have actually asked. Allows and abstains are not evidence.
        if r.verdict != "ask" && r.verdict != "deny" {
            continue;
        }
        // Only rows where vouch acted as the live gate are evidence — a
        // shadow or stood-down row never asked the user anything, and an
        // unknown future mode word must fail the same closed way.
        if r.mode != "live" {
            continue;
        }
        let (name, is_guard) = match stopped_on(&r.reason) {
            Some(x) => x,
            None => continue,
        };
        let section = section_for(r, is_guard);
        // Only a real settable key may become a rule. Some prompt reasons are
        // prose — "path outside every allowed area" is a write-policy verdict,
        // not a construct — and proposing them produced a rule that is not a
        // valid key and would never have any effect.
        let blocked = if is_guard {
            Some("this is a guard. It asks every time on purpose.".to_string())
        } else if is_settable_construct(r, &name) {
            None
        } else {
            Some(format!(
                "'{name}' is not a settable key — it is the reason vouch gave, \
                 not a construct. The prompt itself names the remedy."
            ))
        };
        let key = format!("{section}::{name}");
        let e = acc.entry(key.clone()).or_insert_with(|| Candidate {
            name: name.clone(),
            section: section.clone(),
            approved: 0,
            denied: 0,
            unknown: 0,
            sessions: 0,
            proposable: blocked.is_none(),
            blocked,
            example: r.cmd.chars().take(120).collect(),
        });
        match r.outcome {
            Outcome::Executed => e.approved += 1,
            Outcome::Denied => e.denied += 1,
            // Pending, Failed, and Unknown are evidence of nothing.
            _ => e.unknown += 1,
        }
        sessions
            .entry(key)
            .or_default()
            .insert(r.session.clone());
    }

    let mut out: Vec<Candidate> = acc
        .into_iter()
        .map(|(k, mut c)| {
            c.sessions = sessions.get(&k).map(|s| s.len()).unwrap_or(0);
            c
        })
        .collect();
    // Most-approved first, but guards always last since they are informational.
    out.sort_by_key(|c| (c.proposable == false, std::cmp::Reverse(c.approved)));
    out
}

/// Appends an accepted rule to the config text. Returns the new text.
///
/// Refuses non-proposable candidates. This is the only place vouch writes a
/// rule, and it is reached only from an explicit `--accept`.
pub fn apply(config_text: &str, c: &Candidate) -> Result<String, String> {
    if !c.proposable {
        // Guards keep their own wording — it states the invariant, not just
        // the refusal, and other surfaces quote it.
        if c.section == "guards" {
            return Err(format!(
                "'{}' is a guard. Guards ask every time on purpose and can never become a rule.",
                c.name
            ));
        }
        return Err(c
            .blocked
            .clone()
            .unwrap_or_else(|| format!("'{}' cannot become a rule.", c.name)));
    }
    // Silence is not consent. A prompt the user never answered says nothing
    // about what they want, so it cannot be the evidence for a standing rule.
    if c.approved == 0 {
        return Err(format!(
            "'{}' has no recorded approval ({} unanswered). A prompt that was never \
             answered is not evidence. Nothing written.",
            c.name, c.unknown
        ));
    }
    // Edited as a document, not as text. String splicing looked fine and was
    // silently wrong: it matched the section name inside a COMMENT and inserted
    // the key at top level, where it parses cleanly and does nothing. `--accept`
    // reported success while the rule had no effect. Comments in this file are
    // load-bearing (rule provenance), so the editor has to preserve them too.
    let mut doc: toml_edit::DocumentMut = config_text
        .parse()
        .map_err(|e| format!("config is not valid TOML: {e}"))?;

    let mut item: &mut toml_edit::Item = doc.as_item_mut();
    for part in c.section.split('.') {
        let table = item
            .as_table_like_mut()
            .ok_or_else(|| format!("{} is not a table", c.section))?;
        if table.get(part).is_none() {
            table.insert(part, toml_edit::Item::Table(toml_edit::Table::new()));
        }
        item = table.get_mut(part).expect("just inserted");
    }
    let table = item
        .as_table_like_mut()
        .ok_or_else(|| format!("{} is not a table", c.section))?;
    table.insert(&c.name, toml_edit::value("allow"));

    Ok(doc.to_string())
}
