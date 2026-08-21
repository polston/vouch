//! One shared flag-classification primitive (spec §4.1).
//!
//! Six divergent flag comparisons grew up independently across `guards.rs`:
//! `rule_matches`, `written_paths`, `dir_change_candidates`,
//! `run_dir_with_flag`, `subcommand_index`/`walk_post_subcommand`,
//! `after_flag_snippet`, and `start_process`. Each one re-decided, slightly
//! differently, whether a raw token is a flag, whether it carries an
//! attached value, and whether an abbreviated or case-folded spelling
//! counts — and the differences were the hole (M2.119, M2.128, the
//! `-Confirm` misread `after_flag_snippet`'s own two-character guess used
//! to produce). This module is the one place that decision gets made.
//!
//! `classify` answers "what is this token" for one token in isolation.
//! `spells` answers "does this token, in any of its accepted shapes, name
//! THIS flag" — used when a caller already has a target flag in hand
//! (`wrap_flags`, `write_flags`, a single declared name) rather than the
//! whole vocabulary `classify` searches. `ArgWalk` adds the one piece of
//! state a single-token call cannot carry on its own: whether `--` has
//! already been seen earlier in the same argument vector. `vocab_for` is
//! the one place a `Program` entry's fields turn into the policy `classify`
//! and `spells` read — so no call site invents its own defaults.

use crate::guards::Program;
use crate::paths;

/// The vocabulary and comparison policy a token is classified against.
///
/// Built once per lookup, normally via `vocab_for`. Every field is public
/// because a caller with a narrower need than `vocab_for` provides — the
/// run-dir flag's always-case-sensitive exception (spec §4.1.6) chief among
/// them — constructs or overrides one directly rather than this module
/// inventing a second construction path for it.
pub struct Vocab<'a> {
    /// Flags that consume a following token as their value.
    pub value_options: &'a [String],
    /// Flags that take no value.
    pub no_value_options: &'a [String],
    /// How this vocabulary spells flags. Empty reads as `["-"]` — what an
    /// entry with no `flag_prefix` claim always meant.
    pub flag_prefix: &'a [String],
    /// Exact-case comparison when true; `eq_ignore_ascii_case` when false.
    pub case_sensitive: bool,
    /// Whether an unambiguous single-dash-long-name prefix counts as a
    /// match, and what happens when it does not (§4.1.7).
    pub abbreviation: Abbrev,
    /// Whether the PowerShell `-Name:value` attached spelling is tried.
    pub colon_attach: bool,
}

/// Per-call-site abbreviation policy (spec §4.1.7). Never decided by this
/// module — it is read out of the vocabulary the caller built.
#[derive(Clone, Copy, PartialEq)]
pub enum Abbrev {
    /// A prefix match resolves to the declared flag it prefixes.
    Accept,
    /// A prefix match is reported, loudly, as `Class::RefusedAbbrev` — never
    /// silently treated as unmatched (that would be the same miss class
    /// this module exists to close) and never silently treated as a match
    /// (that would accept a spelling the entry never claimed).
    Refuse,
}

/// What a single raw token turned out to be, once unquoted and read against
/// a `Vocab`.
#[derive(Debug, PartialEq)]
pub enum Class {
    /// Not shaped like a flag under this vocabulary's `flag_prefix` at all —
    /// a positional argument, a subcommand, a value.
    NotFlag,
    /// The literal `--` end-of-options marker. Only `ArgWalk` acts on this;
    /// a single `classify` call cannot itself stop classifying the tokens
    /// that follow (spec §4.1.4 is a per-vector rule).
    EndOfOptions,
    /// A flag from `value_options`, in whichever shape carried the value:
    /// bare (`attached: None`, value is the next token, the caller's job to
    /// consume), `--flag=value`, short `-Xvalue`, or PowerShell
    /// `-Name:value`. `flag` is always the CANONICAL declared spelling, not
    /// the raw text — an abbreviated or case-folded token normalises to the
    /// same string a full, exact spelling would.
    Value { flag: String, attached: Option<String> },
    /// A flag from `no_value_options`, matched whole (exact or accepted
    /// abbreviation) or as a member of an all-described cluster
    /// (`-abc` where every letter is a declared no-value flag) — in the
    /// cluster case `flag` is the raw cluster text itself (`"-abc"`),
    /// because `Bool` has nowhere to put more than one name; a caller that
    /// needs to know whether one particular letter is in the cluster asks
    /// `spells` instead.
    Bool { flag: String },
    /// Flag-shaped, but nothing in this vocabulary describes it — not a
    /// whole-token match, not an accepted abbreviation, not any attached
    /// form, and, if it looked like a cluster, at least one of its letters
    /// was itself undescribed (round-1 finding: an undescribed letter
    /// poisons the whole cluster, it does not just drop out of it).
    Undescribed { token: String },
    /// Flag-shaped, prefix-matches exactly one declared long flag, and this
    /// vocabulary's policy is `Abbrev::Refuse`. `declared` names what it
    /// prefixes, so the prompt this produces can say so.
    RefusedAbbrev { token: String, declared: String },
}

/// What `spells` found, once it checked whether `raw` names one specific
/// `flag`.
///
/// Not `Option<Option<String>>` — a refused abbreviation is a THIRD outcome,
/// not a shade of "no match". `write`/`dest`/`run-dir` derivation (the
/// consumers this exists for, per spec §4.1.7) calls `spells` to ask "is
/// this token my flag", and a refused abbreviation candidate answering the
/// same as a token that is not the flag at all would silently drop the very
/// miss class this module exists to close: an operator who refused
/// abbreviation for a case-sensitive unix entry would have that refusal
/// mean nothing the moment a consumer used `spells` instead of `classify`.
#[derive(Debug, PartialEq)]
pub enum Spell {
    /// `raw` does not name `flag` in any accepted shape.
    No,
    /// `raw` names `flag`, exactly, as an accepted abbreviation, or in an
    /// attached/cluster shape — carrying the attached value, if any.
    Yes(Option<String>),
    /// `raw` prefix-matches `flag` (whole-token or through a colon-attach
    /// pre-colon reading) and this vocabulary's policy is `Abbrev::Refuse`.
    /// Loud, like `Class::RefusedAbbrev` — never folded into `No`.
    RefusedAbbrev { declared: String },
}

/// Per-token classification. Unquotes internally (`paths::unquote`) — the
/// same view heads and write-path candidates already get (CLAUDE.md §8).
pub fn classify(raw: &str, v: &Vocab) -> Class {
    let s = paths::unquote(raw);
    let prefixes = effective_prefixes(v.flag_prefix);

    // `--` is the end-of-options marker for single-dash vocabularies only —
    // checked before the general flag-shape gate below, because `--` is
    // itself flag-shaped under that gate and would otherwise just fall
    // through to Undescribed.
    if prefixes.contains(&"-") && s == "--" {
        return Class::EndOfOptions;
    }

    if !flag_shaped(s, &prefixes) {
        return Class::NotFlag;
    }

    // Whole-token match — exact first, then an abbreviation candidate if
    // the vocabulary's policy allows deciding what to do with one. This
    // runs before every attached-value guess below, so a token that is
    // ITSELF a declared (or abbreviated) flag is never misread as some
    // other flag's attached value.
    if let Some((kind, canon, exact)) = find_declared(s, v) {
        if exact {
            return kind.class(canon, None);
        }
        return match v.abbreviation {
            Abbrev::Accept => kind.class(canon, None),
            Abbrev::Refuse => Class::RefusedAbbrev { token: s.to_string(), declared: canon.to_string() },
        };
    }

    // PowerShell `-Name:value`. Tried before the short attached-value guess
    // below on purpose: when a token could be read either way, the colon
    // reading wins whenever the text before the colon actually spells a
    // declared flag — the vocab_for construction policy this module's own
    // callers rely on.
    if v.colon_attach {
        if let Some((pre, post)) = s.split_once(':') {
            if let Some((kind, canon, exact)) = find_declared(pre, v) {
                if exact || v.abbreviation == Abbrev::Accept {
                    return kind.class(canon, Some(post.to_string()));
                }
                // The pre-colon text is a refused-abbreviation candidate,
                // same as a whole-token one above — loud, not a silent fall
                // through to `=`/short-attach/cluster/Undescribed, which
                // would drop the declared name it prefixes.
                return Class::RefusedAbbrev { token: s.to_string(), declared: canon.to_string() };
            }
        }
    }

    // `--flag=value` (first `=`) — and its short-dash cousin `-f=value`,
    // which no shipped entry uses today but which the shared rule does not
    // need to special-case out.
    if let Some((name, value)) = s.split_once('=') {
        if let Some((Kind::Value, canon, exact)) = find_declared(name, v) {
            if exact || v.abbreviation == Abbrev::Accept {
                return Class::Value { flag: canon.to_string(), attached: Some(value.to_string()) };
            }
        }
    }

    // Short attached value: `-Xvalue` when `-X` is a declared two-character
    // value-taking flag. Boundary-guarded (`get(..2)`) rather than a raw
    // byte index — the flag is ASCII but the token is not, and a fixed
    // offset into a multi-byte character would panic (CLAUDE.md §6.5).
    if s.len() > 2 {
        if let Some(head) = s.get(..2) {
            for d in v.value_options {
                if d.len() == 2 && d.starts_with('-') && eq_case(head, d, v.case_sensitive) {
                    return Class::Value { flag: d.clone(), attached: Some(s[2..].to_string()) };
                }
            }
        }
    }

    // Clustered short flags — single-dash vocabularies only (spec §4.1.3;
    // `--force` never explodes). Whole-cluster rule: every letter must be
    // an independently declared no-value flag, or the cluster reading is
    // refused entirely — a genuine unknown letter does not just drop out of
    // an otherwise-recognised cluster, because that would let an operator's
    // description of `-a` and `-c` silently vouch for whatever `-b` turns
    // out to mean.
    if s.starts_with('-') && !s.starts_with("--") && s.len() > 2 {
        let letters: Vec<char> = s[1..].chars().collect();
        let all_described = !letters.is_empty()
            && letters.iter().all(|c| {
                let short = format!("-{c}");
                v.no_value_options.iter().any(|d| eq_case(d, &short, v.case_sensitive))
            });
        if all_described {
            return Class::Bool { flag: s.to_string() };
        }
    }

    Class::Undescribed { token: s.to_string() }
}

/// Membership: does `raw` spell `flag` in any accepted shape?
///
/// Unlike `classify`, this does not search the vocabulary for whatever flag
/// `raw` might be — it answers for the one `flag` the caller already has in
/// hand, which is why it works for any target name a caller cares about
/// (`wrap_flags`, `write_flags`, a single declared name), not only names
/// that also appear in `value_options`/`no_value_options`. The one place
/// vocabulary content still matters is the cluster reading, because
/// "is every OTHER letter in this cluster described" cannot be answered
/// without `no_value_options` — the same whole-cluster rule `classify`
/// follows: a cluster with any undescribed letter matches nothing, not even
/// the letters it does describe.
///
/// A prefix match under `Abbrev::Refuse` is `Spell::RefusedAbbrev`, not
/// `Spell::No` — the same loudness `classify` gives `Class::RefusedAbbrev`,
/// for the same reason: the `write`/`dest`/`run-dir` consumers this exists
/// for call `spells`, not `classify`, so folding a refused abbreviation into
/// plain non-match here would silently reopen the miss class this module
/// exists to close, one call site later than `classify` closed it.
pub fn spells(flag: &str, raw: &str, v: &Vocab) -> Spell {
    let s = paths::unquote(raw);
    let prefixes = effective_prefixes(v.flag_prefix);

    if s == "--" || !flag_shaped(s, &prefixes) {
        return Spell::No;
    }

    if eq_case(s, flag, v.case_sensitive) {
        return Spell::Yes(None);
    }

    if is_abbrev(s, flag, v.case_sensitive) {
        return match v.abbreviation {
            Abbrev::Accept => Spell::Yes(None),
            Abbrev::Refuse => Spell::RefusedAbbrev { declared: flag.to_string() },
        };
    }

    if v.colon_attach {
        if let Some((pre, post)) = s.split_once(':') {
            if eq_case(pre, flag, v.case_sensitive) {
                return Spell::Yes(Some(post.to_string()));
            }
            if is_abbrev(pre, flag, v.case_sensitive) {
                return match v.abbreviation {
                    Abbrev::Accept => Spell::Yes(Some(post.to_string())),
                    Abbrev::Refuse => Spell::RefusedAbbrev { declared: flag.to_string() },
                };
            }
        }
    }

    if let Some((name, value)) = s.split_once('=') {
        if eq_case(name, flag, v.case_sensitive) {
            return Spell::Yes(Some(value.to_string()));
        }
        if is_abbrev(name, flag, v.case_sensitive) {
            return match v.abbreviation {
                Abbrev::Accept => Spell::Yes(Some(value.to_string())),
                Abbrev::Refuse => Spell::RefusedAbbrev { declared: flag.to_string() },
            };
        }
    }

    // Short attach only when this vocabulary has not itself declared `flag`
    // a no-value flag — a flag the vocab already says never takes a value
    // cannot then be read as attaching one; that reading belongs to the
    // cluster check below instead. A `flag` absent from both declared
    // lists (a `wrap_flags`/`write_flags` member, say) is unconstrained and
    // still gets the attach reading, which is what keeps `spells` usable
    // for a target that classify's own vocabulary search never sees.
    let declared_no_value =
        v.no_value_options.iter().any(|d| eq_case(d, flag, v.case_sensitive));
    if is_bare_short(flag) && s.len() > 2 && !declared_no_value {
        if let Some(head) = s.get(..2) {
            if eq_case(head, flag, v.case_sensitive) {
                return Spell::Yes(Some(s[2..].to_string()));
            }
        }
    }

    if is_bare_short(flag) && s.starts_with('-') && !s.starts_with("--") && s.len() > 2 {
        let letters: Vec<char> = s[1..].chars().collect();
        let all_described = !letters.is_empty()
            && letters.iter().all(|c| {
                let short = format!("-{c}");
                v.no_value_options.iter().any(|d| eq_case(d, &short, v.case_sensitive))
            });
        // Safe: `is_bare_short` guarantees `flag` is exactly `-` plus one
        // ASCII character, so `chars().nth(1)` is always `Some`.
        if all_described && letters.contains(&flag.chars().nth(1).unwrap()) {
            return Spell::Yes(None);
        }
    }

    Spell::No
}

/// Vector-level walk carrying the post-`--` state (§4.1.4 is a per-vector
/// rule; per-token calls cannot honour it on their own). After
/// `EndOfOptions` every subsequent token classifies `NotFlag`.
pub struct ArgWalk<'a> {
    v: &'a Vocab<'a>,
    options_ended: bool,
}

impl<'a> ArgWalk<'a> {
    pub fn new(v: &'a Vocab<'a>) -> Self {
        Self { v, options_ended: false }
    }

    pub fn next(&mut self, raw: &str) -> Class {
        if self.options_ended {
            return Class::NotFlag;
        }
        let class = classify(raw, self.v);
        if class == Class::EndOfOptions {
            self.options_ended = true;
        }
        class
    }
}

/// The one construction policy (round-1: per-caller ad-hoc construction
/// would re-invent the defaults). `case_sensitive =
/// prog.case_sensitive_flags.unwrap_or(false)`. `colon_attach` is set ONLY
/// when the entry's `languages` EXPLICITLY includes `"powershell"` — an
/// empty `languages` (almost every shipped entry) reads as "every
/// language", but colon-attach is a PowerShell spelling (spec §4.1.2) and
/// must not turn on for a unix entry that simply never said which
/// languages it applies to. `abbreviation` is the CALLER's policy
/// argument, passed straight through.
pub fn vocab_for<'a>(prog: &'a Program, abbreviation: Abbrev) -> Vocab<'a> {
    Vocab {
        value_options: &prog.value_options,
        no_value_options: &prog.no_value_options,
        flag_prefix: &prog.flag_prefix,
        case_sensitive: prog.case_sensitive_flags.unwrap_or(false),
        abbreviation,
        colon_attach: prog.languages.iter().any(|l| l == "powershell"),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Which declared list a whole-token match came from — decides whether the
/// token reads as `Class::Value` (a value may follow or attach) or
/// `Class::Bool` (never takes one).
enum Kind {
    Value,
    NoValue,
}

impl Kind {
    fn class(&self, flag: &str, attached: Option<String>) -> Class {
        match self {
            Kind::Value => Class::Value { flag: flag.to_string(), attached },
            Kind::NoValue => Class::Bool { flag: flag.to_string() },
        }
    }
}

fn eq_case(a: &str, b: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// `declared` is `-` plus more than one further character — the structural
/// shape `flag_is` (guards.rs) already used: only single-dash long names
/// abbreviate, never `--` GNU-style long flags and never a bare `-x`.
fn is_abbrev_candidate_shape(declared: &str) -> bool {
    declared.starts_with('-') && !declared.starts_with("--") && declared.len() > 2
}

/// True when `given` is an accepted, non-empty, proper prefix of `declared`
/// under this vocabulary's case rule. Mirrors `flag_is` (guards.rs), which
/// this module's callers replace.
fn is_abbrev(given: &str, declared: &str, case_sensitive: bool) -> bool {
    if !is_abbrev_candidate_shape(declared) {
        return false;
    }
    if !(given.len() >= 2 && given.starts_with('-')) {
        return false;
    }
    if case_sensitive {
        declared.starts_with(given) && given != declared
    } else {
        let (g, d) = (given.to_lowercase(), declared.to_lowercase());
        d.starts_with(&g) && g != d
    }
}

/// `flag` is exactly `-` plus one further character — the shape both the
/// short-attach and the cluster reading key on.
fn is_bare_short(flag: &str) -> bool {
    flag.starts_with('-') && !flag.starts_with("--") && flag.len() == 2
}

/// Searches both declared lists for a whole-token match against `s`: exact
/// first (across both lists), then an abbreviation candidate (across both
/// lists). Returns which list it came from, the CANONICAL declared
/// spelling, and whether it was exact. When more than one declared name
/// could accept `s` as an abbreviation, the first one found (no-value list,
/// then value list, in declared order) wins — this module does not
/// attempt PowerShell's full cross-vocabulary ambiguity rejection, only the
/// accept/refuse policy spec §4.1.7 actually asks for.
fn find_declared<'a>(s: &str, v: &Vocab<'a>) -> Option<(Kind, &'a str, bool)> {
    for d in v.no_value_options {
        if eq_case(s, d, v.case_sensitive) {
            return Some((Kind::NoValue, d.as_str(), true));
        }
    }
    for d in v.value_options {
        if eq_case(s, d, v.case_sensitive) {
            return Some((Kind::Value, d.as_str(), true));
        }
    }
    for d in v.no_value_options {
        if is_abbrev(s, d, v.case_sensitive) {
            return Some((Kind::NoValue, d.as_str(), false));
        }
    }
    for d in v.value_options {
        if is_abbrev(s, d, v.case_sensitive) {
            return Some((Kind::Value, d.as_str(), false));
        }
    }
    None
}

/// How this vocabulary spells flags. Empty in the knowledge file means `-`
/// — the same reading `Vocab::flag_prefix`'s own doc comment states.
///
/// The one definition of that reading. `guards` and `knowledge` both need it —
/// for the subcommand walk, and for the member-shape check the loader and the
/// prompt share — and a rule about what an entry's silence MEANS must not have
/// one copy per module.
pub(crate) fn effective_prefixes(flag_prefix: &[String]) -> Vec<&str> {
    if flag_prefix.is_empty() {
        vec!["-"]
    } else {
        flag_prefix.iter().map(String::as_str).collect()
    }
}

/// cmd.exe-style slash switch: `/s`, `/q`, up to three alphanumeric
/// characters, no nested path separator. Mirrors `is_slash_flag`
/// (guards.rs), duplicated here rather than exposed from there — that
/// function is private and this module changes nothing else in
/// `guards.rs`.
fn is_slash_flag(s: &str) -> bool {
    match s.strip_prefix('/') {
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

/// True when `s` is shaped like SOME flag under this vocabulary's declared
/// prefixes — says nothing about whether any declared flag actually
/// matches it.
fn flag_shaped(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| match *p {
        "/" => is_slash_flag(s),
        _ => s.starts_with('-') && s.len() > 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vocab<'a>(
        value_options: &'a [String],
        no_value_options: &'a [String],
        flag_prefix: &'a [String],
        case_sensitive: bool,
        abbreviation: Abbrev,
        colon_attach: bool,
    ) -> Vocab<'a> {
        Vocab { value_options, no_value_options, flag_prefix, case_sensitive, abbreviation, colon_attach }
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // -- rule 1: the unquoted view --------------------------------------

    #[test]
    fn classify_unquotes_before_matching_a_declared_flag() {
        let no_value = strs(&["--force"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("\"--force\"", &v), Class::Bool { flag: "--force".to_string() });
    }

    #[test]
    fn classify_reads_a_single_quoted_flag_the_same_way() {
        let no_value = strs(&["--force"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("'--force'", &v), Class::Bool { flag: "--force".to_string() });
    }

    // -- rule 2: attached forms ------------------------------------------

    #[test]
    fn classify_reads_the_double_dash_equals_attached_form() {
        let value = strs(&["--output"]);
        let v = vocab(&value, &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(
            classify("--output=/tmp/p", &v),
            Class::Value { flag: "--output".to_string(), attached: Some("/tmp/p".to_string()) }
        );
    }

    #[test]
    fn classify_reads_the_short_attached_form_when_the_short_flag_is_value_taking() {
        let value = strs(&["-o"]);
        let v = vocab(&value, &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(
            classify("-o/tmp/p", &v),
            Class::Value { flag: "-o".to_string(), attached: Some("/tmp/p".to_string()) }
        );
    }

    #[test]
    fn classify_reads_the_powershell_colon_attached_form() {
        let value = strs(&["-Path"]);
        let v = vocab(&value, &[], &[], false, Abbrev::Accept, true);
        assert_eq!(
            classify("-Path:/tmp/p", &v),
            Class::Value { flag: "-Path".to_string(), attached: Some("/tmp/p".to_string()) }
        );
    }

    #[test]
    fn colon_attach_does_not_apply_when_the_vocab_does_not_declare_it() {
        // Same shape, but this entry is not PowerShell-scoped: the colon is
        // just part of an unrecognised token, not an attach form.
        let value = strs(&["-Path"]);
        let v = vocab(&value, &[], &[], false, Abbrev::Accept, false);
        assert_eq!(classify("-Path:/tmp/p", &v), Class::Undescribed { token: "-Path:/tmp/p".to_string() });
    }

    // -- rule 3: clustered short flags ------------------------------------

    #[test]
    fn classify_explodes_a_fully_described_cluster_of_short_flags() {
        let no_value = strs(&["-r", "-f"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("-rf", &v), Class::Bool { flag: "-rf".to_string() });
    }

    #[test]
    fn classify_refuses_a_cluster_with_one_undescribed_letter() {
        let no_value = strs(&["-r"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("-rf", &v), Class::Undescribed { token: "-rf".to_string() });
    }

    #[test]
    fn classify_does_not_explode_a_double_dash_token() {
        let no_value = strs(&["-f", "-o", "-r", "-c", "-e"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("--force", &v), Class::Undescribed { token: "--force".to_string() });
    }

    // -- rule 4: `--` end of options ---------------------------------------

    #[test]
    fn classify_reads_the_end_of_options_marker() {
        let v = vocab(&[], &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("--", &v), Class::EndOfOptions);
    }

    #[test]
    fn arg_walk_classifies_every_token_after_end_of_options_as_not_flag() {
        let value = strs(&["-o"]);
        let v = vocab(&value, &[], &[], true, Abbrev::Refuse, false);
        let mut walk = ArgWalk::new(&v);
        assert_eq!(walk.next("-o"), Class::Value { flag: "-o".to_string(), attached: None });
        assert_eq!(walk.next("--"), Class::EndOfOptions);
        assert_eq!(walk.next("-o"), Class::NotFlag);
        assert_eq!(walk.next("--anything"), Class::NotFlag);
    }

    // -- rule 5: `flag_prefix` ---------------------------------------------

    #[test]
    fn classify_reads_a_slash_flag_when_the_vocab_declares_slash() {
        let no_value = strs(&["/s"]);
        let prefix = strs(&["/"]);
        let v = vocab(&[], &no_value, &prefix, false, Abbrev::Refuse, false);
        assert_eq!(classify("/S", &v), Class::Bool { flag: "/s".to_string() });
    }

    #[test]
    fn a_dash_token_is_not_flag_shaped_for_a_slash_only_vocab() {
        let no_value = strs(&["/s"]);
        let prefix = strs(&["/"]);
        let v = vocab(&[], &no_value, &prefix, false, Abbrev::Refuse, false);
        assert_eq!(classify("-s", &v), Class::NotFlag);
    }

    #[test]
    fn a_mixed_vocab_reads_both_prefix_shapes() {
        let no_value = strs(&["/s", "-r"]);
        let prefix = strs(&["/", "-"]);
        let v = vocab(&[], &no_value, &prefix, false, Abbrev::Refuse, false);
        assert_eq!(classify("/S", &v), Class::Bool { flag: "/s".to_string() });
        assert_eq!(classify("-R", &v), Class::Bool { flag: "-r".to_string() });
    }

    // -- rule 6: case per entry ---------------------------------------------

    #[test]
    fn case_sensitive_vocab_refuses_a_folded_spelling() {
        let value = strs(&["-C"]);
        let v = vocab(&value, &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(classify("-c", &v), Class::Undescribed { token: "-c".to_string() });
    }

    #[test]
    fn case_insensitive_vocab_accepts_a_folded_spelling() {
        let value = strs(&["-C"]);
        let v = vocab(&value, &[], &[], false, Abbrev::Refuse, false);
        assert_eq!(classify("-c", &v), Class::Value { flag: "-C".to_string(), attached: None });
    }

    // -- rule 7: abbreviation ------------------------------------------------

    #[test]
    fn accepted_abbreviation_resolves_to_the_declared_flag() {
        // Only a single-dash long name abbreviates (like PowerShell's own
        // `-Recurse`) — a `--` GNU-style flag never does, covered below.
        let no_value = strs(&["-Recurse"]);
        let v = vocab(&[], &no_value, &[], false, Abbrev::Accept, false);
        assert_eq!(classify("-Recu", &v), Class::Bool { flag: "-Recurse".to_string() });
    }

    #[test]
    fn refused_abbreviation_is_reported_loudly_not_silently_dropped() {
        let no_value = strs(&["-recurse"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(
            classify("-recu", &v),
            Class::RefusedAbbrev { token: "-recu".to_string(), declared: "-recurse".to_string() }
        );
    }

    #[test]
    fn a_double_dash_long_flag_never_abbreviates() {
        let no_value = strs(&["--recursive"]);
        let v = vocab(&[], &no_value, &[], false, Abbrev::Accept, false);
        assert_eq!(classify("--recu", &v), Class::Undescribed { token: "--recu".to_string() });
    }

    // -- the two attach forms, colon precedence over short-attach ----------

    #[test]
    fn colon_reading_wins_when_the_pre_colon_text_spells_a_declared_flag() {
        let value = strs(&["-c"]);
        let v = vocab(&value, &[], &[], false, Abbrev::Accept, true);
        assert_eq!(
            classify("-c:value", &v),
            Class::Value { flag: "-c".to_string(), attached: Some("value".to_string()) }
        );
    }

    #[test]
    fn short_attach_reads_the_token_when_the_pre_colon_text_is_not_declared() {
        let value = strs(&["-c"]);
        let v = vocab(&value, &[], &[], false, Abbrev::Accept, true);
        assert_eq!(
            classify("-cd:value", &v),
            Class::Value { flag: "-c".to_string(), attached: Some("d:value".to_string()) }
        );
    }

    // -- vocab_for's construction policy -------------------------------------

    fn program(
        value_options: Vec<String>,
        no_value_options: Vec<String>,
        case_sensitive_flags: Option<bool>,
        languages: Vec<String>,
    ) -> Program {
        Program { value_options, no_value_options, case_sensitive_flags, languages, ..Default::default() }
    }

    #[test]
    fn vocab_for_defaults_case_sensitivity_to_false_when_unset() {
        let prog = program(vec![], vec![], None, vec![]);
        let v = vocab_for(&prog, Abbrev::Accept);
        assert!(!v.case_sensitive);
    }

    #[test]
    fn vocab_for_reads_a_declared_case_sensitivity() {
        let prog = program(vec![], vec![], Some(true), vec![]);
        let v = vocab_for(&prog, Abbrev::Accept);
        assert!(v.case_sensitive);
    }

    #[test]
    fn vocab_for_does_not_turn_on_colon_attach_for_an_entry_with_no_declared_language() {
        let prog = program(vec![], vec![], None, vec![]);
        let v = vocab_for(&prog, Abbrev::Accept);
        assert!(!v.colon_attach);
    }

    #[test]
    fn vocab_for_does_not_turn_on_colon_attach_for_a_bash_only_entry() {
        let prog = program(vec![], vec![], None, vec!["bash".to_string()]);
        let v = vocab_for(&prog, Abbrev::Accept);
        assert!(!v.colon_attach);
    }

    #[test]
    fn vocab_for_turns_on_colon_attach_for_an_entry_that_declares_powershell() {
        let prog = program(vec![], vec![], None, vec!["powershell".to_string()]);
        let v = vocab_for(&prog, Abbrev::Accept);
        assert!(v.colon_attach);
    }

    // -- spells: the three named cases plus the shapes classify covers -----

    #[test]
    fn spells_reports_case_mismatch_as_no_match_under_a_case_sensitive_vocab() {
        let v = vocab(&[], &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(spells("-C", "-c", &v), Spell::No);
    }

    #[test]
    fn spells_follows_the_same_whole_cluster_rule_as_classify() {
        // `-a` is described, `-b` is not: the whole cluster reading is
        // refused, so `spells` cannot find `-a` in it either, even though
        // `-a` on its own is a perfectly good declared flag.
        let no_value = strs(&["-a"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(spells("-a", "-ab", &v), Spell::No);
    }

    #[test]
    fn spells_finds_a_letter_in_a_fully_described_cluster() {
        let no_value = strs(&["-a", "-b"]);
        let v = vocab(&[], &no_value, &[], true, Abbrev::Refuse, false);
        assert_eq!(spells("-a", "-ab", &v), Spell::Yes(None));
        assert_eq!(spells("-b", "-ab", &v), Spell::Yes(None));
    }

    #[test]
    fn spells_finds_an_attached_value_for_a_target_flag_not_in_the_vocab_lists() {
        // `spells` works for a target the caller supplies directly (e.g. a
        // `wrap_flags` entry), not only names also present in
        // `value_options`/`no_value_options`.
        let v = vocab(&[], &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(spells("-c", "-cvalue", &v), Spell::Yes(Some("value".to_string())));
    }

    #[test]
    fn spells_returns_none_for_a_non_flag_token() {
        let v = vocab(&[], &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(spells("-o", "output.txt", &v), Spell::No);
    }

    // -- fix round 1 (HIGH finding): a refused abbreviation must be loud
    // through `spells` too, not folded into a plain non-match -------------

    #[test]
    fn spells_reports_a_refused_abbreviation_loudly_not_as_a_plain_non_match() {
        let v = vocab(&[], &[], &[], true, Abbrev::Refuse, false);
        assert_eq!(
            spells("-recurse", "-recu", &v),
            Spell::RefusedAbbrev { declared: "-recurse".to_string() }
        );
    }

    #[test]
    fn spells_accepts_an_abbreviation_when_the_policy_allows_it() {
        let v = vocab(&[], &[], &[], false, Abbrev::Accept, false);
        assert_eq!(spells("-Recurse", "-Recu", &v), Spell::Yes(None));
    }

    #[test]
    fn spells_reports_a_refused_abbreviation_reached_through_colon_attach() {
        let v = vocab(&[], &[], &[], false, Abbrev::Refuse, true);
        assert_eq!(
            spells("-Recurse", "-Recu:value", &v),
            Spell::RefusedAbbrev { declared: "-Recurse".to_string() }
        );
    }

    #[test]
    fn classify_reports_a_refused_abbreviation_reached_through_colon_attach() {
        // Same defect, at the `classify` level: before the fix, a refused
        // abbreviation candidate before the colon fell through to `=`,
        // short-attach, cluster, and finally `Undescribed` — losing the
        // declared name it prefixed instead of naming it.
        let no_value = strs(&["-Recurse"]);
        let v = vocab(&[], &no_value, &[], false, Abbrev::Refuse, true);
        assert_eq!(
            classify("-Recu:value", &v),
            Class::RefusedAbbrev { token: "-Recu:value".to_string(), declared: "-Recurse".to_string() }
        );
    }
}
