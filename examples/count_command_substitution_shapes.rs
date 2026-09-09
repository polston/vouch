//! On-demand measurement for the command-substitution changeset (M2.250,
//! M2.155): how many real rows carry a substitution body, at which word
//! positions, how deep they nest, what runs inside them, and how vouch
//! decides those rows today under each replay config.
//!
//! Every arm is proved to fire before any corpus number is printed (CLAUDE.md
//! §6.8), and the negative arm is proved NOT to fire. Bodies are located by
//! walking brush's AST for the design's word positions and reading each word
//! through the same `vouch::shell::substitution_bodies` the walk uses, so the
//! example and the scanner cannot read a word two ways. Inner heads are
//! taken from `cmd_scope == Some(0)` of each body's own scan, so after the
//! walk change the nested walk is never counted twice.
//!
//! No corpus text, path, command or destination is printed — aggregate
//! counts only, and a head is named only when it is a bare program name.
//!
//! Run: `cargo run --release --example count_command_substitution_shapes`

#[path = "../tests/common/mod.rs"]
mod common;

use brush_parser::ast;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use vouch::guards::Knowledge;
use vouch::syntax::{Cmd, Scan, Scanner};

/// Invented commands, one known positive per arm; the last is the known
/// NEGATIVE (a quoted delimiter expands nothing).
const CONTROLS: &[(&str, &str)] = &[
    ("prefilter", "echo $(id)"),
    ("body_confirmed", "echo `id`"),
    ("fp_arith", "echo $((1+2))"),
    ("fp_single", "echo '$(x)'"),
    ("fp_escaped", "echo \"\\$(x)\""),
    ("unreadable", "cat <<EOF\n$(foo\nEOF\n"),
    ("body_parse_failure", "echo $(for)"),
    ("nested", "echo $(echo $(id))"),
    ("pos_head", "$(which ls) -l"),
    ("pos_prefix_assign", "X=$(id) ls"),
    ("pos_suffix", "echo $(id)"),
    ("pos_suffix_assign", "dd of=$(mktemp)"),
    ("pos_redirect", "echo hi > $(mktemp)"),
    ("pos_herestring", "cat <<< \"$(id)\""),
    ("pos_heredoc", "cat <<EOF\n$(id)\nEOF\n"),
    ("pos_for_values", "for x in $(id); do :; done"),
    ("pos_case", "case $(id) in a) echo;; esac"),
    ("pos_extended_test", "[[ $(id) ]] && echo"),
    ("pos_arith_cmd", "(( x = $(id) ))"),
    ("pos_function_redirect", "f() { :; } > $(mktemp)"),
    ("inner_head", "echo $(git status)"),
    ("inner_unmodeled", "echo $(zzznotaprogram)"),
    // `git`'s own shipped entry (design's own sketch used it) has no
    // `subcommands` scope — it covers the whole program, so every verb is
    // "recognised" and this shape never fires against it (measured). `vouch`
    // is the one shipped entry that IS scoped to a subcommand list, so it is
    // the control that actually exercises "described program, unrecognised
    // verb" against the real knowledge.
    ("inner_verb_unrecognised", "echo $(vouch zzznotaverb)"),
    ("inner_guard", "echo $(rm -rf /tmp/zz)"),
    ("inner_dynamic", "echo $($(x))"),
    ("NEGATIVE heredoc_quoted", "cat <<'EOF'\n$(id)\nEOF\n"),
];

/// Which §2.2 word position a visited raw string came from. `None` (passed
/// as the caller's own `Option<Pos>`) is used for the rare shapes §2.2 does
/// not name a row for — a plain (non-assignment) prefix word — so a body
/// found there still counts toward the totals without inventing an arm.
#[derive(Clone, Copy)]
enum Pos {
    Head,
    PrefixAssign,
    Suffix,
    SuffixAssign,
    Redirect,
    HereString,
    HereDoc,
    ForValues,
    Case,
    ExtendedTest,
    ArithCmd,
    FunctionRedirect,
}

#[derive(Default)]
struct Counts {
    // One counter per CONTROLS arm above (the NEGATIVE arm is checked
    // separately, in isolation — see `main`).
    prefilter: usize,
    body_confirmed: usize,
    fp_arith: usize,
    fp_single: usize,
    fp_escaped: usize,
    unreadable: usize,
    body_parse_failure: usize,
    nested: usize,
    pos_head: usize,
    pos_prefix_assign: usize,
    pos_suffix: usize,
    pos_suffix_assign: usize,
    pos_redirect: usize,
    pos_herestring: usize,
    pos_heredoc: usize,
    pos_for_values: usize,
    pos_case: usize,
    pos_extended_test: usize,
    pos_arith_cmd: usize,
    pos_function_redirect: usize,
    inner_head: usize,
    inner_unmodeled: usize,
    inner_verb_unrecognised: usize,
    inner_guard: usize,
    inner_dynamic: usize,

    rows: usize,
    // A row-level text pre-filter, distinct from `prefilter` above (which
    // counts individual WORD positions): how many whole corpus lines carry
    // `$(` or a backtick anywhere at all, before any parse is attempted.
    rows_prefilter: usize,
    // A row where the walk below confirmed at least one real body — the
    // population the verdict split is taken over.
    parsed_rows: usize,
    bodies_total: usize,
    // Nesting level of each found body: 1 is a top-level substitution, 2 is
    // one nested inside another, and so on.
    depth: BTreeMap<usize, usize>,
    // Every bare-name inner head found at `cmd_scope == Some(0)` of a body's
    // own scan, however it is decided.
    inner_heads: BTreeMap<String, usize>,
    // An inner head whose spelling is a path, not a bare name — counted
    // with no text, per the rule at the top of CLAUDE.md.
    inner_path_spelled: usize,
    // Rows carrying at least one UNDESCRIBED inner head, keyed by that
    // head's bare name, for the attribution table `main` prints.
    unmodeled_head_rows: BTreeMap<String, BTreeSet<usize>>,
    // allow / ask / deny, over `parsed_rows`, under each of the three
    // replay shapes §5 names.
    verdict_standing: [usize; 3],
    verdict_live: [usize; 3],
    verdict_subshell: [usize; 3],
}

fn bump_pos(pos: Pos, c: &mut Counts) {
    match pos {
        Pos::Head => c.pos_head += 1,
        Pos::PrefixAssign => c.pos_prefix_assign += 1,
        Pos::Suffix => c.pos_suffix += 1,
        Pos::SuffixAssign => c.pos_suffix_assign += 1,
        Pos::Redirect => c.pos_redirect += 1,
        Pos::HereString => c.pos_herestring += 1,
        Pos::HereDoc => c.pos_heredoc += 1,
        Pos::ForValues => c.pos_for_values += 1,
        Pos::Case => c.pos_case += 1,
        Pos::ExtendedTest => c.pos_extended_test += 1,
        Pos::ArithCmd => c.pos_arith_cmd += 1,
        Pos::FunctionRedirect => c.pos_function_redirect += 1,
    }
}

fn bump_verdict(slot: &mut [usize; 3], verdict: &str) {
    match verdict {
        "allow" => slot[0] += 1,
        "ask" => slot[1] += 1,
        "deny" => slot[2] += 1,
        _ => {}
    }
}

/// True when a word's raw text plainly carries a candidate before any real
/// parse — the same shape `shell::has_command_substitution` tests, kept as
/// its own copy here because that function is private to the crate and this
/// is a text pre-filter over the REPORT, never part of the reader itself.
fn looks_like_a_candidate(raw: &str) -> bool {
    raw.contains("$(") || raw.contains('`')
}

/// Whether the FIRST `$(` or backtick in `text` sits inside an active
/// single-quoted region — bash's own rule for why `'$(x)'` runs nothing. A
/// small local re-implementation of quote tracking, independent of the
/// crate's own (private) quoting helper: this only classifies a false
/// positive for the report, it is never part of the reader.
fn dollar_or_backtick_in_single_quotes(text: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_single {
            match ch {
                '\'' => in_single = false,
                '$' if matches!(chars.peek(), Some('(')) => return true,
                '`' => return true,
                _ => {}
            }
            continue;
        }
        if in_double {
            match ch {
                '\\' => {
                    chars.next();
                }
                '"' => in_double = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '\\' => {
                chars.next();
            }
            '\'' => in_single = true,
            '"' => in_double = true,
            '$' if matches!(chars.peek(), Some('(')) => return false,
            '`' => return false,
            _ => {}
        }
    }
    false
}

/// A false positive the reader correctly reports as no body: which shape it
/// was, for the report's own breakdown. Order matters — checked most
/// specific first, the way the three probed shapes in the design read.
fn classify_false_positive(raw: &str, c: &mut Counts) {
    let text = vouch::shell::strip_line_continuations(raw);
    if text.contains("$((") {
        c.fp_arith += 1;
    } else if dollar_or_backtick_in_single_quotes(&text) {
        c.fp_single += 1;
    } else if text.contains("\\$(") {
        c.fp_escaped += 1;
    }
}

/// The recursive walk: brush's own AST for the §2.2 word positions, reading
/// every word it visits through the public reader so the example and the
/// production walk can never read a word two ways.
struct Walker<'a> {
    kb: &'a Knowledge,
    bash: &'a dyn Scanner,
    // Which corpus row is being walked, for the undescribed-head attribution
    // table. Interior mutability rather than a parameter threaded through
    // every method below: the row does not change mid-walk, and adding it as
    // state here keeps every recursive signature about the WORD it is
    // reading, not about bookkeeping the walk does not need at every level.
    row: Cell<usize>,
}

impl<'a> Walker<'a> {
    /// One word's raw text, at the given §2.2 position.
    fn word(&self, raw: &str, pos: Pos, depth: usize, c: &mut Counts) {
        self.text(raw, Some(pos), depth, c, false);
    }

    /// One unquoted here-document body, read through the heredoc parser
    /// rather than the ordinary word parser (design §2.2).
    fn heredoc(&self, raw: &str, pos: Pos, depth: usize, c: &mut Counts) {
        self.text(raw, Some(pos), depth, c, true);
    }

    fn text(&self, raw: &str, pos: Option<Pos>, depth: usize, c: &mut Counts, is_heredoc: bool) {
        if !looks_like_a_candidate(raw) {
            return;
        }
        c.prefilter += 1;
        let bodies = if is_heredoc {
            vouch::shell::heredoc_substitution_bodies(raw)
        } else {
            vouch::shell::substitution_bodies(raw)
        };
        if bodies.unreadable {
            c.unreadable += 1;
        }
        if bodies.bodies.is_empty() {
            if !bodies.unreadable {
                classify_false_positive(raw, c);
            }
            return;
        }
        c.body_confirmed += 1;
        for body in &bodies.bodies {
            c.bodies_total += 1;
            if let Some(p) = pos {
                bump_pos(p, c);
            }
            let level = depth + 1;
            *c.depth.entry(level).or_insert(0) += 1;
            if depth >= 1 {
                c.nested += 1;
            }
            self.body(body, depth + 1, c);
        }
    }

    /// A found body: classify its own top-level inner heads through vouch's
    /// own bash scanner, then walk the body's OWN word positions for a
    /// deeper body — the recursive half of design §2.1 step 5.
    fn body(&self, body: &str, depth: usize, c: &mut Counts) {
        // A defensive cap, never reached by the real corpus (deepest
        // measured nest is three) — insurance against a runaway recursion
        // on adversarial input, not a claim this changeset needs one.
        if depth > 16 {
            return;
        }
        if let Ok(scan) = self.bash.scan(body) {
            for (i, cmd) in scan.commands.iter().enumerate() {
                if scan.cmd_scope.get(i).copied().flatten() != Some(0) {
                    continue;
                }
                self.classify_inner_head(&scan, i, cmd, c);
            }
        }
        self.program(body, depth, c);
    }

    fn classify_inner_head(&self, scan: &Scan, i: usize, cmd: &Cmd, c: &mut Counts) {
        let head = &cmd.head;
        if head.is_empty() {
            return;
        }
        if looks_like_a_candidate(head) {
            c.inner_dynamic += 1;
            return;
        }
        if !common::is_bare_program_name(head) {
            c.inner_path_spelled += 1;
            return;
        }
        let bare = vouch::guards::base_name(head);
        c.inner_head += 1;
        *c.inner_heads.entry(bare.clone()).or_insert(0) += 1;
        if !vouch::guards::is_modeled(self.kb, head, "bash") {
            c.inner_unmodeled += 1;
            c.unmodeled_head_rows.entry(bare).or_default().insert(self.row.get());
        } else {
            let eligible = common::top_level_eligible(scan, i);
            if !vouch::guards::recognises(self.kb, cmd, "bash", eligible) {
                c.inner_verb_unrecognised += 1;
            }
        }
        if !vouch::guards::check_in(self.kb, cmd, "bash").is_empty() {
            c.inner_guard += 1;
        }
    }

    /// Parse `text` as a whole program and walk it — the top-level call for
    /// a corpus row, and the recursive call for a found body's own text.
    fn program(&self, text: &str, depth: usize, c: &mut Counts) {
        let opts = brush_parser::ParserOptions::default();
        let mut parser = brush_parser::Parser::new(std::io::Cursor::new(text), &opts);
        match parser.parse_program() {
            Ok(program) => {
                for cc in &program.complete_commands {
                    self.compound_list(cc, depth, c);
                }
            }
            // At the top level a row that fails to parse here simply
            // contributes nothing (the corpus loop already skips it via
            // vouch's own scanner). Below the top level this IS the
            // `body_parse_failure` arm: the outer substitution parsed, its
            // body does not.
            Err(_) => {
                if depth > 0 {
                    c.body_parse_failure += 1;
                }
            }
        }
    }

    fn compound_list(&self, list: &ast::CompoundList, depth: usize, c: &mut Counts) {
        for item in &list.0 {
            self.and_or_list(&item.0, depth, c);
        }
    }

    fn and_or_list(&self, aol: &ast::AndOrList, depth: usize, c: &mut Counts) {
        self.pipeline(&aol.first, depth, c);
        for ao in &aol.additional {
            match ao {
                ast::AndOr::And(p) | ast::AndOr::Or(p) => self.pipeline(p, depth, c),
            }
        }
    }

    fn pipeline(&self, p: &ast::Pipeline, depth: usize, c: &mut Counts) {
        for cmd in &p.seq {
            self.command(cmd, depth, c);
        }
    }

    fn command(&self, cmd: &ast::Command, depth: usize, c: &mut Counts) {
        match cmd {
            ast::Command::Simple(sc) => self.simple(sc, depth, c),
            ast::Command::Compound(cc, redirects) => {
                self.compound(cc, depth, c);
                if let Some(list) = redirects {
                    for r in &list.0 {
                        self.redirect(r, Pos::Redirect, depth, c);
                    }
                }
            }
            ast::Command::Function(f) => {
                // The definition's own redirect list (design §2.2's fifth
                // row) is walked separately from the body it wraps.
                if let Some(list) = &f.body.1 {
                    for r in &list.0 {
                        self.redirect(r, Pos::FunctionRedirect, depth, c);
                    }
                }
                self.compound(&f.body.0, depth, c);
            }
            ast::Command::ExtendedTest(e, redirects) => {
                self.extended_test(&e.expr, depth, c);
                if let Some(list) = redirects {
                    for r in &list.0 {
                        // A redirect target, not an operand — same arm every
                        // sibling here uses for its own redirect list.
                        self.redirect(r, Pos::Redirect, depth, c);
                    }
                }
            }
        }
    }

    fn simple(&self, sc: &ast::SimpleCommand, depth: usize, c: &mut Counts) {
        if let Some(w) = &sc.word_or_name {
            self.word(&w.value, Pos::Head, depth, c);
        }
        if let Some(prefix) = &sc.prefix {
            for item in &prefix.0 {
                self.prefix_or_suffix(item, false, depth, c);
            }
        }
        if let Some(suffix) = &sc.suffix {
            for item in &suffix.0 {
                self.prefix_or_suffix(item, true, depth, c);
            }
        }
    }

    fn prefix_or_suffix(
        &self,
        item: &ast::CommandPrefixOrSuffixItem,
        is_suffix: bool,
        depth: usize,
        c: &mut Counts,
    ) {
        match item {
            ast::CommandPrefixOrSuffixItem::IoRedirect(r) => {
                self.redirect(r, Pos::Redirect, depth, c);
            }
            ast::CommandPrefixOrSuffixItem::Word(w) => {
                // A plain (non-assignment) PREFIX word names no §2.2 row of
                // its own — only an assignment does — so it still counts
                // toward the totals without a position arm.
                let pos = is_suffix.then_some(Pos::Suffix);
                self.text(&w.value, pos, depth, c, false);
            }
            ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                // The raw word carries the WHOLE `name=value` (or array)
                // spelling, so one visit covers a scalar assignment, an
                // assignment-shaped suffix argument, and an array literal
                // with its elements and index words alike (design §2.2).
                let pos = if is_suffix { Pos::SuffixAssign } else { Pos::PrefixAssign };
                self.word(&w.value, pos, depth, c);
            }
            ast::CommandPrefixOrSuffixItem::ProcessSubstitution(_, sub) => {
                // Out of scope for this reader — a process substitution
                // carries no `$(`/backtick text of its own, the parser
                // already gave it its own AST shape — but its body can
                // still hold a substitution, so it is walked for
                // completeness with no position arm of its own.
                self.compound_list(&sub.list, depth, c);
            }
        }
    }

    fn compound(&self, cc: &ast::CompoundCommand, depth: usize, c: &mut Counts) {
        match cc {
            ast::CompoundCommand::BraceGroup(bg) => self.compound_list(&bg.list, depth, c),
            ast::CompoundCommand::Subshell(sub) => self.compound_list(&sub.list, depth, c),
            ast::CompoundCommand::ForClause(f) => {
                for w in f.values.iter().flatten() {
                    self.word(&w.value, Pos::ForValues, depth, c);
                }
                self.compound_list(&f.body.list, depth, c);
            }
            ast::CompoundCommand::CaseClause(cc2) => {
                self.word(&cc2.value.value, Pos::Case, depth, c);
                for item in &cc2.cases {
                    for w in &item.patterns {
                        self.word(&w.value, Pos::Case, depth, c);
                    }
                    if let Some(body) = &item.cmd {
                        self.compound_list(body, depth, c);
                    }
                }
            }
            ast::CompoundCommand::IfClause(i) => {
                self.compound_list(&i.condition, depth, c);
                self.compound_list(&i.then, depth, c);
                if let Some(elses) = &i.elses {
                    for e in elses {
                        if let Some(cond) = &e.condition {
                            self.compound_list(cond, depth, c);
                        }
                        self.compound_list(&e.body, depth, c);
                    }
                }
            }
            ast::CompoundCommand::WhileClause(w) | ast::CompoundCommand::UntilClause(w) => {
                self.compound_list(&w.0, depth, c);
                self.compound_list(&w.1.list, depth, c);
            }
            ast::CompoundCommand::Coprocess(cp) => self.command(&cp.body, depth, c),
            ast::CompoundCommand::Arithmetic(a) => {
                self.word(&a.expr.value, Pos::ArithCmd, depth, c);
            }
            ast::CompoundCommand::ArithmeticForClause(f) => {
                for e in [&f.initializer, &f.condition, &f.updater].into_iter().flatten() {
                    self.word(&e.value, Pos::ArithCmd, depth, c);
                }
                self.compound_list(&f.body.list, depth, c);
            }
        }
    }

    fn redirect(&self, r: &ast::IoRedirect, pos: Pos, depth: usize, c: &mut Counts) {
        match r {
            ast::IoRedirect::File(_, _, target) => match target {
                ast::IoFileRedirectTarget::Filename(w) => self.word(&w.value, pos, depth, c),
                ast::IoFileRedirectTarget::Duplicate(w) => self.word(&w.value, pos, depth, c),
                ast::IoFileRedirectTarget::Fd(_) => {}
                ast::IoFileRedirectTarget::ProcessSubstitution(_, sub) => {
                    self.compound_list(&sub.list, depth, c);
                }
            },
            ast::IoRedirect::HereDocument(_, doc) => {
                // A quoted delimiter expands nothing — the NEGATIVE control.
                if doc.requires_expansion {
                    self.heredoc(&doc.doc.value, Pos::HereDoc, depth, c);
                }
            }
            ast::IoRedirect::HereString(_, w) => self.word(&w.value, Pos::HereString, depth, c),
            ast::IoRedirect::OutputAndError(w, _) => self.word(&w.value, pos, depth, c),
        }
    }

    fn extended_test(&self, expr: &ast::ExtendedTestExpr, depth: usize, c: &mut Counts) {
        match expr {
            ast::ExtendedTestExpr::And(l, r) | ast::ExtendedTestExpr::Or(l, r) => {
                self.extended_test(l, depth, c);
                self.extended_test(r, depth, c);
            }
            ast::ExtendedTestExpr::Not(e) | ast::ExtendedTestExpr::Parenthesized(e) => {
                self.extended_test(e, depth, c);
            }
            ast::ExtendedTestExpr::UnaryTest(_, w) => {
                self.word(&w.value, Pos::ExtendedTest, depth, c);
            }
            ast::ExtendedTestExpr::BinaryTest(_, l, r) => {
                self.word(&l.value, Pos::ExtendedTest, depth, c);
                self.word(&r.value, Pos::ExtendedTest, depth, c);
            }
        }
    }
}

/// One command through the whole shape walk — used for both a control and a
/// corpus row. `row` is only meaningful for corpus rows; a control passes 0.
fn walk_row(w: &Walker, row: usize, cmd: &str, c: &mut Counts) {
    w.row.set(row);
    if looks_like_a_candidate(cmd) {
        c.rows_prefilter += 1;
    }
    let before = c.bodies_total;
    w.program(cmd, 0, c);
    if c.bodies_total > before {
        c.parsed_rows += 1;
    }
}

fn main() {
    // The repo-pinning refusal comes before any control output: an
    // unpinned run should refuse loudly, not print a reassuring "controls:
    // all N arms fire" line first and only THEN discover it cannot measure
    // anything. `count_wrapped_snippet_position_shapes` orders it the same
    // way.
    let rows = common::rows_for_measurement();
    let kb = common::shipped_kb();
    let bash = vouch::syntax::scanner_for("bash").expect("bash scanner exists");
    let walker = Walker { kb: &kb, bash: bash.as_ref(), row: Cell::new(0) };

    // The known-positive controls run FIRST and gate the report. The
    // NEGATIVE arm is checked separately, in isolation, so the POSITIVE
    // heredoc control's own contribution to the same counter (`pos_heredoc`)
    // cannot mask a real regression in the quoting check.
    let mut control = Counts::default();
    for (name, command) in CONTROLS {
        if name.starts_with("NEGATIVE") {
            continue;
        }
        walk_row(&walker, 0, command, &mut control);
    }
    let checks: [(&str, usize); 25] = [
        ("prefilter", control.prefilter),
        ("body_confirmed", control.body_confirmed),
        ("fp_arith", control.fp_arith),
        ("fp_single", control.fp_single),
        ("fp_escaped", control.fp_escaped),
        ("unreadable", control.unreadable),
        ("body_parse_failure", control.body_parse_failure),
        ("nested", control.nested),
        ("pos_head", control.pos_head),
        ("pos_prefix_assign", control.pos_prefix_assign),
        ("pos_suffix", control.pos_suffix),
        ("pos_suffix_assign", control.pos_suffix_assign),
        ("pos_redirect", control.pos_redirect),
        ("pos_herestring", control.pos_herestring),
        ("pos_heredoc", control.pos_heredoc),
        ("pos_for_values", control.pos_for_values),
        ("pos_case", control.pos_case),
        ("pos_extended_test", control.pos_extended_test),
        ("pos_arith_cmd", control.pos_arith_cmd),
        ("pos_function_redirect", control.pos_function_redirect),
        ("inner_head", control.inner_head),
        ("inner_unmodeled", control.inner_unmodeled),
        ("inner_verb_unrecognised", control.inner_verb_unrecognised),
        ("inner_guard", control.inner_guard),
        ("inner_dynamic", control.inner_dynamic),
    ];
    let mut inert = false;
    for (name, count) in checks {
        if count == 0 {
            eprintln!("control did not fire: {name}");
            inert = true;
        }
    }
    let mut negative = Counts::default();
    walk_row(&walker, 0, "cat <<'EOF'\n$(id)\nEOF\n", &mut negative);
    if negative.pos_heredoc != 0 {
        eprintln!("control fired when it must not: NEGATIVE heredoc_quoted");
        inert = true;
    }
    if inert {
        eprintln!(
            "This measurement's predicates no longer detect the shapes they \
             were written for, so its corpus counts would be zeros about the \
             detector rather than about the corpus. Fix the predicates before \
             reading any number from this example."
        );
        std::process::exit(1);
    }
    println!("controls: all {} arms fire on invented text, and the negative does not", checks.len());

    // The three replay configs differ by ONE bash construct action each, so
    // they are built the one way: a second spelling of the same load is a
    // second chance for two sides of a comparison to differ by something the
    // report does not name (CLAUDE.md §6.7).
    let replay_config = |construct: &str, action: &str| {
        vouch::config::load(&common::config_text_with(&[("bash", construct, action)]))
            .expect("config parses")
    };
    let standing = replay_config("unmodeled_command", "allow");
    let live = replay_config("unmodeled_command", "ask");
    let subshell_ask = replay_config("subshell", "ask");

    let mut c = Counts::default();
    c.rows = rows.len();
    for (i, row) in rows.iter().enumerate() {
        let before = c.parsed_rows;
        walk_row(&walker, i, &row.cmd, &mut c);
        if c.parsed_rows > before {
            let (v, _) = common::decision_at(&standing, &row.cmd, common::HOOK_HOME);
            bump_verdict(&mut c.verdict_standing, &v);
            let (v, _) = common::decision_at(&live, &row.cmd, common::HOOK_HOME);
            bump_verdict(&mut c.verdict_live, &v);
            let (v, _) = common::decision_at(&subshell_ask, &row.cmd, common::HOOK_HOME);
            bump_verdict(&mut c.verdict_subshell, &v);
        }
    }

    println!();
    println!("corpus rows: {}", c.rows);
    println!("rows carrying `$(` or a backtick anywhere (text pre-filter): {}", c.rows_prefilter);
    println!("parser-confirmed rows (at least one real body found): {}", c.parsed_rows);
    println!();
    println!("--- word positions visited (text pre-filter), and bodies found ---");
    println!("word positions passing the text pre-filter: {}", c.prefilter);
    println!("word positions the parser confirmed carry a body: {}", c.body_confirmed);
    println!("bodies found in total: {}", c.bodies_total);
    println!("unreadable (text plainly holds a substitution vouch could not delimit): {}", c.unreadable);
    println!();
    println!("--- the two false positives §1.4 removes ---");
    println!("arithmetic ($((…))): {}", c.fp_arith);
    println!("single-quoted literal: {}", c.fp_single);
    println!("escaped inside double quotes: {}", c.fp_escaped);
    println!();
    println!("--- bodies per §2.2 position ---");
    println!("command head: {}", c.pos_head);
    println!("prefix assignment (X=$(…) cmd): {}", c.pos_prefix_assign);
    println!("suffix argument: {}", c.pos_suffix);
    println!("suffix assignment-shaped argument: {}", c.pos_suffix_assign);
    println!("redirect target: {}", c.pos_redirect);
    println!("here-string: {}", c.pos_herestring);
    println!("here-document body (unquoted delimiter): {}", c.pos_heredoc);
    println!("for-clause value list: {}", c.pos_for_values);
    println!("case subject/pattern: {}", c.pos_case);
    println!("[[ ]] operand: {}", c.pos_extended_test);
    println!("((…)) / for ((…)) clause text: {}", c.pos_arith_cmd);
    println!("function-definition redirect: {}", c.pos_function_redirect);
    println!();
    println!("--- nesting depth (1 = top-level substitution) ---");
    for (level, count) in &c.depth {
        println!("  depth {level}: {count}");
    }
    println!("bodies nested inside another (depth >= 2): {}", c.nested);
    println!("body re-parse failures below the top level: {}", c.body_parse_failure);
    println!();
    println!("--- inner heads, at cmd_scope == Some(0) of each body's own scan ---");
    println!("bare-name inner heads (occurrences): {}", c.inner_head);
    println!("  … distinct bare names seen: {}", c.inner_heads.len());
    println!("  … undescribed (unmodeled_command): {}", c.inner_unmodeled);
    println!("  … described, verb unrecognised: {}", c.inner_verb_unrecognised);
    println!("  … tripping a guard: {}", c.inner_guard);
    println!("path-spelled inner heads (count only, no text): {}", c.inner_path_spelled);
    println!("dynamic-or-unreadable inner heads (count only, no text): {}", c.inner_dynamic);
    println!();
    println!("--- undescribed inner heads, rows carrying each ---");
    let mut ordered: Vec<_> = c.unmodeled_head_rows.iter().collect();
    ordered.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    for (head, rows) in ordered {
        println!("  {head:<20} rows {}", rows.len());
    }
    println!();
    for (label, split) in [
        ("standing replay (bash unmodeled_command=allow)", c.verdict_standing),
        ("live-shaped (bash unmodeled_command=ask)", c.verdict_live),
        ("subshell override (bash subshell=ask)", c.verdict_subshell),
    ] {
        println!(
            "verdict split over parser-confirmed rows under {label}: allow {} / ask {} / deny {}",
            split[0], split[1], split[2]
        );
    }
}
