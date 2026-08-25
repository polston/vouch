//! Python parsing, for the code interpreters are handed inline.
//!
//! `python -c "…"` was opaque text until 2026-07-25: only the protected paths
//! were searched for inside it, so `python -c "shutil.rmtree('/c/work/x')"` was
//! ALLOW while `rm -rf /c/work/x` hit a declared guard. That was recorded as
//! "vouch has no Python parser", which is a thing not built, not a law.
//!
//! Backed by `ruff_python_parser` 0.0.8, pinned. This module was first
//! written against `rustpython-parser`; it is re-derived here against ruff's
//! AST and visitor shapes, which differ in several places worth naming once:
//! a call's arguments live under `arguments.args`/`arguments.keywords` rather
//! than flat on the call node, literals are their own `Expr` variants
//! (`StringLiteral`, `NumberLiteral`, `BooleanLiteral`, …) rather than one
//! `Constant` wrapper, and the generated `Visitor` trait exposes only
//! `visit_stmt`/`visit_expr` rather than one method per node kind.
//!
//! Rules for this module, the same ones the other scanners follow:
//!
//!   * A parse failure returns `Err`, NEVER an empty `Scan`. "I read this and
//!     found nothing" and "I could not read this" are different answers with
//!     different settings, and collapsing them is how an allow-list quietly
//!     becomes a deny-list.
//!   * NO API NAMES IN THIS FILE'S CODE. What `shutil.rmtree` does is
//!     knowledge and lives in `knowledge.toml` as `[[program]]` data, exactly
//!     like `cp` and `tar`. This module only turns Python syntax into the
//!     head+args shape the guards already match on. Naming one in a COMMENT
//!     to explain a rule is fine — naming one in a `match` arm is the defect,
//!     because a name in code is a rule that cannot be changed, inspected, or
//!     overridden without a rebuild. The only string literals below are
//!     Python SYNTAX or this scanner's own sentinels (the `python:`
//!     prefix; the `$?` unresolved-value marker and the `$**`
//!     nameless-unpack marker it hands downstream; the `?` unnameable-call
//!     and `!` rebound-name sentinels it consumes itself; and the
//!     construct names), never a library or function that vouch has an
//!     opinion on.
//!   * Walking descends by default. `Walk` overrides only `visit_stmt` and
//!     `visit_expr`, and both call the generated `walk_stmt`/`walk_expr`
//!     after recording what they came for — an unconsidered node kind is
//!     still WALKED rather than silently skipped, because the fallthrough is
//!     coverage, not blindness. A hand-written match would have the opposite
//!     default.
//!
//! What comes out: one `Cmd` per call, `head` being `python:` plus the dotted
//! callable name (`python:shutil.rmtree`, `python:open`) and `args` its
//! arguments in order, resolved to literal text where that is possible and
//! left holding the `$?`/`$name` marker where it is not — or `$**` for a
//! nameless `**` unpack, which is a slot with no readable text for a
//! different reason and is deliberately its own token. That is deliberately
//! the same shape a shell command produces, so the snippet goes through the
//! existing guards, `written_paths`, and `[write]` rules rather than through
//! a second decision path of its own.

use ruff_python_ast as ast;
use ruff_python_ast::visitor::{self, Visitor};
use std::collections::HashMap;

pub use crate::syntax::{Cmd, Order, Scan};

/// Every construct this scanner can put in front of the user.
///
/// Python constructs are configured the same way bash's and PowerShell's
/// are: `[lang.python]` is a live config section, and each name below is
/// settable at `lang.python.constructs.<name>` — unset defaults to `ask`,
/// same as any other language. `criterion2_test` enumerates this list from
/// the scanner itself and checks every name, rather than trusting it.
pub const KNOWN_CONSTRUCTS: &[&str] = &[
    "parse_failure",
    "unmodeled_command",
    "dynamic_call",
    "unresolved_path",
    "evaluated_input",
    "wrap_depth_exceeded",
    "wrap_unlocated",
    "wrap_ambiguous",
    "callback_argument",
    "rebound_name",
    "unreadable_language",
    "unread_verb",
];

/// A call whose target vouch cannot name: `f()` where `f` is a parameter, or
/// a call on something built by an expression rather than a plain name.
/// Marks the head so the engine can tell "a call vouch has no description
/// of" from "a call vouch could not even identify" — different problems, and
/// the second one is vouch's own limit.
const UNNAMEABLE: &str = "?";

/// A call target whose plain name (or whose dotted head's root) was bound by
/// an ordinary binding form somewhere in this same snippet — assignment, a
/// `def`, a `class`, a loop/with/except/comprehension/match target, or a
/// function parameter. The name no longer means what the knowledge
/// describes, so `Walk::call` refuses to read it as the original rather than
/// matching an entry the snippet itself invalidated. Distinct from
/// `UNNAMEABLE`: a poisoned name IS nameable, it is just no longer trusted.
const REBOUND: &str = "!";

/// Marks a head as a Python call rather than a program name.
///
/// The knowledge file is not scoped by language — `del` is deliberately both
/// the cmd.exe command and the PowerShell alias. That works for names that
/// mean the same thing, and breaks for names that do not: an entry for
/// `open` would also claim the SHELL program `open` is recognised, which is
/// a false claim of exactly the kind CLAUDE.md §3 forbids, because it
/// launders an unknown into a known. Prefixing removes the possibility
/// rather than relying on nobody running `open` on a Mac.
const PREFIX: &str = "python:";

/// What an argument becomes when vouch cannot resolve it to text.
///
/// `pub(crate)` so `guards::fold_kwargs` and `guards::written_paths` (the
/// python argument model, Task 7) push this exact value rather than a second
/// definition of the same literal — one source of truth for the marker every
/// downstream reader compares against.
pub(crate) const MARKER: &str = "$?";

/// What a nameless `**`-unpacking keyword argument (`f(**opts)`) becomes.
///
/// Distinct from `MARKER` on purpose (roadmap M2.78, task 2b fix round 2):
/// an unresolvable VALUE (an attribute access, a nested call) and a
/// nameless unpack both occupy a slot with no text vouch can read, but only
/// the unpack could be carrying an ARBITRARY set of keywords the call never
/// names — including a declared `callback_args` slot — so a reader that
/// cares about that possibility (`guards::callback_argument_used`) has to
/// tell the two apart. Before this constant existed they shared one marker
/// and could not be told apart at all: `json.load(**opts)` and
/// `json.load(x)` produced the identical single token.
///
/// Deliberately still `$`-prefixed, matching every other unresolved-value
/// spelling (`MARKER` itself, and a named marker like `$varname`) — every
/// site that already recognises "this text is unresolved" by testing for a
/// literal `$` (`src/engine.rs`'s write-target checks) keeps working on this
/// value without being told about it specifically. Sites that compare
/// against `MARKER` by EXACT equality do have to be told: see
/// `guards::fold_kwargs`'s `last_unambiguous_positional` computation, which
/// would otherwise misclassify an unpack as an ordinary resolved positional
/// and stop folding a real `name=value` token that precedes it.
///
/// `pub(crate)` for the same reason as `MARKER`.
pub(crate) const UNPACK_MARKER: &str = "$**";

/// The dotted name of a callable, or `None` when it is not a plain dotted
/// path. `shutil.rmtree` and `os.path.join` come back whole; `d["k"]()` does
/// not, because there is no name to report.
fn dotted(e: &ast::Expr) -> Option<String> {
    match e {
        ast::Expr::Name(n) => Some(n.id.to_string()),
        ast::Expr::Attribute(a) => Some(format!("{}.{}", dotted(&a.value)?, a.attr)),
        _ => None,
    }
}

/// Whatever text a Python expression is known to evaluate to.
///
/// Resolution mirrors the shell path deliberately (CLAUDE.md §8: paths and
/// names get the SAME resolution): literals resolve, names assigned a
/// literal earlier in this same snippet resolve, and everything else keeps a
/// marker so it arrives at the engine as an UNRESOLVED value instead of a
/// confident answer. An f-string is the Python spelling of `"$d/x.json"` and
/// is treated as one.
#[derive(Debug, Clone)]
struct ArgumentValue {
    text: String,
    readable: bool,
}

impl ArgumentValue {
    fn readable(text: impl Into<String>) -> Self {
        Self { text: text.into(), readable: true }
    }

    fn unread(text: impl Into<String>) -> Self {
        Self { text: text.into(), readable: false }
    }
}

fn argument_value(e: &ast::Expr, assigned: &HashMap<String, String>) -> ArgumentValue {
    match e {
        ast::Expr::StringLiteral(s) => ArgumentValue::readable(s.value.to_str()),
        ast::Expr::NumberLiteral(n) => match &n.value {
            ast::Number::Int(i) => ArgumentValue::readable(i.to_string()),
            _ => ArgumentValue::unread(MARKER),
        },
        ast::Expr::BooleanLiteral(b) => ArgumentValue::readable(b.value.to_string()),
        // A name resolves to what it was assigned, or stays a marker.
        // Keeping the marker is the point: `open(p, "w")` where `p` came
        // from argv is a write to a path vouch cannot name, and saying so is
        // the honest answer.
        ast::Expr::Name(n) => assigned
            .get(n.id.as_str())
            .cloned()
            .map(ArgumentValue::readable)
            .unwrap_or_else(|| ArgumentValue::unread(format!("${}", n.id))),
        // f"{d}/x.json" — literal segments keep their text, the
        // interpolated ones become markers. An adjacent plain literal —
        // "dir/" f"{d}.txt" is ONE value made of two PARTS — has to be
        // walked at the part level: `FStringValue::elements()` iterates
        // only the f-string parts and silently drops a plain-literal part,
        // which would turn "dir/$d.txt" into "$d.txt" with no marker
        // showing the loss.
        ast::Expr::FString(f) => {
            let mut out = String::new();
            let mut readable = true;
            for part in f.value.iter() {
                match part {
                    ast::FStringPart::Literal(lit) => out.push_str(&lit.value),
                    ast::FStringPart::FString(fstring) => {
                        for el in &fstring.elements {
                            match el {
                                ast::InterpolatedStringElement::Literal(lit) => {
                                    out.push_str(&lit.value)
                                }
                                ast::InterpolatedStringElement::Interpolation(interp) => {
                                    let v = argument_value(&interp.expression, assigned);
                                    out.push_str(&v.text);
                                    readable &= v.readable;
                                }
                            }
                        }
                    }
                }
            }
            ArgumentValue { text: out, readable }
        }
        // `d + "/x.json"`. Only concatenation; any other operator is
        // arithmetic on something that is not a path.
        ast::Expr::BinOp(b) if matches!(b.op, ast::Operator::Add) => {
            let l = argument_value(&b.left, assigned);
            let r = argument_value(&b.right, assigned);
            ArgumentValue {
                text: format!("{}{}", l.text, r.text),
                readable: l.readable && r.readable,
            }
        }
        _ => ArgumentValue::unread(MARKER),
    }
}

fn literal(e: &ast::Expr, assigned: &HashMap<String, String>) -> Option<String> {
    let value = argument_value(e, assigned);
    value.readable.then_some(value.text)
}

/// Collects calls, in the order they appear.
#[derive(Default)]
struct Walk {
    out: Scan,
    /// Names bound to a literal string in this same snippet, and import
    /// aliases. Both answer the same question — what does this name refer
    /// to — so they share one map.
    assigned: HashMap<String, String>,
    /// `from shutil import rmtree` makes the bare name `rmtree` mean
    /// `shutil.rmtree`. Without this, an entry written against the dotted
    /// name silently fails to match the imported spelling, which is the
    /// deny-list error mode: no signal at all.
    imported: HashMap<String, String>,
    /// Names this snippet binds by a non-import form (`Binder`'s output),
    /// collected in a pass over the whole module BEFORE this walk runs, so a
    /// call textually before its rebinding is refused just like one after it
    /// — coarse and order-blind on purpose (CLAUDE.md §0.0 `rebound_name`).
    poisoned: std::collections::HashSet<String>,
    /// The next sequential position to hand out. Python has no
    /// directory-changing constructs, so the cd walk stays inert over these
    /// orders — sequential is correct and deliberate, mirroring the shell
    /// scanner's own top-level counter (`src/shell.rs`).
    counter: u32,
}

impl Walk {
    /// The name to report for a call target, and any receiver value it
    /// carries.
    ///
    /// A dotted path is a module call only when its first segment was
    /// actually imported (`os.remove`, or `sh.rmtree` from `import shutil as
    /// sh`) — without that check every `d.get(…)` on a local dict would be
    /// reported as the module `d`, which is a name no entry could honestly
    /// be written against. Everything else that is an attribute access is a
    /// method call on something vouch could not name as a module
    /// (`Path(p).unlink()`, `d.get(…)`), reported as `.name` with the
    /// receiver carried alongside it — the receiver often IS the path.
    fn target(&self, func: &ast::Expr) -> (String, Option<ArgumentValue>) {
        if let Some(d) = dotted(func) {
            // Computed once and reused below: `split_once` is pure, so the
            // root/rebound check and the module-resolution match are
            // reading the identical result of splitting `d` on its first
            // `.`, not three independent derivations of it.
            let split = d.split_once('.');
            let root = split.map(|(f, _)| f).unwrap_or(&d);
            // A name this snippet rebound no longer means what the
            // knowledge describes; refuse to read it as the original. A
            // bare poisoned name always refuses. A poisoned DOTTED root
            // only refuses when it would otherwise be read as a module
            // (i.e. it was also imported) — a poisoned root that was never
            // a module falls through to the method-call arm below, whose
            // receiver-unknown basis is group C's, not this check's, so a
            // poisoned local variable's own methods are unaffected here.
            if self.poisoned.contains(root) && (split.is_none() || self.imported.contains_key(root)) {
                return (REBOUND.to_string(), None);
            }
            match split {
                // A bare name: `open(…)`, or a function pulled in by
                // `from shutil import rmtree`, which resolves to the dotted
                // name an entry is written against.
                None => return (self.imported.get(&d).cloned().unwrap_or(d), None),
                Some((first, rest)) => {
                    if let Some(module) = self.imported.get(first) {
                        return (format!("{module}.{rest}"), None);
                    }
                }
            }
        }
        // The trailing attribute of a call target, for a method on something
        // vouch could not name as a module: `Path(p).write_text(…)` yields
        // `.write_text`, reported with the leading dot so a knowledge entry
        // for it is visibly a method-on-anything claim rather than a claim
        // about a particular module. One match on `func`, not two: the
        // receiver comes from the same `Attribute` node the method name did,
        // so testing the shape a second time would only re-derive it.
        if let ast::Expr::Attribute(a) = func {
            let recv = self
                .receiver_path(&a.value)
                .unwrap_or_else(|| ArgumentValue::unread(MARKER));
            return (format!(".{}", a.attr), Some(recv));
        }
        (UNNAMEABLE.to_string(), None)
    }

    /// The text a call's receiver stands for, when it can be read.
    ///
    /// `Path("C:/x").unlink()` holds the path inside a one-argument call.
    /// This makes no claim about WHICH constructor it is — only that a call
    /// taking a single resolvable string, used as a receiver, carries that
    /// string forward, and ONLY when the inner call's own callee is itself
    /// module-shaped (a bare or dotted name — `Path(...)`,
    /// `pathlib.Path(...)`). A one-argument call whose callee is a method
    /// in a chain (`x.joinpath("notes.txt")`, `x.with_suffix(".bak")`)
    /// looks identical in shape but its argument is a fragment the method
    /// transforms the receiver WITH, not the receiver itself — reporting it
    /// as the receiver is a confidently wrong value in the position the
    /// guards read as a path. `target` already draws exactly that line: a
    /// method-shaped callee always comes back with its receiver slot
    /// filled, so checking for an EMPTY slot here reuses that test rather
    /// than inventing a second one.
    ///
    /// A plain name or literal receiver resolves directly through
    /// `literal`, which also supplies the `$name` marker for a name vouch
    /// cannot resolve — so this returns `None` only for receiver shapes
    /// neither path covers (a multi-argument call, a chained method call, a
    /// subscript, …), and the caller falls back to the generic marker for
    /// those.
    fn receiver_path(&self, e: &ast::Expr) -> Option<ArgumentValue> {
        let direct = argument_value(e, &self.assigned);
        if direct.readable || matches!(e, ast::Expr::Name(_)) {
            return Some(direct);
        }
        match e {
            ast::Expr::Call(c)
                if c.arguments.args.len() == 1 && c.arguments.keywords.is_empty() =>
            {
                match self.target(&c.func) {
                    (_, None) => Some(argument_value(&c.arguments.args[0], &self.assigned)),
                    (_, Some(_)) => None,
                }
            }
            _ => None,
        }
    }

    fn call(&mut self, node: &ast::ExprCall) {
        let (head, receiver) = self.target(&node.func);
        if head == UNNAMEABLE {
            self.out.note("dynamic_call");
            return;
        }
        if head == REBOUND {
            self.out.note("rebound_name");
            return;
        }
        let mut args: Vec<String> = Vec::new();
        let mut unread_args = std::collections::HashSet::new();
        if let Some(r) = receiver {
            if !r.readable {
                unread_args.insert(args.len());
            }
            args.push(r.text);
        }
        for a in node.arguments.args.iter() {
            // An argument vouch cannot resolve still has to OCCUPY its
            // position, or `os.rename(compute(), "C:/x")` shifts and the
            // destination is read as the source.
            let value = argument_value(a, &self.assigned);
            if !value.readable {
                unread_args.insert(args.len());
            }
            args.push(value.text);
        }
        // Keyword arguments carry their name, since position says nothing
        // about them: `open(file="x", mode="w")`.
        for k in node.arguments.keywords.iter() {
            match &k.arg {
                Some(name) => {
                    let value = argument_value(&k.value, &self.assigned);
                    if !value.readable {
                        unread_args.insert(args.len());
                    }
                    args.push(format!("{name}={}", value.text));
                }
                // `**opts` — a nameless keyword-unpacking argument. There is
                // no name to attach a value to, but dropping it silently
                // makes this call indistinguishable from one that passed no
                // keywords at all — unread material presenting as nothing to
                // read, the direction CLAUDE.md §0/§1 forbid. `UNPACK_MARKER`
                // occupies the slot without inventing a name for it, and
                // without claiming to be an ordinary unresolved value either
                // (see its own doc comment for why the distinction matters).
                None => {
                    unread_args.insert(args.len());
                    args.push(UNPACK_MARKER.to_string());
                }
            }
        }
        let order = Order::Seq(self.counter);
        self.counter += 1;
        // The input source is not POPULATED for python, and the reason is
        // structural rather than effort: a python snippet's standard input is
        // whatever the enclosing process was handed, so the answer belongs to
        // the layer above — the shell line that started the interpreter — not
        // to this scanner. Python has no syntax of its own for redirecting it.
        // Chain identity and prefix assignments are shell/and-or-list
        // concepts with no python analogue — every call lands with
        // `chain: None, prefix_assigns: vec![]`.
        self.out.push_cmd(
            format!("{PREFIX}{head}"),
            args,
            order,
            crate::syntax::InputSource::Unknown,
            true,
            None,
            vec![],
        );
        if let Some(cmd) = self.out.commands.last_mut() {
            cmd.unread_args = unread_args;
        }
    }
}

impl<'a> Visitor<'a> for Walk {
    fn visit_stmt(&mut self, stmt: &'a ast::Stmt) {
        match stmt {
            // `p = "C:/work/x"` then `open(p, "w")`. The same reason the
            // shell scanner records `f="…"`: the destination is stated in
            // plain sight one line earlier, and not reading it makes a
            // knowable path unknowable.
            ast::Stmt::Assign(assign) => {
                if let Some(v) = literal(&assign.value, &self.assigned) {
                    if !v.contains('$') {
                        for t in &assign.targets {
                            if let ast::Expr::Name(n) = t {
                                self.assigned.insert(n.id.to_string(), v.clone());
                            }
                        }
                    }
                }
            }
            // Plain `import os` binds `os` to itself. Recording it is what
            // separates a MODULE path from a method on a local variable, so
            // a no-op-looking entry is doing the work.
            //
            // What these two arms do NOT do is note a construct, and an
            // import is not inert: it runs the imported module's own
            // top-level code. A snippet whose statements are all imports
            // therefore emits no commands and allows. That is pre-existing
            // (the same is true at this changeset's fork point) and it is
            // recorded as ROADMAP M2.93 — named there for what it is, with
            // the shape of a fix. Do not read the name-map recording below
            // as the whole of what an import means.
            ast::Stmt::Import(import) => {
                for a in &import.names {
                    let bound = a.asname.as_ref().unwrap_or(&a.name);
                    self.imported.insert(bound.to_string(), a.name.to_string());
                }
            }
            ast::Stmt::ImportFrom(import_from) => {
                if let Some(module) = &import_from.module {
                    for a in &import_from.names {
                        let bound = a.asname.as_ref().unwrap_or(&a.name);
                        self.imported
                            .insert(bound.to_string(), format!("{module}.{}", a.name));
                    }
                }
            }
            _ => {}
        }
        visitor::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a ast::Expr) {
        if let ast::Expr::Call(call) = expr {
            self.call(call);
        }
        visitor::walk_expr(self, expr);
    }
}

/// Collects every name the snippet binds by a non-import form, in a pass
/// over the whole module BEFORE `Walk` judges any call. Coarse and
/// order-blind on purpose: a poisoned name refuses entry-matching
/// everywhere in the snippet, which can only cost an unnecessary ask, never
/// a missed read (spec 2026-08-09, rebound-name rules). Import bindings are
/// deliberately absent here — `Walk`'s `imported` map already resolves them
/// to their true dotted names, and poisoning them would replace a truthful
/// judgment with a refusal.
#[derive(Default)]
struct Binder {
    bound: std::collections::HashSet<String>,
}

impl Binder {
    /// Names inside an assignment-target shape: `a`, `(a, b)`, `[a, *b]`.
    fn bind_target(&mut self, e: &ast::Expr) {
        match e {
            ast::Expr::Name(n) => {
                self.bound.insert(n.id.to_string());
            }
            ast::Expr::Tuple(t) => t.elts.iter().for_each(|e| self.bind_target(e)),
            ast::Expr::List(l) => l.elts.iter().for_each(|e| self.bind_target(e)),
            ast::Expr::Starred(s) => self.bind_target(&s.value),
            _ => {}
        }
    }

    fn bind_params(&mut self, params: &ast::Parameters) {
        for p in params.iter() {
            self.bound.insert(p.name().to_string());
        }
    }

    /// A comprehension/generator's own `for` targets — the shared body
    /// behind list/set/dict-comprehension and generator-expression binding,
    /// which differ only in which AST node carries the `generators` field.
    fn bind_generators(&mut self, generators: &[ast::Comprehension]) {
        generators.iter().for_each(|g| self.bind_target(&g.target));
    }

    /// An optional captured name — the shared body behind `match`/`case`'s
    /// `MatchAs`/`MatchStar` `.name` and `MatchMapping`'s `.rest`, which
    /// differ only in which field carries the optional identifier.
    fn bind_opt_name(&mut self, name: &Option<ast::Identifier>) {
        if let Some(n) = name {
            self.bound.insert(n.to_string());
        }
    }
}

impl<'a> Visitor<'a> for Binder {
    fn visit_stmt(&mut self, stmt: &'a ast::Stmt) {
        match stmt {
            ast::Stmt::Assign(a) => a.targets.iter().for_each(|t| self.bind_target(t)),
            ast::Stmt::AugAssign(a) => self.bind_target(&a.target),
            ast::Stmt::AnnAssign(a) => self.bind_target(&a.target),
            ast::Stmt::For(f) => self.bind_target(&f.target),
            ast::Stmt::FunctionDef(f) => {
                self.bound.insert(f.name.to_string());
                self.bind_params(&f.parameters);
            }
            ast::Stmt::ClassDef(c) => {
                self.bound.insert(c.name.to_string());
            }
            ast::Stmt::With(w) => {
                for item in &w.items {
                    if let Some(v) = &item.optional_vars {
                        self.bind_target(v);
                    }
                }
            }
            ast::Stmt::Try(t) => {
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = h;
                    if let Some(n) = &h.name {
                        self.bound.insert(n.to_string());
                    }
                }
            }
            _ => {}
        }
        visitor::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a ast::Expr) {
        match expr {
            ast::Expr::Named(n) => self.bind_target(&n.target),
            ast::Expr::Lambda(l) => {
                if let Some(p) = &l.parameters {
                    self.bind_params(p);
                }
            }
            ast::Expr::ListComp(c) => self.bind_generators(&c.generators),
            ast::Expr::SetComp(c) => self.bind_generators(&c.generators),
            ast::Expr::DictComp(c) => self.bind_generators(&c.generators),
            ast::Expr::Generator(g) => self.bind_generators(&g.generators),
            _ => {}
        }
        visitor::walk_expr(self, expr);
    }

    /// `match`/`case` capture names. Patterns are not `Stmt`/`Expr` nodes —
    /// `walk_stmt`'s own `Stmt::Match` arm already reaches every pattern
    /// through `visit_match_case`/`visit_pattern` (the generated visitor's
    /// default descent), so overriding this one hook is enough; no hand
    /// rolled walk of `Stmt::Match` is needed. `MatchAs` (`case p:`, `case _
    /// as p:`), `MatchStar` (`case [*p]:`) and `MatchMapping`'s `rest`
    /// (`case {**p}:`) are the only pattern shapes that bind a name;
    /// `MatchOr`/`MatchSequence`/`MatchClass` carry no name of their own and
    /// reach their own sub-patterns through the default `walk_pattern`.
    fn visit_pattern(&mut self, pattern: &'a ast::Pattern) {
        match pattern {
            ast::Pattern::MatchAs(p) => self.bind_opt_name(&p.name),
            ast::Pattern::MatchStar(p) => self.bind_opt_name(&p.name),
            ast::Pattern::MatchMapping(p) => self.bind_opt_name(&p.rest),
            _ => {}
        }
        visitor::walk_pattern(self, pattern);
    }
}

pub fn parse(src: &str) -> Result<Scan, String> {
    // A snippet arrives with whatever indentation the shell quoting left on
    // it. `python -c "` … `"` snippets written across lines routinely start
    // with a leading space, which Python rejects as an indentation error —
    // a defect in how vouch received the text, not something the user wrote.
    let src = dedent(&crate::paths::normalize_newlines(src));
    let parsed = ruff_python_parser::parse_module(&src).map_err(|e| e.to_string())?;
    // `parse_module` is already `Err` for every ordinary syntax error; this
    // gate additionally refuses an `Ok` tree carrying unsupported-syntax
    // recoveries — newer-than-target syntax ruff still parsed but flags
    // rather than rejects outright. A recovered-around region is a region
    // nobody inspected.
    if !parsed.has_no_syntax_errors() {
        return Err(first_problem_line(&parsed));
    }
    let module = parsed.into_syntax();
    // A pre-pass over the whole module, before any call is judged, so a
    // call textually BEFORE its rebinding is refused too — poisoning is
    // order-blind on purpose (see `Binder`'s doc comment).
    let mut binder = Binder::default();
    for stmt in &module.body {
        binder.visit_stmt(stmt);
    }
    let mut w = Walk {
        poisoned: binder.bound,
        ..Walk::default()
    };
    for stmt in &module.body {
        w.visit_stmt(stmt);
    }
    Ok(w.out)
}

/// The first reported problem, as one line: a syntax error if `parsed`
/// carries one, else the first unsupported-syntax recovery.
fn first_problem_line<T>(parsed: &ruff_python_parser::Parsed<T>) -> String {
    if let Some(e) = parsed.errors().first() {
        return first_line(&e.to_string());
    }
    match parsed.unsupported_syntax_errors().first() {
        Some(e) => first_line(&e.to_string()),
        None => "parse error".to_string(),
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("parse error").to_string()
}

/// Removes indentation that is common to every non-empty line.
///
/// Snippets are routinely embedded in a shell command with the whole block
/// indented. Python is whitespace-sensitive, so that indentation is a parse
/// error about vouch's own handling rather than about the code.
fn dedent(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    // Counted and cut in CHARACTERS, never bytes. `trim_start`/`is_whitespace`
    // work on Unicode whitespace, which is not all one byte wide (a no-break
    // space or an ideographic space run to 2-3 bytes) — a byte offset taken
    // from one line's leading run can land inside a different line's
    // multi-byte character and slicing there panics instead of returning
    // through this module's `Ok`/`Err` contract.
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).count())
        .min()
        .unwrap_or(0);
    if indent == 0 {
        return src.to_string();
    }
    lines
        .iter()
        .map(|l| {
            if l.chars().count() >= indent {
                l.chars().skip(indent).collect::<String>()
            } else {
                l.trim_start().to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The Python scanner.
pub struct Python;

impl crate::syntax::Scanner for Python {
    fn lang(&self) -> &'static str {
        "python"
    }
    fn scan(&self, src: &str) -> Result<Scan, String> {
        parse(src)
    }
    fn known_constructs(&self) -> &'static [&'static str] {
        KNOWN_CONSTRUCTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `has_no_syntax_errors()` is the part of the gate an ordinary broken
    /// snippet never reaches — `parse_module` already returns `Err` for a
    /// plain syntax error before this check ever runs (see `parse` above).
    /// The gate exists for a second, different shape: text that IS valid
    /// grammar but uses syntax newer than the parser's default target
    /// version (3.10), which ruff parses and flags rather than rejects. A
    /// PEP 695 type-alias statement (added in 3.12) is exactly that shape,
    /// so this exercises the gate directly, through the real public
    /// entry point, with no hand-built error data.
    #[test]
    fn syntax_too_new_for_the_default_target_is_still_refused() {
        assert!(parse("type X = int").is_err());
    }

    /// A no-break space (U+00A0) is `char::is_whitespace()` but 2 bytes wide
    /// in UTF-8; the fixed `dedent` counts and cuts in characters, so a
    /// byte-offset computed from one line's leading run can no longer land
    /// inside a different line's multi-byte character. Reproduces the
    /// review's exact input.
    #[test]
    fn dedent_does_not_panic_on_multi_byte_leading_whitespace() {
        assert_eq!(dedent(" x = 1\n\u{a0}y = 2"), "x = 1\ny = 2");
    }

    /// Every binding form poisons its name: a later call through it must
    /// emit the rebound_name note and no cmd for that call (spec 2026-08-09,
    /// review finding 2). Import bindings are deliberately NOT poison — the
    /// `imported` map already resolves them to their true dotted names.
    #[test]
    fn a_rebound_name_is_not_read_as_the_original() {
        for src in [
            "p = 1\np('x')",                 // assignment
            "p += 1\np('x')",                // augmented
            "p: int = 1\np('x')",            // annotated
            "(p := 1)\np('x')",              // walrus
            "def p(a): pass\np('x')",        // def
            "class p: pass\np('x')",         // class
            "for p in y: p('x')",            // for target
            "with y as p: p('x')",           // with-as
            "[p for p in y]\np('x')",        // comprehension target
            "try:\n    pass\nexcept E as p:\n    p('x')", // except-as
            "match y:\n    case p:\n        p('x')",      // match capture
            "def f(p):\n    p('x')",         // parameter called in the body
        ] {
            let scan = parse(src).expect(src);
            assert!(
                scan.constructs.iter().any(|n| n == "rebound_name"),
                "{src}: no rebound_name note; constructs = {:?}",
                scan.constructs
            );
            assert!(
                !scan.commands.iter().any(|c| c.head == "python:p"),
                "{src}: the call was still read as the plain name"
            );
        }
    }

    /// A rebound ROOT of a dotted module head refuses the module reading.
    #[test]
    fn a_rebound_module_root_is_not_read_as_the_module() {
        // Neutral module name on purpose (fixture-string discipline above).
        let scan = parse("import m\nm = 1\nm.load('x')").expect("parses");
        assert!(scan.constructs.iter().any(|n| n == "rebound_name"));
        assert!(!scan.commands.iter().any(|c| c.head.starts_with("python:m.")));
    }

    /// Plain imports still resolve truthfully — no poison.
    #[test]
    fn imports_are_not_poison() {
        let scan = parse("from a.b import c as d\nd('x')").expect("parses");
        assert!(scan.commands.iter().any(|c| c.head == "python:a.b.c"));
        assert!(!scan.constructs.iter().any(|n| n == "rebound_name"));
    }
}
