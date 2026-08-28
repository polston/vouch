//! The shared vocabulary every language scanner produces.
//!
//! Languages differ in syntax and nothing else. A scanner's entire job is
//! `text -> Scan`. Guards, settings lookup, precedence, and message text are
//! shared and live in `engine`. Adding a language means adding one scanner and
//! one config key — no changes to the pipeline, the guards, or the messages.

/// One simple command, head and arguments separated. Guards match on this
/// rather than on raw text, so flag order and path prefixes cannot hide an
/// operation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub head: String,
    pub args: Vec<String>,
    /// Argument positions whose text is only a placeholder for syntax the
    /// scanner could not resolve. This is out of band because a literal
    /// argument may legally equal any marker spelling.
    pub unread_args: std::collections::HashSet<usize>,
    /// Argument positions emitted from named/keyword syntax rather than
    /// positional syntax. Out of band because a positional string may
    /// legally contain the identical `name=value` text.
    pub keyword_args: std::collections::HashSet<usize>,
    /// This command's position in an `&&`/`||` and-or chain, `None` when it
    /// is not part of one — a plain `;`/newline-separated statement, or the
    /// sole member of a trivial one-pipeline "chain" with no `&&`/`||` link
    /// at all. See `ChainPos`.
    pub chain: Option<ChainPos>,
    /// Names assigned in this command's own PREFIX words (`FOO=bar cmd`,
    /// never `cmd FOO=bar`) — the env vouch knows this one invocation ran
    /// with, independent of whether the assigned VALUE was itself readable.
    pub prefix_assigns: Vec<String>,
    /// Where the receiver of a method-style command came from. Non-method
    /// commands and scanners that do not track values leave this `Unknown`;
    /// knowledge must never infer a receiver claim from missing metadata.
    pub receiver_origin: ValueOrigin,
}

/// A scanner's language-neutral account of where a runtime value came from.
///
/// Origins describe syntax and flow, not policy. The knowledge registry gives
/// producer calls meaning; scanners merely preserve their structure. No list
/// position is stored, so merging scans cannot invalidate an origin reference.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum ValueOrigin {
    /// The scanner cannot prove where the value came from.
    #[default]
    Unknown,
    /// A literal value written directly in the source.
    Literal,
    /// A literal collection or destructured value made from these origins.
    Aggregate(Vec<ValueOrigin>),
    /// The result of calling `head`, optionally as a method on another value.
    Call {
        head: String,
        receiver: Option<Box<ValueOrigin>>,
        arguments: CallArguments,
    },
}

/// Argument-shape facts needed to qualify a producer claim.
///
/// Values are deliberately absent: knowledge needs only which declared
/// callback positions could be occupied, while scanners keep policy names
/// out of their implementations.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CallArguments {
    pub positional: usize,
    pub keywords: Vec<String>,
    pub starred: bool,
    pub keyword_unpack: bool,
}

/// One indexable value a language scanner can identify structurally without
/// deciding where its runtime values come from. Knowledge at a wrapper
/// boundary may connect the dotted `name` and static `index` to an enclosing
/// program argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedValueRef {
    pub name: String,
    pub index: usize,
}

/// One command's position within a bash/powershell and-or chain (`&&`/`||`).
///
/// `id` distinguishes one and-or chain from another — unique within a
/// single parse, meaningless across parses. `idx` counts CHAIN MEMBERS, not
/// `Cmd`s: a member of the chain is one pipeline (`a | b | c` counts as ONE
/// member), and every `Cmd` that member expands to — every piped stage
/// today, every wrapper-unwrapped command later — shares that one member's
/// `ChainPos`; `idx` never increments for a stage inside the same pipeline.
///
/// `and_run_from` is the earliest member index reachable by walking
/// backward over `&&` links only, starting from this member: the set of
/// members whose successful completion this member's own execution
/// certifies. A `||` link breaks that chain — the member on its right is
/// only known to run when the member on its left FAILED, which certifies
/// nothing about anything earlier — so `and_run_from` resets to the
/// member's own `idx` there. `a && b || c`: `a` = {idx:0, and_run_from:0},
/// `b` = {idx:1, and_run_from:0} (reachable from `a` via one `&&` link),
/// `c` = {idx:2, and_run_from:2} (the `||` breaks the chain; nothing before
/// `c` is certified by `c` running).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPos {
    pub id: u32,
    pub idx: u32,
    pub and_run_from: u32,
}

/// What supplies a command's standard input.
///
/// A FACT about the command, carrying no judgement about whether vouch can
/// READ what it names — that is the engine's question, answered by
/// `guards::holds_input`. The third resolved per-command property, beside the
/// run place and the write base.
///
/// Which value a redirect produces is decided by its RESOLVED descriptor —
/// the explicit number when the spelling carries one, else the operator's own
/// default (0 for `<`, `<>`, `<&`, `<<`, `<<<`; 1 for `>`, `>>`, `>|`, `>&`)
/// — and the LAST redirect resolving to descriptor 0 decides. Never by
/// read-versus-write shape: `0> f.txt` replaces standard input while being
/// write-shaped, and `2> err.txt` does not while looking like a competitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    /// A here-document on this command feeds descriptor 0. Carries the
    /// record's own `HeredocId`, stamped once at creation and never
    /// renumbered — selection is `heredoc.id == wanted` wherever the
    /// `heredocs` list is read (filtered per command, merged by
    /// `Scan::absorb`, handed to a nested scan), never a position in that
    /// list. A position-based index was the whole defect class this replaced
    /// (M2.127): a list can be filtered or merged without every reference
    /// into it being re-based in lockstep, and when it isn't, the wrong
    /// record is selected. An identity cannot desync this way — filtering or
    /// merging the list never changes what a record's own id is.
    Heredoc(HeredocId),
    /// A filename redirect resolves to descriptor 0 (`< f`, `0< f`, `<>`, and
    /// a write-shaped spelling aimed at descriptor 0).
    File,
    /// A process substitution, a descriptor duplication or close, or a
    /// here-string resolves to descriptor 0.
    Stream,
    /// A pipeline member other than the FIRST, with no redirect resolving to
    /// descriptor 0.
    Pipe,
    /// Nothing supplies descriptor 0 and no enclosing construct the walk
    /// EXAMINES does either. One accepted exception: an untracked `exec`-family
    /// redirection earlier in the text can make this value wrong (ROADMAP
    /// M2.101) — accepted because no value here can hold an input, so the
    /// error is a false fact, never a false allow.
    Nothing,
    /// Not resolvable, or not populated by this scanner. The fail-closed
    /// default: `Unknown` never holds, so it keeps whatever ask the command
    /// already had.
    Unknown,
}

/// A here-document record's identity.
///
/// Stamped once, at creation (`Scan::alloc_heredoc_id`), from the owning
/// `Scan`'s own counter — never from the record's position in `heredocs`,
/// which can differ from allocation order: a nested construct parsed partway
/// through a command's own prefix/suffix (a process substitution) flushes
/// its OWN records into `heredocs` before the command that is still being
/// walked flushes its pending ones, so a later-allocated id can land at an
/// earlier position. `Scan::absorb` re-stamps an absorbed scan's ids past
/// whatever range the absorbing scan has already handed out, so two scans'
/// ids never collide once merged. What `InputSource::Heredoc` carries, and
/// what every reader compares a record against — never a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeredocId(pub u32);

/// A here-document's body, tied to the command that reads it.
///
/// Captured instead of merely noted (the `"heredoc"` construct) so a locator
/// can hand the body to a scanner when the consuming command actually reads
/// it from standard input — see `guards::heredoc_feeds`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heredoc {
    /// This record's own identity — see `HeredocId`.
    pub id: HeredocId,
    /// The body text, with `<<-`'s leading tabs already stripped when the
    /// parser said to remove them.
    pub body: String,
    /// Whether the delimiter was quoted (`<<'EOF'`) — a quoted delimiter
    /// reaches the consumer verbatim; an unquoted one is expanded by the
    /// shell first, so the raw text is not always what the consumer sees.
    pub quoted_delimiter: bool,
    /// The PROSPECTIVE index of the command this heredoc is attached to:
    /// `commands.len()` at the moment its command is about to be pushed, not
    /// necessarily the index it lands at (a heredoc whose command never
    /// lands — an empty head — has no meaningful index; callers must check
    /// the command actually exists before reading it).
    pub cmd_index: usize,
    /// The RESOLVED descriptor this body feeds: the explicit number when the
    /// spelling carries one (`3<< TAG`), else 0. Signed to match the parser's
    /// own descriptor type rather than converting at the boundary. Read by the
    /// judgement's sibling rule — a body at any other descriptor never reaches
    /// standard input, so it can neither satisfy a stdin claim nor, by being
    /// refused, prevent a sibling from satisfying one.
    pub fd: i32,
}

/// Whether a command's (or redirect's) position in the top-level sequence is
/// provable — i.e. whether the engine can say, with certainty, everything
/// that ran before it and in what order, so `cd` state can be resolved
/// against that position.
///
/// `Seq(n)` is the nth item along a top-level chain of `;`/newline/`&&` —
/// always executes, always in this order. `Unordered` covers everything
/// else: the tail of an and-or chain after the first `||` (may not run at
/// all), any pipeline with more than one member (runs concurrently), a
/// background command, and the inside of every compound body — subshells,
/// `if`/`for`/`while`/`until`/`case`, brace groups, coprocesses, function
/// bodies — at any depth. When it is not provable, it must never be reported
/// as `Seq` — see CLAUDE.md §1: errors fall toward ASK, never toward a false
/// claim of certainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Order {
    Seq(u32),
    Unordered,
}

/// What a scanner found.
#[derive(Debug, Default, Clone)]
pub struct Scan {
    /// Command heads, in order.
    pub heads: Vec<String>,
    /// Commands with their arguments.
    pub commands: Vec<Cmd>,
    /// Named constructs, deduplicated. Each name is a settable key.
    pub constructs: Vec<String>,
    /// Files this text writes to by redirection, where the target is literal.
    pub redirect_targets: Vec<String>,
    /// Whether each command's position (parallel to `commands`) is provable.
    pub order: Vec<Order>,
    /// Whether each redirect's position (parallel to `redirect_targets`) is
    /// provable — the order of the command it is attached to.
    pub redirect_order: Vec<Order>,
    /// Variables assigned in this same text, as (name, value). Last-write-wins
    /// order — a later assignment to the same name shadows an earlier one,
    /// poisoned entries included.
    ///
    /// Agent tooling routinely writes `f="C:/…/x.output"` and
    /// then `> "$f"`. Without these the written path is unknowable even though
    /// it is stated in plain sight two tokens earlier.
    ///
    /// `None` marks a POISONED assignment: a value built by something vouch
    /// cannot read in advance (command substitution, backticks). It is still
    /// recorded — a name whose LAST write is poisoned must read as
    /// unresolvable, never silently fall through to a lookup that answers a
    /// question the shell never actually asked (`std::env::var`, at
    /// resolution time) just because this map stayed silent about it.
    pub assignments: Vec<(String, Option<String>)>,
    /// Here-document bodies captured in this text, tied to the commands that
    /// read them (parallel to nothing — indexed via `Heredoc::cmd_index`,
    /// not position-parallel to `commands` the way `order` is).
    pub heredocs: Vec<Heredoc>,
    /// What supplies each command's standard input (parallel to `commands`).
    ///
    /// Grows where the other parallel arrays grow — `push_cmd` and `absorb` —
    /// because nothing about the default is automatic. Every READ is by
    /// `.get(i)` with `Unknown` as the fallback: a short array must degrade to
    /// asking, never to reading a neighbour's answer.
    pub input_source: Vec<InputSource>,
    /// Whether each command's recorded `args` is a FAITHFUL record of the
    /// arguments the shell will pass (parallel to `commands`).
    ///
    /// False when the parser dropped one, which today means an
    /// argument-position process substitution: `prog <(inner)` pushes no token
    /// while the shell hands the program the substitution's pathname as a
    /// positional argument — for an interpreter, the script that runs. So an
    /// empty `args` does not prove a command carries no source-naming
    /// argument, and any rule reading the tokens must check this first.
    ///
    /// Recording a placeholder token instead was rejected: `args` feeds
    /// recognition, the guards and the write rules, and a synthetic token
    /// would reach all of them.
    ///
    /// A bool rather than a third state, deliberately, and the polarity is
    /// asymmetric on purpose. `true` is not "this scanner analysed the question
    /// and found nothing missing" — it is the narrower claim "this scanner
    /// dropped no argument", which every scanner can make honestly about its own
    /// walk: powershell and python push a token for everything they see, and
    /// only bash has a construct that contributes an argument invisibly. A
    /// MISSING entry is a different matter and readers default it to `false`,
    /// because a short array means the parallelism broke and the fail-closed
    /// reading is that the tokens cannot be trusted.
    pub args_complete: Vec<bool>,
    /// Indexed value references carried by each command argument. Parallel to
    /// `commands`; each map keys a command's argument index. Empty means the
    /// scanner reported no connectable structure for that command.
    pub indexed_values: Vec<std::collections::HashMap<usize, IndexedValueRef>>,
    /// The next `HeredocId` `alloc_heredoc_id` hands out. Private: nothing
    /// outside this `impl` block has a reason to read the counter itself,
    /// only to ask for a fresh id or to merge one scan's range into
    /// another's (`absorb`).
    next_heredoc_id: u32,
}

impl Scan {
    pub fn note(&mut self, name: &str) {
        if !self.constructs.iter().any(|c| c == name) {
            self.constructs.push(name.to_string());
        }
    }

    /// Hand out a fresh, never-repeated identity for a new heredoc record —
    /// see `HeredocId`. Called at the point a here-document candidate is
    /// first captured (`shell.rs`, while it is still pending its consuming
    /// command), not at the point it lands in `heredocs`: those two moments
    /// can come in different orders, and the id has to survive that.
    pub fn alloc_heredoc_id(&mut self) -> HeredocId {
        let id = HeredocId(self.next_heredoc_id);
        self.next_heredoc_id += 1;
        id
    }

    pub fn push_cmd(
        &mut self,
        head: String,
        args: Vec<String>,
        order: Order,
        input_source: InputSource,
        args_complete: bool,
        chain: Option<ChainPos>,
        prefix_assigns: Vec<String>,
    ) {
        if head.is_empty() {
            return;
        }
        self.heads.push(head.clone());
        self.commands.push(Cmd {
            head,
            args,
            unread_args: Default::default(),
            keyword_args: Default::default(),
            chain,
            prefix_assigns,
            receiver_origin: ValueOrigin::Unknown,
        });
        self.order.push(order);
        self.input_source.push(input_source);
        self.args_complete.push(args_complete);
        self.indexed_values.push(Default::default());
    }

    /// Merge a nested scan (a script block, a subshell) into this one.
    ///
    /// Everything absorbed is `Order::Unordered`, regardless of what order it
    /// was provable at within its own nested text — the fact that it needed
    /// absorbing at all (it came from inside a wrapper's snippet, a language
    /// vouch had to hand off to another scanner) means the outer scan cannot
    /// vouch for when, or whether, it runs relative to everything else.
    ///
    /// `other` is itself the product of a fresh, separate parse — a nested
    /// script block or subexpression, re-scanned on its own — so any
    /// `ChainPos` its commands carry has `id`s starting from 0 again, per
    /// `ChainPos`'s own doc ("meaningless across parses"). Left unremapped
    /// those would collide with `id`s `self` already uses for its own,
    /// unrelated and-or chains. Offsetting past `self`'s current maximum,
    /// computed fresh on every call, keeps repeated absorbs (a nested block
    /// inside a nested block) each landing past everything already merged.
    pub fn absorb(&mut self, other: Scan) {
        let n_cmds = other.commands.len();
        let n_redirects = other.redirect_targets.len();
        // Captured BEFORE `self.commands` grows below: the base index other's
        // commands land at, once appended — the same offset `heredocs`'
        // `cmd_index` values need, or a nested capture would point at
        // whatever command already happened to sit at that position in SELF.
        let cmd_offset = self.commands.len();
        // The offset every one of `other`'s heredoc identities is re-stamped
        // by. `other` is its own fresh parse, so its ids start from 0 again —
        // same reasoning as `chain_id_offset` below — and would collide with
        // ids `self` has already handed out. Read from `self`'s own COUNTER,
        // never from `self.heredocs.len()`: the two can differ (see
        // `HeredocId`'s doc — a nested construct can flush its records out of
        // allocation order), and the counter is the one value that always
        // exceeds every id `self` has issued so far, whatever order they
        // landed in. Advancing it past `other`'s own range keeps a SECOND
        // absorb call (a nested block inside a nested block) landing past
        // everything already merged, the same guarantee `chain_id_offset`
        // gets from re-deriving its max on every call.
        let heredoc_id_offset = self.next_heredoc_id;
        self.next_heredoc_id += other.next_heredoc_id;
        let chain_id_offset = self
            .commands
            .iter()
            .filter_map(|c| c.chain.map(|cp| cp.id))
            .max()
            .map_or(0, |m| m + 1);
        for c in other.constructs {
            self.note(&c);
        }
        self.heads.extend(other.heads);
        self.commands.extend(other.commands.into_iter().map(|mut c| {
            if let Some(cp) = c.chain.as_mut() {
                cp.id += chain_id_offset;
            }
            c
        }));
        self.redirect_targets.extend(other.redirect_targets);
        self.order
            .extend(std::iter::repeat(Order::Unordered).take(n_cmds));
        self.redirect_order
            .extend(std::iter::repeat(Order::Unordered).take(n_redirects));
        self.heredocs
            .extend(other.heredocs.into_iter().map(|h| Heredoc {
                id: HeredocId(h.id.0 + heredoc_id_offset),
                cmd_index: h.cmd_index + cmd_offset,
                ..h
            }));
        // This arm exercises no live path today: `absorb`'s only caller is
        // the PowerShell scanner, which records no here-documents and leaves
        // every value `Unknown`. Re-stamped here anyway so that whichever
        // scanner grows a heredoc-bearing absorb path finds the reference
        // already kept in lockstep with the record above, rather than
        // rediscovering that it has to be.
        self.input_source
            .extend(other.input_source.into_iter().map(|s| match s {
                InputSource::Heredoc(id) => {
                    InputSource::Heredoc(HeredocId(id.0 + heredoc_id_offset))
                }
                keep => keep,
            }));
        self.args_complete.extend(other.args_complete);
        let mut indexed_values = other.indexed_values.into_iter();
        self.indexed_values.extend(
            (0..n_cmds).map(|_| indexed_values.next().unwrap_or_default()),
        );
    }
}

/// A language scanner.
///
/// `Err` means "I could not read this" and must NEVER be an empty `Scan` —
/// the engine has to tell "nothing objectionable" apart from "unreadable",
/// because those carry different settings and different messages.
pub trait Scanner {
    /// Config section name, e.g. "bash" or "powershell".
    fn lang(&self) -> &'static str;
    fn scan(&self, src: &str) -> Result<Scan, String>;
    /// Every construct this scanner can emit. Enforced by test.
    fn known_constructs(&self) -> &'static [&'static str];
}

type ScannerConstructor = fn() -> Box<dyn Scanner>;

struct ScannerRegistration {
    lang: &'static str,
    construct: ScannerConstructor,
}

fn bash_scanner() -> Box<dyn Scanner> {
    Box::new(crate::shell::Bash)
}

fn powershell_scanner() -> Box<dyn Scanner> {
    Box::new(crate::powershell::PowerShell)
}

fn python_scanner() -> Box<dyn Scanner> {
    Box::new(crate::python::Python)
}

/// The one registration seam for scanner-backed languages.
///
/// Runtime dispatch and every exhaustive consumer enumerate this table, so
/// adding a scanner is one additive change rather than a match arm plus copied
/// language lists that can drift while tests remain green.
const SCANNERS: &[ScannerRegistration] = &[
    ScannerRegistration {
        lang: "bash",
        construct: bash_scanner,
    },
    ScannerRegistration {
        lang: "powershell",
        construct: powershell_scanner,
    },
    ScannerRegistration {
        lang: "python",
        construct: python_scanner,
    },
];

/// Every registered scanner language, in stable registration order.
pub fn scanner_languages() -> impl Iterator<Item = &'static str> + Clone {
    SCANNERS.iter().map(|registration| registration.lang)
}

/// Resolves a language name to its scanner.
pub fn scanner_for(lang: &str) -> Option<Box<dyn Scanner>> {
    SCANNERS
        .iter()
        .find(|registration| registration.lang == lang)
        .map(|registration| (registration.construct)())
}
