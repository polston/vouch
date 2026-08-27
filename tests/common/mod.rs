//! Corpus loading shared by the integration tests AND by the `examples/`
//! on-demand measurements, which include this file with `#[path]`.
//!
//! That second audience is a compile constraint, not a detail. Anything added
//! here must compile in BOTH: a test-only macro such as `env!("CARGO_BIN_EXE_…")`
//! is undefined for an example target and `env!` expands whether or not the
//! function is called, so it fails there even as dead code — and because
//! `cargo test` compiles examples, that takes the whole run red rather than one
//! target. Gate anything of that kind on `#[cfg(test)]`; see `hook_bash_at`.
//! For the same reason, repository paths here resolve against
//! `CARGO_MANIFEST_DIR` read at run time rather than the working directory: a
//! test runs at the crate root, an example inherits the invocation directory.
//!
//! There are two corpora and they are not interchangeable:
//!
//!   synthetic_corpus.json  committed, invented, contains no real data.
//!                          Used to prove PROPERTIES.
//!   bash_corpus.json       gitignored, real harvested traffic.
//!                          Used to take MEASUREMENTS. Never committed.
//!
//! A measurement taken over invented commands is a fabricated measurement, so
//! a measurement test skips when the real corpus is absent. It must never fall
//! back to the synthetic one.
//!
//! Each test binary that includes this module uses a different part of it, so
//! the unused rest would warn in every other binary.
#![allow(dead_code)]

use serde::Deserialize;

pub const REAL: &str = "tests/fixtures/bash_corpus.json";
pub const SYNTHETIC: &str = "tests/fixtures/synthetic_corpus.json";

/// Set this to turn a skipped measurement into a failure. A default run stays
/// quiet, because the real corpus legitimately does not exist on most
/// machines; a run whose PURPOSE is to measure sets this and finds out.
pub const REQUIRE_REAL: &str = "VOUCH_REQUIRE_REAL_CORPUS";

#[derive(Debug, Clone)]
pub struct Row {
    pub cmd: String,
    pub verdict: String,
}

/// Both fields are required on purpose. If `build_fixture.py` ever stops
/// emitting `verdict`, defaulting it would silently deflate every
/// "the old tool prompted on N" figure toward zero and print an improvement
/// that never happened (CLAUDE.md §6.6). Fail loudly instead.
#[derive(Deserialize)]
struct RawRow {
    cmd: String,
    verdict: String,
}

/// The package root, read at RUN time.
///
/// `cargo test` runs test binaries with the crate root as the working directory,
/// but `cargo run --example` inherits the INVOCATION directory — so a relative
/// fixture path is invisible from a subdirectory and the corpus reports as
/// absent, which is evidence about the lookup and not about the file
/// (CLAUDE.md §6.3).
///
/// Read with `env::var` rather than `env!` for two reasons: no absolute path from
/// a real machine is compiled into a build artefact, and a binary that outlives a
/// moved or renamed checkout fails loudly instead of pointing at a directory that
/// no longer exists.
///
/// A test panics here on purpose. A process exit would produce no `test result:`
/// line at all, which `scripts/verify.sh` now reports as NOTHING COMPILED — a
/// failure disguised as a different failure. The example path exits instead, in
/// `require_repo_pinning`.
fn manifest_dir() -> std::path::PathBuf {
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => panic!("CARGO_MANIFEST_DIR is unset: run this through cargo"),
    }
}

/// A repository-relative path resolved against the package root.
pub fn repo_path(rel: &str) -> std::path::PathBuf {
    manifest_dir().join(rel)
}

fn load(rel: &str) -> Option<Vec<Row>> {
    let path = repo_path(rel);
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        // Absent is a skip. Anything else — unreadable, locked, half-written —
        // is a fault, and reporting it as "absent" would assert something
        // false about the file (CLAUDE.md §6.3).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        // `rel`, never `path`: the resolved form is an absolute path from a real
        // machine, and this string reaches terminals and transcripts.
        Err(e) => panic!("{rel} exists but could not be read: {e}"),
    };
    let raw: Vec<RawRow> =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("{rel} does not parse: {e}"));
    Some(
        raw.into_iter()
            .map(|r| Row {
                cmd: r.cmd,
                verdict: r.verdict,
            })
            .collect(),
    )
}

/// The real recorded corpus, or None when it has not been built on this machine.
pub fn real() -> Option<Vec<Row>> {
    load(REAL)
}

/// The committed synthetic corpus. Absence is a broken checkout, not a skip.
pub fn synthetic() -> Vec<Row> {
    load(SYNTHETIC).expect("synthetic_corpus.json is committed; the checkout is incomplete")
}

/// Every corpus available here: synthetic always, real when it exists.
pub fn all() -> Vec<(&'static str, Vec<Row>)> {
    let mut v = vec![("synthetic", synthetic())];
    if let Some(r) = real() {
        v.push(("real", r));
    }
    v
}

/// The one SKIP wording, so a skipped measurement is obvious in the output.
///
/// libtest hides stderr unless `--nocapture`, so a skipped measurement
/// otherwise reports as an ordinary pass and a reader concludes the
/// measurement ran. Setting `VOUCH_REQUIRE_REAL_CORPUS` makes that case fail
/// instead — use it for any run whose numbers are going to be reported.
pub fn skip(what: &str) {
    if std::env::var_os(REQUIRE_REAL).is_some() {
        panic!(
            "{what}: {REAL} is absent and {REQUIRE_REAL} is set. This run was \
             supposed to measure real traffic and cannot."
        );
    }
    eprintln!(
        "SKIP {what}: {REAL} is absent. It is gitignored real machine history - \
         rebuild it locally with tests/fixtures/build_fixture.py. This is a \
         measurement test and must not run on synthetic data. Set \
         {REQUIRE_REAL} to make this a failure instead."
    );
}

/// The configuration a real operator would run: the constructs that are merely
/// *unknowable* are allowed, so only vouch's own defects produce a prompt.
///
/// Shared because `replay_test`'s measurement and `property_test`'s assertion
/// are only comparable while both use the same config.
/// The knowledge schema version a fixture should declare, from the constant
/// rather than typed as a number.
///
/// It was typed as a number in twenty-one fixtures until 2026-08-19, when the
/// schema went 6 → 7 and fourteen tests failed at once, none of them about
/// schema versions. A fixture that must be edited whenever an unrelated field
/// is added is a hardcode wearing a test's clothing. Lives here rather than in
/// each test file because the first fix put four identical copies of it in
/// four files, which is the duplication ROADMAP M2.142 already complains about.
pub fn v() -> u32 {
    vouch::knowledge::KNOWLEDGE_SCHEMA_VERSION
}

pub fn realistic_config() -> vouch::config::Config {
    realistic_config_with("")
}

/// The same configuration with extra TOML appended — a `[tools]` section, in
/// practice. Shared rather than copied so a routing fixture that needs the
/// operator to have named a tool is deciding against the SAME language and
/// write settings every other test uses; two texts that drift apart would
/// compare fixtures nobody ran.
pub fn realistic_config_with(extra: &str) -> vouch::config::Config {
    vouch::config::load(&format!(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
dynamic_command = "allow"
dynamic_redirect = "allow"
subshell = "allow"
background = "allow"
heredoc = "allow"
function_def = "allow"
unmodeled_command = "allow"
parse_failure = "ask"
redirect = "allow"
[lang.powershell.constructs]
# The mirror of the bash line above, and it exists for one reason: since M2.46
# an unknown program inside a SNIPPET is judged under the snippet's OWN
# language, so a `powershell -Command "…"` on a bash line would meet
# PowerShell's unset default (ask) where it used to meet bash's allow. Without
# this line the replay would move rows because a language nobody configured
# started answering — a change to what the measurement measures, decided by
# nobody. Both languages allow the unknowable so that only vouch's own defects
# produce a prompt, which is the whole point of this config.
unmodeled_command = "allow"
[lang.python]
default = "allow"
[lang.python.constructs]
# The python mirror of the bash/powershell lines above, same reason: the
# replay measures vouch's defects, not the operator's unset policy.
unmodeled_command = "allow"
dynamic_call = "allow"
evaluated_input = "allow"
parse_failure = "ask"
[write]
default = "ask"
allow_paths = [
  "C:/work/**", "C:/workspace/**", "C:/claude/**", "C:/tmp/**",
  "$HOME/**", "/tmp/**", "/private/tmp/**", "/Users/**",
]
{extra}
"#
    ))
    .expect("config parses")
}

/// `realistic_config` with ONE construct's action changed.
///
/// Every measurement that needs "the standard config, except this construct
/// asks" goes through here rather than repeating the clone-and-mutate: the
/// paired dumps a transition matrix diffs must differ ONLY by the setting under
/// test, and five hand-written copies of the same mutation are five chances for
/// one of them to differ in some other way.
///
/// Mutated on the LOADED config rather than appended as TOML text because the
/// construct tables are already written in `realistic_config`'s source, and a
/// second table with the same path is a duplicate-key parse error.
pub fn realistic_config_with_construct(
    lang: &str,
    construct: &str,
    action: vouch::config::Action,
) -> vouch::config::Config {
    let mut cfg = realistic_config();
    cfg.langs
        .get_mut(lang)
        .unwrap_or_else(|| panic!("realistic_config writes a [lang.{lang}] section"))
        .constructs
        .insert(construct.to_string(), action);
    cfg
}

/// The shipped `knowledge.toml`, loaded fresh — no `my-knowledge.toml`
/// overlay, no shared process-wide cache. `tests/trust_test.rs`'s `SHIPPED`
/// constant reads the same file.
///
/// Resolved against the package root rather than the working directory. `cargo
/// test` does run at the crate root, but this module is now shared with examples,
/// which inherit the invocation directory instead — so the old claim that the
/// crate root is always the working directory was true of tests only.
///
/// Shared because `tests/routing_test.rs` and `tests/property_test.rs` both
/// drive fixture calls through `route::decide` against this same starting
/// point — two copies of the same load-and-parse would only be able to drift
/// apart, never usefully differ.
pub fn shipped_kb() -> vouch::guards::Knowledge {
    let text = std::fs::read_to_string(repo_path("knowledge.toml"))
        .expect("the repo's own knowledge.toml reads");
    vouch::guards::load(&text).expect("the repo's own knowledge.toml parses")
}

/// The shipped knowledge with an operator layer laid over it: `guards::load`
/// per side, `knowledge::merge` between them, passed straight to
/// `route::decide`. Never `guards::in_effect()`'s process-global cache and
/// never the `target/test-my-knowledge.toml` fixture other tests write to
/// concurrently.
pub fn kb_with(mine: &str) -> vouch::guards::Knowledge {
    let mine = vouch::guards::load(mine).expect("the fixture's own knowledge parses");
    vouch::knowledge::merge(shipped_kb(), mine)
}

/// One parsed command, built by hand. Shared for the reason `decision_at` is:
/// every test binary already includes this module, so the four pre-existing
/// copies (`guards_test.rs`, `knowledge_merge_test.rs`, `rider_test.rs`,
/// `standalone_test.rs`) were never necessary — this is the point a fifth copy
/// should have become a shared one instead.
pub fn cmd(head: &str, args: &[&str]) -> vouch::syntax::Cmd {
    vouch::syntax::Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
    }
}

/// The home a child-process run is judged against — a neutral account name,
/// never a real login (CLAUDE.md, top).
pub const HOOK_HOME: &str = "C:/Users/dev";

/// One `vouch --hook` run in a CHILD process: the shipped knowledge (pinned by
/// `.cargo/config.toml` and inherited) plus `mine` as the operator's overlay,
/// `cfg` as the config, deciding `command` from `cwd`. Returns the verdict and
/// its reason.
///
/// A child, not an in-process call, because the engine reads its knowledge
/// from the process-global `guards::in_effect()` cache: an operator overlay
/// cannot be handed to `decide_command_at`, and setting the env vars that
/// select one would be a process-wide mutation racing every other test in the
/// same binary (CLAUDE.md §9). A child gets its own environment, its own
/// cache, and the real `--hook` path, which is where an operator meets this
/// anyway.
///
/// Shared rather than copied because `tests/place_recognition_test.rs`'s
/// per-shape pins and `tests/property_test.rs`'s settings net drive the same
/// runs; two copies of the spawn could only drift apart, never usefully
/// differ. `tag` names the temp directory, so each caller prefixes its own
/// binary's name — two binaries running in parallel with one tag would write
/// each other's fixture files.
/// `cfg(test)` because the run it delegates to spawns the built binary through
/// `env!("CARGO_BIN_EXE_vouch")`, which cargo defines for test and bench targets
/// only. An example target does not get it, and `env!` expands during macro
/// expansion whether or not the function is ever called — so without this
/// attribute every example that includes this module fails to compile, and
/// because `cargo test` compiles examples that takes the whole run red rather
/// than one target. Measured both directions: `cfg(test)` is set for an
/// integration test and unset for an example.
#[cfg(test)]
pub fn hook_bash_at(tag: &str, mine: &str, cfg: &str, cwd: &str, command: &str) -> (String, String) {
    // No permission mode — these callers pre-date the field.
    let text = hook_bash_stdout(tag, mine, cfg, cwd, command, "", &[]);
    let v: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|e| panic!("no decision emitted ({e}): {text}"));
    emitted_pair(&v)
}

/// Everything one hook invocation produced: what it emitted (`None` =
/// nothing at all) and the journal rows it wrote. The mode-keyed-shadow
/// tests need both, and "nothing emitted" is a PASS condition for them, so
/// this cannot share `hook_bash_at`'s panic-on-silence contract — and a
/// crash also emits nothing, so the rows are what tell the two apart
/// (CLAUDE.md §6.5): a stood-down call writes its rows, a dead binary
/// writes none.
#[cfg(test)]
pub struct HookRun {
    pub emitted: Option<(String, String)>,
    pub rows: Vec<serde_json::Value>,
}

#[cfg(test)]
pub fn hook_bash_run(
    tag: &str,
    mine: &str,
    cfg: &str,
    cwd: &str,
    command: &str,
    permission_mode: &str,
) -> HookRun {
    let dir = hook_dir(tag);
    let _ = std::fs::remove_dir_all(&dir); // fresh journal per invocation
    let text = hook_bash_stdout(tag, mine, cfg, cwd, command, permission_mode, &[]);

    let emitted =
        serde_json::from_str::<serde_json::Value>(text.trim()).ok().map(|v| emitted_pair(&v));
    let rows = std::fs::read_to_string(dir.join("state").join("journal.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    HookRun { emitted, rows }
}

/// Where one `--hook` run's fixture files and its journal live. Named once so
/// that a caller wanting a fresh journal can clear the directory before the
/// run without working out where it is a second time.
#[cfg(test)]
fn hook_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("vouch_{tag}"))
}

/// The verdict and the reason out of one emitted decision. Both runners read
/// the same two fields, so the shape of an emission is read in one place.
#[cfg(test)]
fn emitted_pair(v: &serde_json::Value) -> (String, String) {
    let h = &v["hookSpecificOutput"];
    (
        h["permissionDecision"].as_str().unwrap_or_default().to_string(),
        h["permissionDecisionReason"].as_str().unwrap_or_default().to_string(),
    )
}

/// The run both runners above share: writes the operator overlay and the
/// config under `hook_dir(tag)`, feeds one PreToolUse call in on standard
/// input, and returns exactly what the binary printed. It does not read that
/// output, because the two read SILENCE differently — one panics on it, the
/// other counts it as a pass — and whether the directory is cleared first is
/// likewise the caller's to decide. An empty `permission_mode` leaves the
/// field out of the input altogether, which is what a caller reporting no
/// mode looks like on the wire.
/// The TOML text of `realistic_config` with `(lang, construct, action)` overrides
/// folded into the construct tables. Used by child-process harnesses that take
/// config as text, and also usable via `vouch::config::load` for in-process tests
/// needing keys in two language sections at once.
///
/// Overrides are substituted into each `[lang.<l>.constructs]` table; there is a
/// single `[write]` table and appending a second is a duplicate-key parse error.
pub fn config_text_with(overrides: &[(&str, &str, &str)]) -> String {
    let mut construct_strs = std::collections::HashMap::new();

    // Start with the base constructs from realistic_config
    construct_strs.insert("bash", vec![
        ("dynamic_command", "allow"),
        ("dynamic_redirect", "allow"),
        ("subshell", "allow"),
        ("background", "allow"),
        ("heredoc", "allow"),
        ("function_def", "allow"),
        ("unmodeled_command", "allow"),
        ("parse_failure", "ask"),
        ("redirect", "allow"),
    ]);

    construct_strs.insert("powershell", vec![
        ("unmodeled_command", "allow"),
    ]);

    construct_strs.insert("python", vec![
        ("unmodeled_command", "allow"),
        ("dynamic_call", "allow"),
        ("evaluated_input", "allow"),
        ("parse_failure", "ask"),
    ]);

    // Apply overrides
    for (lang, construct, action) in overrides {
        if let Some(constructs) = construct_strs.get_mut(lang) {
            // Replace if exists, otherwise add
            if let Some(pos) = constructs.iter().position(|(c, _)| c == construct) {
                constructs[pos] = (construct, action);
            } else {
                constructs.push((construct, action));
            }
        } else {
            construct_strs.insert(lang, vec![(construct, action)]);
        }
    }

    // Build the TOML text
    let mut result = r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
"#.to_string();

    for (construct, action) in &construct_strs["bash"] {
        result.push_str(&format!("{} = \"{}\"\n", construct, action));
    }

    result.push_str("[lang.powershell.constructs]\n");
    // Comment for powershell section (mirrors bash, exists for language-specific snippet handling)
    result.push_str("# The mirror of the bash line above, and it exists for one reason: since M2.46\n");
    result.push_str("# an unknown program inside a SNIPPET is judged under the snippet's OWN\n");
    result.push_str("# language, so a `powershell -Command \"…\"` on a bash line would meet\n");
    result.push_str("# PowerShell's unset default (ask) where it used to meet bash's allow. Without\n");
    result.push_str("# this line the replay would move rows because a language nobody configured\n");
    result.push_str("# started answering — a change to what the measurement measures, decided by\n");
    result.push_str("# nobody. Both languages allow the unknowable so that only vouch's own defects\n");
    result.push_str("# produce a prompt, which is the whole point of this config.\n");
    for (construct, action) in &construct_strs["powershell"] {
        result.push_str(&format!("{} = \"{}\"\n", construct, action));
    }

    result.push_str("[lang.python]\n");
    result.push_str("default = \"allow\"\n");
    result.push_str("[lang.python.constructs]\n");
    // Comment for python section
    result.push_str("# The python mirror of the bash/powershell lines above, same reason: the\n");
    result.push_str("# replay measures vouch's defects, not the operator's unset policy.\n");
    for (construct, action) in &construct_strs["python"] {
        result.push_str(&format!("{} = \"{}\"\n", construct, action));
    }

    result.push_str("[write]\n");
    result.push_str("default = \"ask\"\n");
    result.push_str("allow_paths = [\n");
    result.push_str("  \"C:/work/**\", \"C:/workspace/**\", \"C:/claude/**\", \"C:/tmp/**\",\n");
    result.push_str("  \"$HOME/**\", \"/tmp/**\", \"/private/tmp/**\", \"/Users/**\",\n");
    result.push_str("]\n");

    result
}

/// The same as `hook_bash_at`, with extra variables set in the SPAWNED
/// process's environment — what a test needs when the thing under test reads
/// one. The boundary suite's same-line-assignment probe uses it to set a name
/// in the child and check the verdict does not change with it.
#[cfg(test)]
pub fn hook_bash_at_env(
    tag: &str,
    mine: &str,
    cfg: &str,
    cwd: &str,
    command: &str,
    env: &[(&str, &str)],
) -> (String, String) {
    let text = hook_bash_stdout(tag, mine, cfg, cwd, command, "", env);
    let v: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|e| panic!("no decision emitted ({e}): {text}"));
    emitted_pair(&v)
}

/// `cfg(test)` for the `env!` reason spelled out on `hook_bash_at`.
#[cfg(test)]
fn hook_bash_stdout(
    tag: &str,
    mine: &str,
    cfg: &str,
    cwd: &str,
    command: &str,
    permission_mode: &str,
    env: &[(&str, &str)],
) -> String {
    use std::io::Write;
    let dir = hook_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let mine_path = dir.join("my-knowledge.toml");
    std::fs::write(&mine_path, mine).unwrap();
    let cfg_path = dir.join("vouch.toml");
    std::fs::write(&cfg_path, cfg).unwrap();

    let mut input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_use_id": tag,
        "session_id": "vouch-test",
        "cwd": cwd,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    });
    if !permission_mode.is_empty() {
        input["permission_mode"] = serde_json::json!(permission_mode);
    }

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_vouch"));
    child
        .env("VOUCH_CONFIG", &cfg_path)
        .env("VOUCH_MY_KNOWLEDGE", &mine_path)
        .env("VOUCH_STATE_DIR", dir.join("state"))
        .env("HOME", HOOK_HOME)
        .env("USERPROFILE", HOOK_HOME);
    // What the CHILD's environment holds, for a test whose subject reads one
    // — the boundary suite's same-line-assignment probe sets a name in the
    // child and checks the verdict does not depend on it.
    for (key, val) in env {
        child.env(key, val);
    }
    let mut child = child
        .arg("--hook")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

// --- What an ON-DEMAND MEASUREMENT needs (M2.103) --------------------------
//
// The on-demand measurements under `examples/` that need corpus rows include
// this module by `#[path]`. They are not tests: no gate runs them, `cargo test`
// only compiles them, and someone types their name when they want a number.
// That changes two things about loading a corpus and one about where the run
// is allowed to happen.

/// The real corpus for an on-demand measurement: someone typed the program's
/// name, so an absent corpus is a failure rather than a skip.
///
/// Exit 1 with one line, not a panic. Exit 101 plus a panic notice reads as a
/// crash, and CLAUDE.md §6.5 exists to keep a crash distinguishable from a
/// measurement that could not run. `VOUCH_REQUIRE_REAL_CORPUS` is deliberately
/// not consulted: it exists to turn a measurement TEST's silent skip into a
/// failure, and there is nothing silent here.
pub fn real_or_exit() -> Vec<Row> {
    match real() {
        Some(rows) => rows,
        None => {
            eprintln!(
                "{REAL} is absent, so there is nothing to measure. Build it with \
                 tests/fixtures/build_fixture.py, or copy it from the main checkout."
            );
            std::process::exit(1);
        }
    }
}

/// Containment on a PATH BOUNDARY, through the repository's own canonicaliser.
///
/// `vouch::paths::normalize` unifies separators and collapses `.` and `..`
/// segments. Reused rather than hand-rolled: a hand-rolled version compared raw
/// string prefixes, which accepted `<root>/../elsewhere` — the `..` climbs out of
/// the tree while the text still starts with the root, measured — and that is the
/// precise case this function exists to refuse. Lower-cased after, because this
/// platform is case-insensitive.
///
/// The boundary matters too. Without it a sibling directory whose name merely
/// starts with the root's name passes, and this repository makes that reachable:
/// its worktrees sit UNDER the main checkout, so a run rooted at the main checkout
/// would otherwise accept variables resolving into any worktree, measure against
/// another branch's knowledge, and attribute the numbers to the main checkout.
///
/// `home` is passed empty on purpose: the values compared here are absolute paths
/// produced by `.cargo/config.toml`'s `relative = true`, so no `~` is involved,
/// and a path that did start with one normalises to something that fails the
/// comparison — which is the fail-closed direction.
fn under(root: &std::path::Path, candidate: &std::path::Path) -> bool {
    let norm = |p: &std::path::Path| {
        vouch::paths::normalize(&p.to_string_lossy(), "")
            .trim_end_matches('/')
            .to_lowercase()
    };
    let (root, cand) = (norm(root), norm(candidate));
    !root.is_empty() && (cand == root || cand.starts_with(&format!("{root}/")))
}

/// Refuse to measure unless the run was made through THIS repository's cargo.
///
/// `.cargo/config.toml` pins the three `VOUCH_*` variables so a measurement
/// decides against the repository's own files rather than whatever the operator
/// has installed. Cargo finds that file by walking up from the working directory,
/// so `--manifest-path` from outside the tree never applies it and a bare run of
/// the built binary gets nothing at all. Measurements that reach process-global
/// knowledge can otherwise produce plausible numbers attributed to the wrong
/// files, so every shared corpus entry point enforces the same footing.
///
/// Checked by CONTAINMENT. Not by presence: a value exported in the calling shell
/// is present and wrong, and `force = true` never ran to override it — measured.
/// Not by existence either: `VOUCH_MY_KNOWLEDGE` names a file under `target/` that
/// does not exist on a clean tree, so requiring existence would refuse every
/// legitimate run.
pub fn require_repo_pinning() {
    let root = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(d) => std::path::PathBuf::from(d),
        Err(_) => {
            eprintln!(
                "CARGO_MANIFEST_DIR is unset. Run this as \
                 `cargo run --release --example <name>` from inside the repository, \
                 not as a bare executable from target/."
            );
            std::process::exit(1);
        }
    };
    for var in ["VOUCH_KNOWLEDGE", "VOUCH_MY_KNOWLEDGE", "VOUCH_CONFIG"] {
        let inside = std::env::var(var)
            .ok()
            .map(std::path::PathBuf::from)
            .is_some_and(|p| under(&root, &p));
        if !inside {
            // Names the variable, never its value: a resolved value is an
            // absolute path from a real machine and this line reaches
            // transcripts.
            eprintln!(
                "{var} does not point inside this repository, so this measurement would \
                 not decide against the repository's own files. Run it through this \
                 repository's cargo so .cargo/config.toml applies."
            );
            std::process::exit(1);
        }
    }
}

/// The rows for an on-demand measurement, with the run's footing checked first.
///
/// ONE entry point rather than two calls, because two calls is a convention every
/// example has to remember: an example that called only the loader would compile,
/// run, and print a full set of plausible numbers decided against the operator's
/// installed knowledge rather than this repository's — silently, since nothing
/// about the output would look wrong. This makes that shape unexpressible.
pub fn rows_for_measurement() -> Vec<Row> {
    require_repo_pinning();
    real_or_exit()
}

/// One command through the whole decide pipeline at a stated working
/// directory, as a `(decision word, reason)` pair.
///
/// Here rather than copied per file: an integration-test binary cannot see
/// another's items, which is why this used to be duplicated — but every one of
/// those binaries already includes THIS module, so the copies were never
/// necessary, and two of them drifting is a changed call signature that goes
/// stale in one file with nothing to catch it.
pub fn decision_at(cfg: &vouch::config::Config, cmd: &str, cwd: &str) -> (String, String) {
    use vouch::protocol::Decision::*;
    match vouch::engine::decide_command_at(cfg, "bash", cmd, Some(HOOK_HOME), None, Some(cwd)) {
        Allow(r) => ("allow".into(), r),
        Ask(r) => ("ask".into(), r),
        Deny(r) => ("deny".into(), r),
        Abstain => ("abstain".into(), String::new()),
    }
}

/// One command's decision and, optionally, a substring its reason must carry.
pub fn assert_verdict(
    cfg: &vouch::config::Config,
    cwd: &str,
    cmd: &str,
    want: &str,
    reason_has: Option<&str>,
) {
    let (d, r) = decision_at(cfg, cmd, cwd);
    assert_eq!(d, want, "{cmd}\nreason: {r}");
    if let Some(needle) = reason_has {
        assert!(r.contains(needle), "reason lacks {needle:?}: {r}");
    }
}

/// Whether occurrence `ci` of a TOP-LEVEL scan is standalone-eligible: with
/// nothing above it to append arguments, the occurrence's own scanned
/// completeness is the whole fold, and an absent entry reads false the way
/// the engine's own fold reads it.
///
/// Defined here rather than in each measurement that wants it: an eligibility
/// rule is logic, and two examples deriving it separately is two places a
/// change to the rule has to reach.
pub fn top_level_eligible(scan: &vouch::syntax::Scan, ci: usize) -> bool {
    scan.args_complete.get(ci).copied().unwrap_or(false)
}

/// The body the four decision dumps share. Shared rather than copied so the
/// sides of a pair can only differ by the config they were handed — two texts
/// free to drift apart would produce a transition matrix nobody could attribute.
///
/// Rows arrive as a parameter rather than being loaded here. Loading them here
/// meant an absent corpus returned through `skip`, which in an example would
/// print a skip line, exit 0 having measured nothing, and leave the PREVIOUS dump
/// file in place — so a diff against it would report zero movement no matter what
/// changed. That is the M2.81 defect verbatim.
pub fn dump_every_row_under(cfg: vouch::config::Config, rows: &[Row]) {
    let path = std::env::var("VOUCH_DUMP_DECISIONS")
        .expect("set VOUCH_DUMP_DECISIONS to the output path before running this dump");

    let mut out = String::new();
    for (i, row) in rows.iter().enumerate() {
        let d = vouch::engine::decide_command_in(&cfg, "bash", &row.cmd, Some("C:/Users/dev"), None);
        let (verdict, reason): (&str, &str) = match &d {
            vouch::protocol::Decision::Allow(r) => ("ALLOW", r.as_str()),
            vouch::protocol::Decision::Ask(r) => ("ASK", r.as_str()),
            vouch::protocol::Decision::Deny(r) => ("DENY", r.as_str()),
            // Not reachable for lang "bash" (a scanner always exists), but
            // covered rather than left to panic mid-dump if that ever changes.
            vouch::protocol::Decision::Abstain => ("ABSTAIN", ""),
        };
        let first_line = reason.lines().next().unwrap_or("");
        out.push_str(&format!("{i}\t{verdict}\t{first_line}\n"));
    }
    std::fs::write(&path, &out).unwrap_or_else(|e| panic!("could not write {path}: {e}"));
    println!("wrote {} decision rows to {path}", rows.len());
}
