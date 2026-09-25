# Changelog

## 0.49.0 (2026-09-25)


### Features

* **Add mechanical CI gates for documentation host completeness and changelog richness**
  - **Problem & Explanation:** CI previously lacked mechanical tests to enforce that README documentation, plugin manifests, and changelog release notes accurately enumerate supported agent hosts, registered language scanners, and demonstrative patch notes. Gates 9 and 10 in schema_docs_test now mechanically prevent documentation drift.
  - **Example Scenario:** Running cargo test to verify repository documentation and release note richness invariants.
  - **Delta:**
    - *Configuration Delta:* Added Gate 9 and Gate 10 assertions in schema_docs_test.rs.
    - *Behavior Contrast:* Before: documentation and manifest drift went undetected by CI. After: mechanical gates assert host/scanner completeness and four-part patch note richness.

* **Demonstrative changelog patch notes and automated release note enrichment**
  - **Problem & Explanation:** Release notes previously contained bare one-line commit summaries without explaining problem context, reproducing scenarios, or deltas. CHANGELOG.md entries from v0.48.0 back through v0.38.0 are now expanded into demonstrative four-part patch notes, and the release-please plugin runner now automates enrichment on candidate releases.
  - **Example Scenario:** Viewing release notes in CHANGELOG.md or GitHub release pages.
  - **Delta:**
    - *Configuration Delta:* Enhanced release-please plugin runner with enrichChangelog.
    - *Behavior Contrast:* Before: bare single-line summaries. After: rich patch notes detailing problem explanations, example scenarios, configuration deltas, and behavioral contrasts.

* **Reconcile public documentation and plugin manifests across all supported hosts and native scanners**
  - **Problem & Explanation:** Public documentation and plugin manifests omitted Google Antigravity and JavaScript scanner support, and schema docs had drifted from struct definitions. Documentation and manifests now declare all three hosts (Claude Code, Codex, Google Antigravity) and all four native scanners (bash, powershell, python, javascript).
  - **Example Scenario:** Reading README.md or inspecting plugin metadata in Claude Code, Codex, or Google Antigravity.
  - **Delta:**
    - *Configuration Delta:* Reconciled schema reference documentation and plugin manifests.
    - *Behavior Contrast:* Before: omitted newly supported agent hosts and native scanners. After: accurate enumeration across all manifests and user-facing documentation.

## 0.48.0 (2026-09-24)

### Features

* **Emit `unmodeled_import` construct on unmodeled Python top-level imports**
  - **Problem & Explanation:** When running Python inline snippets (`python -c "..."`), importing a module executes its top-level code immediately. Previously, vouch only recorded imported names to resolve function calls, but did not analyze the `import` statements themselves. Untrusted or unvetted package imports had no security check and were silently allowed. vouch now inspects top-level imports and flags any module outside a curated inert standard library list as an unmodeled import.
  - **Example Scenario:**
    ```bash
    python -c "import untrusted_pkg; print('done')"
    ```
  - **Delta:**
    - *Configuration Delta:* Added construct `unmodeled_import` under `[lang.python.constructs]`:
      ```toml
      [lang.python.constructs]
      unmodeled_import = "allow"
      ```
    - *Behavior Contrast:* Before: evaluated as `ALLOW` with 0 commands detected. After: prompts with `ASK` citing construct `unmodeled_import (untrusted_pkg)` with an actionable configuration off-switch.

* **Model bare `exec` redirection sequences across subsequent shell pipeline commands**
  - **Problem & Explanation:** In shell scripts, `exec < file` redirects descriptor 0 (standard input) for subsequent commands. Previously, `exec` was treated as an isolated command without propagating stdin to later commands, causing subsequent commands to evaluate input as empty instead of file-backed. vouch now tracks sequential descriptor 0 redirections from bare `exec` commands and propagates input provenance across same-scope and child-scope subsequent commands.
  - **Example Scenario:**
    ```bash
    exec < /etc/passwd; cat
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: `cat` evaluated with empty stdin (`Nothing`). After: `cat` inherits descriptor 0 file provenance (`File`) and is evaluated against file read/guard rules.

* **Extend `runs_file` script-file ask mechanism to Node, Perl, Ruby, and Bun interpreters**
  - **Problem & Explanation:** Executing unmodeled external script files via interpreters (`node script.js`, `ruby app.rb`, `perl script.pl`, `bun index.ts`) previously bypassed script gating because `runs_file` was only declared for Python and shells. vouch now declares `runs_file = "arg_0"` for `node`, `perl`, `ruby`, and `bun` in shipped knowledge, while allowing inline code flags (`node -e`, `perl -e`) to bypass `runs_file` and evaluate inline syntax directly.
  - **Example Scenario:**
    ```bash
    node untrusted_script.js
    ```
  - **Delta:**
    - *Configuration Delta:* Declared `runs_file = "arg_0"` for `node`, `perl`, `ruby`, and `bun` in `knowledge.toml`.
    - *Behavior Contrast:* Before: script file execution bypassed file gating. After: script file execution prompts with `ASK` on `runs_file (untrusted_script.js)`. Inline code evaluations (`node -e "..."`) continue to evaluate inline AST directly.

* **Deduplicate on-demand verdict measurement dumps into single-pass execution**
  - **Problem & Explanation:** Measurement test suites previously evaluated the entire test corpus twice when writing both TSV decisions and JSONL per-row dumps, doubling test execution time and CPU overhead. The test harness now unifies evaluation passes so both TSV decisions and JSONL per-row dumps are generated from a single pass over the decision engine.
  - **Example Scenario:** Running `cargo test --test measurement_dump_test`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling & Performance Contrast:* Before: two complete passes over the decision engine. After: unified single-pass evaluation emitting both TSV and JSONL formats simultaneously.

* **Smoke test macOS release asset execution before release publishing**
  - **Problem & Explanation:** The automated release workflow built macOS Apple Silicon binaries without verifying they execute properly on native runners before packaging and uploading release bundles, risking publishing broken binary assets. The release build matrix now runs native execution smoke tests on each runner before asset staging and upload.
  - **Example Scenario:** GitHub Actions release workflow execution during release publishing.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Workflow Contrast:* Before: packaged and uploaded binary bundles directly. After: runs `vouch --version`, `vouch-mcp-broker --version`, and smoke probes on the native runner before packaging.

## 0.47.0 (2026-09-24)

### Features

* **Separate internal sentinels into typed tokens and unify position offset indexing across write arms**
  - **Problem & Explanation:** Internal string sentinel markers (`"$?"`, `"$**"`, `"$,"`) previously shared string representations with potential user arguments, risking unread marker collisions during write destination resolution. vouch now separates sentinels into strongly-typed `ArgToken` and `TargetHead` enums and unifies position offset indexing across write evaluation arms.
  - **Example Scenario:** A command passing literal argument `"$?"` to an executable.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: literal argument matching sentinel spelling could resolve as an unread marker. After: strongly-typed tokens distinguish internal markers from real literal paths, resolving arguments deterministically.

* **Support gitignored operator patterns file in private data scanner and git hooks**
  - **Problem & Explanation:** Operators needing custom privacy scans for internal identifiers or project-specific secrets previously had to edit tracked scanner regexes, risking leaking sensitive patterns into repository history. vouch now supports an uncommitted, gitignored operator patterns file (`.vouch-private-patterns` or `VOUCH_PRIVATE_PATTERNS_FILE`).
  - **Example Scenario:** Staging an internal secret matching a pattern in `.vouch-private-patterns`.
  - **Delta:**
    - *Configuration Delta:* Uncommitted file `.vouch-private-patterns` read by `scan-private-data.sh`.
    - *Behavior Contrast:* Before: scanner only checked built-in generic patterns. After: checks operator-defined patterns case-insensitively, redacts pattern values in diagnostics, and refuses staging the patterns file.

### Bug Fixes

* **Check redirection descriptor bounds in shell parser to prevent integer overflow panics**
  - **Problem & Explanation:** When parsing shell redirection operators with very large descriptor numbers (e.g. `9999999999999>&1`), standard integer conversion could overflow and cause a panic in the parser thread. Pre-parse descriptor bounds checking now ensures descriptor tokens fit safely within 32-bit signed integer limits.
  - **Example Scenario:**
    ```bash
    echo test 9999999999999999>&1
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: thread panic on integer overflow. After: parser safely catches bounds errors and returns a structured parse diagnostic without crashing.

* **Handle raw strings and structural test markers in Python scanner test harness**
  - **Problem & Explanation:** The Python scanner test harness previously truncated test modules across arbitrary boundaries, occasionally slicing through raw string literals and producing invalid AST parse errors during test runs. The harness now respects raw string boundaries and structural module markers.
  - **Example Scenario:** Running Python scanner property and AST tests with raw string regex literals (`r"..."`).
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: test harness truncation caused spurious syntax errors on raw strings. After: parses raw strings cleanly and bounds module slices to valid AST statements.

* **Refuse sample destination when no existing ancestor path can be canonicalized in parse failure dumps**
  - **Problem & Explanation:** In parse failure sample dumps (`examples/dump_parse_failures.rs`), providing an output destination whose parent directories did not exist resulted in unhandled raw I/O errors rather than clear refusal diagnostics.
  - **Example Scenario:** Running `cargo run --example dump_parse_failures -- /nonexistent/dir/out.tsv`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: raw filesystem I/O panic. After: cleanly refuses with `DestinationRefusal::NoExistingAncestor` and reports actionable remediation.

## 0.46.0 (2026-09-23)

### Features

* **Reconcile skill installation destination files, prune bytecode cache directories, and report file-level progress**
  - **Problem & Explanation:** Installing developer skills previously copied directory trees wholesale without pruning Python bytecode caches (`__pycache__`, `*.pyc`), cluttering installation directories and leaving orphaned skill files behind when skills were renamed or removed. The skill installer now reconciles destination files, deletes orphaned files, strips cache directories, and reports explicit file-level progress.
  - **Example Scenario:** Running `scripts/install-skill.sh`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: stale files and bytecode caches lingered in skill install directories. After: destination directories match source trees exactly with clean file-level reporting.

* **Record verified minimum supported Rust version 1.96 in package manifest**
  - **Problem & Explanation:** `Cargo.toml` lacked an explicit `rust-version` field, allowing users on older unsupported compilers to encounter confusing syntax or feature compilation errors instead of clear compatibility diagnostics.
  - **Example Scenario:** Building vouch on an outdated Rust toolchain.
  - **Delta:**
    - *Configuration Delta:* Added `rust-version = "1.96"` in `Cargo.toml`.
    - *Build Contrast:* Before: build failed late with internal macro/compiler errors. After: cargo warns or errors immediately with the exact required compiler floor.

### Bug Fixes

* **Clarify host plugin tooling version warning contract and align documentation with present-tense rules**
  - **Problem & Explanation:** Documentation previously described future or past mechanisms in ambiguous tenses, creating confusion about whether plugin version mismatch warnings were advisory or blocking. Documentation was aligned to present-tense rules and the advisory warning contract clarified.
  - **Example Scenario:** Inspecting plugin version warnings in status output.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Documentation Contrast:* Before: ambiguous predictive phrasing. After: crisp, present-tense statements defining the advisory warning boundary.

* **Harden setup replay verification assertions, isolate run paths, and partition stood-down denials**
  - **Problem & Explanation:** In the setup replay test harness (`scripts/verify_settings.py`), test assertions did not strictly partition stood-down permission denials from live gate denials, risking masked regressions. The harness now runs across isolated temporary state directories and partitions verdict classes strictly.
  - **Example Scenario:** Running `python3 scripts/verify_settings.py`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: potential test state crosstalk between replay runs. After: fully isolated scratch environments with independent verdict assertions.

* **Optimize advisory predictor module lookups, unify false-positive ledger lists, and eliminate redundant tree hashing**
  - **Problem & Explanation:** The test-impact predictor (`scripts/predict_affected_tests.py`) repeatedly rehashed git trees and performed redundant file lookups across candidate test modules, adding noticeable delay to pre-commit checks. Lookups were memoized and unified into single-pass tree traversals.
  - **Example Scenario:** Running `scripts/test-predict-affected.sh`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Performance Contrast:* Before: multi-second tree hashing per test prediction. After: instant single-pass module lookups.

## 0.45.0 (2026-09-23)

### Features

* **Isolate measurement session records from production journal traffic and doctor statistics**
  - **Problem & Explanation:** Verification and measurement test runs (`cargo test`, benchmark runs) recorded dummy decisions into the live audit journal, inflating decision counts and skewing `vouch doctor` diagnostic reports. Journal records now carry a measurement marker under `VOUCH_MEASUREMENT=1` and are filtered from production views.
  - **Example Scenario:** Running `vouch doctor` after executing test suites.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: doctor showed thousands of test decisions mixed with user commands. After: test records are cleanly separated and excluded from production statistics.

* **Declarative program rule veto argument positions in knowledge schema**
  - **Problem & Explanation:** In `knowledge.toml`, `unless_flags` vetoes previously evaluated flags across all argument positions or hardcoded positions in Rust logic. Knowledge rules now declaratively specify `unless_position = "arg_0"` or `"any"`, allowing fine-grained position matching for commands like `kill -0 1234`.
  - **Example Scenario:** `kill -0 1234` (process ping) vs `kill 1234` (process termination).
  - **Delta:**
    - *Configuration Delta:* Added `unless_position` to `[[program.rule]]` in `knowledge.toml`.
    - *Behavior Contrast:* Before: positional flag matching required custom Rust code. After: declaratively vetted in knowledge schema v19.

* **Declarative parameter vocabulary for handed-over receiver object method execution**
  - **Problem & Explanation:** In Python snippets, passing objects whose own methods are invoked internally (e.g. `datetime.now(tz=timezone.utc)`) triggered false `callable_argument` or write prompts because vouch could not express receiver method delegation. Knowledge program entries now declare `invokes_methods`.
  - **Example Scenario:**
    ```bash
    python -c "import datetime; datetime.datetime.now(datetime.timezone.utc)"
    ```
  - **Delta:**
    - *Configuration Delta:* Added `invokes_methods` to `[[program]]` in `knowledge.toml`.
    - *Behavior Contrast:* Before: prompted on `callable_argument` or unmodeled method. After: allows safe receiver method execution cleanly.

### Bug Fixes

* **Canonicalize git hook path comparisons across drive-letter and posix representations**
  - **Problem & Explanation:** On Windows, git hook installers comparing `core.hooksPath` between Windows drive-letter format (`C:/...`) and POSIX format (`/c/...`) reported false configuration mismatches and prompted for redundant reinstalls. Paths are now canonicalized before comparison.
  - **Example Scenario:** Running `scripts/install-hooks.sh` in Git Bash on Windows.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: false mismatch error on drive representation. After: idempotent execution recognizing matching physical paths.

## 0.44.0 (2026-09-23)

### Features

* **Add synthetic PowerShell corpus and section 5 net property test coverage across all constructs**
  - **Problem & Explanation:** Property tests previously verified the Section 5 invariant ("every prompt names the setting that turns it off") exclusively over bash command syntax. PowerShell constructs were only tested by individual unit tests. A synthetic PowerShell corpus and generator now tests the Section 5 invariant exhaustively across all 27 PowerShell constructs.
  - **Example Scenario:** Running `cargo test --test property_test`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Test Coverage Contrast:* Before: Section 5 property checks covered bash only. After: automated property verification covers all PowerShell AST syntax trees.

* **Add duplicate match checks and directory changer claim guarding to `vouch trust`**
  - **Problem & Explanation:** Running `vouch trust <program>` blindly appended new entries to `my-knowledge.toml` without checking if the entry already existed, allowing bare entries to shadow richer existing rules. It also allowed directory changers to be trusted without specifying `changes_dir`. `vouch trust` now detects duplicates and rejects unbacked directory changer claims.
  - **Example Scenario:** Running `vouch trust git` when `git` already has custom knowledge rules.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: shadowed existing custom rules with duplicate entries. After: warns or updates in place without clobbering rich definitions.

* **Add mechanical verification of shipped and development skills against repository invariants**
  - **Problem & Explanation:** Documentation and procedures in skill files (`.claude/skills/`, `plugin/skills/`) previously had no automated validation against repository rules, allowing outdated advice or broken section references to ship unnoticed. Gate 8 in `tests/schema_docs_test.rs` now verifies frontmatter, anti-patterns, and section anchors.
  - **Example Scenario:** Running `cargo test --test schema_docs_test`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Quality Contrast:* Before: skill file drift discovered only through manual review. After: mechanical CI gate fails builds on any skill invariant violation.

### Bug Fixes

* **Break engine verdict ties by diagnostic specificity to preserve by-reference and guard reasons**
  - **Problem & Explanation:** When a command triggered multiple checks at the same decision priority, the first writer retained the reason slot, allowing a generic write prompt to mask a more informative guard or callable reference diagnostic. The engine now breaks ties by diagnostic specificity.
  - **Example Scenario:** A Python snippet triggering both a generic write check and a specific guard check.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: displayed generic prompt reason. After: presents the most specific diagnostic reason explaining the exact risk.

* **Order config migration instructions to prioritize moving legacy `vouch.toml` before example templates**
  - **Problem & Explanation:** When migrating from older setups, initialization diagnostics suggested copying the example config and moving old configs in an ambiguous order that could lead operators to overwrite their custom configurations. Instructions were reordered to prioritize preserving existing configs.
  - **Example Scenario:** Running `vouch` on a machine with legacy `~/.config/vouch.toml`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: risk of clobbering user config by following instructions in printed order. After: strictly ordered safe migration steps.

## 0.43.0 (2026-09-22)

### Features

* **Compact audit journals and outcome logs during review and doctor passes to enforce bounded storage while preserving recent decisions**
  - **Problem & Explanation:** The audit journal in `~/.local/state/vouch/journal.jsonl` grew unboundedly with every tool call, consuming disk space and slowing review passes. Journaling now features atomic deduplicating compaction, preserving a recent window (1,000 records) and collapsing historical duplicates with aggregated counts under a hard cap (5,000 records).
  - **Example Scenario:** Running `vouch doctor` or `vouch review` on a high-traffic host.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Performance Contrast:* Before: unbounded log file growth. After: automatic bounded storage with sub-millisecond tail reads.

* **Declare literalpath destination flag for powershell pushd and push-location**
  - **Problem & Explanation:** Navigating directories in PowerShell using `pushd -LiteralPath <path>` triggered undeclared option prompts because `-LiteralPath` was missing from knowledge definitions.
  - **Example Scenario:**
    ```powershell
    pushd -LiteralPath "C:/Users/dev/[project]"
    ```
  - **Delta:**
    - *Configuration Delta:* Added `"-literalpath"` to `dest_dir_flags` for `pushd` and `push-location` in `knowledge.toml`.
    - *Behavior Contrast:* Before: prompted on undeclared option `-literalpath`. After: allows directory stack navigation to paths containing bracket wildcards cleanly.

### Bug Fixes

* **Cap doctor undeclared options display at twenty items and anchor option line parsing**
  - **Problem & Explanation:** On developer hosts with many custom scripts, `vouch doctor` could print thousands of lines of undeclared options, scrolling actionable diagnostics off screen. Display is now capped at 20 representative items with total counts reported in the header.
  - **Example Scenario:** Running `vouch doctor` on a machine with varied tool invocations.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: unbounded terminal output flooding stdout. After: concise 20-item preview with total unique count.

* **Clean up newly written `my-knowledge` on failed trust rollback and route slash-shaped flags into member validation**
  - **Problem & Explanation:** If `vouch trust` failed verification during rollback, newly created zero-byte `my-knowledge.toml` files could be left on disk. Rollback now cleans up newly created files. Slash-shaped flags (`/flag`) are also routed into member validation to reject invalid subcommands.
  - **Example Scenario:** `vouch trust tool /invalid-flag`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: empty zero-byte residue left on disk. After: atomic cleanup and rejection of slash-shaped invalid subcommands.

* **Isolate relative directory navigation from ambient CDPATH search diversion**
  - **Problem & Explanation:** In bash, relative directory navigation (`cd dirname`) can be diverted to unrelated locations if the `CDPATH` environment variable is set. Unanchored relative directory changes now fail closed to Ask under ambient `CDPATH`, while dot-anchored (`cd ./dirname`) and absolute paths remain allowed.
  - **Example Scenario:**
    ```bash
    export CDPATH="/other/dir"; cd project
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: evaluated directory change against local cwd, ignoring `CDPATH` diversion. After: detects ambient `CDPATH` and prompts on unanchored relative moves.

## 0.42.0 (2026-09-21)


### Features

* **Automatically detect parent shell environment for explain and why commands**
  - **Problem & Explanation:** When developers queried `vouch explain` or `vouch why` from a PowerShell prompt, vouch defaulted to POSIX bash syntax unless `--shell powershell` was passed explicitly, showing bash-oriented quoting and diagnostics. Vouch now inspects the parent process environment to detect PowerShell and automatically format diagnostics for the calling shell.
  - **Example Scenario:** Running `vouch explain "Get-ChildItem -Path C:\Project"` from a PowerShell terminal.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: required `--shell powershell` or defaulted to bash parsing rules. After: automatically detects parent PowerShell shell and parses with native PowerShell syntax.

* **Evaluate higher-order callable references in functools.reduce**
  - **Problem & Explanation:** Python scripts passing write or destructive functions into `functools.reduce` (such as `functools.reduce(os.remove, items)`) bypassed callable target detection because `reduce` was not modeled as taking a callable in its first argument position. The Python scanner now models callback positions in `functools.reduce`, accurately detecting write targets passed by reference.
  - **Example Scenario:**
    ```python
    import functools, os
    functools.reduce(os.remove, file_list)
    ```
  - **Delta:**
    - *Configuration Delta:* Modeled in knowledge schema callback declarations.
    - *Behavior Contrast:* Before: treated `os.remove` as an uninvoked reference and missed write tracking. After: intercepts higher-order call and gates write paths against allowed write destinations.

* **Recognize standard stream writes on sys.stdout and sys.stderr**
  - **Problem & Explanation:** Python code writing to `sys.stdout.write(...)` or `sys.stderr.write(...)` triggered unmodeled filesystem write prompts because any method named `write` was conservatively classified as a file-modification side effect. Standard stream writes are now explicitly recognized as terminal handle writes, keeping harmless console output unblocked.
  - **Example Scenario:**
    ```python
    import sys
    sys.stdout.write("task complete\n")
    ```
  - **Delta:**
    - *Configuration Delta:* Standard stream handles modeled in built-in Python knowledge.
    - *Diagnostic Contrast:* Before: prompted operator for permission to write to unmodeled file targets. After: recognizes standard stream handle writes and allows console output without interruption.


### Bug Fixes

* **Halt on rebound_name when shadowed imported callables are passed by reference**
  - **Problem & Explanation:** If a script imported a safe function and later rebound that name to a different function or variable in local scope, passing that identifier by reference could incorrectly resolve to the original imported symbol. Vouch now halts resolution on rebound names and asks the operator rather than dispatching under false assumptions.
  - **Example Scenario:**
    ```python
    from os import path
    path = custom_mutator
    dispatch(path)
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: evaluated reference using original imported target. After: halts on `rebound_name` and safely prompts when local reassignments shadow imported symbols.

* **Provide actionable build and copy guidance on absent corpus in test gate**
  - **Problem & Explanation:** When property or measurement tests ran in environments where the private real-traffic corpus was absent, tests emitted ambiguous skip or failure notices that did not explain how to acquire or regenerate the dataset. The gate runner now displays direct commands for building or copying the corpus.
  - **Example Scenario:** Running cargo test on a fresh machine without local fixture cache.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: vague test skip message without remediation steps. After: prints exact copy and build commands (`tests/fixtures/build_fixture.py`).

## 0.41.0 (2026-09-18)


### Features

* **Detect unified diff added environment dumps in pre-push hook**
  - **Problem & Explanation:** The pre-push git hook safety scanner checked committed file content but did not inspect patch hunks specifically for added lines that dump process environments or secret variables (`env`, `printenv`, `export -p`). The scanner now scans unified diff additions specifically, catching accidental leak inclusions before push.
  - **Example Scenario:** A commit adding `env > /tmp/debug.log` to a deployment script.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: only full tracked file scans ran, missing transient patch hunk additions. After: pre-push hook verifies added patch lines and blocks credential/environment dumps.

* **Evaluate mode-conditioned writes by reference as unresolved invocations**
  - **Problem & Explanation:** When a Python file opener or handler was passed as a function reference without an explicit mode argument, vouch assumed default read mode (`r`) even when the callable was invoked downstream for writing. Mode-conditioned references are now conservatively marked as unresolved invocations that require operator permission when writing cannot be ruled out.
  - **Example Scenario:** Passing an uninvoked `open` reference to a helper function that chooses write mode at runtime.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: assumed read mode and allowed potentially destructive file opening. After: flags mode-conditioned callable references as unresolved and prompts safely.

* **Exempt literal None in higher-order callback argument positions**
  - **Problem & Explanation:** In Python idioms like `filter(None, sequence)`, passing literal `None` as the callback function caused vouch to report an unmodeled callable error, prompting the operator even though `filter(None, ...)` is standard Python for filtering truthy elements. Literal `None` in callback positions is now exempted as a built-in identity filter.
  - **Example Scenario:**
    ```python
    truthy_items = list(filter(None, raw_items))
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: raised unmodeled callable diagnostic on `None`. After: evaluates `filter(None, ...)` as safe in-memory filtering without prompting.

* **Format unresolved python variable targets with unresolved marker token**
  - **Problem & Explanation:** When a Python script wrote to an expression that could not be statically evaluated, the resulting diagnostic output rendered shell variable syntax (`$VAR`) instead of Python notation, confusing operators reviewing the prompt. Unresolved Python targets now use the canonical `<?>` marker token.
  - **Example Scenario:** `f = open(get_dynamic_target(), "w")`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: printed `$target` in prompt summary. After: displays `<?>` with context explaining that the write target could not be statically derived.

* **Replace phantom reconcile skill with inline remediation in config diagnostics**
  - **Problem & Explanation:** Configuration diagnostics and parse errors directed operators to invoke a non-existent `/vouch-reconcile` agent skill when configuration keys were missing or drifted. These messages have been replaced with clear inline remediation steps and suggestions to run `vouch doctor`.
  - **Example Scenario:** Encountering a deprecated or drifted key in `config.toml`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: advised running `/vouch-reconcile`. After: provides concrete inline remediation and points directly to `vouch doctor`.

## 0.40.0 (2026-09-18)


### Features

* **Guard vocabulary is declared in knowledge schema version 17 with prompt effect descriptions**
  - **Problem & Explanation:** Security guard names and categories were hardcoded in Rust source code, making it impossible for knowledge files to declare human-readable prompt explanations for custom guards. Knowledge schema version 17 moves guard definitions into data declarations with clear effect descriptions that display in prompts.
  - **Example Scenario:** A guard triggering on recursive directory deletion explains the exact risk in plain language.
  - **Delta:**
    - *Configuration Delta:* Schema version bumped to 17 with new `[guards]` tables.
    - *Diagnostic Contrast:* Before: cryptic internal guard identifiers shown to the operator. After: human-readable explanation of why the guard fired and what destructive effect it prevents.

* **In-snippet PowerShell environment variable assignments evaluate against rebound name lookup checks**
  - **Problem & Explanation:** When PowerShell scripts executed through `-Command` set environment variables (`$env:TARGET = "val"`), subsequent commands within the same snippet that referenced `$env:TARGET` failed rebound variable lookup checks and caused false-positive unmodeled prompts. In-snippet environment assignments are now tracked across statements.
  - **Example Scenario:**
    ```powershell
    $env:DEST = "C:\Allowed\dest"; Copy-Item src.txt $env:DEST
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: treated `$env:DEST` as an unknown external variable and prompted. After: tracks in-snippet assignment and resolves the destination path within the allowed zone.

* **Mechanical lint test and path helper prevent un-drive-qualified test fixture paths**
  - **Problem & Explanation:** Integration tests on Windows runners frequently broke when fixture paths used Unix-style `/tmp` paths that lacked drive qualifiers (`C:`), leading to platform-specific test flake. A mechanical lint test and shared path helper now prevent un-drive-qualified paths from entering test fixtures.
  - **Example Scenario:** Creating a temporary directory fixture in an integration test.
  - **Delta:**
    - *Configuration Delta:* Shared test helper in `tests/common`.
    - *Tooling Contrast:* Before: platform-dependent test failures on Windows runners. After: mechanical CI gate enforces normalized drive-qualified paths across all platforms.

* **Slash-shaped flags support colon-attached values and runas is modeled as a rest wrapper**
  - **Problem & Explanation:** Windows command-line utilities frequently use slash-style flags with colon separators (such as `/user:Administrator`). Vouch's flag parser previously split on whitespace only, misparsing colon-attached arguments. Slash flags with attached values are now parsed properly, enabling wrapper tools like `runas` to be modeled accurately.
  - **Example Scenario:** `runas /user:Administrator "cmd.exe /c cleanup.bat"`.
  - **Delta:**
    - *Configuration Delta:* `runas` modeled as a rest wrapper in Windows knowledge definitions.
    - *Behavior Contrast:* Before: misidentified `/user:Administrator` as an invalid flag. After: parses slash flag values and unpacks wrapped commands for security evaluation.


### Bug Fixes

* **Git hook scanner excludes consecutive assignments containing command substitutions from dump backstops**
  - **Problem & Explanation:** Pre-commit hooks designed to block accidental environment dumps falsely flagged shell scripts containing consecutive local variable assignments when those assignments included command substitutions (`VAR=$(cmd)`). The hook scanner now distinguishes shell variable assignments from bulk environment dumping.
  - **Example Scenario:**
    ```bash
    FIRST=$(git rev-parse HEAD)
    SECOND=$(git rev-parse HEAD~1)
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged in git hook definitions.
    - *Tooling Contrast:* Before: hook rejected legitimate multi-line assignment scripts as potential credential dumps. After: allows consecutive assignments containing command substitutions.

## 0.39.0 (2026-09-18)


### Features

* **Support subcommand-specific option definitions and output destination derivation in knowledge schemas**
  - **Problem & Explanation:** Many CLI tools use the same flag letter for different purposes depending on the subcommand (for example, `-o` meaning output file in one verb but something unrelated in another). Knowledge definitions previously applied options globally across a program, leading to false destination inferences. Schema version 16 introduced subcommand-scoped option definitions.
  - **Example Scenario:** A multi-verb tool where `tool build -o file.bin` writes to a file, but `tool query -o json` specifies formatting.
  - **Delta:**
    - *Configuration Delta:* Knowledge schemas support `[commands.tool.subcommands.verb.options]`.
    - *Behavior Contrast:* Before: global flag definitions caused false write prompts on query verbs. After: resolves options and write destinations specific to the invoked subcommand.

* **Enumerate command substitution positions via canonical AST visitors shared between the shell parser and measurement harnesses**
  - **Problem & Explanation:** The shell execution parser and the fixture measurement harnesses previously used independent AST traversal logic to find `$(...)` and backtick substitutions. Slight differences in traversal led to subtle mismatches during verification. A shared canonical AST visitor now guarantees identical command substitution enumeration.
  - **Example Scenario:** Nested command substitutions inside arithmetic expressions and heredocs.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Tooling Contrast:* Before: potential discrepancies between production gating and offline measurement scripts. After: single canonical AST visitor shared across engine and test harnesses.

* **Introduce unified restriction, grant, and ranked reduction combinators on candidate base sets**
  - **Problem & Explanation:** Decision resolution across trust zones, distrust zones, guards, and knowledge grants used ad-hoc boolean logic in multiple evaluation paths, making precedence order subtle and difficult to audit. Base set combinators now unify candidate evaluation into formal ranked restriction and grant reductions.
  - **Example Scenario:** Evaluating a command that touches both an allowed read path and a distrusted zone.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: scattered conditional checks for zone precedence. After: deterministic ranked reduction combinators with transparent decision auditing in `vouch why`.

* **Unify wrapper expansion state into structured occurrence records with consolidated source provenance**
  - **Problem & Explanation:** When unwrapping commands inside `sudo`, `xargs`, or `sh -c`, the parser maintained parallel arrays of command names, arguments, and sources. If these arrays fell out of sync, error messages could report misleading source line numbers. Wrapper expansion now uses strongly typed occurrence records with consolidated provenance.
  - **Example Scenario:** `sudo sh -c "echo clean > /tmp/out"`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: error messages could point to outer wrapper positions instead of inner commands. After: each unwrapped command retains exact source provenance back to its original location.


### Bug Fixes

* **Skip parameter expansions as units and enforce arithmetic context for heredoc operators in substitution parsing**
  - **Problem & Explanation:** The command substitution boundary scanner previously misidentified parameter expansions containing braces (such as `${VAR//foo/bar}`) or arithmetic shift operators (`<<`) inside heredocs as nested substitutions or heredoc delimiters, triggering false syntax errors. The parser now handles parameter expansions as atomic units and verifies arithmetic context.
  - **Example Scenario:**
    ```bash
    echo "${PATH//:/ }"
    cat <<EOF
    $(( 1 << 4 ))
    EOF
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: failed parsing with syntax error prompts. After: accurately identifies parameter expansion boundaries and heredoc contents without false alarms.

## 0.38.0 (2026-09-18)


### Features

* **Support bash 5.3 non-forking value substitutions in same-process scopes**
  - **Problem & Explanation:** Bash 5.3 introduced non-forking value substitutions (`${ cmd; }`), which execute inside the main shell process without creating a subshell. Vouch treated all substitutions as subshells, missing variable modifications or triggering subshell warnings. Vouch now models non-forking substitutions as same-process child scopes while still enforcing safety checks.
  - **Example Scenario:**
    ```bash
    val=${ cat /tmp/token.txt; }
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: flagged non-forking substitutions as unmodeled syntax or subshell constructs. After: walks substitution commands in a same-process scope, accurately tracking effects.

* **Deduplicate wrapped snippet AST scans across decision evaluations**
  - **Problem & Explanation:** Scripts passed into interpreters via `-c` or `-Command` were being parsed twice: once during initial occurrence discovery and again during policy gating. On large shell scripts or wrapped Python commands, this redundant parsing added measurable latency to agent tool calls. Snippet ASTs are now scanned once and cached on the occurrence record.
  - **Example Scenario:** Multi-line inline scripts invoked via `bash -c "..."` or `python -c "..."`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Performance Contrast:* Before: redundant AST traversals on every wrapper evaluation. After: single-pass scan cached on occurrence records, cutting tool-call gating overhead.

* **Distinguish literal single-quoted tokens from expandable arguments in PowerShell**
  - **Problem & Explanation:** In PowerShell, single-quoted strings are verbatim literals, whereas double-quoted strings can expand variables. Vouch's token scanner previously treated single-quoted tokens containing `$` signs as expandable variables, prompting operators for unbound variable names that were actually string literals.
  - **Example Scenario:**
    ```powershell
    Write-Output 'Price is $100'
    ```
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: prompted operator for undefined variable `$100`. After: recognizes verbatim single-quoted strings and suppresses false variable expansion prompts.

* **Report trigger-specific diagnostic details for scanner constructs**
  - **Problem & Explanation:** When a scanner rejected a command due to an unmodeled syntax construct (such as process substitutions or coprocesses), the diagnostic prompt only reported a generic construct error without explaining which token triggered it. An out-of-band diagnostic channel now surfaces the specific token and reason in prompts.
  - **Example Scenario:** Running a command using bash process substitution `<(cmd)`.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Diagnostic Contrast:* Before: generic "unmodeled construct" message. After: detailed prompt naming the exact construct (`ProcessSubstitution`), token location, and explaining why it was gated.


### Bug Fixes

* **Cap nested subshell recursion depth to prevent stack exhaustion**
  - **Problem & Explanation:** Malicious or deeply nested command inputs containing hundreds of nested subshells or arithmetic groups (`$(( $(( $(( ... )) )) ))`) could cause deep recursion in the parser and exhaust the thread stack. A recursion depth limit now halts traversal cleanly with a contextual error prompt.
  - **Example Scenario:** Highly nested generated shell expressions.
  - **Delta:**
    - *Configuration Delta:* Unchanged.
    - *Behavior Contrast:* Before: potential stack overflow crash on deeply nested syntax trees. After: safely caps recursion depth and returns a clean parse failure prompt.

## 0.37.0 (2026-09-18)


### Features

* comprehensive PowerShell AST construct classification via poshtree
* full ECMAScript AST parsing via oxc for JavaScript inline snippets


### Bug Fixes

* relocate Windows boundary junction test target outside allowed paths

## 0.36.0 (2026-09-18)


### Features

* inline JavaScript snippet scanner for node, bun, and deno inline evaluation
* literal loop variable enumeration in compound shell commands


### Bug Fixes

* deduplicate unknown command heads case-insensitively in unmodeled command prompts
* reconcile Deno CLI inline evaluation knowledge claims
* same-command variable assignment resolution in guard prompt target display
* validate shipped knowledge fixture schema versions against drift
* Windows temp mount target canonicalization resolving 8.3 aliases

## 0.35.0 (2026-09-17)


### Features

* attribute acting command and attempted sources in unresolved path diagnostics
* benchmark per-tool-call overhead across lifecycle phases
* inherit tool server snippet declarations in bare exact entries


### Bug Fixes

* isolate relative target resolution in replay against test runner cwd

## 0.34.0 (2026-09-17)


### Features

* derive archive creation write destinations conditionally from mode flags in program knowledge

## 0.33.0 (2026-09-16)


### Features

* add positional-count-dependent write thresholds for program entries
* redact secret shapes and exclude active sessions in the corpus builder


### Bug Fixes

* display canonical resolved paths in shell redirection diagnostic prompts
* preserve explicit zero when overriding subcommand positional write thresholds
* validate run-dir and wrap-head flags against merged knowledge options

## 0.32.0 (2026-09-16)


### Features

* configurable gated read paths prevent sensitive files and credentials from silent exposure in transcripts
* diagnostics and environment redirection notices format filesystem paths with canonical forward slashes
* unparseable hook input and tool snippets emit explicit configurable decisions rather than silently abstaining
* write rule suggestions in prompts narrow to specific files and leaf directories rather than root drives

## 0.31.0 (2026-09-16)


### Features

* recognize shell functions defined within the same command as non-programs rather than unmodeled binaries

## 0.30.0 (2026-09-15)


### Features

* resolve shell mount points to canonical host destinations during path normalization

## 0.29.1 (2026-09-15)


### Bug Fixes

* emit force_ask for Antigravity so Ask decisions prompt unconditionally

## 0.29.0 (2026-09-15)


### Features

* track intra-line environment variable exports in compound shell commands

## 0.28.0 (2026-09-15)


### Features

* enable operator subcommands in user knowledge to refine whole-program recognition


### Bug Fixes

* avoid early pipe termination on changelog diff during mirror publish

## 0.27.0 (2026-09-14)


### Features

* add token-normalized shape extraction with PII and literal sanitization to vouch-setup
* expose six-stage pipeline visualizer in vouch why output
* itemize per-command breakdown on multi-command lines in diagnostic traces
* resolve variable targets in guard diagnostic prompts and report unresolvable variable notices


### Bug Fixes

* preserve host execution permissions for workspace file writes and redirections to prevent sandbox denial

## 0.26.3 (2026-09-14)


### Bug Fixes

* restore standard cargo target directory layout for cross-platform release builds

## 0.26.2 (2026-09-14)


### Bug Fixes

* auto-seed Git and Cargo subcommand permissions and disable redundant sandbox prompts during Antigravity installation
* model Python os.environ.copy, os.getenv, os.listdir, and os.scandir in shipped knowledge

## 0.26.1 (2026-09-13)


### Bug Fixes

* enforce command head containment and preserve host execution for script files
* seed standard shell and Python interpreter permissions in Antigravity settings

## 0.26.0 (2026-09-13)


### Features

* evaluate argument paths and script files for Antigravity sandbox containment
* reconcile vouch and git tool permissions in Antigravity settings

## 0.25.0 (2026-09-13)


### Features

* auto-seed clean unsandboxed tool wildcards in Antigravity settings during vouch install
* recognize PowerShell expressions and extract command heads inside parenthesized subexpressions
* statically resolve predictable command substitutions for intra-command variable assignments
* support subcommand-level capability filtering in knowledge schema v15 and demote offline subcommands to sandbox
* synthesize baseline knowledge overlays from multi-host transcripts and verify candidate rules

## 0.24.0 (2026-09-13)


### Features

* support $WORKSPACE_ROOT expansion in program location trust rules
* support wildcard name_patterns in program location trust rules

## 0.23.0 (2026-09-12)


### Features

* evaluate host and network capabilities through the AST for Antigravity sandbox demotion

## 0.22.0 (2026-09-11)


### Features

* model gh, kubectl, flux, just, tmux, gofmt, npx, curl, man, col, lsof, helm, gitleaks, and harness tools

## 0.21.0 (2026-09-10)


### Features

* demote BypassSandbox on local Ask verdicts in Antigravity host protocol
* inspect readable literal argv and eval strings in Python subprocess and eval calls
* unify entry_applies in heredoc_feeds with standalone run check


### Bug Fixes

* exclude gh from sandbox demotion in Antigravity
* exclude git mutating commands from sandbox demotion in Antigravity
* exclude release scripts from sandbox demotion in Antigravity

## 0.20.0 (2026-09-10)


### Features

* harvest tool calls across Claude Code, Codex, and Antigravity transcripts
* introduce `vouch uninstall [--host claude|codex|agy] [--write]` to cleanly remove vouch hooks while preserving other configuration
* model `uninstall` and `--write` mutating operations in `knowledge.toml` under `in_place_edit` guard
* model native Codex and Antigravity agent tools in shipped knowledge
* support `--write` flag on `vouch install` to atomically write merged configuration to the host settings/hooks file

## 0.19.0 (2026-09-09)


### Features

* agy hook installer generation targeting hooks.json
* automatic sandbox demotion for safe local workspace operations when BypassSandbox is requested
* knowledge definitions for Antigravity tools (run_command, write_to_file, replace_file_content, and inspection tools)
* native Google Antigravity (agy) host support, toolCall protocol parsing, and decision rendering

## 0.18.1 (2026-09-09)


### Bug Fixes

* a case statement inside a command substitution is read past its pattern parentheses
* a command substitution holding a dollar-single-quote string with an escaped quote is read whole instead of refused
* a command substitution in a for-clause value list, a case subject or pattern, or an extended-test operand is judged instead of silently allowed
* a command substitution in a redirect target, a here-string or an unquoted here-document body is judged
* a command substitution inside an arithmetic expression is walked instead of refused as unreadable
* a command substitution nested inside another's double-quoted string is read to its own closer
* a command substitution whose body carries a here-document is read whole, apostrophes and backticks in the here-document's text included
* a comment beginning right after a close parenthesis inside a command substitution no longer ends the substitution early
* a comment inside a command substitution no longer ends the substitution at a parenthesis in the comment's text
* a comment marker right after a nested substitution's closing parenthesis is text, not a comment
* a deeply nested substitution is refused at the nesting cap instead of costing the gate exponential time
* a function definition's own redirect list is judged, including a substitution in its target
* a guard, a write or an undescribed program inside a command substitution is judged instead of allowed by the subshell construct
* a substitution or subshell in an or-tail no longer coarsens the enclosing line's directory placement
* arithmetic expansion, a single-quoted or escaped substitution spelling no longer raise the subshell construct

## 0.18.0 (2026-09-06)


### Features

* javascript, awk and perl snippets each name their own construct setting, rather than sharing one setting that silenced all of them together
* the knowledge schema is 13, so a wrap language may name javascript, awk or perl


### Bug Fixes

* a PowerShell Start-Process handed a variable as its argument list now asks instead of allowing silently

## 0.17.5 (2026-09-06)


### Bug Fixes

* a flag unrelated to standard input no longer makes an inline-code run ask
* a shell given its code by an inline-code flag no longer asks about code vouch cannot see merely because an unrelated flag looks like a standard-input marker
* a snippet in a language vouch cannot scan names that language's setting on the command path, as it already did on the tool path
* a verb an entry does not cover no longer asks citing code vouch cannot see, and a flag an entry lists as standalone no longer does either
* an entry scoped to one shell language no longer has its standard-input claim consulted on a line of another
* an inline-code flag written with its payload attached is judged the same as one written with a space, instead of asking about code vouch had already read
* an unquoted here-document body carrying a backslash is no longer treated as reaching its consumer unchanged
* an unread-code ask raised by a python call names python's own construct setting instead of the host shell's, so setting python's turns it off
* an unresolved write path found in a snippet names that snippet's language, matching the sibling site that already did
* an unresolved write path found in a snippet whose base directory could not be proven also names that snippet's language, not the host's

## 0.17.4 (2026-09-06)


### Bug Fixes

* a described write inside a compound body within a wrapped snippet now names its destination instead of refusing with unresolved_path
* a redirect inside a wrapped snippet now resolves against the directory that snippet's own cd moved to, instead of the directory the wrapping command ran in

## 0.17.3 (2026-09-05)


### Bug Fixes

* a brace form in a for-loop's value list raises its construct instead of passing unexamined
* a command inside a subshell whose only content is a subshell is judged instead of allowed unseen, so a delete there reaches its guard and a write there reaches the write rules
* a recursive delete inside an arithmetic for-loop asks on its guard, like the same delete written in a plain loop
* an arithmetic expression carrying a command substitution asks instead of allowing a command whose text is absent from the line

## 0.17.2 (2026-09-04)


### Bug Fixes

* the shipped knowledge's read-only section says where build, install and deploy tools do get described, instead of claiming they are not described at all
* the vouch-trust skill now describes a destructive operation and proposes the rule that makes it ask by naming the effect, instead of directing you to leave it unrecognised

## 0.17.1 (2026-09-03)


### Bug Fixes

* a place-scoped entry and a loosening guard override reach a command on the same terms, and the allow names every tree and directory that let it through
* a place-scoped entry missed by known directories recommends widening only_under, instead of saying no remedy can help
* a place-scoped run.guards entry no longer tightens a command whose every possible directory is known and outside its tree
* a prompt naming a place-scoped guard override names every entry holding the line, not only the first
* a prompt no longer says vouch cannot prove where a command runs when every directory it could be in is known
* a redirect after a directory change that an and-chain proved is judged from the directory the shell actually moved to, rather than from both that directory and the one it left
* a redirect written on a loop, brace group or conditional is judged from the directory that construct runs in, instead of asking about a position vouch could not place
* a run-place prompt no longer says vouch cannot prove where a command runs when it has proven every possibility
* a trust zone recognises a command when every directory it could be running in is inside the zone, instead of refusing because there is more than one
* a trust zone that covers some but not all of a command's possible directories says so, and names the ones it does not cover
* a trust_nothing_under zone no longer holds a command whose every possible directory is known and outside the zone

## 0.17.0 (2026-09-01)


### Features

* a cd inside a subshell, pipeline stage, or backgrounded member is contained in its own child scope, so the rest of the line keeps its provable directory instead of going unplaceable
* a write behind a fallback or failable cd is judged over every surviving candidate directory - an and-chained success certifies the move, an or-branch fall-through refutes it, and a target that provably exists discharges the failure branch
* a write inside a brace group or conditional body is judged over the directories that body can actually be in, rather than the top level's walk state
* an unplaceable directory change asks with its actual cause named - the stack form, the unreadable destination, the loop carry, the unplaced position - instead of one blanket cannot-order sentence


### Bug Fixes

* a relative destination after a cd that only moved a subshell or pipeline stage is no longer resolved as if the whole line had moved

## 0.16.0 (2026-08-30)


### Features

* a new guard, bypass_enforcement, asks when a command instructs a tool to skip its own configured checks
* git --no-verify on commit, push, merge, rebase and am now asks under that guard, while the -n spellings meaning dry-run or no-stat continue to allow

## 0.15.0 (2026-08-30)


### Features

* a function vouch already describes, handed to a call like sorted through its key argument, is now judged and allowed instead of asking about a function it could not see
* a new lang.python.constructs.callable_argument setting controls the prompt for a by-reference callable vouch could not resolve or fully evaluate
* handing a destructive function to another function is now judged as what it does
* sorted, min, max, map and filter are now recognized, so a real callable handed to their key or function argument is judged instead of the whole call going unmodeled


### Bug Fixes

* datetime.now with a timezone no longer prompts about a function it never calls
* passing a plain replacement string to re.sub no longer prompts about a function

## 0.14.0 (2026-08-28)


### Features

* vouch-landing ends as a consumer, installing the verified released pair and updating the plugin instead of leaving a dev build live
* vouch-update distinguishes a same-version dev build from the release archive by byte-comparing against a present clone's build

## 0.13.0 (2026-08-28)


### Features

* a /vouch:status command surfaces the status check beside /vouch:setup and /vouch:update
* a vouch-status skill reports installed binary, knowledge, and plugin versions against the newest release, read-only

## 0.12.0 (2026-08-28)


### Features

* a /vouch:update command surfaces the update procedure beside /vouch:setup
* a vouch-update skill updates an installed gate from the newest verified release bundle on an explicit accept

## 0.11.0 (2026-08-28)


### Features

* Reuse an exact public candidate test on publisher push while repeating every privacy and mutation-boundary scan
* Reuse exact full and phase verification evidence by default while retaining an explicit forced-rerun command


### Bug Fixes

* Continue already-authorized required gates through bounded repair and rerun recovery without repeating a matching successful pass

## 0.10.0 (2026-08-28)


### Features

* add retractable snippet_args knowledge declarations for indexed snippet argument vectors
* resolve static Python sys.argv indices from inline and explicit standard input interpreter arguments


### Bug Fixes

* discard indexed snippet references after dynamic reassignment

## 0.9.0 (2026-08-28)


### Features

* Resume exact completed verification phases after a later isolated phase fails
* Run independent short verification suites concurrently while keeping publisher verification isolated

## 0.8.1 (2026-08-27)


### Bug Fixes

* reject incomplete or version-mismatched notes before release automation
* require every release-bearing commit to enumerate independently visible outcomes
* restore the missing v0.8.0 release details
* verify the pinned release engine emits multiple detail bullets without the private summary

## 0.8.0 (2026-08-27)


### Features

* add exact nested command paths without trusting sibling operations
* recognize only codex mcp get, codex mcp remove, codex plugin list, and codex plugin remove
* guard confidential output, local-state initialization, and removals independently
* teach the trust procedure to add and prove exact nested paths


### Bug Fixes

* keep one watcher attached to long landing gates and freeze their worktree inputs

## 0.7.0 (2026-08-27)


### Features

* track Python directory changes

## 0.6.0 (2026-08-27)


### Features

* track Python value provenance

## 0.5.4 (2026-08-27)


### Bug Fixes

* resolve project roots in diagnostics

## 0.5.3 (2026-08-27)


### Bug Fixes

* pass portable cwd to Windows fixture

## 0.5.2 (2026-08-27)


### Bug Fixes

* normalize Windows program-location fixtures

## 0.5.1 (2026-08-27)


### Bug Fixes

* harden and accelerate release closeout

## 0.5.0 (2026-08-26)


### Features

* define program-location trust rules
* explain program-location recognition
* recognise programs by proven location
* resolve existing program locations


### Bug Fixes

* preserve program-location path identity

## 0.4.1 (2026-08-26)


### Bug Fixes

* test the assembled public tree before publishing

## 0.4.0 (2026-08-26)


### Features

* make declared repository state mechanically enforceable

## 0.3.6 (2026-08-26)


### Bug Fixes

* treat Git identity email as public attribution

## 0.3.5 (2026-08-25)


### Bug Fixes

* preserve the exact scanned public release

## 0.3.4 (2026-08-25)


### Bug Fixes

* make verb resolution and Codex shadow evidence reliable
* scan release candidates before remote writes

## 0.3.3 (2026-08-24)


### Bug Fixes

* compare Windows directories by identity

## 0.3.2 (2026-08-24)


### Bug Fixes

* distinguish repository exposure from local context
* install source binaries outside the build tree
* preserve binary recovery copies
* show the complete release route before landing

## 0.3.1 (2026-08-22)


### Bug Fixes

* preserve unrelated Codex hook entries
* the full verifier keeps real command samples out of transcripts
* use native Codex approval for broker

## 0.3.0 (2026-08-22)


### Features

* eval says what vouch knows about it
* the public commit message carries the change's own account, and a commit skill teaches the shape
* the push hook refuses a push that is not built on the remote's live tip


### Bug Fixes

* a relative cwd yields no project root, instead of borrowing the process's directory
* stage first, then scan exactly the index
* the private-data scanner fails closed on a bad invocation, and stands down the account-name check for git's own identity fields
* the publish scans what git add -A will commit, not the whole working tree
* verify discovers a squash-merged publish, and an empty discovery refuses aloud

## 0.2.0 (2026-08-22)


### Features

* commit subjects take a conventional prefix, and content is judged first
* first-publish seeds an empty destination, and refuses one with history
* release-please runs here, and the build workflow's tag path stays in the mirror
* tag cuts the release, runs the verify itself, and reads the mirror's own version
* the manifest names workflows one at a time, refuses dead entries, and validates its flag
* the publish delivers a branch and a pull request, never a push to master
* verify proves the merge landed what was published, under every merge method


### Bug Fixes

* close the review holes in verify.sh's gate and the commit-msg hook
* the mirror's version comes from the mirror, and stray files stop riding along

## Changelog

Release notes are generated by release-please from the structured nested
`feat`/`fix` entries in release-bearing commits, with private summary lines and
forge links removed before anything is merged. Entries begin at the first
release cut after 2026-08-21.
