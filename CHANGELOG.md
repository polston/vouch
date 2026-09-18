# Changelog

## 0.41.0 (2026-09-18)


### Features

* detect unified diff added environment dumps in pre-push hook
* evaluate mode-conditioned writes by reference as unresolved invocations
* exempt literal None in higher-order callback argument positions
* format unresolved python variable targets with unresolved marker token
* replace phantom reconcile skill with inline remediation in config diagnostics

## 0.40.0 (2026-09-18)


### Features

* guard vocabulary is declared in knowledge schema version 17 with prompt effect descriptions
* in-snippet PowerShell environment variable assignments evaluate against rebound name lookup checks
* mechanical lint test and path helper prevent un-drive-qualified test fixture paths
* slash-shaped flags support colon-attached values and runas is modeled as a rest wrapper


### Bug Fixes

* git hook scanner excludes consecutive assignments containing command substitutions from dump backstops

## 0.39.0 (2026-09-18)


### Features

* enumerate command substitution positions via canonical AST visitors shared between the shell parser and measurement harnesses
* introduce unified restriction, grant, and ranked reduction combinators on candidate base sets
* support subcommand-specific option definitions and output destination derivation in knowledge schemas
* unify wrapper expansion state into structured occurrence records with consolidated source provenance


### Bug Fixes

* skip parameter expansions as units and enforce arithmetic context for heredoc operators in substitution parsing

## 0.38.0 (2026-09-18)


### Features

* deduplicate wrapped snippet AST scans across decision evaluations
* distinguish literal single-quoted tokens from expandable arguments in PowerShell
* report trigger-specific diagnostic details for scanner constructs
* support bash 5.3 non-forking value substitutions in same-process scopes


### Bug Fixes

* cap nested subshell recursion depth to prevent stack exhaustion

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
