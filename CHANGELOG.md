# Changelog

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
