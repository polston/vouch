mod common;
use vouch::engine::decide_command_at;
use vouch::guards::SecondWord;
use vouch::protocol::Decision;

/// A second verb word vouch read successfully — `SecondWord::Word("add")`.
fn word(w: &str) -> SecondWord {
    SecondWord::Word(w.to_string())
}

fn cfg_with(toml: &str) -> vouch::config::Config {
    vouch::config::load(toml).unwrap()
}

/// The same config with `lang.bash.default = "allow"` in front of it.
///
/// The tests above judge a PATH (`decide_file`), where no language is
/// involved. The write-scope tests below judge a COMMAND, and a command that
/// raises no objection is answered by `lang.bash.default` — unset, that is
/// "ask", so every one of them would read as an ask that the write rules had
/// no part in. Setting it allow is what makes the verdict the write rules'
/// own answer, and it is what `tests/place_guard_override_test.rs` does for
/// the same reason.
fn cmd_cfg(toml: &str) -> vouch::config::Config {
    cfg_with(&format!("[lang.bash]\ndefault = \"allow\"\n{toml}"))
}

#[test]
fn a_case_variant_write_matches_the_allow_rule_on_windows() {
    // NTFS is case-preserving but case-insensitive: C:/Users/dev/work and
    // C:/Users/dev/Work are one tree. A grant missed by case costs an ask
    // (safe but wrong); a restriction missed by case fails silent — the
    // protected pin below is the one with teeth.
    let cfg = cfg_with("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/Users/dev/work/**\"]");
    let d = vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/Work/x.txt");
    if cfg!(any(windows, target_os = "macos")) {
        assert!(matches!(d, Decision::Allow(_)), "{d:?}");
    } else {
        assert!(matches!(d, Decision::Ask(_)), "linux is exact: {d:?}");
    }
}

#[test]
fn a_case_variant_protected_path_still_hits_the_protected_rule_on_windows() {
    let cfg = cfg_with("[protected]\npaths = [\"C:/Users/dev/.claude/settings.json\"]\n[write]\ndefault = \"allow\"");
    let d = vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/.Claude/Settings.json");
    if cfg!(any(windows, target_os = "macos")) {
        match d {
            // write.default is allow, so reaching Ask at all proves the
            // protected loop fired; the reason pin proves it fired for the
            // right cause (review: with default = ask this test passed
            // before the fix, through the wrong path).
            Decision::Ask(r) => assert!(r.contains("protected"), "{r}"),
            other => panic!("case variant must hit the protected rule: {other:?}"),
        }
    }
}

#[test]
fn the_ask_wall_beats_an_allow_rule_and_never_offers_allow_paths() {
    let cfg = cfg_with("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/Users/dev/**\"]\nask_paths = [\"C:/Users/dev/notes/**\"]");
    match vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/notes/a.txt") {
        Decision::Ask(r) => {
            assert!(r.contains("write.ask_paths") && r.contains("C:/Users/dev/notes/**"), "{r}");
            assert!(r.contains("no allow rule is consulted"), "{r}");
            assert!(!r.contains("add to write.allow_paths"), "the fallback suggestion does not work here (M2.12 class): {r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_deny_wall_denies_with_the_reason_carried() {
    let cfg = cfg_with("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/Users/dev/**\"]\ndeny_paths = [\"C:/Users/dev/photos/**\"]");
    match vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/photos/a.txt") {
        Decision::Deny(r) => assert!(r.contains("write.deny_paths") && r.contains("C:/Users/dev/photos/**"), "{r}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn deny_wins_when_both_walls_cover_the_same_tree() {
    // Precedence pair from the spec's Testing list: deny vs ask lists.
    // (Only the three OPPOSING pairs `validate` checks — allow vs ask, allow
    // vs deny, trust vs distrust — refuse identical patterns at load.
    // ask_paths and deny_paths are not one of them: identical or nested
    // patterns in the two are legal, and deny wins by being checked first —
    // an ask_paths line entirely inside a deny_paths glob is doctor's
    // overlap bucket (Task 11), not a load-time refusal.)
    let cfg = cfg_with("[write]\ndefault = \"allow\"\nask_paths = [\"C:/Users/dev/photos/**\"]\ndeny_paths = [\"C:/Users/dev/photos/raw/**\"]");
    let d = vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/photos/raw/a.cr2");
    assert!(matches!(d, Decision::Deny(_)), "{d:?}");
}

#[test]
fn a_case_variant_write_is_caught_by_the_wall_on_windows() {
    // Moved here from Task 3 at review: the wall must exist before this
    // can run. On Linux the case variant is a different tree — it falls
    // through to allow_paths.
    let cfg = cfg_with("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/Users/dev/**\"]\nask_paths = [\"C:/Users/dev/photos/**\"]");
    let d = vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/Photos/x.txt");
    if cfg!(any(windows, target_os = "macos")) {
        assert!(matches!(d, Decision::Ask(_)), "case variant must hit the wall: {d:?}");
    } else {
        assert!(matches!(d, Decision::Allow(_)), "{d:?}");
    }
}

#[cfg(windows)]
fn make_symlink(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
fn make_symlink(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[test]
fn a_symlink_into_the_wall_is_caught_by_its_real_path() {
    // <tmp>/real/ sits under a walled glob; <tmp>/alias -> <tmp>/real. Asking
    // about <tmp>/alias/f.txt must hit the wall via the REAL form (decide_file
    // resolves textual vs real before either wall or allow_paths is checked).
    let dir = std::env::temp_dir().join(format!("vouch-write-wall-symlink-{}", std::process::id()));
    let real_dir = dir.join("real");
    let alias_dir = dir.join("alias");
    std::fs::create_dir_all(&real_dir).unwrap();
    std::fs::write(real_dir.join("f.txt"), "x").unwrap();

    if make_symlink(&real_dir, &alias_dir).is_err() {
        // Windows non-admin cannot create symlinks — skip silently.
        std::fs::remove_dir_all(&dir).ok();
        return;
    }

    // The glob is built from the RESOLVED spelling of the real directory,
    // which is what an operator writes — not from whatever spelling
    // temp_dir() happens to return. On the Windows CI runner that spelling
    // is an 8.3 short name (RUNNER~1), so an unresolved glob can never match
    // the long form the engine resolves the alias to, and the assertion
    // failed there on this test's first-ever run with symlink privileges —
    // local non-admin Windows had always taken the skip path above.
    let real_glob = format!(
        "{}/**",
        vouch::paths::resolve_links(&real_dir.to_string_lossy().replace('\\', "/"))
    );
    let cfg = cfg_with(&format!("[write]\ndefault = \"allow\"\nask_paths = [\"{real_glob}\"]"));
    let target = alias_dir.join("f.txt").to_string_lossy().replace('\\', "/");
    let d = vouch::engine::decide_file(&cfg, "C:/Users/dev", None, &target);
    assert!(matches!(d, Decision::Ask(_)), "must catch the symlink via its real path: {d:?}");

    std::fs::remove_dir_all(&dir).ok();
}

// --- per-program write scope (spec 2026-08-06 §Per-program write scope,
// §Precedence step 4) ----------------------------------------------------
//
// A `[[write.scope]]` rule judges the writes its program DECLARES — the
// destinations the knowledge file says the program writes to — and judges
// them alone: inside its `only_under` trees allow, anywhere else ask, with
// `write.allow_paths` never consulted for that program. A redirect beside the
// program belongs to the shell, and a file tool has no program at all, so
// both keep the ordinary walk.

#[test]
fn a_scoped_program_writes_inside_its_trees_even_off_the_allow_list() {
    let cfg = cmd_cfg("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init C:/scratch/newrepo", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn a_scoped_program_outside_its_trees_asks_naming_the_scope() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init C:/work/newrepo", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("write.scope") && r.contains("git init") && r.contains("C:/scratch/**"), "{r}");
            assert!(!r.contains("add to write.allow_paths"), "{r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_scoped_programs_unprovable_target_asks_naming_the_scope_and_the_attempt() {
    // Spec prompt table row "write scope, target unprovable": the ask names
    // the scope rule and what resolution was attempted — NOT the generic
    // unresolved_path text.
    // The or-fallback shape now RESOLVES to concrete candidates (design
    // 2026-08-30 §4.3) and gets the concrete outside-scope ask, so the
    // unprovable-row fixture is a destination genuinely nobody can read: a
    // variable the line never assigns.
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "cd \"$SOMEWHERE\"; git init newrepo", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("write.scope"), "{r}");
            // "what resolution was attempted" is the walk's own cause, kept
            // from the generic text — the M2.58 standard: saying a place is
            // unprovable without saying what made it unprovable leaves the
            // operator no move to make.
            assert!(
                r.contains("somewhere vouch cannot resolve"),
                "the cause, not just the fact: {r}"
            );
            // §5: the setting named must be one that actually turns this
            // prompt off. `unresolved_path` does not — the scope holds it
            // open — so naming it would be the M2.12 defect class.
            assert!(!r.contains("constructs.unresolved_path"), "names an off-switch that does not work: {r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_scoped_programs_variable_destination_asks_naming_the_scope() {
    // The other unprovable shape: the destination survived every expansion
    // still holding a variable, so vouch cannot say where it lands. Same
    // answer as the unplaceable one — a scope restricts, so it applies until
    // the destination is proven inside its trees, and `write.default =
    // "allow"` (which is what that arm reads) must not open it.
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init \"$TARGET/newrepo\"", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("write.scope"), "{r}");
            assert!(r.contains("$TARGET"), "the ask must say what it could not resolve: {r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unscoped_verb_of_the_same_program_is_untouched() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git status", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn a_redirect_beside_a_scoped_program_is_judged_by_the_normal_rules_not_the_scope() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init C:/scratch/r > C:/work/log.txt", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn the_deny_wall_beats_a_write_scope() {
    // Precedence: deny (step 2) is checked before scope (step 4).
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\ndeny_paths = [\"C:/scratch/**\"]\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init C:/scratch/newrepo", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Deny(_)), "{d:?}");
}

#[test]
fn a_scoped_unprovable_write_denied_by_a_setting_names_that_setting_not_the_scope() {
    // The scope's own answer for an unprovable destination is ask. When the
    // operator's `unresolved_path` is STRICTER than that, the setting is what
    // decided, and the prompt must say so: "take the program out of
    // [[write.scope]]" would not lift a refusal the scope did not make (§5,
    // the M2.12 defect class).
    // Same unprovable-row fixture swap as above (design 2026-08-30 §4.3):
    // the or-fallback now resolves concretely, so an unassigned variable is
    // what genuinely cannot be read.
    let cfg = cmd_cfg("[lang.bash.constructs]\nunresolved_path = \"deny\"\n[write]\ndefault = \"allow\"\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "cd \"$SOMEWHERE\"; git init newrepo", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Deny(r) => {
            assert!(r.contains("lang.bash.constructs.unresolved_path"), "the decider is unnamed: {r}");
            assert!(r.contains("write.scope"), "the scope context is still why this matters: {r}");
            assert!(
                !r.contains("take the program out of [[write.scope]]"),
                "offers a remedy that would not lift the refusal: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_scoped_variable_write_denied_by_write_default_names_write_default() {
    // The same rule in the other unprovable arm, where the setting that
    // decides when no construct is named is `write.default` — a different key,
    // so naming the construct here would name one the operator never set.
    let cfg = cmd_cfg("[write]\ndefault = \"deny\"\n[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git init \"$TARGET/newrepo\"", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Deny(r) => {
            assert!(r.contains("write.default"), "the decider is unnamed: {r}");
            assert!(r.contains("write.scope"), "the scope context is still why this matters: {r}");
            assert!(
                !r.contains("take the program out of [[write.scope]]"),
                "offers a remedy that would not lift the refusal: {r}"
            );
        }
        other => panic!("{other:?}"),
    }
}

// --- the write rules answer for themselves, whatever `write.default` says ---
//
// A write the command performs takes the action the write rules RETURNED. The
// two tests below are the non-scope half of that: without them, a refactor
// reinstating the old `let a = cfg.write.default` would pass the whole suite
// while silently downgrading both walls to an allow.

#[test]
fn a_command_write_into_the_deny_wall_refuses_even_when_write_default_is_allow() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\ndeny_paths = [\"C:/work/secret/**\"]");
    let d = decide_command_at(&cfg, "bash", "echo hi > C:/work/secret/a.txt", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Deny(r) => assert!(r.contains("write.deny_paths"), "{r}"),
        other => panic!("the wall's deny must survive write.default = allow: {other:?}"),
    }
}

#[test]
fn a_command_write_into_the_ask_wall_asks_even_when_write_default_is_allow() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\nask_paths = [\"C:/work/notes/**\"]");
    let d = decide_command_at(&cfg, "bash", "echo hi > C:/work/notes/a.txt", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => assert!(r.contains("write.ask_paths"), "{r}"),
        other => panic!("the wall's ask must survive write.default = allow: {other:?}"),
    }
}

// Same shape, for `[protected]` rather than the two walls above (final
// whole-branch review of the place-scoped-rules changeset, finding 4): a
// command write into a protected file is decided by the protected check
// inside `decide_file_for`, whichever way `write.default` is set — before
// this loop started reading the write rules' own returned action, a command
// write to a protected file was re-cast to `write.default`, so
// `write.default = "allow"` waved it through and `write.default = "deny"`
// answered Deny rather than the Ask the file-tool path (`Write`/`Edit`) has
// always given the same file under the same config. Neither direction had a
// pin naming `write.default`.

#[test]
fn a_command_write_into_a_protected_file_asks_even_when_write_default_is_deny() {
    let cfg = cmd_cfg("[protected]\npaths = [\"C:/Users/dev/.claude/settings.json\"]\n[write]\ndefault = \"deny\"");
    let d = decide_command_at(&cfg, "bash", "echo hi > C:/Users/dev/.claude/settings.json", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => assert!(r.contains("protected"), "{r}"),
        other => panic!("a protected file must ask, not take write.default's deny: {other:?}"),
    }
}

#[test]
fn a_command_write_into_a_protected_file_asks_even_when_write_default_is_allow() {
    let cfg = cmd_cfg("[protected]\npaths = [\"C:/Users/dev/.claude/settings.json\"]\n[write]\ndefault = \"allow\"");
    let d = decide_command_at(&cfg, "bash", "echo hi > C:/Users/dev/.claude/settings.json", Some("C:/Users/dev"), None, Some("C:/work"));
    match d {
        Decision::Ask(r) => assert!(r.contains("protected"), "{r}"),
        other => panic!("a protected file must ask, not be waved through by write.default = allow: {other:?}"),
    }
}

#[test]
fn two_scope_entries_naming_the_same_program_refuse() {
    // Only the first entry would ever judge `git init` — the walk takes the
    // first rule that names a command — so the second is silently inert and
    // swapping the two in the file changes the verdict. Refused with the same
    // remedy two my-knowledge entries for one name get: one entry carrying
    // both trees.
    let cfg = cfg_with(
        "[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/work/**\"]",
    );
    let e = vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap_err();
    assert!(e.contains("git init"), "the error does not name the program: {e}");
    assert!(e.contains("ONE entry"), "the error does not give the one-entry remedy: {e}");
}

#[test]
fn a_case_varied_duplicate_scope_entry_still_refuses() {
    // Program names fold case everywhere else they are compared, so a
    // case-varied spelling must not slip past the duplicate refusal — the
    // M2.26 bug class, pinned the same way `place_config_test.rs` pins it for
    // my-knowledge entries.
    let cfg = cfg_with(
        "[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"Git INIT\"]\nonly_under = [\"C:/work/**\"]",
    );
    let e = vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap_err();
    assert!(e.contains("ONE entry"), "{e}");
}

#[test]
fn a_wider_entry_beside_a_verb_entry_is_not_refused() {
    // The boundary of the refusal above. `git` and `git init` are not the same
    // rule: the wider one still judges every other verb, so it is inert only
    // for the verb they share. That is precedence making a rule PARTLY inert —
    // spec §Overlaps tier 2, doctor's bucket — not a config saying two things
    // about one subject, and refusing it would refuse "git under A, init under
    // B" outright.
    let cfg = cfg_with(
        "[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"git\"]\nonly_under = [\"C:/work/**\"]",
    );
    vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap();
}

// --- a verb of two words (`git worktree add`) ------------------------------
//
// The knowledge file models git's worktree destination as `subcommand =
// "worktree", then = "add"`, because that IS git's verb. A scope entry has to
// be able to say the same thing, or the case M2.13 was written for —
// repository creation only under a scratch tree — cannot be written down at
// all: the spec's own config-surface example is `["git init", "git clone",
// "git worktree add"]`.

#[test]
fn the_specs_own_three_entry_example_loads() {
    // Copied character for character out of the spec's §Config surface block.
    // It refused at load until this fix, so an operator copying the documented
    // example lost their whole config.
    let cfg = cfg_with(
        "[[write.scope]]\nprograms = [\"git init\", \"git clone\", \"git worktree add\"]\n\
         only_under = [\"C:/scratch/**\"]",
    );
    vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap();
}

#[test]
fn a_two_word_verb_writes_inside_its_trees_and_asks_outside_them() {
    let cfg = cmd_cfg(
        "[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/scratch/**\"]",
    );
    let inside = decide_command_at(&cfg, "bash", "git worktree add C:/scratch/wt", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(inside, Decision::Allow(_)), "inside the scope's trees: {inside:?}");

    let outside = decide_command_at(&cfg, "bash", "git worktree add C:/work/wt", Some("C:/Users/dev"), None, Some("C:/work"));
    match outside {
        Decision::Ask(r) => {
            assert!(r.contains("write.scope") && r.contains("git worktree add"), "{r}");
            assert!(r.contains("C:/scratch/**"), "{r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_two_word_verb_entry_does_not_govern_the_programs_other_operations() {
    // `git worktree list` is a different operation and the entry must not
    // claim it. Pinned twice: on the matching rule itself, which answers even
    // for an operation that writes nothing, and on the verdict.
    let cfg = cmd_cfg(
        "[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/scratch/**\"]",
    );
    let rule = &cfg.write.scope[0];
    assert!(rule.names("git", Some("worktree"), &word("add")), "must claim its own operation");
    assert!(!rule.names("git", Some("worktree"), &word("list")), "must not claim another verb pair");
    assert!(!rule.names("git", Some("init"), &SecondWord::Absent), "must not claim another verb");

    let d = decide_command_at(&cfg, "bash", "git worktree list", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn a_two_word_verb_entry_reports_a_command_whose_second_word_is_unprovable() {
    // The hole this pins: an unread word can neither select a scope grant nor
    // prove that no scope applies. With "could not read" and "there is none"
    // collapsed, one undescribed flag walked a scoped command out of its own
    // scope — and with `unresolved_path` set to allow, out of any prompt at
    // all.
    //
    // The two-token entry `["git worktree"]` always asked here, because it
    // states no second word to be defeated by. The three-token entry must not
    // be the weaker rule.
    let cfg = cmd_cfg(
        "[lang.bash.constructs]\nunresolved_path = \"allow\"\n[write]\ndefault = \"allow\"\n\
         allow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/scratch/**\"]",
    );
    let d = decide_command_at(
        &cfg,
        "bash",
        "git worktree --undescribedflag add C:/work/wt",
        Some("C:/Users/dev"),
        None,
        Some("C:/work"),
    );
    match d {
        Decision::Ask(r) => {
            assert!(r.contains("write.scope"), "{r}");
            // The token that made it unreadable, so the operator has a move.
            assert!(r.contains("--undescribedflag"), "the ask does not name the cause: {r}");
        }
        other => panic!("a scope must survive a word vouch cannot read: {other:?}"),
    }

    // And on the matching rule itself, where the three answers are visible.
    let rule = &cfg.write.scope[0];
    assert!(matches!(
        rule.match_command(
            "git",
            &vouch::guards::VerbWord::Word("worktree".into()),
            &SecondWord::Unknown("--x".into()),
        ),
        vouch::config::ScopeMatch::Unprovable(_)
    ));
    assert!(rule.names("git", Some("worktree"), &word("add")));
    assert!(!rule.names("git", Some("worktree"), &word("list")));
    assert!(!rule.names("git", Some("worktree"), &SecondWord::Absent));
}

#[test]
fn an_unread_scope_word_cannot_select_one_of_two_scope_grants_by_file_order() {
    let cfg = cmd_cfg(
        "[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"unzip archive.zip x\"]\nonly_under = [\"C:/work/x/**\"]\n\
         [[write.scope]]\nprograms = [\"unzip archive.zip y\"]\nonly_under = [\"C:/work/y/**\"]",
    );
    vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap();

    let d = decide_command_at(
        &cfg,
        "bash",
        "unzip archive.zip --zzz y -d C:/work/x/out",
        Some("C:/Users/dev"),
        None,
        Some("C:/work"),
    );
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("write scope"), "{reason}");
            assert!(reason.contains("--zzz"), "{reason}");
        }
        other => panic!("an unread scope word must not borrow the first grant: {other:?}"),
    }

    let first = &cfg.write.scope[0];
    assert!(matches!(
        first.match_command(
            "unzip",
            &vouch::guards::VerbWord::Word("archive.zip".into()),
            &SecondWord::Unknown("--zzz".into()),
        ),
        vouch::config::ScopeMatch::Unprovable(_)
    ));
}

#[test]
fn an_unread_narrow_scope_cannot_borrow_a_later_program_wide_grant() {
    let cfg = cmd_cfg(
        "[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"truncate C:/work/out\"]\nonly_under = [\"C:/scratch/**\"]\n\
         [[write.scope]]\nprograms = [\"truncate\"]\nonly_under = [\"C:/work/**\"]",
    );
    vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap();

    let d = decide_command_at(
        &cfg,
        "bash",
        "truncate \"C:/work/out\"",
        Some("C:/Users/dev"),
        None,
        Some("C:/work"),
    );
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("write scope"), "{reason}");
            assert!(reason.contains("C:/work/out"), "{reason}");
        }
        other => panic!("an unread narrow scope must stop before the wider grant: {other:?}"),
    }
}

#[test]
fn a_two_word_verb_entry_does_not_claim_a_command_that_has_no_second_word() {
    // Absent is not the same answer as unreadable, and it decides the other
    // way: nothing followed the verb, so vouch KNOWS this is not the `add`
    // operation and a `git worktree add` entry has nothing to say about it.
    // (Bare `git worktree` writes nothing either, so there is no destination
    // for any rule to judge — the rule-level assertion is what carries this.)
    let cfg = cmd_cfg(
        "[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]\n\
         [[write.scope]]\nprograms = [\"git worktree add\"]\nonly_under = [\"C:/scratch/**\"]",
    );
    assert!(!cfg.write.scope[0].names("git", Some("worktree"), &SecondWord::Absent));
    let d = decide_command_at(&cfg, "bash", "git worktree", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "{d:?}");
}

#[test]
fn a_one_word_verb_entry_still_covers_every_operation_under_it() {
    // The wider spelling is unchanged: `git worktree` covers add, list and
    // everything else — that is what makes it the wider rule, and why doctor
    // reports it shadowing a `git worktree add` entry placed after it.
    let cfg = cfg_with("[[write.scope]]\nprograms = [\"git worktree\"]\nonly_under = [\"C:/scratch/**\"]");
    let rule = &cfg.write.scope[0];
    assert!(rule.names("git", Some("worktree"), &word("add")));
    assert!(rule.names("git", Some("worktree"), &word("list")));
    assert!(rule.names("git", Some("worktree"), &SecondWord::Absent));
    assert!(rule.names("git", Some("worktree"), &SecondWord::Unknown("--x".into())));
    assert!(!rule.names("git", Some("init"), &SecondWord::Absent));
}

#[test]
fn a_four_token_scope_entry_refuses() {
    // The verb the knowledge file can express is at most two words, so a
    // fourth could never match and would sit in the config looking like a rule.
    let cfg = cfg_with("[[write.scope]]\nprograms = [\"git worktree add extra\"]\nonly_under = [\"C:/scratch/**\"]");
    let e = vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap_err();
    assert!(e.contains("git worktree add extra"), "{e}");
    assert!(e.contains("second word"), "the error does not say what an entry may be: {e}");
}

#[test]
fn a_three_token_scope_entry_for_an_undescribed_program_refuses() {
    // Same rule as the two-token case: locating a verb at all needs the
    // program's argument grammar, and a second word is located after the first.
    let cfg = cfg_with("[[write.scope]]\nprograms = [\"probe-tool worktree add\"]\nonly_under = [\"C:/scratch/**\"]");
    let e = vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap_err();
    assert!(e.contains("probe-tool"), "{e}");
}

#[test]
fn a_two_token_scope_entry_for_an_undescribed_program_refuses() {
    // validate_scopes(cfg, kb): "probe-tool init" with no entry describing
    // probe-tool's grammar -> Err naming probe-tool (vouch cannot locate
    // the verb of an undescribed program).
    let cfg = cfg_with("[[write.scope]]\nprograms = [\"probe-tool init\"]\nonly_under = [\"C:/scratch/**\"]");
    let kb = vouch::guards::in_effect();
    let e = vouch::config::validate_scopes(&cfg, kb).unwrap_err();
    assert!(e.contains("probe-tool"), "{e}");
}

#[test]
fn a_two_token_scope_entry_for_a_described_program_is_accepted() {
    // The other side of the refusal above: `git` declares `value_options`, so
    // vouch can locate the verb and the entry stands. Without this, the
    // refusal could be "every two-token entry" and the test above would not
    // notice.
    let cfg = cfg_with("[[write.scope]]\nprograms = [\"git init\"]\nonly_under = [\"C:/scratch/**\"]");
    vouch::config::validate_scopes(&cfg, vouch::guards::in_effect()).unwrap();
}

#[test]
fn validate_scopes_is_wired_into_the_config_load() {
    // The test above calls `validate_scopes` directly; this one proves the
    // refusal reaches an operator running vouch for real. A refused config
    // decides as no-config — everything asks — and the banner names the
    // offending entry (spec §Validation and version skew).
    let dir = std::env::temp_dir().join(format!("vouch-scope-wiring-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        "[lang.bash]\ndefault = \"allow\"\n[[write.scope]]\nprograms = [\"probe-tool init\"]\nonly_under = [\"C:/scratch/**\"]\n",
    )
    .unwrap();

    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_vouch"));
    cmd.env("VOUCH_STATE_DIR", dir.join("state"));
    cmd.env("VOUCH_CONFIG", &path);
    cmd.env("HOME", &dir).env("USERPROFILE", &dir);
    cmd.arg("--hook");
    let snippet = r#"{"hook_event_name":"PreToolUse","tool_use_id":"t","session_id":"s","cwd":"C:/claude","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(snippet.as_bytes()).unwrap();
    }
    let out = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).to_string();
    assert!(out.contains("\"permissionDecision\":\"ask\""), "a refused config must decide as no-config: {out}");
    assert!(out.contains("probe-tool"), "the banner must name the offending entry: {out}");
    std::fs::remove_dir_all(&dir).ok();
}

// --- bare `git clone <url>` derives its destination (M2.35) ---------------

#[test]
fn a_bare_clone_derives_the_url_basename_destination() {
    let cfg = cmd_cfg("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]");
    let d = decide_command_at(&cfg, "bash", "git clone https://example.test/thing.git", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Allow(_)), "C:/work/thing is inside allow_paths: {d:?}");
    let outside = decide_command_at(&cfg, "bash", "git clone https://example.test/thing.git", Some("C:/Users/dev"), None, Some("C:/elsewhere"));
    match &outside {
        // The DERIVED name, not the identity function, must be what the ask
        // is about — an identity `url_basename` (return the spec unchanged)
        // would still pass a bare `matches!(.., Decision::Ask(_))`, so the
        // reason has to be checked: it must name the derived leaf ("thing")
        // and must NOT carry the URL's own scheme, which only an identity
        // derivation (or a raw string never parsed at all) would leak.
        Decision::Ask(r) => {
            assert!(r.contains("/thing"), "the derived name must appear in the ask: {r}");
            assert!(!r.contains("https://"), "the full URL leaked instead of a derived name: {r}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_flagship_scope_case_fires_on_the_bare_clone_spelling() {
    let cfg = cmd_cfg("[write]\ndefault = \"allow\"\nallow_paths = [\"C:/work/**\"]\n[[write.scope]]\nprograms = [\"git clone\"]\nonly_under = [\"C:/scratch/**\"]");
    let d = decide_command_at(&cfg, "bash", "git clone https://example.test/thing.git", Some("C:/Users/dev"), None, Some("C:/work"));
    assert!(matches!(d, Decision::Ask(_)), "the scope must see the derived destination: {d:?}");
}

#[test]
fn an_explicit_clone_destination_still_wins_over_derivation() {
    let cfg = cmd_cfg("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]");
    let d = decide_command_at(&cfg, "bash", "git clone https://example.test/thing.git C:/work/mydir", Some("C:/Users/dev"), None, Some("C:/elsewhere"));
    assert!(matches!(d, Decision::Allow(_)), "two positionals -> the existing min_positional=2 rule alone: {d:?}");
}

#[test]
fn a_url_ending_in_a_bare_dotgit_segment_falls_back_to_the_segment_before_it() {
    // `https://example.test/repo/.git` strips its LAST segment (".git") to
    // empty — real git does not create a directory called nothing, it backs
    // up and uses "repo" (verified against git itself at review). Before the
    // fix this fell all the way through to Allow: an empty derived name is
    // no destination at all, which is the ALLOW this changeset exists to
    // remove, not a safe abstention.
    let cfg = cmd_cfg("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]");
    let d = decide_command_at(&cfg, "bash", "git clone https://example.test/repo/.git", Some("C:/Users/dev"), None, Some("C:/elsewhere"));
    match d {
        Decision::Ask(r) => assert!(r.contains("/repo") && !r.contains(".git"), "{r}"),
        other => panic!("a bare-dotgit URL must still derive a destination, not fall open: {other:?}"),
    }
}

#[test]
fn bare_and_mirror_clones_derive_the_dot_git_suffixed_directory() {
    // `git clone --bare <url>` / `--mirror` create `<name>.git`, not `<name>`
    // — only when git itself derives the name (an explicit destination
    // argument is used verbatim either way, so this is scoped to the
    // one-positional form). The parent directory is identical, so an
    // allow/ask verdict never turns on this, but the printed name and the
    // "add to write.allow_paths" remedy must name the real directory.
    let cfg = cmd_cfg("[write]\ndefault = \"ask\"\nallow_paths = [\"C:/work/**\"]");
    for flag in ["--bare", "--mirror"] {
        let cmd = format!("git clone {flag} https://example.test/thing.git");
        let d = decide_command_at(&cfg, "bash", &cmd, Some("C:/Users/dev"), None, Some("C:/elsewhere"));
        match d {
            Decision::Ask(r) => assert!(r.contains("thing.git"), "{flag}: {r}"),
            other => panic!("{flag}: {other:?}"),
        }
    }
}

#[test]
fn protected_still_beats_the_deny_wall() {
    let cfg = cfg_with("[protected]\npaths = [\"C:/Users/dev/.claude/settings.json\"]\n[write]\ndefault = \"allow\"\ndeny_paths = [\"C:/Users/dev/.claude/**\"]");
    match vouch::engine::decide_file(&cfg, "C:/Users/dev", None, "C:/Users/dev/.claude/settings.json") {
        Decision::Ask(r) => assert!(r.contains("protected"), "protected is first and asks: {r}"),
        other => panic!("{other:?}"),
    }
}
