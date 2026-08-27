//! Operator-side knowledge shapes, and why one shipped verb-scoped entry does
//! not make a corpus measurement representative of an operator's vocabulary
//! (#8, ROADMAP M2.144).
//!
//! `.cargo/config.toml` pins every test and every `examples/` measurement to
//! THIS repository's `knowledge.toml`. That is exactly right for
//! reproducibility, but one deliberately scoped shipped CLI is not the varied
//! operator vocabulary a measurement is trying to model. Candidate counts are
//! still mandatory: one candidate and many are different findings.
//!
//! These tests pin both halves — that the shipped file really is blind, and
//! that the committed fixture really does exercise what it claims — so a later
//! measurement can be pointed at the fixture and believed.

mod common;

fn fixture() -> String {
    std::fs::read_to_string(common::repo_path("tests/fixtures/operator_knowledge.toml"))
        .expect("the operator fixture is committed")
}

/// The shipped set has one deliberate verb-scoped exception: vouch itself.
/// `all_subcommands` remains operator-only, and the fixture remains the broad,
/// invented vocabulary used to exercise both shapes.
#[test]
fn the_shipped_knowledge_scopes_only_vouch_and_never_uses_all_subcommands() {
    let kb = common::shipped_kb();
    let names_where = |pred: fn(&vouch::guards::Program) -> bool| -> Vec<&str> {
        kb.program
            .iter()
            .filter(|p| pred(p))
            .flat_map(|p| p.match_names.iter())
            .map(String::as_str)
            .collect()
    };

    let scoped = names_where(|p| p.subcommands.is_some());
    assert_eq!(scoped, ["vouch"], "unexpected shipped verb scopes: {scoped:?}");

    let widened = names_where(|p| p.all_subcommands);
    assert!(
        widened.is_empty(),
        "shipped entries now use `all_subcommands`: {widened:?}"
    );
}

/// The fixture carries both recognition shapes and keyed rules, rather than
/// treating vouch's one entry as representative operator evidence.
#[test]
fn the_operator_fixture_exercises_the_keys_the_shipped_file_never_does() {
    let kb = common::kb_with(&fixture());

    assert!(
        kb.program.iter().any(|p| p.subcommands.is_some()),
        "the fixture must carry a verb-scoped entry"
    );
    assert!(
        kb.program.iter().any(|p| p.all_subcommands),
        "the fixture must carry a whole-program entry"
    );
    assert!(
        kb.program
            .iter()
            .flat_map(|p| p.rule.iter())
            .any(|r| !r.subcommand_in.is_empty()),
        "the fixture must carry a rule keyed on a verb"
    );
    assert!(
        kb.program
            .iter()
            .flat_map(|p| p.rule.iter())
            .any(|r| !r.sub_arg_0_in.is_empty()),
        "the fixture must carry a rule keyed on a verb's second word"
    );
}

/// A verb-scoped entry recognises the verbs it names and nothing else — §2,
/// "recognition is per COMMAND, not per program name". Unexercisable against
/// the shipped file, which is the whole point.
#[test]
fn a_verb_scoped_entry_covers_only_the_verbs_it_names() {
    let kb = common::kb_with(&fixture());

    for verb in ["status", "list"] {
        assert!(
            vouch::guards::recognises(&kb, &common::cmd("gadget", &[verb]), "bash", true),
            "`gadget {verb}` is named by the entry"
        );
    }
    assert!(
        !vouch::guards::recognises(&kb, &common::cmd("gadget", &["destroy"]), "bash", true),
        "a verb the entry does not name must stay unrecognised — §1, \
         \"unknown subcommand of a known program → ask. Not allow.\""
    );

    // The whole-program entry beside it is the contrast: every verb covered.
    for verb in ["approve", "anything-at-all"] {
        assert!(
            vouch::guards::recognises(&kb, &common::cmd("widget", &[verb]), "bash", true),
            "`all_subcommands` covers `widget {verb}`"
        );
    }
}

/// The fixture holds no real program name — asserted as a SET, so adding one
/// fails. An earlier version looped over the three known-good names checking
/// each was present and unshipped, which is a different claim: pasting a real
/// entry in beside them changed none of its assertions while `CLAUDE.md` said
/// this test enforced the invented half. A test that cannot fail for the
/// reason it is named is worse than no test, because the doc then rests on it.
#[test]
fn the_operator_fixture_names_only_invented_programs() {
    // `common::kb_with` is the wrong helper here — it MERGES the fixture over
    // the shipped knowledge, so it would return every shipped name too.
    // `guards::load` on the fixture text alone is the right call, and is
    // exactly what `kb_with` uses internally.
    let kb = vouch::guards::load(&fixture()).expect("the fixture's knowledge parses");
    let named: std::collections::BTreeSet<String> = kb
        .program
        .iter()
        .flat_map(|p| p.match_names.iter().cloned())
        .collect();

    let invented: std::collections::BTreeSet<String> =
        ["gadget", "sprocket", "widget"].iter().map(|s| s.to_string()).collect();
    assert_eq!(
        named, invented,
        "the fixture must name these and ONLY these invented programs — a name \
         that is not one of them is either a real program or a copy from a real \
         my-knowledge, and both are the leak this file's header forbids"
    );

    // And none of them may collide with something vouch actually ships.
    let shipped = common::shipped_kb();
    for n in &named {
        assert!(
            !shipped.program.iter().any(|p| p.match_names.iter().any(|m| m == n)),
            "`{n}` is a real shipped program name; the fixture must stay invented"
        );
    }
}
