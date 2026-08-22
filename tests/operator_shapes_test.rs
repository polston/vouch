//! The operator-side knowledge shapes, and why a corpus measurement cannot see
//! them (#8, ROADMAP M2.144).
//!
//! `.cargo/config.toml` pins every test and every `examples/` measurement to
//! THIS repository's `knowledge.toml`. That is exactly right for
//! reproducibility, and it makes one class of question unaskable: the shipped
//! file uses none of the keys an operator's own file routinely uses, so a count
//! of a shape that depends on them comes back 0 out of 0 candidates. A zero out
//! of zero and a zero out of many are different findings, and only one of them
//! means "this does not happen".
//!
//! These tests pin both halves — that the shipped file really is blind, and
//! that the committed fixture really does exercise what it claims — so a later
//! measurement can be pointed at the fixture and believed.

mod common;

fn fixture() -> String {
    std::fs::read_to_string(common::repo_path("tests/fixtures/operator_knowledge.toml"))
        .expect("the operator fixture is committed")
}

/// The fact that makes the measurement blind. If this ever fails because the
/// shipped file gained a `subcommands` entry, that is good news and this test
/// is the place to find out — but the fixture's reason for existing changes,
/// and so does anything that cites this count.
#[test]
fn the_shipped_knowledge_uses_none_of_the_operator_side_recognition_keys() {
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
    assert!(
        scoped.is_empty(),
        "shipped entries now use `subcommands`, so measurements over the \
         shipped file are no longer structurally blind to verb scoping: {scoped:?}"
    );

    let widened = names_where(|p| p.all_subcommands);
    assert!(
        widened.is_empty(),
        "shipped entries now use `all_subcommands`: {widened:?}"
    );
}

/// And the fixture is not blind. Every key the test above proves absent from
/// the shipped file is present here, or the fixture is not doing its job.
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
