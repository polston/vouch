//! A tool can be described AND still ask.

use vouch::config::Action;
use vouch::guards::{load, tool_entry};

#[test]
fn a_tool_entry_with_no_action_is_allowed() {
    let kb = load("[[tool]]\nmatch = [\"Reader\"]\nsource = \"reads only\"\n").expect("parses");
    assert_eq!(tool_entry(&kb, "Reader").expect("described").action.unwrap_or(Action::Allow), Action::Allow);
}

#[test]
fn a_tool_entry_can_ask() {
    let kb = load("[[tool]]\nmatch = [\"Remover\"]\nsource = \"removes a directory\"\naction = \"ask\"\n").expect("parses");
    assert_eq!(tool_entry(&kb, "Remover").unwrap().action, Some(Action::Ask));
}

#[test]
fn a_tool_entry_can_deny() {
    let kb = load("[[tool]]\nmatch = [\"Nope\"]\nsource = \"never\"\naction = \"deny\"\n").expect("parses");
    assert_eq!(tool_entry(&kb, "Nope").unwrap().action, Some(Action::Deny));
}

#[test]
fn a_misspelt_key_is_an_error_not_an_allow() {
    // [review] `actoin = "ask"` used to parse fine and yield allow. The
    // operator writes "ask", reads "ask" in their file, and gets allow.
    for bad in [
        "[[tool]]\nmatch = [\"T\"]\nsource = \"s\"\nactoin = \"ask\"\n",
        "[[program]]\nmatch = [\"p\"]\nsubcommmands = [\"get\"]\n",
        "[[program]]\nmatch = [\"p\"]\n[[program.rule]]\nguard = \"g\"\nsouce = \"s\"\n",
    ] {
        assert!(load(bad).is_err(), "a misspelt key parsed silently: {bad}");
    }
}

#[test]
fn my_entry_for_one_name_does_not_take_out_the_others_beside_it() {
    let base = load("[[tool]]\nmatch = [\"Alpha\", \"Beta\"]\nsource = \"both read\"\n").expect("parses");
    let mine = load("[[tool]]\nmatch = [\"Beta\"]\nsource = \"mine\"\naction = \"ask\"\n").expect("parses");
    let merged = vouch::knowledge::merge(base, mine);
    assert_eq!(tool_entry(&merged, "Beta").unwrap().action, Some(Action::Ask), "mine did not win");
    assert!(tool_entry(&merged, "Alpha").unwrap().action.is_none(), "the neighbouring name changed too");
}

// --- what SILENCE in the operator's file means, for a tool ------------------
//
// [review] CRITICAL. The tests above all have the operator SETTING something.
// The hole was the operator writing an entry that sets nothing: tool entries
// were appended and `tool_entry` takes the last match WHOLE, so an unset
// `action` replaced a shipped `action = "ask"` — and an unset action on a tool
// entry means allow, because on a SHIPPED entry being listed at all is the
// recognition claim. "I said nothing about this field" meant KEEP everywhere
// else in the file and ALLOW here. Reproduced against the real
// `knowledge.toml`: a `my-knowledge.toml` containing nothing but
// `[[tool]] match = ["ExitWorktree"] source = "mine"` took that tool from ask
// to allow, while the same silence in `[[program]] match = ["rm"]` left
// `rm -rf C:/work/x` asking.

const SHIPPED_ASK: &str =
    "[[tool]]\nmatch = [\"Remover\", \"Keeper\"]\nsource = \"shipped\"\naction = \"ask\"\n";

#[test]
fn my_tool_entry_that_says_nothing_changes_nothing() {
    let mine = load("[[tool]]\nmatch = [\"Remover\"]\nsource = \"mine\"\n").expect("parses");
    let merged = vouch::knowledge::merge(load(SHIPPED_ASK).expect("parses"), mine);

    let named = tool_entry(&merged, "Remover").expect("still described");
    assert_eq!(named.action, Some(Action::Ask), "silence unset a shipped action");
    assert_eq!(
        named.action.unwrap_or(Action::Allow),
        Action::Ask,
        "the action vouch would act on became allow because the operator said nothing"
    );

    let beside = tool_entry(&merged, "Keeper").expect("the sibling name is still described");
    assert_eq!(beside.action, Some(Action::Ask), "a name the operator never wrote changed");
    assert_eq!(beside.source, "shipped", "a name the operator never wrote lost its claim");
}

#[test]
fn my_tool_entry_that_sets_an_action_still_wins() {
    // The counterpart. Keeping a shipped action must not become ignoring the
    // operator's — and an entry that sets ONLY an action must not blank out
    // the shipped `source`, which is the sentence the prompt reads out as
    // "what it does".
    let mine = load("[[tool]]\nmatch = [\"Remover\"]\naction = \"allow\"\n").expect("parses");
    let merged = vouch::knowledge::merge(load(SHIPPED_ASK).expect("parses"), mine);

    let named = tool_entry(&merged, "Remover").expect("still described");
    assert_eq!(named.action, Some(Action::Allow), "the operator's own action was ignored");
    assert_eq!(
        named.source, "shipped",
        "setting an action wiped the description the prompt reads out"
    );
}

#[test]
fn m2_26_a_tool_name_beside_a_known_one_is_not_silently_dropped() {
    // docs/ROADMAP.md M2.26, confirmed for tools 2026-07-29: the same
    // per-ENTRY "did this match anything" flag dropped a brand-new tool name
    // written beside one the shipped file already described. Fixed as part
    // of Task 4's generalised `overlay_all` (coverage tracked per name, for
    // both `[[program]]` and `[[tool]]`).
    let base = load("[[tool]]\nmatch = [\"Known\"]\nsource = \"shipped\"\n").expect("parses");
    let mine = load("[[tool]]\nmatch = [\"Known\", \"NewTool\"]\nsource = \"mine\"\n").expect("parses");
    let merged = vouch::knowledge::merge(base, mine);
    assert!(tool_entry(&merged, "NewTool").is_some(), "a tool name beside a known one was dropped");
    assert!(tool_entry(&merged, "Known").is_some(), "the known tool name was lost too");
}

#[test]
fn every_shipped_tool_entry_states_why_it_is_there() {
    let kb = vouch::guards::in_effect();
    assert!(!kb.tool.is_empty(), "no tool entries loaded — this test would pass over an empty set");
    for t in &kb.tool {
        assert!(!t.source.trim().is_empty(), "tool entry {:?} has no source", t.match_names);
    }
}
