use vouch::guards::{self, load};
use vouch::syntax::{CallArguments, Cmd, ValueOrigin};

const GATED: &str = r#"
[[program]]
match = ["python:.gate"]
receiver_from = ["data"]
writes = "arg_1"
wraps = "rest"
evaluates_input = "always"
runs_file = "arg_1"
remote_dest = true
changes_dir = "stated"
arg_names = ["path", "cb"]
callback_args = ["cb"]

[[program.rule]]
guard = "probe_guard"
source = "test fixture"
always = true
"#;

fn command(origin: ValueOrigin) -> Cmd {
    Cmd {
        head: "python:.gate".to_string(),
        args: vec![
            "$receiver".to_string(),
            "payload".to_string(),
            "$callback".to_string(),
        ],
        // Finding 1 (task-final-review, spec §5.2 per-slot exclusivity): a
        // slot the scanner resolved to a `CallableArg` is now excluded from
        // `callback_argument_used` — it is judged specifically elsewhere
        // (`by_reference_invocations`/`unresolved_callback_argument`), never
        // by this generic construct too. `$callback` stands for a genuine
        // occupant vouch could not read as literal text and did NOT resolve
        // to a callable reference — the shape the generic construct still
        // exists for — marked the same way the real python scanner marks an
        // unread token, at the same raw index as `cmd.args`. This is what
        // this test's `callback_argument_used` assertions exercise; the
        // receiver gate above (`receiver_gate_holds`) is what still makes
        // `unknown` return false regardless of this mark.
        unread_args: std::collections::HashSet::from([2]),
        receiver_origin: origin,
        ..Cmd::default()
    }
}

#[test]
fn every_program_effect_uses_the_same_receiver_gate() {
    let knowledge = load(GATED).expect("fixture parses");
    let unknown = command(ValueOrigin::Unknown);
    let known = command(ValueOrigin::Literal);

    assert!(!guards::recognises(&knowledge, &unknown, "python", true));
    assert!(guards::recognises(&knowledge, &known, "python", true));

    assert!(guards::check_in(&knowledge, &unknown, "python").is_empty());
    assert_eq!(guards::check_in(&knowledge, &known, "python").len(), 1);

    assert!(guards::written_paths_in(&knowledge, &unknown, "python")
        .paths
        .is_empty());
    assert_eq!(
        guards::written_paths_in(&knowledge, &known, "python").paths,
        vec!["payload".to_string()]
    );

    assert!(!guards::callback_argument_used(&knowledge, &unknown));
    assert!(guards::callback_argument_used(&knowledge, &known));

    assert!(!guards::evaluates_input_in(&knowledge, &unknown, "python", false, true).0);
    assert!(guards::evaluates_input_in(&knowledge, &known, "python", false, true).0);

    assert!(!guards::appended_args_could_change_the_answer(
        &knowledge, &unknown, "python"
    ));
    assert!(guards::appended_args_could_change_the_answer(
        &knowledge, &known, "python"
    ));

    assert!(guards::entry_for_cmd(&knowledge, &unknown, "python").is_none());
    assert!(guards::entry_for_cmd(&knowledge, &known, "python")
        .is_some_and(|entry| entry.remote_dest));
    assert!(guards::dir_change_entry_for_cmd(&knowledge, &unknown, "python").is_none());
    assert!(guards::dir_change_entry_for_cmd(&knowledge, &known, "python").is_some());

    assert_eq!(
        guards::expand_wrappers(&knowledge, &[unknown], "python").len(),
        1
    );
    assert!(guards::expand_wrappers(&knowledge, &[known], "python").len() > 1);
}

#[test]
fn producer_matching_recurses_through_receiver_gated_calls() {
    let knowledge = load(
        r#"
[[program]]
match = ["python:source"]
produces = ["data"]

[[program]]
match = ["python:.clean"]
receiver_from = ["data"]
produces = ["data"]

[[program]]
match = ["python:.gate"]
receiver_from = ["data"]
"#,
    )
    .expect("fixture parses");
    let source = ValueOrigin::Call {
        head: "python:source".to_string(),
        receiver: None,
        arguments: CallArguments::default(),
    };
    let clean = ValueOrigin::Call {
        head: "python:.clean".to_string(),
        receiver: Some(Box::new(source)),
        arguments: CallArguments::default(),
    };

    assert!(guards::recognises(
        &knowledge,
        &command(clean),
        "python",
        true
    ));
    assert!(!guards::recognises(
        &knowledge,
        &command(ValueOrigin::Call {
            head: "python:unknown_source".to_string(),
            receiver: None,
            arguments: CallArguments::default(),
        }),
        "python",
        true
    ));
}

#[test]
fn an_explicit_empty_receiver_gate_is_unconditional() {
    let knowledge = load("[[program]]\nmatch = [\"python:.gate\"]\nreceiver_from = []\n")
        .expect("fixture parses");

    assert!(guards::recognises(
        &knowledge,
        &command(ValueOrigin::Unknown),
        "python",
        true
    ));
}

#[test]
fn a_declared_callback_suppresses_the_producers_origin_tag() {
    let knowledge = load(
        r#"
[[program]]
match = ["python:source"]
arg_names = ["hook"]
callback_args = ["hook"]
produces = ["data"]

[[program]]
match = ["python:.gate"]
receiver_from = ["data"]
"#,
    )
    .expect("fixture parses");
    let origin = |arguments| ValueOrigin::Call {
        head: "python:source".to_string(),
        receiver: None,
        arguments,
    };

    assert!(guards::recognises(
        &knowledge,
        &command(origin(CallArguments::default())),
        "python",
        true
    ));
    assert!(!guards::recognises(
        &knowledge,
        &command(origin(CallArguments {
            positional: 1,
            ..CallArguments::default()
        })),
        "python",
        true
    ));
    assert!(!guards::recognises(
        &knowledge,
        &command(origin(CallArguments {
            starred: true,
            ..CallArguments::default()
        })),
        "python",
        true
    ));
    assert!(!guards::recognises(
        &knowledge,
        &command(origin(CallArguments {
            keywords: vec!["hook".to_string()],
            ..CallArguments::default()
        })),
        "python",
        true
    ));
    assert!(!guards::recognises(
        &knowledge,
        &command(origin(CallArguments {
            keyword_unpack: true,
            ..CallArguments::default()
        })),
        "python",
        true
    ));
}
