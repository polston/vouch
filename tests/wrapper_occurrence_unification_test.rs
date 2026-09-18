use vouch::guards::{
    expand_wrappers_with_sources, SourceProvenance,
};
use vouch::syntax::Cmd;

#[test]
fn source_provenance_is_code_held_classification() {
    assert!(!SourceProvenance::Direct.is_code_held());
    assert!(!SourceProvenance::StandardInput.is_code_held());
    assert!(SourceProvenance::LocatedSnippet.is_code_held());
    assert!(SourceProvenance::ConsumedHeredoc.is_code_held());
}

#[test]
fn top_level_commands_have_direct_provenance() {
    let kb = common::shipped_kb();
    let scan = vouch::syntax::scanner_for("bash")
        .expect("bash scanner exists")
        .scan("ls -la && git status")
        .expect("parses");
    let ex = expand_wrappers_with_sources(
        &kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );

    assert_eq!(ex.occurrences.len(), 2);
    for occ in &ex.occurrences {
        assert_eq!(occ.provenance, SourceProvenance::Direct);
        assert!(!occ.provenance.is_code_held());
        assert!(!occ.args_from_input);
        assert!(occ.inherited_run_dir.is_none());
    }
}

#[test]
fn located_snippet_arms_record_located_snippet_provenance() {
    let kb = common::shipped_kb();
    let scan = vouch::syntax::scanner_for("bash")
        .expect("bash scanner exists")
        .scan("bash -c 'echo inner_command'")
        .expect("parses");
    let ex = expand_wrappers_with_sources(
        &kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );

    let bash_occ = ex
        .occurrences
        .iter()
        .find(|o| o.cmd.head == "bash")
        .expect("bash occurrence exists");
    assert_eq!(bash_occ.provenance, SourceProvenance::LocatedSnippet);
    assert!(bash_occ.provenance.is_code_held());

    let echo_occ = ex
        .occurrences
        .iter()
        .find(|o| o.cmd.head == "echo")
        .expect("echo occurrence exists");
    assert_eq!(echo_occ.provenance, SourceProvenance::Direct);
}

#[test]
fn consumed_heredocs_record_consumed_heredoc_provenance() {
    let kb = common::shipped_kb();
    let scan = vouch::syntax::scanner_for("bash")
        .expect("bash scanner exists")
        .scan("bash - <<'EOF'\necho heredoc_inner\nEOF")
        .expect("parses");
    let ex = expand_wrappers_with_sources(
        &kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );

    let bash_occ = ex
        .occurrences
        .iter()
        .find(|o| o.cmd.head == "bash")
        .expect("bash occurrence exists");
    assert_eq!(bash_occ.provenance, SourceProvenance::ConsumedHeredoc);
    assert!(bash_occ.provenance.is_code_held());

    let echo_occ = ex
        .occurrences
        .iter()
        .find(|o| o.cmd.head == "echo")
        .expect("echo occurrence exists");
    assert_eq!(echo_occ.provenance, SourceProvenance::Direct);
}

#[test]
fn wrapper_metadata_and_run_dir_propagate_across_occurrences() {
    let kb = common::shipped_kb();
    let scan = vouch::syntax::scanner_for("bash")
        .expect("bash scanner exists")
        .scan("env -C /custom/dir echo foo")
        .expect("parses");
    let ex = expand_wrappers_with_sources(
        &kb,
        &scan.commands,
        &scan.heredocs,
        &scan.input_source,
        &scan.args_complete,
        "bash",
        &|_| 4,
    );

    let echo_occ = ex
        .occurrences
        .iter()
        .find(|o| o.cmd.head == "echo")
        .expect("echo occurrence exists");
    assert_eq!(echo_occ.inherited_run_dir.as_deref(), Some("/custom/dir"));
}

#[test]
fn evaluates_input_provenance_suppresses_ask_when_code_held() {
    let kb = common::shipped_kb();
    let cmd = Cmd {
        head: "bash".to_string(),
        args: vec!["-".to_string()],
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        expandable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        env_assigns: Default::default(),
        is_intra_command_function: false,
    };

    // Direct provenance: stdin read without held code triggers evaluates_input
    let (triggered_direct, _, _) = vouch::guards::evaluates_input_provenance(
        &kb,
        &cmd,
        "bash",
        SourceProvenance::Direct,
        true,
    );
    assert!(triggered_direct, "direct invocation reading stdin should trigger evaluates_input");

    // Consumed heredoc provenance: held code suppresses evaluates_input
    let (triggered_held, _, _) = vouch::guards::evaluates_input_provenance(
        &kb,
        &cmd,
        "bash",
        SourceProvenance::ConsumedHeredoc,
        true,
    );
    assert!(!triggered_held, "consumed heredoc provenance should suppress evaluates_input ask");

    // Located snippet provenance: held code suppresses evaluates_input
    let (triggered_snippet, _, _) = vouch::guards::evaluates_input_provenance(
        &kb,
        &cmd,
        "bash",
        SourceProvenance::LocatedSnippet,
        true,
    );
    assert!(!triggered_snippet, "located snippet provenance should suppress evaluates_input ask");
}

mod common;
