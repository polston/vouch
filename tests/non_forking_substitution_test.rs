//! Non-forking value substitutions in bash walk (M2.251).
mod common;

use vouch::config::load as load_config;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::shell::{substitution_bodies, SubstitutionKind};

#[test]
fn non_forking_substitutions_delimited_and_classified() {
    let read = substitution_bodies("${ echo hi; }");
    assert_eq!(read.bodies, vec![" echo hi; "]);
    assert_eq!(read.items.len(), 1);
    assert_eq!(read.items[0].kind, SubstitutionKind::NonForking);

    let read_reply = substitution_bodies("${| echo hi; }");
    assert_eq!(read_reply.bodies, vec![" echo hi; "]);
    assert_eq!(read_reply.items.len(), 1);
    assert_eq!(read_reply.items[0].kind, SubstitutionKind::NonForking);

    let read_tab = substitution_bodies("${\techo hi;\t}");
    assert_eq!(read_tab.bodies, vec!["\techo hi;\t"]);
    assert_eq!(read_tab.items.len(), 1);
    assert_eq!(read_tab.items[0].kind, SubstitutionKind::NonForking);

    let read_newline = substitution_bodies("${\necho hi;\n}");
    assert_eq!(read_newline.bodies, vec!["\necho hi;\n"]);
    assert_eq!(read_newline.items.len(), 1);
    assert_eq!(read_newline.items[0].kind, SubstitutionKind::NonForking);
}

#[test]
fn parameter_expansion_not_confused_with_non_forking_substitutions() {
    let read = substitution_bodies("${VAR}");
    assert!(read.bodies.is_empty());
    assert!(!read.unreadable);

    let read_default = substitution_bodies("${VAR:-default}");
    assert!(read_default.bodies.is_empty());
    assert!(!read_default.unreadable);
}

#[test]
fn non_forking_substitution_does_not_note_subshell() {
    let parsed = vouch::shell::parse("echo ${ echo safe; }").expect("parses");
    assert!(!parsed.constructs.contains(&"subshell".to_string()));

    let parsed_forked = vouch::shell::parse("echo $(echo safe)").expect("parses");
    assert!(parsed_forked.constructs.contains(&"subshell".to_string()));
}

#[test]
fn non_forking_substitution_triggers_guards_in_current_process() {
    let cfg = load_config(r#"
version = 1
[lang.bash]
default = "allow"
"#).expect("parses");

    let decision = decide_command_in(&cfg, "bash", "${ rm -rf /tmp/test; }", None, None);
    assert!(matches!(decision, Decision::Ask(_)), "guard must fire on destructive command in non-forking substitution");
}
