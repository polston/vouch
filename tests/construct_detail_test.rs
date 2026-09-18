//! Scanner constructs detail channel (M2.237).
mod common;

use vouch::config::load as load_config;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::syntax::Scan;

#[test]
fn note_with_detail_populates_construct_details() {
    let mut scan = Scan::default();
    scan.note_with_detail("parse_failure", "unexpected token");
    assert!(scan.constructs.contains(&"parse_failure".to_string()));
    assert_eq!(
        scan.construct_details,
        vec![("parse_failure".to_string(), "unexpected token".to_string())]
    );

    // Repeated identical detail deduplicated
    scan.note_with_detail("parse_failure", "unexpected token");
    assert_eq!(scan.construct_details.len(), 1);
}

#[test]
fn construct_detail_surfaces_in_ask_reason() {
    let cfg = load_config(r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
subshell = "allow"
parse_failure = "ask"
"#).expect("parses");

    // Command that hits depth cap in nested subshell:
    let mut cmd = "echo test".to_string();
    for _ in 0..12 {
        cmd = format!("( ( {} ) )", cmd);
    }

    let decision = decide_command_in(&cfg, "bash", &cmd, None, None);
    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("could not read: nested subshell depth cap exceeded"),
                "expected reason to contain construct detail, got: {}",
                reason
            );
        }
        other => panic!("expected Ask, got {:?}", other),
    }
}
