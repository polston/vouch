//! Arithmetic nested subshell recursion depth cap (M2.253).
mod common;

use vouch::shell::parse;

#[test]
fn shallow_nested_subshell_parses() {
    let parsed = parse("( ( echo hello ) )").expect("parses");
    assert!(parsed.constructs.contains(&"subshell".to_string()));
    assert!(!parsed.constructs.contains(&"parse_failure".to_string()));
}

#[test]
fn deeply_nested_subshells_hit_depth_cap_gracefully() {
    // 12 levels of nested subshells via ( ( ( ... ) ) )
    let mut cmd = "echo deep".to_string();
    for _ in 0..12 {
        cmd = format!("( ( {} ) )", cmd);
    }
    let parsed = parse(&cmd).expect("parses without stack overflow");
    assert!(parsed.constructs.contains(&"parse_failure".to_string()), "depth cap must report parse_failure");
    assert!(
        parsed.construct_details.iter().any(|(c, d)| c == "parse_failure" && d.contains("nested subshell depth cap exceeded")),
        "depth cap failure detail must be captured"
    );
}
