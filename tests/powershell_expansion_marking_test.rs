//! PowerShell out-of-band expansion marking (M2.245).
mod common;

use vouch::config::load;
use vouch::powershell::parse;
use vouch::protocol::Decision;

#[test]
fn powershell_marks_expandable_arguments_correctly() {
    // Unquoted variable $var is expandable
    let p_unquoted = parse("Write-Output $var").expect("parses");
    assert_eq!(p_unquoted.commands.len(), 1);
    assert!(p_unquoted.commands[0].expandable_args.contains(&0));

    // Double-quoted string with $var is expandable
    let p_double = parse(r#"Write-Output "$var""#).expect("parses");
    assert_eq!(p_double.commands.len(), 1);
    assert!(p_double.commands[0].expandable_args.contains(&0));

    // Single-quoted string '$var' is literal (NOT expandable)
    let p_single = parse(r#"Write-Output '$var'"#).expect("parses");
    assert_eq!(p_single.commands.len(), 1);
    assert!(
        !p_single.commands[0].expandable_args.contains(&0),
        "single-quoted string in PowerShell must not be marked expandable"
    );

    // Literal without $ or backtick is not expandable
    let p_lit = parse("Write-Output literal_val").expect("parses");
    assert_eq!(p_lit.commands.len(), 1);
    assert!(!p_lit.commands[0].expandable_args.contains(&0));
}

#[test]
fn powershell_single_quoted_dollar_is_not_unreadable_token() {
    let cfg = load(r#"
[lang.powershell]
default = "allow"
[guards]
history_rewrite = "deny"
"#).expect("parses");

    // Double-quoted "$Verb" is expandable, so at verb slot it triggers unread_verb
    match vouch::engine::decide_powershell(&cfg, r#"git "$Verb" --all"#) {
        Decision::Ask(reason) => assert!(reason.contains("unread_verb"), "{reason}"),
        other => panic!("expected unread_verb for double-quoted expansion, got: {other:?}"),
    }

    // Single-quoted '$Verb' is a literal argument string, not expandable
    // It should NOT be treated as unread_verb; instead it's a recognised or unmodeled verb
    let res = vouch::engine::decide_powershell(&cfg, r#"git '$Verb' --all"#);
    // Should NOT be unread_verb
    if let Decision::Ask(ref reason) = res {
        assert!(!reason.contains("unread_verb"), "single-quoted literal must not trigger unread_verb, got: {reason}");
    }
}
