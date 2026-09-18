use vouch::shell::{for_each_substitution_position_in_src, SubstitutionPosition};

#[test]
fn test_substitution_positions_all_variants_covered() {
    let cases: &[(&str, SubstitutionPosition, &str)] = &[
        ("$(which ls) -l", SubstitutionPosition::Head, "$(which ls)"),
        ("X=$(id) ls", SubstitutionPosition::PrefixAssign, "X=$(id)"),
        ("echo $(id)", SubstitutionPosition::Suffix, "$(id)"),
        ("dd of=$(mktemp)", SubstitutionPosition::SuffixAssign, "of=$(mktemp)"),
        ("echo hi > $(mktemp)", SubstitutionPosition::Redirect, "$(mktemp)"),
        ("cat <<< \"$(id)\"", SubstitutionPosition::HereString, "\"$(id)\""),
        ("cat <<EOF\n$(id)\nEOF\n", SubstitutionPosition::HereDoc, "$(id)\n"),
        ("for x in $(id); do :; done", SubstitutionPosition::ForValues, "$(id)"),
        ("case $(id) in a) echo;; esac", SubstitutionPosition::Case, "$(id)"),
        ("[[ $(id) ]] && echo", SubstitutionPosition::ExtendedTest, "$(id)"),
        ("(( x = $(id) ))", SubstitutionPosition::ArithCmd, "x = $(id)"),
        ("f() { :; } > $(mktemp)", SubstitutionPosition::FunctionRedirect, "$(mktemp)"),
    ];

    for (cmd, expected_pos, expected_fragment) in cases {
        let mut found = false;
        for_each_substitution_position_in_src(cmd, |pos, word| {
            if pos == *expected_pos && word == *expected_fragment {
                found = true;
            }
        });
        assert!(
            found,
            "failed to find expected position {:?} with word {:?} in {:?}",
            expected_pos, expected_fragment, cmd
        );
    }
}

#[test]
fn test_substitution_positions_negative_and_parse_error() {
    // Quoted heredocs require no expansion
    let quoted_heredoc = "cat <<'EOF'\n$(id)\nEOF\n";
    let mut found_heredoc = false;
    for_each_substitution_position_in_src(quoted_heredoc, |pos, _| {
        if pos == SubstitutionPosition::HereDoc {
            found_heredoc = true;
        }
    });
    assert!(!found_heredoc, "quoted heredoc should not produce HereDoc position");

    // Syntax error does not panic or produce positions
    let mut count = 0;
    for_each_substitution_position_in_src("echo ( unbalanced", |_, _| {
        count += 1;
    });
    assert_eq!(count, 0);
}

#[test]
fn test_substitution_position_as_str() {
    assert_eq!(SubstitutionPosition::Head.as_str(), "head");
    assert_eq!(SubstitutionPosition::PrefixAssign.as_str(), "prefix_assign");
    assert_eq!(SubstitutionPosition::Suffix.as_str(), "suffix");
    assert_eq!(SubstitutionPosition::SuffixAssign.as_str(), "suffix_assign");
    assert_eq!(SubstitutionPosition::Redirect.as_str(), "redirect");
    assert_eq!(SubstitutionPosition::HereString.as_str(), "herestring");
    assert_eq!(SubstitutionPosition::HereDoc.as_str(), "heredoc");
    assert_eq!(SubstitutionPosition::ForValues.as_str(), "for_values");
    assert_eq!(SubstitutionPosition::Case.as_str(), "case");
    assert_eq!(SubstitutionPosition::ExtendedTest.as_str(), "extended_test");
    assert_eq!(SubstitutionPosition::ArithCmd.as_str(), "arith_cmd");
    assert_eq!(SubstitutionPosition::FunctionRedirect.as_str(), "function_redirect");
    assert_eq!(SubstitutionPosition::Other.as_str(), "other");
}
