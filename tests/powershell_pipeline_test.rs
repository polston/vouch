use vouch::config::load;
use vouch::engine::decide_powershell;
use vouch::protocol::Decision;
use vouch::syntax::Cmd;

mod common;

fn test_config() -> vouch::config::Config {
    load(
        "version = 1\n\
         [lang.powershell]\n\
         default = \"allow\"\n\
         [lang.powershell.constructs]\n\
         method_call = \"allow\"\n"
    ).expect("parses")
}

#[test]
fn powershell_where_object_pure_filter_allowed() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-Process | Where-Object { $_.Name -eq 'test' }");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn powershell_where_alias_pure_filter_allowed() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "gps | ? { $_.CPU -gt 10 }");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn powershell_pipeline_to_stop_process_triggers_process_control_guard() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-Process | Where-Object { $_.Name -eq 'test' } | Stop-Process");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_pipeline_to_spps_alias_triggers_process_control_guard() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "gps | ? { $_.Name -eq 'test' } | spps");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_foreach_kill_method_call_synthesizes_process_control() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-Process | ForEach-Object { $_.Kill() }");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_foreach_delete_method_call_synthesizes_remove_item() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-ChildItem | ForEach-Object { $_.Delete() }");
    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive (guard)") || reason.contains("path outside every allowed area"),
                "got {}",
                reason
            );
        }
        other => panic!("expected Ask on write/delete guard, got {other:?}"),
    }
}

#[test]
fn powershell_foreach_remove_item_command_triggers_delete_guard() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-ChildItem | ForEach-Object { Remove-Item -Recurse $_ }");
    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive (guard)") || reason.contains("path outside every allowed area"),
                "got {}",
                reason
            );
        }
        other => panic!("expected Ask on write/delete guard, got {other:?}"),
    }
}

#[test]
fn powershell_select_object_pipeline_allowed() {
    let cfg = test_config();
    let d = decide_powershell(&cfg, "Get-Process | Select-Object -Property Id, ProcessName");
    assert!(matches!(d, Decision::Allow(_)), "got {d:?}");
}

#[test]
fn powershell_pipeline_stage_analysis_pure_predicate() {
    assert!(vouch::powershell_pipeline::is_pure_predicate_block("{ $_.Length -gt 100 }"));
    assert!(vouch::powershell_pipeline::is_pure_predicate_block("{ $_.Name -match '^node' }"));
    assert!(!vouch::powershell_pipeline::is_pure_predicate_block("{ $_.Kill() }"));
    assert!(!vouch::powershell_pipeline::is_pure_predicate_block("{ Remove-Item -Force $_ }"));
}

#[test]
fn powershell_analyze_pipeline_stages_synthesizes_cmds() {
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ $_.Kill() }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 2);
    assert_eq!(res[1].head, "Stop-Process");
}

#[test]
fn powershell_string_literal_immunity_against_kill_and_delete() {
    let cfg = test_config();

    // 1. Literal strings mentioning .kill() or .delete() in ForEach-Object produce zero synthesized guard commands
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ Write-Host \"calling .kill() or .delete()\" }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 1, "Must produce zero synthesized commands for string literals");

    // 2. Pure predicate block containing .kill() in a string literal remains pure
    assert!(vouch::powershell_pipeline::is_pure_predicate_block(
        "{ $_.Name -eq 'don''t call .kill()' }"
    ));
    assert!(vouch::powershell_pipeline::is_pure_predicate_block(
        "{ Write-Host \"don't call .kill()\" }"
    ));

    // 3. Engine evaluation allows cleanly without triggering process_control guard
    let d = decide_powershell(&cfg, "Get-Process | ForEach-Object { Write-Host \"don't call .kill()\" }");
    assert!(
        matches!(d, Decision::Allow(_)),
        "Must allow harmless string literal, got {d:?}"
    );
}

#[test]
fn powershell_whitespace_variation_kill_synthesizes_stop_process() {
    let cfg = test_config();

    // Pipeline analysis detects whitespace inside parentheses: $_.Kill( )
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ $_.Kill( ) }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 2);
    assert_eq!(res[1].head, "Stop-Process");
    assert_eq!(res[1].args, vec!["-Id", "$_.Id"]);

    // Engine evaluation triggers process_control guard
    let d = decide_powershell(&cfg, "Get-Process | ForEach-Object { $_.Kill( ) }");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_whitespace_variation_delete_with_arguments() {
    let cfg = test_config();

    // Pipeline analysis detects spaces around dot and arguments: $x . Delete ( $true )
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ $x . Delete ( $true ) }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 2);
    assert_eq!(res[1].head, "Remove-Item");
    assert_eq!(res[1].args, vec!["-Recurse", "-Path", "$x.FullName"]);

    let d = decide_powershell(&cfg, "Get-ChildItem | ForEach-Object { $x . Delete ( $true ) }");
    match d {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive (guard)") || reason.contains("path outside every allowed area"),
                "got {}",
                reason
            );
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_chained_member_access_synthesizes_stop_process() {
    let cfg = test_config();

    // Chained member access: $proc.Parent.Kill()
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ $proc.Parent.Kill() }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 2);
    assert_eq!(res[1].head, "Stop-Process");
    assert_eq!(res[1].args, vec!["-Id", "$proc.Id"]);

    let d = decide_powershell(&cfg, "Get-Process | ForEach-Object { $proc.Parent.Kill() }");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_multi_statement_scriptblock_detects_mutation() {
    let cfg = test_config();

    // Semicolon-separated statements: { $x = 1; $_.Kill() }
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec!["{ $x = 1; $_.Kill() }".to_string()],
        ..Default::default()
    }];
    let res = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    assert_eq!(res.len(), 2);
    assert_eq!(res[1].head, "Stop-Process");

    assert!(!vouch::powershell_pipeline::is_pure_predicate_block("{ $x = 1; $_.Kill() }"));

    let d = decide_powershell(&cfg, "Get-Process | ForEach-Object { $x = 1; $_.Kill() }");
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on guard, got {other:?}"),
    }
}

#[test]
fn powershell_tokenizer_token_stream_structural_verification() {
    use vouch::powershell_pipeline::{PsLexer, PsToken, PsTokenStream};

    let script = "<# comment #> $proc . Kill( ) # end-line comment\n$item.Delete($true)";
    let tokens = PsLexer::tokenize(script);

    assert_eq!(tokens[0], PsToken::Variable("$proc".to_string()));
    assert_eq!(tokens[1], PsToken::MemberAccess(".Kill".to_string()));
    assert_eq!(tokens[2], PsToken::OpenParen);
    assert_eq!(tokens[3], PsToken::CloseParen);
    assert_eq!(tokens[4], PsToken::Newline);
    assert_eq!(tokens[5], PsToken::Variable("$item".to_string()));
    assert_eq!(tokens[6], PsToken::MemberAccess(".Delete".to_string()));
    assert_eq!(tokens[7], PsToken::OpenParen);
    assert_eq!(tokens[8], PsToken::Variable("$true".to_string()));
    assert_eq!(tokens[9], PsToken::CloseParen);

    let mut stream = PsTokenStream::new(tokens);
    assert_eq!(stream.peek(), Some(&PsToken::Variable("$proc".to_string())));
    assert_eq!(stream.peek_ahead(1), Some(&PsToken::MemberAccess(".Kill".to_string())));
    assert_eq!(stream.next_token(), Some(PsToken::Variable("$proc".to_string())));
    assert_eq!(stream.remaining().len(), 9);
    assert!(!stream.is_empty());
}

#[test]
fn powershell_dynamic_input_path_taint_synthesizes_recurse_delete() {
    let script = "{ $file = Read-Host; Remove-Item $file }";
    let cmds = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(script);
    assert!(!cmds.is_empty());
    assert_eq!(cmds[0].head, "Remove-Item");
    assert!(cmds[0].args.iter().any(|a| a == "-Recurse"));
}

#[test]
fn powershell_process_origin_kill_synthesizes_guarded_stop_process() {
    let script = "{ $p = Get-Process evil; $p.Kill() }";
    let cmds = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(script);
    assert!(!cmds.is_empty());
    assert_eq!(cmds[0].head, "Stop-Process");
    assert_eq!(cmds[0].args[0], "-Id");
    assert_eq!(cmds[0].args[1], "$p.Id");
    assert_eq!(cmds[0].args[2], "origin:Get-Process");
}

#[test]
fn powershell_string_literal_immunity_no_synthesized_commands() {
    let script = "{ Write-Host 'calling .kill() or $x = Read-Host' }";
    let cmds = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(script);
    assert!(cmds.is_empty());

    let double_quoted = "{ Write-Output \"$bad = Read-Host; Remove-Item $bad\" }";
    let cmds2 = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(double_quoted);
    assert!(cmds2.is_empty());
}

#[test]
fn powershell_foreach_loop_induction_variable_delete() {
    let script = "foreach ($f in Get-ChildItem) { $f.Delete() }";
    let cmds = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(script);
    assert!(!cmds.is_empty());
    assert_eq!(cmds[0].head, "Remove-Item");
    assert_eq!(cmds[0].args[0], "-Recurse");
    assert_eq!(cmds[0].args[1], "-Path");
    assert_eq!(cmds[0].args[2], "$f.FullName");
}

#[test]
fn powershell_transitive_taint_propagation_synthesizes_recurse() {
    let script = "{ $bad = Read-Host; $target = $bad; Remove-Item $target }";
    let cmds = vouch::powershell_pipeline::extract_scriptblock_synthesized_commands(script);
    assert!(!cmds.is_empty());
    assert_eq!(cmds[0].head, "Remove-Item");
    assert!(cmds[0].args.iter().any(|a| a == "-Recurse"));
}

#[test]
fn powershell_taint_table_isolation_and_normalization() {
    use vouch::powershell_pipeline::{VariableOrigin, VariableTaintTable};

    let mut table = VariableTaintTable::new();
    assert_eq!(table.get("$_"), Some(&VariableOrigin::PipelineItem));
    assert_eq!(table.get("$psitem"), Some(&VariableOrigin::PipelineItem));

    table.set("myVar", VariableOrigin::DynamicInput { source: "Read-Host".into() });
    assert!(table.is_tainted_or_dynamic("$myvar"));
    assert!(table.is_tainted_or_dynamic("MYVAR"));

    table.set("$proc", VariableOrigin::CmdletResult { cmdlet: "Get-Process".into() });
    assert!(!table.is_tainted_or_dynamic("$proc"));
    assert_eq!(table.get("PROC"), Some(&VariableOrigin::CmdletResult { cmdlet: "Get-Process".into() }));
}
