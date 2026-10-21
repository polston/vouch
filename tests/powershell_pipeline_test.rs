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

#[test]
fn powershell_cfg_prunes_dead_false_branch_and_evaluates_reachable_branch() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. Static `$false` condition prunes dead destructive branch
    let script = "{ if ($false) { Remove-Item -Recurse C:/Users/dev/secret } else { Get-Process } }";
    let cfg = PsControlFlowGraph::build(script);
    assert!(
        cfg.synthesized_commands.is_empty(),
        "dead branch must not synthesize Remove-Item, got {:?}",
        cfg.synthesized_commands
    );
    assert!(cfg.unreachable_block_count() >= 1);

    // 2. Variable literal condition `$env_mode = 'prod'; if ($env_mode -eq 'dev') { $_.Kill() }` prunes dead branch
    let script2 = "{ $env_mode = 'prod'; if ($env_mode -eq 'dev') { $_.Kill() } }";
    let cfg2 = PsControlFlowGraph::build(script2);
    assert!(
        cfg2.synthesized_commands.is_empty(),
        "statically false -eq comparison must prune branch, got {:?}",
        cfg2.synthesized_commands
    );

    // 3. Static true condition `$isAdmin = $true; if ($isAdmin) { $_.Kill() }` executes reachable branch
    let script3 = "{ $isAdmin = $true; if ($isAdmin) { $_.Kill() } }";
    let cfg3 = PsControlFlowGraph::build(script3);
    assert_eq!(cfg3.synthesized_commands.len(), 1);
    assert_eq!(cfg3.synthesized_commands[0].head, "Stop-Process");
}

#[test]
fn powershell_cfg_conservatively_traverses_both_branches_on_dynamic_condition() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // Dynamic condition from Read-Host is Unknown -> fail-closed: both branches are reachable!
    let script = "{ $confirm = Read-Host; if ($confirm -eq 'yes') { $_.Kill() } else { Get-Process } }";
    let cfg = PsControlFlowGraph::build(script);
    assert_eq!(
        cfg.synthesized_commands.len(),
        1,
        "dynamic condition must fail-closed and traverse then branch"
    );
    assert_eq!(cfg.synthesized_commands[0].head, "Stop-Process");
    assert_eq!(cfg.unreachable_block_count(), 0);
}

#[test]
fn powershell_cfg_early_return_or_exit_prunes_subsequent_dead_statements() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    let script = "{ Write-Output 'done'; return; $_.Kill(); Remove-Item -Recurse C:/Users/dev/x }";
    let cfg = PsControlFlowGraph::build(script);
    assert!(
        cfg.synthesized_commands.is_empty(),
        "statements after unconditional return must be pruned as unreachable, got {:?}",
        cfg.synthesized_commands
    );
    assert!(cfg.unreachable_block_count() >= 1);
}

#[test]
fn powershell_cfg_interprocedural_function_call_propagates_arguments_and_respects_reachability() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // Function declared locally and called from a reachable branch with tainted input
    let script_reachable = "{
        function Invoke-Cleanup($targetPath) {
            Remove-Item $targetPath
        }
        $userInput = Read-Host
        if ($true) {
            Invoke-Cleanup $userInput
        }
    }";
    let cfg_reach = PsControlFlowGraph::build(script_reachable);
    assert_eq!(cfg_reach.functions.len(), 1);
    assert_eq!(cfg_reach.synthesized_commands.len(), 1);
    assert_eq!(cfg_reach.synthesized_commands[0].head, "Remove-Item");
    assert!(
        cfg_reach.synthesized_commands[0]
            .args
            .iter()
            .any(|a| a == "-Recurse"),
        "tainted argument passed into local function must synthesize -Recurse"
    );

    // Same function called only inside a statically dead `if ($false)` branch
    let script_dead = "{
        function Invoke-Cleanup($targetPath) {
            Remove-Item -Recurse $targetPath
        }
        if ($false) {
            Invoke-Cleanup C:/Users/dev/important
        }
    }";
    let cfg_dead = PsControlFlowGraph::build(script_dead);
    assert_eq!(cfg_dead.functions.len(), 1);
    assert!(
        cfg_dead.synthesized_commands.is_empty(),
        "function called only from unreachable branch must not synthesize commands"
    );
}

#[test]
fn powershell_cfg_bounded_recursion_terminates_cleanly() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    let recursive_script = "{
        function Invoke-Loop($x) {
            Invoke-Loop $x
        }
        Invoke-Loop 'test'
    }";
    let cfg = PsControlFlowGraph::build(recursive_script);
    assert_eq!(cfg.functions.len(), 1);
    assert!(cfg.synthesized_commands.is_empty());
}

#[test]
fn powershell_cfg_switch_prunes_unmatched_arms_and_executes_matched_arm() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. Static switch selector ('prod') prunes 'dev' arm and dead 'default' arm
    let script_matched = "{
        $env = 'prod'
        switch ($env) {
            'dev' { $_.Kill() }
            'prod' { Write-Output 'safe' }
            default { Remove-Item -Recurse C:/Users/dev/secret }
        }
    }";
    let cfg_matched = PsControlFlowGraph::build(script_matched);
    assert!(
        cfg_matched.synthesized_commands.is_empty(),
        "unmatched 'dev' and dead 'default' switch arms must be pruned, got {:?}",
        cfg_matched.synthesized_commands
    );
    assert!(cfg_matched.unreachable_block_count() >= 2);

    // 2. Static switch selector ('staging') falls through to 'default' arm
    let script_default = "{
        switch ('staging') {
            'dev' { Write-Output 'dev' }
            'prod' { Write-Output 'prod' }
            default { $_.Kill() }
        }
    }";
    let cfg_default = PsControlFlowGraph::build(script_default);
    assert_eq!(cfg_default.synthesized_commands.len(), 1);
    assert_eq!(cfg_default.synthesized_commands[0].head, "Stop-Process");

    // 3. Dynamic switch selector (from Read-Host) fails closed and traverses all arms
    let script_dynamic = "{
        $userChoice = Read-Host
        switch ($userChoice) {
            'clean' { $_.Delete() }
            'keep'  { Write-Output 'ok' }
        }
    }";
    let cfg_dynamic = PsControlFlowGraph::build(script_dynamic);
    assert_eq!(cfg_dynamic.synthesized_commands.len(), 1);
    assert_eq!(cfg_dynamic.synthesized_commands[0].head, "Remove-Item");
}

#[test]
fn powershell_cfg_try_catch_finally_models_exception_and_finally_reachability() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. `throw` inside `try` prunes dead code after `throw`, reaches `catch` and `finally`
    let script_throw = "{
        try {
            throw 'boom'
            $_.Kill()
        } catch [System.Exception] {
            Remove-Item $_
        } finally {
            Write-Output 'cleanup'
        }
    }";
    let cfg_throw = PsControlFlowGraph::build(script_throw);
    assert_eq!(
        cfg_throw.synthesized_commands.len(),
        1,
        "dead $_.Kill() after throw must be pruned while catch Remove-Item $_ is reached: {:?}",
        cfg_throw.synthesized_commands
    );
    assert_eq!(cfg_throw.synthesized_commands[0].head, "Remove-Item");
    assert!(
        cfg_throw.synthesized_commands[0]
            .args
            .iter()
            .any(|a| a == "-Recurse"),
        "$_ inside catch block is a dynamic ErrorRecord and must trigger tainted -Recurse"
    );

    // 2. Pure literal `try` that cannot throw prunes `catch`, while `finally` still runs even after `return`
    let script_pure_try = "{
        try {
            $mode = 'safe'
            return
        } catch {
            $_.Kill()
        } finally {
            $_.Delete()
        }
        Remove-Item -Recurse C:/Users/dev/after_return
    }";
    let cfg_pure = PsControlFlowGraph::build(script_pure_try);
    assert_eq!(
        cfg_pure.synthesized_commands.len(),
        1,
        "catch and post-return statements must be pruned while finally executes: {:?}",
        cfg_pure.synthesized_commands
    );
    assert_eq!(cfg_pure.synthesized_commands[0].head, "Remove-Item");
    assert!(cfg_pure.synthesized_commands[0].args.contains(&"$_.FullName".to_string()));
}

#[test]
fn powershell_foreach_multi_block_begin_process_end_and_multi_stage_pipeline_taint() {
    use vouch::powershell_pipeline::{analyze_pipeline_stages, PsControlFlowGraph};

    // 1. Named -Begin / -Process / -End parameters (even when passed out of order on command line)
    // evaluate in lifecycle order: Begin -> Process -> End
    let cmds = vec![Cmd {
        head: "ForEach-Object".to_string(),
        args: vec![
            "-End".to_string(),
            "{ $targetProc.Kill() }".to_string(),
            "-Begin".to_string(),
            "{ $targetProc = Get-Process evil }".to_string(),
            "-Process".to_string(),
            "{ Write-Output $targetProc.Name }".to_string(),
        ],
        ..Default::default()
    }];
    let analyzed = analyze_pipeline_stages(&cmds);
    assert_eq!(analyzed.len(), 2);
    assert_eq!(analyzed[1].head, "Stop-Process");
    assert_eq!(
        analyzed[1].args,
        vec!["-Id", "$targetProc.Id", "origin:Get-Process"]
    );

    // 2. Inline `begin { ... } process { ... } end { ... }` inside a single scriptblock
    let inline_stages = "{
        begin { $taintedPath = Read-Host }
        process { Write-Output $taintedPath }
        end { Remove-Item $taintedPath }
    }";
    let cfg_inline = PsControlFlowGraph::build(inline_stages);
    assert_eq!(cfg_inline.synthesized_commands.len(), 1);
    assert_eq!(cfg_inline.synthesized_commands[0].head, "Remove-Item");
    assert!(cfg_inline.synthesized_commands[0]
        .args
        .contains(&"-Recurse".to_string()));

    // 3. Multi-stage pipeline taint propagation across consecutive ForEach-Object stages
    let multi_stage = vec![
        Cmd {
            head: "ForEach-Object".to_string(),
            args: vec!["{ Get-Process evil }".to_string()],
            ..Default::default()
        },
        Cmd {
            head: "ForEach-Object".to_string(),
            args: vec!["{ $PSItem.Kill() }".to_string()],
            ..Default::default()
        },
    ];
    let stage_res = analyze_pipeline_stages(&multi_stage);
    assert_eq!(stage_res.len(), 3);
    assert_eq!(stage_res[2].head, "Stop-Process");
    assert_eq!(
        stage_res[2].args,
        vec!["-Id", "$PSItem.Id", "origin:Get-Process"]
    );
}

#[test]
fn powershell_cfg_cross_scope_script_and_global_taint_propagation() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. `$script:` and `$global:` assignments inside a local function propagate to caller scope
    let script = "{
        function Resolve-Target {
            $script:targetProc = Get-Process evil
            $global:userPath = Read-Host
            $local:isolated = Get-Process local_only
        }
        Resolve-Target
        $script:targetProc.Kill()
        Remove-Item $global:userPath
    }";
    let cfg = PsControlFlowGraph::build(script);
    assert_eq!(cfg.synthesized_commands.len(), 2);
    assert_eq!(cfg.synthesized_commands[0].head, "Stop-Process");
    assert_eq!(
        cfg.synthesized_commands[0].args,
        vec!["-Id", "$script:targetProc.Id", "origin:Get-Process"]
    );
    assert_eq!(cfg.synthesized_commands[1].head, "Remove-Item");
    assert!(
        cfg.synthesized_commands[1]
            .args
            .contains(&"-Recurse".to_string()),
        "$global:userPath tainted inside callee must trigger -Recurse in caller"
    );

    // 2. Unprefixed `$targetProc.Kill()` in caller also resolves against `$script:targetProc`
    let script_fallback = "{
        function Init-Target {
            $script:targetProc = Get-Process evil
        }
        Init-Target
        $targetProc.Kill()
    }";
    let cfg_fb = PsControlFlowGraph::build(script_fallback);
    assert_eq!(cfg_fb.synthesized_commands.len(), 1);
    assert_eq!(
        cfg_fb.synthesized_commands[0].args,
        vec!["-Id", "$targetProc.Id", "origin:Get-Process"]
    );
}

#[test]
fn powershell_cfg_trap_statement_handler_reachability_and_break_continue_semantics() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. `trap { Remove-Item $_; break }` executes trap handler when scope can throw and prunes post-throw code
    let script_trap_break = "{
        trap [System.Exception] {
            Remove-Item $_
            break
        }
        throw 'fatal'
        $_.Kill()
    }";
    let cfg_break = PsControlFlowGraph::build(script_trap_break);
    assert_eq!(
        cfg_break.synthesized_commands.len(),
        1,
        "trap handler Remove-Item $_ must be synthesized while post-throw $_.Kill() is pruned: {:?}",
        cfg_break.synthesized_commands
    );
    assert_eq!(cfg_break.synthesized_commands[0].head, "Remove-Item");
    assert!(cfg_break.synthesized_commands[0]
        .args
        .contains(&"-Recurse".to_string()));

    // 2. `trap { Write-Output $_; continue }` resumes execution at statement following `throw`
    let script_trap_continue = "{
        trap {
            Write-Output $_
            continue
        }
        throw 'recoverable'
        $_.Kill()
    }";
    let cfg_cont = PsControlFlowGraph::build(script_trap_continue);
    assert_eq!(
        cfg_cont.synthesized_commands.len(),
        1,
        "trap with continue must allow post-throw $_.Kill() to remain reachable"
    );
    assert_eq!(cfg_cont.synthesized_commands[0].head, "Stop-Process");
}

#[test]
fn powershell_cfg_labeled_loops_break_and_continue_prune_outer_loop_statements() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // `break :outer` inside `:inner` prunes both the remainder of `:inner` (`$b.Kill()`)
    // AND the remainder of `:outer` (`$a.Delete()`), while statements after `:outer` remain reachable.
    let script = "{
        :outer foreach ($a in Get-ChildItem C:/Users/dev/work) {
            :inner foreach ($b in Get-Process) {
                break :outer
                $b.Kill()
            }
            $a.Delete()
        }
        $afterLoop = Get-Process tail
        $afterLoop.Kill()
    }";
    let cfg = PsControlFlowGraph::build(script);
    assert_eq!(
        cfg.synthesized_commands.len(),
        1,
        "only $afterLoop.Kill() after :outer should be reachable; $b.Kill() and $a.Delete() must be pruned: {:?}",
        cfg.synthesized_commands
    );
    assert_eq!(cfg.synthesized_commands[0].head, "Stop-Process");
    assert_eq!(
        cfg.synthesized_commands[0].args,
        vec!["-Id", "$afterLoop.Id", "origin:Get-Process"]
    );
}

#[test]
fn powershell_splatting_hashtable_and_array_taint_propagation() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. Hashtable splatting `@params` with tainted `Read-Host` value synthesizes `-Path`, `-Recurse`, and `untrusted_input`
    let script_hash = "{
        $params = @{ Path = (Read-Host); Recurse = $true }
        Remove-Item @params
    }";
    let cfg_hash = PsControlFlowGraph::build(script_hash);
    assert_eq!(cfg_hash.synthesized_commands.len(), 1);
    let cmd = &cfg_hash.synthesized_commands[0];
    assert_eq!(cmd.head, "Remove-Item");
    assert!(
        cmd.args.contains(&"-Path".to_string()),
        "splatted hashtable must expand -Path key: {:?}",
        cmd.args
    );
    assert!(
        cmd.args.contains(&"-Recurse".to_string()),
        "splatted hashtable with Recurse = $true must expand -Recurse: {:?}",
        cmd.args
    );
    assert!(
        cmd.args.contains(&"untrusted_input".to_string()),
        "tainted hashtable splat must propagate untrusted_input: {:?}",
        cmd.args
    );

    // 2. Array splatting `@arr` with tainted variable and switch flag
    let script_arr = "{
        $userTarget = Read-Host
        $arr = @('-Path', $userTarget, '-Force')
        Remove-Item @arr
    }";
    let cfg_arr = PsControlFlowGraph::build(script_arr);
    assert_eq!(cfg_arr.synthesized_commands.len(), 1);
    let cmd_arr = &cfg_arr.synthesized_commands[0];
    assert_eq!(cmd_arr.head, "Remove-Item");
    assert!(cmd_arr.args.contains(&"-Path".to_string()));
    assert!(cmd_arr.args.contains(&"-Force".to_string()));
    assert!(cmd_arr.args.contains(&"-Recurse".to_string()));
    assert!(cmd_arr.args.contains(&"untrusted_input".to_string()));
}

#[test]
fn powershell_switch_regex_and_wildcard_branch_pruning_and_fallthrough() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. `switch -Regex ($mode)` prunes non-matching regex arm and executes matching regex arm
    let script_regex = "{
        $mode = 'prod-us-east-1'
        switch -Regex ($mode) {
            '^dev-.*' { Remove-Item -Recurse C:/Users/dev/work; break }
            '^prod-[a-z]+-[a-z]+-[0-9]+$' { $p = Get-Process app; $p.Kill(); break }
            default { $f = Get-ChildItem C:/Users/dev/tmp; $f.Delete() }
        }
    }";
    let cfg_regex = PsControlFlowGraph::build(script_regex);
    assert_eq!(
        cfg_regex.synthesized_commands.len(),
        1,
        "only matching regex arm should execute and break before default: {:?}",
        cfg_regex.synthesized_commands
    );
    assert_eq!(cfg_regex.synthesized_commands[0].head, "Stop-Process");

    // 2. `switch -Wildcard ($envName)` matches glob pattern, prunes non-matching arm, and falls through without break
    let script_wildcard = "{
        $envName = 'staging_node_04'
        switch -Wildcard ($envName) {
            'prod_*' { Remove-Item -Recurse C:/Users/dev/prod; break }
            'staging_node_??' { $p = Get-Process worker; $p.Kill() }
            '*_04' { $f = Get-ChildItem C:/Users/dev/cache; $f.Delete(); break }
        }
    }";
    let cfg_wildcard = PsControlFlowGraph::build(script_wildcard);
    assert_eq!(
        cfg_wildcard.synthesized_commands.len(),
        2,
        "both matching wildcard arms must execute when the first lacks break, while prod_* is pruned: {:?}",
        cfg_wildcard.synthesized_commands
    );
    assert_eq!(cfg_wildcard.synthesized_commands[0].head, "Stop-Process");
    assert_eq!(cfg_wildcard.synthesized_commands[1].head, "Remove-Item");
}

#[test]
fn powershell_pipeline_variable_pv_taint_propagation_across_multi_stage_pipeline() {
    let cfg = test_config();

    // 1. `Get-ChildItem -PipelineVariable dirItem | Get-Process | ForEach-Object { Remove-Item $dirItem.FullName }`
    // Or calling `$dirItem.Delete()` / `Remove-Item` in a later pipeline stage after `$_` was overwritten by `Get-Process`
    let cmds = vec![
        Cmd {
            head: "Get-Content".to_string(),
            args: vec![
                "C:/Users/dev/targets.txt".to_string(),
                "-PipelineVariable".to_string(),
                "rawTarget".to_string(),
            ],
            ..Default::default()
        },
        Cmd {
            head: "Get-Process".to_string(),
            args: vec!["-pv".to_string(), "procItem".to_string()],
            ..Default::default()
        },
        Cmd {
            head: "ForEach-Object".to_string(),
            args: vec!["{ $procItem.Kill(); Remove-Item $rawTarget }".to_string()],
            ..Default::default()
        },
    ];
    let analyzed = vouch::powershell_pipeline::analyze_pipeline_stages(&cmds);
    let stop_cmd = analyzed
        .iter()
        .find(|c| c.head == "Stop-Process")
        .expect("expected synthesized Stop-Process from $procItem.Kill()");
    assert!(
        stop_cmd.args.contains(&"origin:Get-Process".to_string()),
        "-pv procItem must retain Get-Process origin across stages: {:?}",
        stop_cmd.args
    );

    let rm_cmd = analyzed
        .iter()
        .find(|c| c.head == "Remove-Item")
        .expect("expected synthesized Remove-Item from $rawTarget");
    assert!(
        rm_cmd.args.contains(&"-Recurse".to_string())
            && rm_cmd.args.contains(&"untrusted_input".to_string()),
        "-PipelineVariable rawTarget from Get-Content must retain DynamicInput taint in stage 3: {:?}",
        rm_cmd.args
    );

    // Verify end-to-end decision triggers guard Ask
    let d = decide_powershell(
        &cfg,
        "Get-Process -PipelineVariable p | Get-ChildItem | ForEach-Object { $p.Kill() }",
    );
    match d {
        Decision::Ask(reason) => {
            assert!(reason.contains("process_control (guard)"), "got {}", reason);
        }
        other => panic!("expected Ask on process_control guard via -PipelineVariable, got {other:?}"),
    }
}

#[test]
fn powershell_ps_default_parameter_values_taint_injection_and_wildcard_matching() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. Indexed assignment `$PSDefaultParameterValues['Remove-Item:Path'] = (Read-Host)`
    // and wildcard `$PSDefaultParameterValues['Remove-*:Recurse'] = $true`
    let script_indexed = "{
        $PSDefaultParameterValues['Remove-Item:Path'] = (Read-Host)
        $PSDefaultParameterValues['Remove-*:Recurse'] = $true
        Remove-Item -Force
    }";
    let cfg_idx = PsControlFlowGraph::build(script_indexed);
    assert_eq!(cfg_idx.synthesized_commands.len(), 1);
    let cmd = &cfg_idx.synthesized_commands[0];
    assert_eq!(cmd.head, "Remove-Item");
    assert!(
        cmd.args.contains(&"-Path".to_string()),
        "$PSDefaultParameterValues['Remove-Item:Path'] must inject -Path: {:?}",
        cmd.args
    );
    assert!(
        cmd.args.contains(&"-Recurse".to_string()),
        "wildcard $PSDefaultParameterValues['Remove-*:Recurse'] must inject -Recurse: {:?}",
        cmd.args
    );
    assert!(
        cmd.args.contains(&"untrusted_input".to_string()),
        "tainted $PSDefaultParameterValues entry must propagate untrusted_input: {:?}",
        cmd.args
    );

    // 2. Hashtable assignment `$PSDefaultParameterValues = @{ '*:Path' = $userTarget }`
    // and `.Add('Stop-Process:Id', $procId)`
    let script_hash = "{
        $userTarget = Read-Host
        $PSDefaultParameterValues = @{ 'Remove-Item:Path' = $userTarget }
        $PSDefaultParameterValues.Add('Remove-Item:Force', $true)
        Remove-Item
    }";
    let cfg_hash = PsControlFlowGraph::build(script_hash);
    assert_eq!(cfg_hash.synthesized_commands.len(), 1);
    let cmd_hash = &cfg_hash.synthesized_commands[0];
    assert_eq!(cmd_hash.head, "Remove-Item");
    assert!(cmd_hash.args.contains(&"-Path".to_string()));
    assert!(cmd_hash.args.contains(&"-Force".to_string()));
    assert!(cmd_hash.args.contains(&"-Recurse".to_string()));
    assert!(cmd_hash.args.contains(&"untrusted_input".to_string()));
}

#[test]
fn powershell_dynamic_call_and_dot_source_operators_resolve_literals_and_flag_tainted_targets() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    // 1. Dynamic call `& $cmd` where `$cmd` is a known literal resolves to the underlying cmdlet
    let script_resolved = "{
        $cmd = 'Remove-Item'
        $target = Read-Host
        & $cmd $target
    }";
    let cfg_res = PsControlFlowGraph::build(script_resolved);
    assert_eq!(cfg_res.synthesized_commands.len(), 1);
    assert_eq!(cfg_res.synthesized_commands[0].head, "Remove-Item");
    assert!(cfg_res.synthesized_commands[0]
        .args
        .contains(&"-Recurse".to_string()));
    assert!(cfg_res.synthesized_commands[0]
        .args
        .contains(&"untrusted_input".to_string()));

    // 2. Dynamic call `& $dynCmd` or dot-source `. $dynScript` where target is tainted synthesizes Invoke-Expression
    let script_tainted = "{
        $dynCmd = Read-Host
        & $dynCmd '-Force'
        $dynScript = Get-Content C:/Users/dev/plugin.ps1
        . $dynScript
    }";
    let cfg_tainted = PsControlFlowGraph::build(script_tainted);
    assert_eq!(cfg_tainted.synthesized_commands.len(), 2);
    assert_eq!(cfg_tainted.synthesized_commands[0].head, "Invoke-Expression");
    assert!(cfg_tainted.synthesized_commands[0]
        .args
        .contains(&"untrusted_input".to_string()));
    assert_eq!(cfg_tainted.synthesized_commands[1].head, "Invoke-Expression");
    assert!(cfg_tainted.synthesized_commands[1]
        .args
        .contains(&"untrusted_input".to_string()));
}

#[test]
fn powershell_class_instance_methods_and_this_property_taint_propagation() {
    use vouch::powershell_pipeline::PsControlFlowGraph;

    let script = "{
        class Cleaner {
            [string] $TargetPath
            SetTarget($p) {
                $this.TargetPath = $p
            }
            Purge() {
                Remove-Item $this.TargetPath
            }
        }
        $c = [Cleaner]::new()
        $untrusted = Read-Host
        $c.SetTarget($untrusted)
        $c.Purge()
    }";
    let cfg = PsControlFlowGraph::build(script);
    assert_eq!(
        cfg.synthesized_commands.len(),
        1,
        "Cleaner.Purge() must synthesize Remove-Item with tainted $this.TargetPath: {:?}",
        cfg.synthesized_commands
    );
    let cmd = &cfg.synthesized_commands[0];
    assert_eq!(cmd.head, "Remove-Item");
    assert!(
        cmd.args.contains(&"-Recurse".to_string())
            && cmd.args.contains(&"untrusted_input".to_string()),
        "$this.TargetPath tainted via SetTarget($untrusted) must trigger -Recurse and untrusted_input in Purge(): {:?}",
        cmd.args
    );
}
