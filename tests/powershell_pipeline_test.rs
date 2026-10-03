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
