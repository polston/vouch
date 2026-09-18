//! Tests for subcommand-specific options (M2.235).

use vouch::guards::{load, written_paths};
use vouch::knowledge::{merge, validate_text};
use vouch::syntax::Cmd;

fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        env_assigns: Default::default(),
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        is_intra_command_function: false,
        expandable_args: Default::default(),
    }
}

#[test]
fn test_kubectl_kustomize_write_destination() {
    let toml = r#"
[[program]]
match = ["kubectl"]
value_options = ["-o", "--output", "-n", "--namespace"]
no_value_options = ["-h", "--help"]

[[program.subcommand_options]]
subcommands = ["kustomize"]
value_options = ["-o", "--output"]
write_flags = ["-o", "--output"]
"#;
    let kb = load(toml).expect("knowledge should load");

    // kubectl kustomize /dir -o /tmp/manifest.yaml -> writes to /tmp/manifest.yaml
    let c_kustomize = cmd("kubectl", &["kustomize", "/dir", "-o", "/tmp/manifest.yaml"]);
    let wt = written_paths(&kb, &c_kustomize);
    assert_eq!(wt.paths, vec!["/tmp/manifest.yaml"]);

    // kubectl get pods -o yaml -> does NOT write to yaml
    let c_get = cmd("kubectl", &["get", "pods", "-o", "yaml"]);
    let wt_get = written_paths(&kb, &c_get);
    assert!(wt_get.paths.is_empty(), "get pods -o yaml must not claim write to yaml");
}

#[test]
fn test_subcommand_options_validation() {
    // Empty subcommands rejected
    let empty_subs = r#"
[[program]]
match = ["tool"]
[[program.subcommand_options]]
subcommands = []
"#;
    assert!(validate_text(empty_subs).is_err());

    // Empty string in subcommands rejected
    let empty_str_sub = r#"
[[program]]
match = ["tool"]
[[program.subcommand_options]]
subcommands = [""]
"#;
    assert!(validate_text(empty_str_sub).is_err());

    // Duplicate subcommand rejected
    let dup_subs = r#"
[[program]]
match = ["tool"]
[[program.subcommand_options]]
subcommands = ["build"]
[[program.subcommand_options]]
subcommands = ["build"]
"#;
    assert!(validate_text(dup_subs).is_err());

    // write_flag not in value_options rejected
    let bad_wf = r#"
[[program]]
match = ["tool"]
value_options = ["-f"]
[[program.subcommand_options]]
subcommands = ["build"]
write_flags = ["-o"]
"#;
    assert!(validate_text(bad_wf).is_err());
}

#[test]
fn test_subcommand_options_merge() {
    let base_toml = r#"
[[program]]
match = ["tool"]
value_options = ["-o"]

[[program.subcommand_options]]
subcommands = ["export"]
value_options = ["-o"]
write_flags = ["-o"]
"#;

    let mine_toml = r#"
[[program]]
match = ["tool"]
value_options = ["-o", "-f"]

[[program.subcommand_options]]
subcommands = ["export"]
value_options = ["-o", "-f"]
write_flags = ["-o", "-f"]

[[program.subcommand_options]]
subcommands = ["save"]
value_options = ["-o"]
write_flags = ["-o"]
"#;

    let base_kb = load(base_toml).expect("base parses");
    let mine_kb = load(mine_toml).expect("mine parses");
    let merged = merge(base_kb, mine_kb);

    let prog = merged.program.iter().find(|p| p.match_names.iter().any(|n| n == "tool")).unwrap();
    assert_eq!(prog.subcommand_options.len(), 2);
    let export_opt = prog.subcommand_options.iter().find(|s| s.subcommands == vec!["export"]).unwrap();
    assert_eq!(export_opt.write_flags, vec!["-o", "-f"]);
    let save_opt = prog.subcommand_options.iter().find(|s| s.subcommands == vec!["save"]).unwrap();
    assert_eq!(save_opt.write_flags, vec!["-o"]);
}
