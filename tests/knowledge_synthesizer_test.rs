use std::path::PathBuf;
use vouch::synthesizer::{extract_flags_and_subcommands, synthesize_candidate, synthesize_candidates};
use vouch::cli::model::run_model;

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "{prefix}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&p);
    p
}

#[test]
fn test_synthesize_python_callable() {
    let cand = synthesize_candidate("python:os.path.abspath").expect("should synthesize python callable");
    assert_eq!(cand.name, "python:os.path.abspath");
    assert!(cand.toml.contains("match = [\"python:os.path.abspath\"]"));

    // Verify generated TOML is valid TOML
    let parsed: toml::Value = toml::from_str(&cand.toml).expect("valid toml syntax");
    assert!(parsed.get("program").is_some());
}

#[test]
fn test_synthesize_candidates_batch() {
    let names = vec![
        "python:time.sleep".to_string(),
        "python:argparse.ArgumentParser".to_string(),
    ];
    let cands = synthesize_candidates(&names);
    assert_eq!(cands.len(), 2);
    assert!(cands[0].toml.contains("python:time.sleep"));
    assert!(cands[1].toml.contains("python:argparse.ArgumentParser"));
}

#[test]
fn test_extract_flags_and_subcommands_from_help() {
    let mock_help = r#"
Usage: mytool <COMMAND> [OPTIONS]

Commands:
  build    Build project artifacts
  test     Run unit test suite
  publish  Publish package to registry

Options:
  -v, --verbose           Increase output verbosity
  -o, --output <FILE>     Output artifact destination path
  --config <PATH>         Custom configuration file path
  -h, --help              Print help information
"#;

    let (subs, val_flags) = extract_flags_and_subcommands(mock_help);
    assert!(subs.contains(&"build".to_string()));
    assert!(subs.contains(&"test".to_string()));
    assert!(subs.contains(&"publish".to_string()));

    assert!(val_flags.contains(&"--output".to_string()));
    assert!(val_flags.contains(&"--config".to_string()));
}

#[test]
fn test_cli_model_auto() {
    let tmp = temp_dir("synth_test");
    let home = tmp.to_str().unwrap();

    let args = vec!["--auto".to_string(), "python:json.loads".to_string()];
    let res = run_model(&args, home).expect("run_model --auto succeeds");
    assert!(res.contains("python:json.loads"));

    // Now test with --write
    let write_args = vec!["--auto".to_string(), "python:json.loads".to_string(), "--write".to_string()];
    let write_res = run_model(&write_args, home).expect("run_model --auto --write succeeds");
    assert!(write_res.contains("Synthesized and wrote"));

    let path = vouch::knowledge::my_knowledge_path(home);
    let my_kb = std::fs::read_to_string(&path).unwrap();
    assert!(my_kb.contains("python:json.loads"));
    let _ = std::fs::remove_dir_all(&tmp);
}
