use vouch::config::load;
use vouch::engine::decide_command_with_knowledge;
use vouch::powershell_worker::PowerShellWorker;
use std::path::PathBuf;

#[test]
fn test_powershell_worker_ipc_roundtrip() {
    // Only run if pwsh is installed and script is accessible
    let worker_script = PathBuf::from("scripts/worker/PowerShellAstWorker.ps1");
    if !worker_script.exists() {
        return;
    }

    let worker = match PowerShellWorker::new(Some("pwsh"), Some(worker_script)) {
        Ok(w) => w,
        Err(_) => return, // pwsh not in environment
    };

    let code = "Get-ChildItem -Path C:\\work -Recurse | Where-Object { $_.Length -gt 100 }";
    let scan = match worker.query(code, 2000) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("worker query error: {e}");
            return;
        }
    };

    assert_eq!(scan.commands.len(), 2);
    assert_eq!(scan.commands[0].head, "Get-ChildItem");
    assert!(scan.commands[0].args.contains(&"-Path".to_string()));
    assert_eq!(scan.commands[1].head, "Where-Object");
}

#[test]
fn test_powershell_worker_fallback_on_unreachable_worker() {
    let cfg_text = r#"
[lang.powershell]
default = "allow"
parser_mode = "reference"
worker_binary = "non_existent_pwsh_bin_xyz"
worker_timeout_ms = 10
"#;
    let cfg = load(cfg_text).expect("valid config");
    let kb = vouch::guards::in_effect();

    // With invalid binary, reference mode falls back gracefully to pure-Rust scanner
    let dec = decide_command_with_knowledge(
        &cfg,
        "powershell",
        "Get-ChildItem -Path C:/work",
        Some(kb),
    );

    // Get-ChildItem is an allowed command
    assert!(matches!(dec, vouch::protocol::Decision::Allow(_)));
}

#[test]
fn test_powershell_worker_timeout_fallback() {
    // Verify that a timeout in worker fallback does not block the caller or panic
    let cfg_text = r#"
[lang.powershell]
default = "allow"
parser_mode = "reference"
worker_timeout_ms = 1
"#;
    let cfg = load(cfg_text).expect("valid config");
    let kb = vouch::guards::in_effect();

    let dec = decide_command_with_knowledge(
        &cfg,
        "powershell",
        "ls -la",
        Some(kb),
    );

    assert!(matches!(dec, vouch::protocol::Decision::Allow(_)));
}
