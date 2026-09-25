use std::fs;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(suffix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vouch_test_runs_file_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test temp dir");
        TempDir { path }
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().replace('\\', "/")
    }

    fn write_file(&self, name: &str, content: &str) -> String {
        let p = self.path.join(name);
        fs::write(&p, content).expect("write temp file");
        p.to_string_lossy().replace('\\', "/")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_config() -> vouch::config::Config {
    vouch::config::load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
evaluated_input = "ask"
parse_failure = "ask"
[lang.python]
default = "allow"
[lang.python.constructs]
unmodeled_command = "allow"
evaluated_input = "ask"
parse_failure = "ask"
[lang.javascript]
default = "allow"
[lang.javascript.constructs]
unmodeled_command = "allow"
evaluated_input = "ask"
parse_failure = "ask"
[lang.awk]
default = "allow"
[lang.awk.constructs]
unmodeled_command = "allow"
evaluated_input = "ask"
parse_failure = "ask"
[lang.perl]
default = "allow"
[lang.perl.constructs]
evaluated_input = "ask"
unreadable_language = "allow"
[guards]
delete_recursive = "ask"
[write]
default = "ask"
allow_paths = [
  "C:/work/**", "C:/workspace/**", "C:/claude/**", "C:/tmp/**",
  "$HOME/**", "/tmp/**", "/private/tmp/**", "/Users/**", "/var/**", "/private/var/**",
]
"#,
    )
    .expect("test config parses")
}

fn decide(cfg: &vouch::config::Config, cmd: &str, dir: &str) -> Decision {
    decide_command_at(cfg, "bash", cmd, Some("C:/Users/dev"), None, Some(dir))
}

#[test]
fn safe_python_script_file_allows() {
    let tmp = TempDir::new("py_safe");
    tmp.write_file("script.py", "x = 1 + 2\nprint(x)\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "python script.py", &dir);

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for safe python script, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe python script file, got: {other:?}"),
    }
}

#[test]
fn malicious_python_script_file_caught_by_delete_recursive_guard() {
    let tmp = TempDir::new("py_malicious");
    tmp.write_file("script.py", "import os\nos.system('rm -rf /')\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "python script.py", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive") || reason.contains("rm -rf /"),
                "expected delete_recursive guard prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for malicious python script, got: {other:?}"),
    }
}

#[test]
fn safe_node_script_file_allows() {
    let tmp = TempDir::new("js_safe");
    tmp.write_file("app.js", "console.log(42);\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "node app.js", &dir);

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for safe node script, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe node script file, got: {other:?}"),
    }
}

#[test]
fn malicious_node_script_file_caught_by_guard() {
    let tmp = TempDir::new("js_malicious");
    tmp.write_file("app.js", "const { execSync } = require('child_process');\nexecSync('rm -rf /');\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "node app.js", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive") || reason.contains("child_process") || reason.contains("rm -rf /"),
                "expected delete_recursive or child_process guard prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for malicious node script, got: {other:?}"),
    }
}

#[test]
fn safe_bash_script_file_allows() {
    let tmp = TempDir::new("sh_safe");
    tmp.write_file("script.sh", "echo 'hello world'\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "bash script.sh", &dir);

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for safe bash script, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe bash script file, got: {other:?}"),
    }
}

#[test]
fn malicious_bash_script_file_caught_by_guard() {
    let tmp = TempDir::new("sh_malicious");
    tmp.write_file("script.sh", "rm -rf /\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "bash script.sh", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for malicious bash script, got: {other:?}"),
    }
}

#[test]
fn safe_awk_script_file_allows() {
    let tmp = TempDir::new("awk_safe");
    tmp.write_file("script.awk", "{ print $1, $2 }\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "awk -f script.awk data.txt", &dir);

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for safe awk script, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe awk script file, got: {other:?}"),
    }
}

#[test]
fn malicious_awk_script_file_caught_by_guard() {
    let tmp = TempDir::new("awk_malicious");
    tmp.write_file("script.awk", "BEGIN { system(\"rm -rf /\") }\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "awk -f script.awk data.txt", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive") || reason.contains("rm -rf /"),
                "expected delete_recursive guard prompt, got: {reason}"
            );
        }
        other => panic!("expected Ask for malicious awk script, got: {other:?}"),
    }
}

#[test]
fn missing_script_file_falls_closed_to_evaluated_input() {
    let tmp = TempDir::new("py_missing");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "python nonexistent_script.py", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input prompt for missing script, got: {reason}"
            );
        }
        other => panic!("expected Ask for missing script file, got: {other:?}"),
    }
}

#[test]
fn oversized_script_file_falls_closed_to_evaluated_input() {
    let tmp = TempDir::new("py_oversized");
    // Generate 70KB python comment script (> 64KiB)
    let content = "# oversized\n".repeat(6000);
    assert!(content.len() > 65536);
    tmp.write_file("big.py", &content);
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "python big.py", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input prompt for oversized script, got: {reason}"
            );
        }
        other => panic!("expected Ask for oversized script file, got: {other:?}"),
    }
}

#[test]
fn unscanned_language_script_file_falls_closed_to_evaluated_input() {
    let tmp = TempDir::new("pl_unscanned");
    tmp.write_file("script.pl", "print \"hello\\n\";\n");
    let cfg = test_config();
    let dir = tmp.path_str();

    let decision = decide(&cfg, "perl script.pl", &dir);

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("evaluated_input"),
                "expected evaluated_input prompt for perl script file, got: {reason}"
            );
        }
        other => panic!("expected Ask for unscanned language script file, got: {other:?}"),
    }
}
