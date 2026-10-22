//! Integration tests for verified script-file construct overrides (`[[lang.<L>.script_constructs]]`).

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use vouch::config;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Result<Self, std::io::Error> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "vouch_script_constructs_test_{}_{}",
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    format!("{:x}", h.finalize())
}

#[test]
fn script_constructs_allows_matching_inspected_script_and_asks_on_inline_or_outside() {
    let tmp = TempDir::new().expect("tempdir");
    let proj = tmp.path().join("project");
    let scripts_dir = proj.join("scripts");
    let outside_dir = tmp.path().join("outside");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    // A Python script with a dynamic_call (`(a or b)()`)
    let py_code = "(a or b)()\n";
    let trusted_script = scripts_dir.join("build.py");
    let outside_script = outside_dir.join("other.py");
    std::fs::write(&trusted_script, py_code).unwrap();
    std::fs::write(&outside_script, py_code).unwrap();

    let cfg_toml = r#"
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "ask"

[lang.python]
default = "allow"
[lang.python.constructs]
dynamic_call = "ask"
unmodeled_command = "ask"

[[lang.python.script_constructs]]
under = ["$PROJECT_ROOT/scripts/**"]
dynamic_call = "allow"
"#;
    let cfg = config::load(cfg_toml).expect("valid config");
    let proj_str = proj.to_string_lossy().replace('\\', "/");

    // 1. Trusted inspected script under $PROJECT_ROOT/scripts/** allows dynamic_call
    let cmd_trusted = format!(
        "python3 {}",
        trusted_script.to_string_lossy().replace('\\', "/")
    );
    let d_trusted = decide_command_at(
        &cfg,
        "bash",
        &cmd_trusted,
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_trusted {
        Decision::Allow(reason) => assert!(
            reason.contains("[[lang.python.script_constructs]] #1"),
            "expected script_constructs grant in reason, got: {reason}"
        ),
        other => panic!("expected Allow for trusted script, got {other:?}"),
    }

    // 2. Inline `python3 -c` snippet with identical code still asks on dynamic_call
    let d_inline = decide_command_at(
        &cfg,
        "bash",
        "python3 -c '(a or b)()'",
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_inline {
        Decision::Ask(reason) => assert!(
            reason.contains("dynamic_call"),
            "expected dynamic_call ask on inline snippet, got: {reason}"
        ),
        other => panic!("expected Ask on inline snippet, got {other:?}"),
    }

    // 3. Script outside $PROJECT_ROOT/scripts/** still asks on dynamic_call
    let cmd_outside = format!(
        "python3 {}",
        outside_script.to_string_lossy().replace('\\', "/")
    );
    let d_outside = decide_command_at(
        &cfg,
        "bash",
        &cmd_outside,
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_outside {
        Decision::Ask(reason) => assert!(
            reason.contains("dynamic_call"),
            "expected dynamic_call ask on outside script, got: {reason}"
        ),
        other => panic!("expected Ask on outside script, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn script_constructs_rejects_symlink_pointing_outside_allowed_tree() {
    let tmp = TempDir::new().expect("tempdir");
    let proj = tmp.path().join("project");
    let scripts_dir = proj.join("scripts");
    let outside_dir = tmp.path().join("outside");
    std::fs::create_dir_all(&scripts_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let outside_script = outside_dir.join("real_evil.py");
    std::fs::write(&outside_script, "(a or b)()\n").unwrap();

    let symlink_in_scripts = scripts_dir.join("link.py");
    std::os::unix::fs::symlink(&outside_script, &symlink_in_scripts).unwrap();

    let cfg_toml = r#"
[lang.bash]
default = "allow"
[lang.python]
default = "allow"
[lang.python.constructs]
dynamic_call = "ask"

[[lang.python.script_constructs]]
under = ["$PROJECT_ROOT/scripts/**"]
dynamic_call = "allow"
"#;
    let cfg = config::load(cfg_toml).expect("valid config");
    let proj_str = proj.to_string_lossy().replace('\\', "/");

    let cmd = format!(
        "python3 {}",
        symlink_in_scripts.to_string_lossy().replace('\\', "/")
    );
    let d = decide_command_at(
        &cfg,
        "bash",
        &cmd,
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d {
        Decision::Ask(reason) => assert!(
            reason.contains("dynamic_call"),
            "expected symlink escaping scripts/** to ask on dynamic_call, got: {reason}"
        ),
        other => panic!("expected Ask on symlink escape, got {other:?}"),
    }
}

#[test]
fn script_constructs_enforces_sha256_digest_and_preserves_guards_and_nested_isolation() {
    let tmp = TempDir::new().expect("tempdir");
    let proj = tmp.path().join("project");
    let scripts_dir = proj.join("scripts");
    std::fs::create_dir_all(&scripts_dir).unwrap();

    let sh_code = "echo $(uname)\n";
    let digest = sha256_hex(sh_code);
    let script_path = scripts_dir.join("check.sh");
    std::fs::write(&script_path, sh_code).unwrap();

    let cfg_toml = format!(
        r#"
[lang.bash]
default = "allow"
[lang.bash.constructs]
subshell = "ask"
unmodeled_command = "ask"

[[lang.bash.script_constructs]]
under = ["$PROJECT_ROOT/scripts/check.sh"]
sha256 = ["{digest}"]
subshell = "allow"

[guards]
delete_recursive = "ask"
"#
    );
    let cfg = config::load(&cfg_toml).expect("valid config");
    let proj_str = proj.to_string_lossy().replace('\\', "/");
    let script_str = script_path.to_string_lossy().replace('\\', "/");

    // Matching path + matching sha256 allows and notes verified sha256 digest
    let d_ok = decide_command_at(
        &cfg,
        "bash",
        &format!("bash {script_str}"),
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_ok {
        Decision::Allow(reason) => assert!(
            reason.contains("verified sha256 digest"),
            "expected verified sha256 digest in allow reason, got: {reason}"
        ),
        other => panic!("expected Allow on matching sha256, got {other:?}"),
    }

    // Mutate file contents so sha256 no longer matches -> must ask!
    std::fs::write(&script_path, "echo $(uname -a)\n").unwrap();
    let d_tampered = decide_command_at(
        &cfg,
        "bash",
        &format!("bash {script_str}"),
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_tampered {
        Decision::Ask(reason) => assert!(
            reason.contains("subshell"),
            "expected subshell ask on sha256 mismatch, got: {reason}"
        ),
        other => panic!("expected Ask on sha256 mismatch, got {other:?}"),
    }

    // Nested inline `bash -c` inside an allowed script does NOT inherit script_constructs!
    let nested_script = scripts_dir.join("nested.sh");
    std::fs::write(&nested_script, "bash -c 'echo $(uname)'\n").unwrap();
    let cfg_nested = config::load(
        r#"
[lang.bash]
default = "allow"
[lang.bash.constructs]
subshell = "ask"

[[lang.bash.script_constructs]]
under = ["$PROJECT_ROOT/scripts/**"]
subshell = "allow"

[guards]
delete_recursive = "ask"
"#,
    )
    .unwrap();
    let nested_str = nested_script.to_string_lossy().replace('\\', "/");
    let d_nested = decide_command_at(
        &cfg_nested,
        "bash",
        &format!("bash {nested_str}"),
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_nested {
        Decision::Ask(reason) => assert!(
            reason.contains("subshell"),
            "expected nested inline bash -c to still ask on subshell, got: {reason}"
        ),
        other => panic!("expected Ask on nested inline snippet, got {other:?}"),
    }

    // Guards inside an allowed script still fire!
    let guard_script = scripts_dir.join("clean.sh");
    std::fs::write(&guard_script, "echo $(uname)\nrm -rf /tmp/build\n").unwrap();
    let guard_str = guard_script.to_string_lossy().replace('\\', "/");
    let d_guard = decide_command_at(
        &cfg_nested,
        "bash",
        &format!("bash {guard_str}"),
        Some(&proj_str),
        Some(&proj_str),
        Some(&proj_str),
    );
    match d_guard {
        Decision::Ask(reason) => assert!(
            reason.contains("delete_recursive"),
            "expected delete_recursive guard to still fire, got: {reason}"
        ),
        other => panic!("expected Ask on guard inside script, got {other:?}"),
    }
}

#[test]
fn script_constructs_config_validation_rejects_malformed_entries() {
    // Empty `under`
    assert!(config::load(
        r#"
[[lang.python.script_constructs]]
under = []
dynamic_call = "allow"
"#
    )
    .is_err());

    // Mid-path wildcard in `under`
    assert!(config::load(
        r#"
[[lang.python.script_constructs]]
under = ["/tmp/*/script.py"]
dynamic_call = "allow"
"#
    )
    .is_err());

    // Invalid sha256 length
    assert!(config::load(
        r#"
[[lang.python.script_constructs]]
under = ["/tmp/**"]
sha256 = ["deadbeef"]
dynamic_call = "allow"
"#
    )
    .is_err());

    // Empty constructs map
    assert!(config::load(
        r#"
[[lang.python.script_constructs]]
under = ["/tmp/**"]
"#
    )
    .is_err());
}
