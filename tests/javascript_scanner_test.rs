mod common;

use common::{realistic_config, realistic_config_with_construct};
use vouch::config::Action;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

#[test]
fn safe_js_snippet_allows_console_log() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "console.log(42)""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe console.log, got: {other:?}"),
    }
}

#[test]
fn safe_js_pure_expression_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const x = 1 + 2; console.log(x);""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow, got: {reason}"
            );
        }
        other => panic!("expected Allow for pure expression with console.log, got: {other:?}"),
    }
}

#[test]
fn safe_js_without_calls_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const a = 10; const b = 20; a * b;""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow, got: {reason}"
            );
        }
        other => panic!("expected Allow for JS without calls, got: {other:?}"),
    }
}

#[test]
fn mutating_js_snippet_halts_on_delete_recursive_exec_sync() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "require('child_process').execSync('rm -rf /')""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) for child_process.execSync, got: {other:?}"),
    }
}

#[test]
fn mutating_js_snippet_halts_on_destructured_exec_sync() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const { execSync } = require('child_process'); execSync('rm -rf /');""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) for destructured execSync, got: {other:?}"),
    }
}

#[test]
fn mutating_js_snippet_halts_on_aliased_child_process() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const cp = require('child_process'); cp.execSync('rm -rf /');""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) for aliased cp.execSync, got: {other:?}"),
    }
}

#[test]
fn mutating_js_snippet_halts_on_spawn_sync_argv() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const cp = require('child_process'); cp.spawnSync('rm', ['-rf', '/']);""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("delete_recursive"),
                "expected delete_recursive guard, got: {reason}"
            );
        }
        other => panic!("expected Ask(delete_recursive) for spawnSync, got: {other:?}"),
    }
}

#[test]
fn js_file_write_in_allowed_path_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const fs = require('fs'); fs.writeFileSync('/tmp/safe.txt', 'hello');""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(
                reason.contains("allowed"),
                "expected allow for /tmp write, got: {reason}"
            );
        }
        other => panic!("expected Allow for safe fs.writeFileSync, got: {other:?}"),
    }
}

#[test]
fn js_file_write_outside_allowed_path_asks() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const fs = require('fs'); fs.writeFileSync('/etc/shadow', 'hello');""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("/etc/shadow"),
                "expected ask mentioning /etc/shadow, got: {reason}"
            );
        }
        other => panic!("expected Ask for write outside allow_paths, got: {other:?}"),
    }
}

#[test]
fn js_dynamic_eval_halts_on_dynamic_call() {
    let cfg = realistic_config_with_construct("javascript", "dynamic_call", Action::Ask);
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "eval('1 + 1');""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("dynamic_call") || reason.contains("evaluates_input"),
                "expected dynamic_call or evaluates_input, got: {reason}"
            );
        }
        other => panic!("expected Ask on eval, got: {other:?}"),
    }
}

#[test]
fn js_dynamic_new_function_halts_on_dynamic_call() {
    let cfg = realistic_config_with_construct("javascript", "dynamic_call", Action::Ask);
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const f = new Function('return 42'); f();""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("dynamic_call"),
                "expected dynamic_call for new Function, got: {reason}"
            );
        }
        other => panic!("expected Ask on new Function, got: {other:?}"),
    }
}

#[test]
fn js_syntax_error_fails_closed_on_unclosed_string() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "console.log('unclosed""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Ask(reason) => {
            assert!(
                reason.contains("parse_failure") || reason.contains("could not read") || reason.contains("syntax"),
                "expected parse failure for unclosed string, got: {reason}"
            );
        }
        other => panic!("expected Ask on syntax error, got: {other:?}"),
    }
}

#[test]
fn modern_js_regex_and_optional_chaining_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const re = /pattern\d+/gi; const obj = {}; if (re.test('foo')) { console.log(obj?.a?.b); }""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(reason.contains("allowed"), "expected allow for modern regex and optional chaining, got: {reason}");
        }
        other => panic!("expected Allow for modern regex and optional chaining, got: {other:?}"),
    }
}

#[test]
fn modern_js_classes_and_arrow_destructuring_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "class App { #id = 1; get() { return this.#id; } } const f = ({ x = 10 }) => console.log(x); f({});""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(reason.contains("allowed"), "expected allow for modern classes and arrow destructuring, got: {reason}");
        }
        other => panic!("expected Allow for modern classes and arrow destructuring, got: {other:?}"),
    }
}

#[test]
fn modern_js_nullish_coalescing_and_top_level_return_allows() {
    let cfg = realistic_config();
    let decision = decide_command_at(
        &cfg,
        "bash",
        r#"node -e "const val = null ?? 'fallback'; if (!val) return; console.log(val);""#,
        Some(HOME),
        None,
        Some("C:/scratch"),
    );

    match decision {
        Decision::Allow(reason) => {
            assert!(reason.contains("allowed"), "expected allow for nullish coalescing and top-level return, got: {reason}");
        }
        other => panic!("expected Allow for nullish coalescing, got: {other:?}"),
    }
}
