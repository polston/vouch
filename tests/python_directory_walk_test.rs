//! Python's `os.chdir` moves the write base inside one parsed snippet scope.
//! The child process inherits its caller's run place, but its directory state
//! never leaks back to the enclosing shell or across sibling snippets.

use vouch::config::load;
use vouch::engine::decide_command_at;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";
const PROJECT: &str = "C:/work/project";

fn config() -> vouch::config::Config {
    load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
[lang.python]
default = "allow"
[lang.python.constructs]
unmodeled_command = "allow"
[write]
default = "ask"
allow_paths = ["C:/work/project/output/**"]
"#,
    )
    .expect("config parses")
}

fn decide(command: &str, cwd: &str) -> Decision {
    decide_with(&config(), command, cwd)
}

fn decide_with(config: &vouch::config::Config, command: &str, cwd: &str) -> Decision {
    decide_command_at(config, "bash", command, Some(HOME), None, Some(cwd))
}

fn assert_allow(command: &str, cwd: &str) {
    match decide(command, cwd) {
        Decision::Allow(_) => {}
        other => panic!("expected Allow for {command}, got {other:?}"),
    }
}

fn assert_ask(command: &str, cwd: &str) -> String {
    match decide(command, cwd) {
        Decision::Ask(reason) => reason,
        other => panic!("expected Ask for {command}, got {other:?}"),
    }
}

#[test]
fn relative_writes_follow_python_chdir_but_not_before_it() {
    assert_allow(
        r#"python -c "import os; os.chdir('output'); open('a.txt', 'w')""#,
        PROJECT,
    );
    assert_ask(r#"python -c "open('a.txt', 'w')""#, PROJECT);
    assert_ask(
        r#"python -c "import os; open('a.txt', 'w'); os.chdir('output')""#,
        PROJECT,
    );
}

#[test]
fn repeated_relative_and_absolute_python_changes_compose() {
    assert_allow(
        r#"python -c "import os; os.chdir('output'); os.chdir('nested'); open('a.txt', 'w')""#,
        PROJECT,
    );
    assert_allow(
        r#"python -c "import os; os.chdir('C:/work/project/output'); open('a.txt', 'w')""#,
        "C:/elsewhere",
    );
}

#[test]
fn keyword_spelled_chdir_uses_the_declared_path_position() {
    assert_allow(
        r#"python -c "import os; os.chdir(path='output'); open(file='a.txt', mode='w')""#,
        PROJECT,
    );
    assert_ask(
        r#"python -c "import os; os.chdir('path=output'); open('a.txt', 'w')""#,
        PROJECT,
    );
}

#[test]
fn unread_chdir_destination_fails_closed_as_an_unresolved_path() {
    for command in [
        r#"python -c "import os; os.chdir(destination); open('a.txt', 'w')""#,
        r#"python -c "import os; os.chdir(); open('a.txt', 'w')""#,
        r#"python -c "import os; os.chdir(**options); open('a.txt', 'w')""#,
    ] {
        let reason = assert_ask(command, PROJECT);
        assert!(reason.contains("unresolved_path"), "{reason}");
    }
}

#[test]
fn a_later_absolute_python_change_clears_an_ordered_unknown_base() {
    assert_allow(
        r#"python -c "import os; os.chdir(destination); os.chdir('C:/work/project/output'); open('a.txt', 'w')""#,
        PROJECT,
    );
}

#[test]
fn conditional_and_deferred_chdir_calls_never_mint_a_known_base() {
    for command in [
        "python -c \"import os\nif condition:\n    os.chdir('output')\nopen('a.txt', 'w')\"",
        "python -c \"import os\nfor destination in destinations:\n    os.chdir(destination)\nopen('a.txt', 'w')\"",
        "python -c \"import os\ndef move():\n    os.chdir('output')\nopen('a.txt', 'w')\"",
        "python -c \"from __future__ import annotations\nimport os\nvalue: os.chdir('output')\nopen('a.txt', 'w')\"",
        "python -c \"import os\n0 > 1 > os.chdir('output')\nopen('a.txt', 'w')\"",
    ] {
        let reason = assert_ask(command, PROJECT);
        assert!(reason.contains("unresolved_path"), "{reason}");
    }
}

#[test]
fn python_directory_state_does_not_leak_to_the_parent_or_a_sibling() {
    assert_ask(
        r#"python -c "import os; os.chdir('output')"; cp source.txt a.txt"#,
        PROJECT,
    );
    assert_ask(
        r#"python -c "import os; os.chdir('output')"; python -c "open('a.txt', 'w')""#,
        PROJECT,
    );
}

#[test]
fn child_local_order_cannot_capture_a_later_parent_redirect() {
    assert_ask(
        r#"python -c "import os; os.chdir('output'); print('x')"; echo x > parent.txt"#,
        PROJECT,
    );
}

#[test]
fn a_python_scope_inherits_outer_cd_and_wrapper_run_dir() {
    let snippet = r#"import os; os.chdir('output'); open('a.txt', 'w')"#;
    assert_allow(
        &format!(r#"cd {PROJECT} && python -c "{snippet}""#),
        "C:/elsewhere",
    );
    assert_allow(
        &format!(r#"env -C {PROJECT} python -c "{snippet}""#),
        "C:/elsewhere",
    );
}

#[test]
fn nested_shell_scope_inherits_python_chdir_without_leaking_back() {
    assert_allow(
        r#"python -c "import os; os.chdir('output'); os.system('cp source.txt a.txt')""#,
        PROJECT,
    );
    assert_allow(
        r#"python -c "import os; os.chdir('output'); os.system('cd nested'); open('a.txt', 'w')""#,
        PROJECT,
    );
}

#[test]
fn write_scopes_and_protected_paths_keep_their_stricter_precedence() {
    let scoped = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.python]
default = "allow"
[write]
default = "allow"
[[write.scope]]
programs = ["python:open"]
only_under = ["C:/work/project/output/**"]
"#,
    )
    .unwrap();
    let moved = decide_with(
        &scoped,
        r#"python -c "import os; os.chdir('output'); open('a.txt', 'w')""#,
        PROJECT,
    );
    assert!(matches!(moved, Decision::Allow(_)), "{moved:?}");
    match decide_with(&scoped, r#"python -c "open('a.txt', 'w')""#, PROJECT) {
        Decision::Ask(reason) => assert!(reason.contains("write.scope"), "{reason}"),
        other => panic!("write scope must restrict the unmoved target: {other:?}"),
    }

    let protected = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.python]
default = "allow"
[write]
default = "allow"
[protected]
paths = ["C:/work/project/output/secret.txt"]
"#,
    )
    .unwrap();
    match decide_with(
        &protected,
        r#"python -c "import os; os.chdir('output'); open('secret.txt', 'w')""#,
        PROJECT,
    ) {
        Decision::Ask(reason) => assert!(reason.contains("protected file"), "{reason}"),
        other => panic!("protected path must remain protected: {other:?}"),
    }
}

#[test]
fn guard_overrides_resolve_at_the_python_moved_place() {
    let config = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.python]
default = "allow"
[guards]
delete_recursive = "ask"
[[run.guards]]
under = ["C:/work/project/output/**"]
delete_recursive = "allow"
[write]
default = "allow"
"#,
    )
    .unwrap();
    let moved = decide_with(
        &config,
        r#"python -c "import os, shutil; os.chdir('output'); shutil.rmtree('victim')""#,
        PROJECT,
    );
    match moved {
        Decision::Allow(reason) => assert!(reason.contains("run.guards"), "{reason}"),
        other => panic!("moved guard hit should use the scoped override: {other:?}"),
    }
    let literal_marker = decide_with(
        &config,
        r#"python -c "import os, shutil; os.chdir('output/$?'); shutil.rmtree('victim')""#,
        PROJECT,
    );
    assert!(
        matches!(literal_marker, Decision::Allow(_)),
        "a readable marker spelling is a literal directory: {literal_marker:?}"
    );
    assert!(matches!(
        decide_with(
            &config,
            r#"python -c "import shutil; shutil.rmtree('victim')""#,
            PROJECT,
        ),
        Decision::Ask(_)
    ));
}

#[test]
fn an_unmodeled_call_still_asks_after_a_known_python_chdir() {
    let config = load(
        r#"
version = 1
[lang.bash]
default = "allow"
[lang.python]
default = "allow"
[lang.python.constructs]
unmodeled_command = "ask"
[write]
default = "allow"
"#,
    )
    .unwrap();
    match decide_with(
        &config,
        r#"python -c "import os; os.chdir('output'); custom_call()""#,
        PROJECT,
    ) {
        Decision::Ask(reason) => assert!(reason.contains("unmodeled_command"), "{reason}"),
        other => panic!("unknown call must remain unmodeled: {other:?}"),
    }
}
