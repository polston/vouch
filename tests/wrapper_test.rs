//! A wrapper program must not be a way around every guard.
//!
//! `env rm -rf x` has head `env`; guards match on head+argv, so without
//! unwrapping, every one of these was a free pass. All of these were ALLOW
//! before 2026-07-25.

use vouch::config::load;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

fn decide(cmd: &str) -> Decision {
    let cfg = load(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n[lang.bash.constructs]\n\
         unmodeled_command = \"allow\"\nsubshell = \"allow\"\n",
    )
    .expect("parses");
    decide_command_in(&cfg, "bash", cmd, Some("C:/Users/dev"), None)
}

fn assert_asks(cmd: &str) {
    assert!(matches!(decide(cmd), Decision::Ask(_)), "evaded the guard: {cmd}");
}

fn assert_allows(cmd: &str) {
    assert!(matches!(decide(cmd), Decision::Allow(_)), "false positive: {cmd}");
}

#[test]
fn env_style_wrappers_do_not_hide_the_command() {
    assert_asks("env rm -rf /c/work/x");
    assert_asks("env FOO=1 BAR=2 rm -rf /c/work/x");
    assert_asks("nohup rm -rf /c/work/x");
    assert_asks("nice rm -rf /c/work/x");
}

#[test]
fn a_leading_data_positional_does_not_become_the_command() {
    // `timeout 5 rm -rf x` — the 5 must be crossed, not treated as the
    // program. Same assertions, different mechanism since Task 9: this used
    // to be a guess at the token's SHAPE (anything reading like a duration
    // was skipped, for every rest wrapper alike), and is now a count the
    // `timeout` entry states about itself — `leading_args = 1`, from
    // `timeout --help`'s own `[OPTION] DURATION COMMAND`. The three spellings
    // below are pinned because they are what the shape guess was written for;
    // what makes them pass now is that `timeout` crosses exactly one leading
    // positional whatever it looks like.
    assert_asks("timeout 5 rm -rf /c/work/x");
    assert_asks("timeout 30s rm -rf /c/work/x");
    assert_asks("timeout 1.5h rm -rf /c/work/x");
    // What the shape guess could not do: cross a leading positional that
    // arrives AFTER a value flag, whose own value (`TERM`) is not
    // duration-shaped and used to be read as the wrapped program.
    assert_asks("timeout --signal TERM 5 rm -rf /c/work/x");
}

#[test]
fn a_nested_shell_script_is_scanned() {
    assert_asks(r#"sh -c "rm -rf /c/work/x""#);
    assert_asks("bash -c 'git reset --hard'");
    assert_asks(r#"zsh -c "chmod +x evil.sh""#);
}

#[test]
fn xargs_and_find_exec_are_scanned() {
    assert_asks("echo /c/work/x | xargs rm -rf");
    assert_asks("find . -name '*.o' -exec rm -rf {} ;");
}

#[test]
fn wrappers_around_harmless_commands_stay_quiet() {
    assert_allows("timeout 5 ls -la");
    assert_allows(r#"sh -c "ls -la""#);
    assert_allows("env FOO=1 git status");
    assert_allows("nohup npm run build");
}

#[test]
fn a_deeply_nested_wrapper_still_resolves() {
    assert_asks(r#"env nohup sh -c "rm -rf /c/work/x""#);
}

#[test]
fn nesting_cannot_hang_the_gate() {
    // Depth is capped; this must return rather than recurse forever.
    let deep = "sh -c \"".repeat(30) + "ls" + &"\"".repeat(30);
    let _ = decide(&deep);
}

#[test]
fn a_past_cap_command_asks_naming_both_settings() {
    // Reaching the wrapper-nesting cap is an ask, never a silent truncation
    // (M2.55): the layers past it are exactly the ones nothing scanned, so
    // the prompt has to name both the construct's own setting and the depth
    // setting that would let vouch look further.
    //
    // Two real `sh -c` layers around a marker command, with the cap set to
    // 1: the marker sits at depth 2, one past it.
    let nested = "sh -c \"sh -c 'ls -la'\"";

    let cfg = |extra: &str| {
        load(&format!(
            "version = 1\n[lang.bash]\ndefault = \"allow\"\nwrap_depth = 1\n\
             [lang.bash.constructs]\nunmodeled_command = \"allow\"\nsubshell = \"allow\"\n{extra}"
        ))
        .expect("parses")
    };

    match vouch::engine::decide_command_in(&cfg(""), "bash", nested, Some("C:/Users/dev"), None) {
        Decision::Ask(r) => {
            assert!(r.contains("wrap_depth_exceeded"), "no construct name: {r}");
            assert!(
                r.contains("lang.bash.wrap_depth"),
                "no depth setting named: {r}"
            );
        }
        other => panic!("expected Ask, got {other:?}"),
    }

    // Settable both directions (§5): naming the construct's own action turns
    // the prompt off, the same as every other construct.
    assert!(
        matches!(
            vouch::engine::decide_command_in(
                &cfg("wrap_depth_exceeded = \"allow\"\n"),
                "bash",
                nested,
                Some("C:/Users/dev"),
                None,
            ),
            Decision::Allow(_)
        ),
        "wrap_depth_exceeded = allow did not stop the prompt"
    );
}
