//! The `bypass_enforcement` guard and git's `--no-verify` (M2.90, M2.218).
//!
//! The interesting half is what must NOT trip. `-n` is a different option in
//! each verb — `--no-verify` for `commit` and `am`, `--dry-run` for `push`,
//! `--no-stat` for `merge` and `rebase` — so one rule matching `-n` everywhere
//! would be a false claim in three places, and a false ASK on a dry run is
//! still a defect (§3: every entry is a claim, and must be true).

mod common;

use vouch::config::load as load_config;
use vouch::protocol::Decision;

const HOME: &str = "C:/Users/dev";

fn config() -> vouch::config::Config {
    // No `[guards]` table: an unset guard resolves to ask, which is the
    // shipped behaviour this rule relies on.
    load_config(
        "version = 1\n[lang.bash]\ndefault = \"allow\"\n\
         [lang.bash.constructs]\nunmodeled_command = \"ask\"\n\
         [write]\ndefault = \"allow\"\n",
    )
    .expect("config parses")
}

fn decide(command: &str) -> Decision {
    vouch::engine::decide_command_in(&config(), "bash", command, Some(HOME), None)
}

fn reason(command: &str) -> String {
    match decide(command) {
        Decision::Ask(r) => r,
        other => panic!("{command} did not ask: {other:?}"),
    }
}

#[test]
fn every_verb_that_accepts_no_verify_trips_the_guard() {
    // Read from `git <verb> -h` on git 2.50.1 rather than assumed.
    for command in [
        "git commit --no-verify -m x",
        "git push --no-verify",
        "git merge --no-verify topic",
        "git rebase --no-verify main",
        "git am --no-verify p.patch",
    ] {
        let r = reason(command);
        assert!(
            r.contains("bypass_enforcement"),
            "{command} asked for the wrong reason: {r}"
        );
    }
}

#[test]
fn the_short_spelling_trips_only_where_it_means_no_verify() {
    for command in ["git commit -n -m x", "git am -n p.patch"] {
        let r = reason(command);
        assert!(
            r.contains("bypass_enforcement"),
            "{command} asked for the wrong reason: {r}"
        );
    }

    // `-n` here is `--dry-run` and `--no-stat`. Tripping the guard on these
    // would claim a hook was skipped when none was.
    for command in ["git push -n", "git merge -n topic", "git rebase -n main"] {
        match decide(command) {
            Decision::Allow(_) => {}
            other => panic!("{command} should not trip anything: {other:?}"),
        }
    }
}

#[test]
fn the_prompt_names_the_setting_that_turns_it_off() {
    let r = reason("git commit --no-verify -m x");
    assert!(
        r.contains("guards.bypass_enforcement"),
        "no off-switch named (CLAUDE.md §5): {r}"
    );
}

#[test]
fn the_neighbouring_force_push_rule_is_undisturbed() {
    let r = reason("git push --force");
    assert!(
        r.contains("history_rewrite"),
        "force push lost its own guard: {r}"
    );
}
