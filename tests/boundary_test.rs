//! The boundary acceptance suite (spec §2). Two spellings the shell treats
//! identically must get the same decision. RED on this branch by design
//! (§2.0.9); every test cites its ROADMAP row.
mod common;

use common::{assert_verdict, decision_at};

/// Two spellings the shell treats identically, asserted to reach the same
/// decision — the shape this whole suite is about, and the one harness
/// function that is this file's alone.
#[allow(dead_code)]
fn assert_pair(cfg: &vouch::config::Config, cwd: &str, plain: &str, equivalent: &str,
               want: &str, reason_has: Option<&str>) {
    let (dp, rp) = decision_at(cfg, plain, cwd);
    let (de, re) = decision_at(cfg, equivalent, cwd);
    assert_eq!(dp, want, "plain spelling: {plain}\nreason: {rp}");
    assert_eq!(de, want, "equivalent spelling: {equivalent}\nreason: {re}");
    if let Some(needle) = reason_has {
        assert!(rp.contains(needle), "plain reason lacks {needle:?}: {rp}");
        assert!(re.contains(needle), "equivalent reason lacks {needle:?}: {re}");
    }
}

/// Outside every allowed tree in common::realistic_config's write section.
const OUTSIDE: &str = "C:/outside/of/every/allowed/tree";

/// Inside common::realistic_config's write section (`C:/tmp/**`).
const INSIDE: &str = "C:/tmp";

use vouch::config::Action;

// ============================================================================
// M2.111 — the wrapper walk cannot tell where the wrapped command starts
// ============================================================================

/// `env -u ls rm -rf d` — the interposed value `ls` has a DESCRIBED basename,
/// so the walk reads `ls` as the wrapped head and `rm -rf d` is never judged.
/// Probed: today ALLOW; the bare form already asks on `delete_recursive`.
#[test]
fn m2_111_env_dash_u_interposed_basename() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "rm -rf d", "env -u ls rm -rf d", "ask", Some("delete_recursive"));
}

/// `xargs -E ls rm -rf d` — same shape, xargs's `-E` end-of-file string.
#[test]
fn m2_111_xargs_dash_e_interposed_basename() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "rm -rf d", "xargs -E ls rm -rf d", "ask", Some("delete_recursive"));
}

/// `wsl --distribution x rm -rf d` ≡ `wsl rm -rf d` — the bare form already
/// asks; the flag-before-head form reads the distribution name as the head.
#[test]
fn m2_111_wsl_distribution_flag_interposed() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "wsl rm -rf d", "wsl --distribution x rm -rf d", "ask", Some("delete_recursive"));
}

/// The interposed value's DESCRIBED basename still resolves the same wrong
/// way as a path, an `.exe`-suffixed name, or a case variant — the same
/// normalisation `env -u ls` benefits from. Correct target for all of them
/// is `ask` on `delete_recursive`, same as the bare form.
#[test]
fn m2_111_env_dash_u_interposed_variants() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "rm -rf d", "env -u ls.exe rm -rf d", "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, "rm -rf d", "env -u LS rm -rf d", "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, "rm -rf d", "env -u C:/bin/ls rm -rf d", "ask", Some("delete_recursive"));
}

/// `env -S'rm -rf d'` and `--split-string=rm -rf d` carry the WHOLE wrapped
/// command inside one flag value the walk never opens — probed ALLOW with
/// nothing judged at all. Fix must read it as an unreadable snippet, not
/// silently pass it.
#[test]
fn m2_111_env_split_string_whole_command_in_flag_value() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "env -S'rm -rf d'", "env --split-string=rm -rf d", "ask", Some("unreadable_language"));
}

/// Same shape with a trailing token after the split-string value.
#[test]
fn m2_111_env_split_string_with_trailing_token() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "env -S'rm -rf d' extra", "env --split-string=rm -rf d extra", "ask", Some("unreadable_language"));
}

/// Regression floor: an undescribed interposed word, or a flag that consumes
/// no value, still reaches the guard today. These must stay green.
#[test]
fn m2_111_regression_floor_still_asks() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "command --unknown rm -rf d", "ask", Some("delete_recursive"));
    assert_verdict(&cfg, OUTSIDE, "nice -5 rm -rf d", "ask", Some("delete_recursive"));
    assert_verdict(&cfg, OUTSIDE, "env -- rm -rf d", "ask", Some("delete_recursive"));
}

/// `timeout 5 rm -rf d` already reaches the guard (the bare duration is
/// already skipped); `timeout 5 ls` already allows a described program.
/// Both stay green — the regression floor `leading_args` protects (§3.2.4).
#[test]
fn m2_111_timeout_duration_positional_regression_floor() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "timeout 5 rm -rf d", "ask", Some("delete_recursive"));
    assert_verdict(&cfg, OUTSIDE, "timeout 5 ls", "allow", None);
}

/// False-ask-removal pin (§2.0.2 mirrored rule, round 2): under the default
/// allow this is vacuous (sleep is unmodeled but allowed either way), so it
/// is built with `unmodeled_command = "ask"` instead. Today `--signal TERM`
/// is misread as the head (`TERM`, unmodeled, asks); the duration positional
/// `5` is required by the real `timeout` program and must not be read as the
/// head either — after the fix, `sleep` is the wrapped head and it is a
/// DESCRIBED program, so this allows outright rather than through the
/// unmodeled-command setting.
#[test]
fn m2_111_timeout_signal_value_misread_as_head() {
    let cfg = common::realistic_config_with_construct("bash", "unmodeled_command", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "timeout --signal TERM 5 sleep 1", "allow", None);
}

// ============================================================================
// M2.112 — a rejoined wrapper snippet loses a statement separator inside a
// quoted word (verified live: "Get-Date; Remove-Item -Recurse ..." rejoins
// correctly when the whole script is one token, and swallows the ";" when
// the first word is bare and the rest is quoted)
// ============================================================================

#[test]
fn m2_112_powershell_wrap_join_swallows_separator() {
    let cfg = common::realistic_config();
    let whole = r#"powershell -Command "Get-Date; Remove-Item -Recurse C:/allowed/x""#;
    let split = r#"powershell -Command Get-Date "; Remove-Item -Recurse C:/allowed/x""#;
    assert_pair(&cfg, OUTSIDE, whole, split, "ask", Some("delete_recursive"));
}

/// The cmd twin of the same two spellings — verdict equality only, since the
/// deciding mechanism differs today (bash-scanner fallback) from what it
/// will be once cmd is tagged its own language (§5.2.4, `unreadable_language`).
#[test]
fn m2_112_cmd_twin_wrap_join_swallows_separator() {
    let cfg = common::realistic_config();
    let whole = r#"cmd /c "Get-Date; Remove-Item -Recurse C:/allowed/x""#;
    let split = r#"cmd /c Get-Date "; Remove-Item -Recurse C:/allowed/x""#;
    assert_pair(&cfg, OUTSIDE, whole, split, "ask", None);
}

// ============================================================================
// M2.113 — `hash -p` rebinds a described name to an arbitrary path
// ============================================================================

#[test]
fn m2_113_hash_dash_p_rebinds_name() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "hash -p C:/x/p q", "ask", Some("rebound_name"));
}

#[test]
fn m2_113_hash_bare_stays_allow() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "hash", "allow", None);
}

// ============================================================================
// M2.114 — two spellings of the same cmd.exe recursive delete get opposite
// answers, because the `rmdir` entry lists only unix-style flags
// ============================================================================

#[test]
fn m2_114_rd_rmdir_slash_flags_bare() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "rd /s /q d", "rmdir /s /q d", "ask", Some("delete_recursive"));
}

/// Through `cmd /c` — verdict equality only (§5.2.4 changes the mechanism).
#[test]
fn m2_114_rd_rmdir_slash_flags_via_cmd() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "cmd /c rd /s /q d", "cmd /c rmdir /s /q d", "ask", None);
}

// ============================================================================
// M2.115 — construct attribution: the reason must name the key that
// answered (the donor, on inheritance), not the key the operator never set
// ============================================================================

#[test]
fn m2_115_construct_attribution_names_the_donor_key() {
    // realistic_config() sets dynamic_command = "allow" and never names
    // evaluated_input, which inherits from it (engine.rs:82-90, §2.0.2).
    let cfg = common::realistic_config();
    // A piped stdin into bash trips evaluates_input="stdin" without a held
    // heredoc, raising `evaluated_input`.
    assert_verdict(&cfg, OUTSIDE, "echo hi | bash", "allow", Some("dynamic_command"));
}

// ============================================================================
// M2.116 — xargs's arguments can arrive from stdin or a file, a channel the
// line never names
// ============================================================================

#[test]
fn m2_116_xargs_touch_from_piped_stdin() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "touch f.txt", "echo f.txt | xargs touch", "ask", None);
}

#[test]
fn m2_116_xargs_echo_stays_allow() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "xargs echo", "allow", None);
}

#[test]
fn m2_116_xargs_inline_destination_stays_ask() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "xargs -I{} touch {}", "ask", None);
}

// ============================================================================
// M2.117 — `command -v x` does not run its argument; the EXPANSION LOOP
// (guards.rs:1895-1901) runs every matching entry, so `command` has to leave
// the shared "rest" entry to stop being wrapped at all
// ============================================================================

/// Vacuous under the default allow (probed): built with `unmodeled_command
/// = "ask"` per §2.0.2's mirrored rule so today's misread of `x` is
/// red-visible.
#[test]
fn m2_117_command_dash_v_does_not_judge_its_argument() {
    let cfg = common::realistic_config_with_construct("bash", "unmodeled_command", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "command -v x", "allow", None);
}

// ============================================================================
// M2.118 — a script FILE handed to an interpreter is recognised whole-
// program and the file is never read
// ============================================================================

#[test]
fn m2_118_script_file_shell_interpreters() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    for cmd in ["bash s.sh", "sh s.sh", "zsh s.sh", "dash s.sh", "ksh s.sh"] {
        assert_verdict(&cfg, OUTSIDE, cmd, "ask", Some("evaluated_input"));
    }
}

/// After the end-of-options marker every token is an operand, so a file
/// whose NAME spells the wrap flag is a script — `python -- -c` runs a file
/// called `-c`, verified by running it. Found by the task review: the walk
/// tested the flag spelling regardless of whether the program was still
/// reading flags, and read this as "the snippet arm owns this line".
#[test]
fn m2_118_script_file_named_like_the_wrap_flag() {
    let cfg = common::realistic_config_with_construct("python", "evaluated_input", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "python -- -c", "ask", Some("evaluated_input"));
}

#[test]
fn m2_118_script_file_python_interpreters() {
    // python's own construct table, not the host shell's: the file python
    // runs is python, and its entry says so (`wrap_lang`). Same rule the
    // piped spelling has followed since M2.79, so one program's blindness
    // has one off-switch however the code reaches it.
    let cfg = common::realistic_config_with_construct("python", "evaluated_input", Action::Ask);
    for cmd in ["python s.py", "python3 s.py", "py s.py", "python -m mod"] {
        assert_verdict(&cfg, OUTSIDE, cmd, "ask", Some("evaluated_input"));
    }
}

// ============================================================================
// M2.119 — a quoted flag token is invisible to every guard rule, because
// rule matching compares RAW tokens while unquoting is applied elsewhere
// ============================================================================

#[test]
fn m2_119_git_push_force_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "git push --force", "git push \"--force\"", "ask", Some("history_rewrite"));
    assert_pair(&cfg, OUTSIDE, "git push --force", "git push '--force'", "ask", Some("history_rewrite"));
}

#[test]
fn m2_119_git_reset_hard_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "git reset --hard", "git reset \"--hard\"", "ask", Some("history_rewrite"));
}

#[test]
fn m2_119_git_branch_dash_d_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "git branch -D b", "git branch \"-D\" b", "ask", Some("history_rewrite"));
}

#[test]
fn m2_119_sed_dash_i_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "sed -i s/a/b/ f", "sed \"-i\" s/a/b/ f", "ask", Some("in_place_edit"));
}

#[test]
fn m2_119_find_delete_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "find d -delete", "find d \"-delete\"", "ask", Some("delete_recursive"));
}

/// `rm "-r" d` still asks, but on the WRITE rule (the path check) rather
/// than its guard — the guard is defeated here too, only the write rule
/// happens to catch it, so `reason_has` compares the deciding rule and must
/// go red until both spellings name `delete_recursive`.
#[test]
fn m2_119_rm_dash_r_quoted() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "rm -r d", "rm \"-r\" d", "ask", Some("delete_recursive"));
}

// ============================================================================
// M2.120 — an assignment prefix that changes where programs are found, or
// that names a startup file, is treated as inert
// ============================================================================

/// Described head, per §2.0.6 — the pair's plain side is `ls` alone so the
/// pair is not vacuously ask-on-an-undescribed-placeholder.
#[test]
fn m2_120_path_assignment_rebinds_lookup() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "PATH=C:/x ls", "ask", Some("rebound_name"));
}

#[test]
fn m2_120_env_path_assignment_same() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "env PATH=C:/x ls", "ask", Some("rebound_name"));
}

/// Startup-file case: needs `evaluated_input` named, per §2.0.2's group list.
#[test]
fn m2_120_bash_env_startup_file() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "BASH_ENV=C:/x/f bash -c 'echo hi'", "ask", Some("evaluated_input"));
}

/// Inert names stay inert: `LC_ALL` does not change program lookup.
#[test]
fn m2_120_inert_assignment_names_stay_inert() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "sort f", "LC_ALL=C sort f", "allow", None);
}

// ============================================================================
// M2.121 — the name vouch looks up is not always the name the shell runs
// ============================================================================

/// A backslash is an escape in bash, not a separator — `who\ami` and
/// `whoami` must be judged as the same name the shell runs. Built with
/// `unmodeled_command = "ask"`, same as the Kelvin-sign pin two tests below
/// (a review found the original encoding here provably vacuous: under the
/// default allow both spellings already read ALLOW regardless of whether
/// the backslash is handled correctly, so the pair proved nothing). Probed
/// live under the override: `whoami` is a DESCRIBED program and allows;
/// `who\ami` is read as a path with a directory component and asks,
/// unmodeled, naming `ami` — a real differential that converges only once
/// escape handling treats the backslash as bash does.
#[test]
fn m2_121_backslash_escape_same_name() {
    let cfg = common::realistic_config_with_construct("bash", "unmodeled_command", Action::Ask);
    assert_pair(&cfg, OUTSIDE, "whoami", "who\\ami", "allow", None);
}

/// `.exe`-trimming happens before the wrapper-cluster lookup, so `bash.exe`
/// can never reach the `wsl`/`wsl.exe`/`bash.exe` entry and lands on the
/// plain POSIX-shell entry instead. Verdict equality only — which entry
/// answers is the §4.4.3 knowledge decision.
#[test]
fn m2_121_exe_trim_misses_the_wrapper_entry() {
    // Built with the script-file construct asking, like its M2.118 siblings:
    // once `bash.exe` lands on the POSIX-shell entry, `rm` is that shell's
    // first OPERAND — the name of a file it will run, not the rm program —
    // and the construct that says so is settable. At the construct's
    // inherited default (this config allows `dynamic_command`) the two
    // spellings genuinely differ, which is a config choice rather than the
    // lookup defect this row is about.
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    assert_pair(&cfg, OUTSIDE, "wsl rm -rf d", "bash.exe rm -rf d", "ask", None);
}

/// Full-Unicode lowercasing folds the Kelvin sign onto ASCII `k`, which the
/// shell and filesystem keep distinct (measured live). Built with
/// `unmodeled_command = "ask"` (§2.0.2's confusable-spelling group) so a
/// wrong fold reads as a false ALLOW rather than vanishing into the default.
#[test]
fn m2_121_kelvin_sign_confusable_spelling() {
    let cfg = common::realistic_config_with_construct("bash", "unmodeled_command", Action::Ask);
    assert_verdict(&cfg, OUTSIDE, "\u{212A}SH", "ask", Some("unmodeled_command"));
}

// ============================================================================
// M2.122 — a same-line assignment vouch cannot read must not fall through
// to the JUDGING PROCESS's own environment
// ============================================================================

/// One fixed line whose head comes through an unreadable same-line
/// assignment (`$(true)`, a command substitution vouch cannot read); the
/// verdict must be the same whether or not the CHILD process happens to
/// have the same-named variable set in its own environment (§2.0.4). Runs
/// through the child harness because the environment being varied belongs
/// to the JUDGING process, never the test binary's own (CLAUDE.md §9).
#[test]
fn m2_122_poisoned_assignment_ignores_judging_process_env() {
    // dynamic_command stays at realistic_config's default "allow" on
    // purpose: the scanner notes that construct UNCONDITIONALLY whenever a
    // head is written as a variable reference (shell.rs:257), independent
    // of whether the later resolution loop succeeds — so asking on it would
    // mask the very difference this pin exists to show (verified live).
    // unmodeled_command is the channel a successfully-resolved head (found
    // via the judging process's own environment) and an unresolved one
    // actually diverge on, so that is the key this pin names.
    let cfg_text = common::config_text_with(&[("bash", "unmodeled_command", "ask")]);
    let line = "VOUCHTEST_PROBE_HEAD=$(true) $VOUCHTEST_PROBE_HEAD";
    let (d_set, r_set) = common::hook_bash_at_env(
        "m2122set", "", &cfg_text, OUTSIDE, line, &[("VOUCHTEST_PROBE_HEAD", "ls")],
    );
    let (d_unset, r_unset) = common::hook_bash_at_env(
        "m2122unset", "", &cfg_text, OUTSIDE, line, &[],
    );
    assert_eq!(d_set, "ask", "with the variable set in the child env: {r_set}");
    assert_eq!(d_unset, "ask", "with the variable unset in the child env: {r_unset}");
    assert_eq!(d_set, d_unset, "one fixed line must not get its verdict from the judging process's own environment");
}

// ============================================================================
// M2.123 — a wrap arm that cannot find its declared payload returns an
// empty scan, indistinguishable from a wrapper that genuinely wrapped
// nothing — at least nine live wrong ALLOWs share this one root cause
// ============================================================================

#[test]
fn m2_123_bash_dash_c_combined_short_options() {
    let cfg = common::realistic_config();
    let base = "bash -c 'rm -rf d'";
    for combined in ["bash -lc 'rm -rf d'", "bash -cx 'rm -rf d'", "bash -ec 'rm -rf d'",
                     "bash -uc 'rm -rf d'", "bash -ic 'rm -rf d'"] {
        assert_pair(&cfg, OUTSIDE, base, combined, "ask", Some("delete_recursive"));
    }
}

#[test]
fn m2_123_bash_dash_c_intervening_option_spellings() {
    let cfg = common::realistic_config();
    let base = "bash -c 'rm -rf d'";
    assert_pair(&cfg, OUTSIDE, base, "bash -lc -x 'rm -rf d'", "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, base, "bash -c -e 'rm -rf d'", "ask", Some("delete_recursive"));
}

#[test]
fn m2_123_python_dash_c_combined_short_options() {
    let cfg = common::realistic_config();
    let base = "python -c \"import os; os.system('rm -rf d')\"";
    for combined in [
        "python -Sc \"import os; os.system('rm -rf d')\"",
        "python -Ec \"import os; os.system('rm -rf d')\"",
        "python -uc \"import os; os.system('rm -rf d')\"",
        "python -Bc \"import os; os.system('rm -rf d')\"",
    ] {
        assert_pair(&cfg, OUTSIDE, base, combined, "ask", Some("delete_recursive"));
    }
}

/// The combined spelling also walks past the protected-path list, the one
/// prompt CLAUDE.md §5 says has no override.
#[test]
fn m2_123_combined_option_defeats_protected_path() {
    let text = format!(
        "{}\n[protected]\npaths = [\"C:/Users/dev/.claude/settings.json\"]\n",
        common::config_text_with(&[])
    );
    let cfg = vouch::config::load(&text).expect("protected-list config parses");
    assert_pair(
        &cfg, OUTSIDE,
        "bash -c 'echo x > C:/Users/dev/.claude/settings.json'",
        "bash -lc 'echo x > C:/Users/dev/.claude/settings.json'",
        "ask", Some("protected"),
    );
}

/// Only the FIRST `-exec` of a `find` line is unwrapped today — a benign
/// first exec and a delete second must both be judged.
#[test]
fn m2_123_find_second_exec_unjudged() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "find d -exec echo x \\; -exec rm -rf d \\;", "ask", Some("delete_recursive"));
}

/// PowerShell's `Start-Process -ArgumentList` is found only by exact flag
/// name and an exact-flag lookup, broken by an abbreviated parameter name
/// and by a leading switch other than the one tested for.
#[test]
fn m2_123_powershell_start_process_argument_list_spellings() {
    let cfg = common::realistic_config();
    let base = r#"start-process powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x""#;
    assert_pair(&cfg, OUTSIDE, base,
        r#"start-process powershell -Args "-Command","Remove-Item -Recurse C:/allowed/x""#,
        "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, base,
        r#"start-process powershell -verb runas -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x""#,
        "ask", Some("delete_recursive"));
}

/// The program named by a FLAG rather than by a positional. `-FilePath` and
/// its `-PSPath` alias are how `Start-Process` spells the same thing the
/// positional form spells, so the two must decide the same way.
///
/// Added in fix round 1: every other pin in this family used the positional
/// spelling, and the flag spelling was allowing the wrapped delete silently
/// — the walk consumed the program name as an ordinary flag value, found no
/// positional, and read that as "this wrapped nothing" while the argument
/// list sat one token away.
#[test]
fn m2_123_powershell_start_process_program_named_by_flag() {
    let cfg = common::realistic_config();
    let base = r#"start-process powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x""#;
    for equivalent in [
        r#"start-process -FilePath powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x""#,
        r#"start-process -PSPath powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x""#,
        r#"start-process -FilePath powershell -Args "-Command","Remove-Item -Recurse C:/allowed/x""#,
        // A trailing switch after the list: what made the reviewer's twelve
        // measured spellings differ from the pins that already existed.
        r#"start-process -FilePath powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x" -Wait"#,
        r#"start-process -FilePath powershell -ArgumentList "-Command","Remove-Item -Recurse C:/allowed/x" -NoNewWindow"#,
        r#"start-process -PSPath powershell -Args "-Command","Remove-Item -Recurse C:/allowed/x" -PassThru"#,
    ] {
        assert_pair(&cfg, OUTSIDE, base, equivalent, "ask", Some("delete_recursive"));
    }
}

/// The other direction of the same fix: a benign wrapped command stays quiet
/// whichever way the program is named, so the fix is not a blanket ask on the
/// flag spelling.
#[test]
fn m2_123_powershell_start_process_flag_spelling_has_no_false_ask() {
    let cfg = common::realistic_config();
    assert_pair(
        &cfg, OUTSIDE,
        r#"start-process powershell -ArgumentList "-Command","Get-Date""#,
        r#"start-process -FilePath powershell -ArgumentList "-Command","Get-Date" -Wait"#,
        "allow", None,
    );
}

/// An array-literal argument list is not found by the exact-flag-value
/// locator at all — raises `wrap_unlocated` once the locator stops
/// returning an empty scan on a miss (§4.1's fix).
#[test]
fn m2_123_powershell_start_process_array_literal_unlocated() {
    let cfg = common::realistic_config();
    assert_verdict(
        &cfg, OUTSIDE,
        r#"start-process powershell -ArgumentList @("-Command","Remove-Item -Recurse C:/allowed/x")"#,
        "ask", Some("wrap_unlocated"),
    );
}

// ============================================================================
// M2.124 — an interpreter's eval flag or input channel is only partly
// described, so a sibling spelling runs unread text
// ============================================================================

/// PowerShell's pre-encoded command parameter is not among its wrap flags.
/// Equal VERDICTS asserted, `reason_has: None` — the reasons legitimately
/// differ (guard vs `unreadable_language`, §2.1 rule 9).
#[test]
fn m2_124_encoded_command_vs_plain() {
    let cfg = common::realistic_config();
    assert_pair(
        &cfg, OUTSIDE,
        "powershell -Command 'rm -r d'",
        "powershell -EncodedCommand cgBtACAALQByACAAZAA=",
        "ask", None,
    );
}

/// No powershell (or sh) entry declares `evaluates_input`, so text piped
/// into either on standard input is unjudged. Needs `evaluated_input` named
/// for both languages at once — a two-language case, so `config_text_with`
/// feeds `vouch::config::load` in-process (§2.0.2).
#[test]
fn m2_124_piped_stdin_into_interpreter() {
    let text = common::config_text_with(&[
        ("bash", "evaluated_input", "ask"),
        ("powershell", "evaluated_input", "ask"),
    ]);
    let cfg = vouch::config::load(&text).expect("two-language override config parses");
    assert_pair(&cfg, OUTSIDE, "echo hi | powershell", "echo hi | sh", "ask", Some("evaluated_input"));
}

/// awk's entry captures only its program-FILE flag; its own comment says
/// the reason it exists is that awk writes from inside its program TEXT.
#[test]
fn m2_124_awk_inline_program_writes_unseen() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, r#"awk 'BEGIN{print > "C:/x/f"}'"#, "ask", Some("unreadable_language"));
}

/// The opaque interpreters list one eval flag but not its siblings.
#[test]
fn m2_124_opaque_interpreter_eval_flag_siblings() {
    let cfg = common::realistic_config();
    let base = "node -e 'rm -rf d'";
    for sibling in ["perl -E 'rm -rf d'", "node -p 'rm -rf d'", "node --print 'rm -rf d'", "deno eval 'rm -rf d'"] {
        assert_pair(&cfg, OUTSIDE, base, sibling, "ask", None);
    }
}

/// `find`'s own file-writing predicates are undeclared.
#[test]
fn m2_124_find_write_predicates_undeclared() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "find d -fprint C:/x/f", "ask", Some("write"));
    assert_verdict(&cfg, OUTSIDE, "find d -fprintf C:/x/f fmt", "ask", Some("write"));
    assert_verdict(&cfg, OUTSIDE, "find d -fls C:/x/f", "ask", Some("write"));
}

/// `find`'s confirming-action predicates are not wrap sites at all.
///
/// The terminator is spelled `\;` or `+`. A BARE `;` is a shell statement
/// separator, so find never receives it — verified by running it (GNU
/// findutils 4.10.0): the shell splits the line, find reports a missing
/// argument to the predicate and exits 1 having run nothing. That spelling
/// is therefore not an equivalent spelling of this command at all, and it
/// gets its own pin below.
#[test]
fn m2_124_find_confirming_action_predicates() {
    let cfg = common::realistic_config();
    let base = r"find d -ok rm -rf {} \;";
    assert_pair(&cfg, OUTSIDE, base, r"find d -okdir rm -rf {} \;", "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, base, r"find d -exec rm -rf {} \;", "ask", Some("delete_recursive"));
    assert_pair(&cfg, OUTSIDE, base, "find d -exec rm -rf {} +", "ask", Some("delete_recursive"));
}

/// The spelling the shell eats: with a bare `;` the predicate never reaches
/// a terminator, so vouch cannot tell where the wrapped command ends. It
/// says exactly that instead of guessing an end — fail-closed, and about a
/// line find itself refuses to run.
#[test]
fn m2_124_find_predicate_without_a_terminator() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "find d -ok rm -rf {} ;", "ask", Some("wrap_unlocated"));
}

// ============================================================================
// M2.125 — inline code in a language vouch has no scanner for is ALLOWED
// UNREAD; the tool-snippet and program-snippet halves disagree
// ============================================================================

#[test]
fn m2_125_opaque_interpreter_inline_eval() {
    let cfg = common::realistic_config();
    for cmd in ["node -e 'rm -rf d'", "perl -e 'rm -rf d'", "ruby -e 'rm -rf d'",
                "deno -e 'rm -rf d'", "bun -e 'rm -rf d'"] {
        assert_verdict(&cfg, OUTSIDE, cmd, "ask", Some("unreadable_language"));
    }
}

/// A here-document feeding one of these interpreters is unconsumed and only
/// notes the (allowed-by-default) `heredoc` construct today; it must raise
/// `evaluated_input` instead. Needs the construct named, same mechanism as
/// M2.118/M2.120's startup case (§2.0.2).
#[test]
fn m2_125_heredoc_feeding_opaque_interpreter() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    let cmd = "node <<'EOF'\nrm -rf d\nEOF";
    assert_verdict(&cfg, OUTSIDE, cmd, "ask", Some("evaluated_input"));
}

/// An unregistered `wrap_lang` must be a load refusal, not a silent
/// fall-back to the bash scanner — the `[[tool]]` side already validates
/// its language against a closed set.
#[test]
fn m2_125_unregistered_wrap_lang_load_refusal() {
    let text = r#"
version = 5
[[program]]
match = ["vouchtest-fakeprog"]
wraps = "after_flag"
wrap_flags = ["-e"]
wrap_lang = "klingon"
"#;
    let result = vouch::guards::load(text);
    assert!(result.is_err(), "an unregistered wrap_lang must refuse to load, not fall back silently");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("vouchtest-fakeprog") || msg.contains("klingon"),
        "the refusal should name the entry or the bad language: {msg}");
}

// ============================================================================
// M2.126 — the PowerShell splitter does not split on `&&`/`||`
// ============================================================================

#[test]
fn m2_126_powershell_chain_operators() {
    let cfg = common::realistic_config();
    let semicolon = r#"powershell -Command "Get-Date; Remove-Item -Recurse C:/allowed/x""#;
    let and_and = r#"powershell -Command "Get-Date && Remove-Item -Recurse C:/allowed/x""#;
    assert_pair(&cfg, OUTSIDE, semicolon, and_and, "ask", Some("delete_recursive"));
}

/// `||` already asks today, by accident of the old `|`-only splitter —
/// regression floor, must stay green once the real split lands.
#[test]
fn m2_126_powershell_or_operator_regression_floor() {
    let cfg = common::realistic_config();
    let or_or = r#"powershell -Command "Get-Date || Remove-Item -Recurse C:/allowed/x""#;
    assert_verdict(&cfg, OUTSIDE, or_or, "ask", Some("delete_recursive"));
}

// ============================================================================
// M2.127 — inside a snippet, the delivered here-document is selected with
// an index into the wrong list once a scan boundary is crossed
// ============================================================================

/// Re-derived from the code, not the row summary, after a review found the
/// original encoding here vacuous (see task-2-report.md's fix log). Traced
/// through `collect_expanded` (engine.rs:1449-1496) and the recursive walk
/// in `expand_wrappers_with_sources` (guards.rs, the heredoc locator around
/// 2099-2131): a here-document consumed INSIDE a wrapped snippet is matched
/// against `own_source == Heredoc(nth)`, where `nth` is the position within
/// THIS COMMAND's own filtered heredoc list, but `own_source` (from the
/// freshly re-scanned inner snippet's own `input_source`) still carries an
/// index into the WHOLE inner scan's heredoc list — never re-based the way
/// `collect_expanded` re-bases a TOP-LEVEL command's index. An earlier
/// sibling command's own heredoc inside the same wrapped snippet shifts the
/// whole-list index without shifting the filtered one, so the two indices
/// only ever coincide when nothing precedes this command's own heredoc.
///
/// The recursion that SCANS the heredoc's body does not gate on that
/// comparison — it fires whenever `heredoc_feeds` recognises the consumer,
/// independent of it — so a dangerous body (verified across 13 probed
/// shapes, listed in task-2-report.md) still reaches its guard regardless of
/// the desync, and no wrong ALLOW was reproducible through this path. What
/// the desync actually breaks is `guards::holds_input`, which the
/// mismatch always drives toward FALSE for a command with a preceding
/// sibling — the `evaluated_input` construct then fires even though the
/// input genuinely was scanned, which is a wrong ASK on an otherwise
/// benign, already-verbatim-read body. Probed live: with a benign here-doc
/// body and `evaluated_input` named (so a suppressed-vs-fired construct is
/// visible rather than masked by inheritance), a lone nested consumer
/// allows — matching the top-level case — and the identical consumer with
/// one silent sibling ahead of it asks instead, solely because of the
/// desync.
#[test]
fn m2_127_nested_heredoc_sibling_desyncs_the_index() {
    let cfg = common::realistic_config_with_construct("bash", "evaluated_input", Action::Ask);
    let nested_no_sibling = "bash -c 'bash <<B\nls\nB'";
    let nested_with_sibling = "bash -c 'cat <<A\nsib\nA\nbash <<B\nls\nB'";
    assert_pair(&cfg, OUTSIDE, nested_no_sibling, nested_with_sibling, "allow", None);
}

// ============================================================================
// M2.128 — the attached spelling of a write flag derives NO destination at
// all, on every entry that names one
// ============================================================================

#[test]
fn m2_128_curl_output_attached_forms() {
    let cfg = common::realistic_config();
    let base = format!("curl --output {OUTSIDE}/p u");
    assert_pair(&cfg, INSIDE, &base, &format!("curl --output={OUTSIDE}/p u"), "ask", Some("write"));
    assert_pair(&cfg, INSIDE, &base, &format!("curl -o{OUTSIDE}/p u"), "ask", Some("write"));
}

#[test]
fn m2_128_sort_output_attached_form() {
    let cfg = common::realistic_config();
    let base = format!("sort --output {OUTSIDE}/p f");
    assert_pair(&cfg, INSIDE, &base, &format!("sort --output={OUTSIDE}/p f"), "ask", None);
}

#[test]
fn m2_128_cp_target_directory_attached_form() {
    let cfg = common::realistic_config();
    let base = format!("cp --target-directory {OUTSIDE} a");
    assert_pair(&cfg, INSIDE, &base, &format!("cp --target-directory={OUTSIDE} a"), "ask", None);
}

#[test]
fn m2_128_tar_directory_attached_form() {
    let cfg = common::realistic_config();
    let base = format!("tar --directory {OUTSIDE} -xf a.tar");
    assert_pair(&cfg, INSIDE, &base, &format!("tar --directory={OUTSIDE} -xf a.tar"), "ask", None);
}

#[test]
fn m2_128_unzip_dash_d_joined_form() {
    let cfg = common::realistic_config();
    let base = format!("unzip -d {OUTSIDE} a.zip");
    assert_pair(&cfg, INSIDE, &base, &format!("unzip -d{OUTSIDE} a.zip"), "ask", None);
}

#[test]
fn m2_128_wget_output_document_attached_form() {
    let cfg = common::realistic_config();
    let base = format!("wget --output-document {OUTSIDE}/p u");
    assert_pair(&cfg, INSIDE, &base, &format!("wget --output-document={OUTSIDE}/p u"), "ask", None);
}

/// PowerShell writer family: full name, abbreviated, and colon-attached.
#[test]
fn m2_128_powershell_writer_family_spellings() {
    let cfg = common::realistic_config();
    let base = format!("Set-Content -Path {OUTSIDE}/p -Value v");
    assert_pair(&cfg, INSIDE, &base, &format!("Set-Content -Path:{OUTSIDE}/p -Value v"), "ask", None);
    assert_pair(&cfg, INSIDE, &base, &format!("Set-Content -pa {OUTSIDE}/p -Value v"), "ask", None);
}

/// PS positional spelling: the destination is already correctly derived
/// from the path parameter's own positional, not the content — a regression
/// floor confirming that reading holds.
#[test]
fn m2_128_powershell_positional_derives_path_not_content() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, INSIDE, &format!("Set-Content {OUTSIDE}/p"), "ask", None);
}

// ============================================================================
// M2.129 — a destination that is simply the current directory is never
// derived, so the commonest download-and-extract spellings are unjudged
// ============================================================================

#[test]
fn m2_129_tar_extract_into_cwd_unjudged() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "tar -xf a.tar", "ask", None);
}

#[test]
fn m2_129_tar_extract_explicit_dot_matches_implicit_cwd() {
    let cfg = common::realistic_config();
    assert_pair(&cfg, OUTSIDE, "tar -xf a.tar", "tar -xf a.tar -C .", "ask", None);
}

#[test]
fn m2_129_curl_wget_unzip_ln_into_cwd_unjudged() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "curl -O u", "ask", None);
    assert_verdict(&cfg, OUTSIDE, "wget u", "ask", None);
    assert_verdict(&cfg, OUTSIDE, "unzip a.zip", "ask", None);
    assert_verdict(&cfg, OUTSIDE, "ln -s t", "ask", None);
}

/// `ln` is wrong twice over: its declared write position derives the
/// SOURCE, so a source inside an allowed tree wrongly carries the allow for
/// a link created anywhere — judged by the LINK path, never the target.
#[test]
fn m2_129_ln_judged_by_link_path_not_target() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, &format!("ln -s {INSIDE}/t {OUTSIDE}/l"), "ask", None);
}

/// The run-dir flag composes the place the same way a `cd` does (§3.2.5).
#[test]
fn m2_129_run_dir_flag_composes_place_like_cd() {
    let cfg = common::realistic_config();
    assert_pair(
        &cfg, OUTSIDE,
        &format!("cd {INSIDE} && tar -xf a.tar"),
        &format!("env -C {INSIDE} tar -xf a.tar"),
        "allow", None,
    );
}

// ============================================================================
// M2.130 — a directory change on the RIGHT of `&&` is folded into the run
// place as though certain; `&&`'s conditional twin `||` needs the same care
// ============================================================================

/// Execution implies the `cd` succeeded — stays allow (today-pinned shape,
/// bash_writes_test.rs:667).
#[test]
fn m2_130_and_chain_write_after_cd_stays_allow() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, &format!("ls && cd {INSIDE} && echo x > f"), "allow", None);
}

/// The write does not imply the `cd` succeeded once separated by `;`.
#[test]
fn m2_130_semicolon_after_cd_does_not_imply_success() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, &format!("ls && cd {INSIDE}; echo x > f"), "ask", None);
}

/// An unconditional mover AFTER a conditional one does not launder it: the
/// state it composes already carries the conditional directory, so the write
/// still lands somewhere the shell may never have reached. Found by the task
/// review, which reproduced the allow.
#[test]
fn m2_130_unconditional_mover_does_not_launder_a_conditional_one() {
    let cfg = common::realistic_config();
    assert_verdict(
        &cfg,
        OUTSIDE,
        &format!("ls && cd {INSIDE}; cd sub; echo x > f"),
        "ask",
        None,
    );
}

/// The other half of the same rule: a later change that STANDS ON ITS OWN —
/// an absolute destination, composing against nothing — ends the uncertainty,
/// because where the shell had got to stops mattering. Found by the round-2
/// verifier, which measured the over-reach as a false ask.
#[test]
fn m2_130_an_absolute_mover_clears_an_earlier_conditional_one() {
    let cfg = common::realistic_config();
    assert_verdict(
        &cfg,
        OUTSIDE,
        &format!("ls && cd {OUTSIDE}/other; cd {INSIDE}; echo x > f"),
        "allow",
        None,
    );
}

/// `>&<name>` is not a descriptor duplication — with a NAME there it is
/// bash's own spelling for "send both streams to this file", and it creates
/// the file (verified by running). It reached even a protected path, which
/// CLAUDE.md section 5 says no rule can open. Found by a blind adversarial
/// pass; the defect predates this branch.
#[test]
fn m2_131_ampersand_redirect_to_a_name_is_a_write() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "echo x >& f", "ask", Some("write"));
    // The real duplication spellings stay what they are.
    assert_verdict(&cfg, OUTSIDE, "echo x >&2", "allow", None);
    assert_verdict(&cfg, OUTSIDE, "echo x >&-", "allow", None);
}

/// Mixed-chain pin (round 2): the write runs exactly when the earlier `cd`
/// FAILED, so this must not fold to allow.
#[test]
fn m2_130_or_chain_write_runs_only_on_cd_failure() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, &format!("ls && cd {INSIDE} || echo x > f"), "ask", None);
}

/// Unconditional mover — stays allow (today-pinned shape, bash_writes_test.rs:782).
#[test]
fn m2_130_unconditional_cd_then_write_stays_allow() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, &format!("cd {INSIDE}; echo x > f"), "allow", None);
}

/// The PowerShell twin of the semicolon-after-`cd` split, once §3.4.2 lands.
#[test]
fn m2_130_powershell_and_twin_of_semicolon_split() {
    let cfg = common::realistic_config();
    let semicolon = format!(r#"powershell -Command "Set-Location {INSIDE}; echo x > f""#);
    let and_and = format!(r#"powershell -Command "Set-Location {INSIDE} && echo x > f""#);
    assert_pair(&cfg, OUTSIDE, &semicolon, &and_and, "ask", None);
}

// ============================================================================
// M2.131 — the walls and the protected list can be evaded by spellings the
// filesystem folds and vouch compares as text; link resolution answers only
// for files that already exist
// ============================================================================

/// A directory junction whose target sits outside every allowed tree, with
/// the junction itself created INSIDE the allowed tree — so the write is
/// textually allowed and resolved-outside. `#[cfg(windows)]`: uses
/// `cmd /c mklink /J`, panics (not skips) on fixture failure, and removes
/// the fixtures on the way out via a drop guard.
#[cfg(windows)]
mod m2_131_junction {
    use super::*;

    struct JunctionFixture {
        junction_dir: std::path::PathBuf,
        target_dir: std::path::PathBuf,
        link: std::path::PathBuf,
    }

    impl JunctionFixture {
        fn build() -> Self {
            let junction_dir = std::path::PathBuf::from("C:/tmp/vouch_boundary_junction");
            let target_dir = std::env::temp_dir().join("vouch_boundary_junction_target");
            std::fs::create_dir_all(&junction_dir)
                .unwrap_or_else(|e| panic!("could not create {}: {e}", junction_dir.display()));
            std::fs::create_dir_all(&target_dir)
                .unwrap_or_else(|e| panic!("could not create {}: {e}", target_dir.display()));
            let link = junction_dir.join("link");
            // Clean a leftover link from a previous aborted run before
            // re-creating it — mklink refuses to overwrite one that exists.
            let _ = std::fs::remove_dir(&link);
            // mklink is a cmd built-in that treats `/` inside a path as an
            // attempted SWITCH ("Invalid switch") rather than a separator —
            // it wants backslashes, unlike vouch's own path handling.
            let backslash = |p: &std::path::Path| p.to_string_lossy().replace('/', "\\");
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(backslash(&link))
                .arg(backslash(&target_dir))
                .status()
                .unwrap_or_else(|e| panic!("could not run mklink: {e}"));
            assert!(status.success(), "mklink /J failed to build the junction fixture");
            JunctionFixture { junction_dir, target_dir, link }
        }
    }

    impl Drop for JunctionFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.link);
            let _ = std::fs::remove_dir_all(&self.target_dir);
            let _ = std::fs::remove_dir_all(&self.junction_dir);
        }
    }

    /// A write through the junction to a NOT-YET-EXISTING file is allowed
    /// today (canonicalize fails on the absent leaf and falls back to the
    /// written, textually-inside form); the same write once the file
    /// exists already asks — a real red-to-green once link resolution
    /// walks to the deepest EXISTING ancestor (T19).
    #[test]
    fn m2_131_write_through_junction_to_new_file() {
        let fx = JunctionFixture::build();
        let cfg = common::realistic_config();
        let new_file_cmd = format!("echo x > {}/newfile.txt", fx.link.to_string_lossy().replace('\\', "/"));
        assert_verdict(&cfg, OUTSIDE, &new_file_cmd, "ask", None);

        // The existing-target case already resolves outside and asks —
        // confirms the two spellings are compared against the SAME link.
        let existing = fx.target_dir.join("already-there.txt");
        std::fs::write(&existing, b"x").expect("seed the existing-target file");
        let existing_cmd = format!("echo x > {}/already-there.txt", fx.link.to_string_lossy().replace('\\', "/"));
        assert_verdict(&cfg, OUTSIDE, &existing_cmd, "ask", None);
    }
}

/// A trailing dot on a path component — Windows strips it, vouch compares
/// text, so a walled tree is walked into by a not-yet-existing target.
/// Built via `vouch::config::load` with a `write.deny_paths` wall over a
/// fixture tree (only one `[write]` table can exist per config text, so
/// this is hand-written rather than layered on `config_text_with`).
#[test]
#[cfg(windows)]
fn m2_131_trailing_dot_evades_the_wall() {
    let text = r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
parse_failure = "ask"
[write]
default = "ask"
allow_paths = ["C:/tmp/**"]
deny_paths = ["C:/tmp/vouch_boundary_walltest/**"]
"#;
    let cfg = vouch::config::load(text).expect("wall config parses");
    let plain = "echo x > C:/tmp/vouch_boundary_walltest/f";
    let trailing_dot = "echo x > C:/tmp/vouch_boundary_walltest./f";
    assert_pair(&cfg, OUTSIDE, plain, trailing_dot, "deny", None);
}

/// Off Windows the trailing-dot spelling names a DIFFERENT directory - the
/// collapse is a Windows filesystem semantic (src/paths.rs, `collapse`) -
/// so the wall holds for the plain spelling and the dotted one is an
/// ordinary allowed write under the C:/tmp/** allow rule.
#[test]
#[cfg(not(windows))]
fn m2_131_trailing_dot_is_a_distinct_directory_off_windows() {
    let text = r#"
version = 1
[lang.bash]
default = "allow"
[lang.bash.constructs]
unmodeled_command = "allow"
parse_failure = "ask"
[write]
default = "ask"
allow_paths = ["C:/tmp/**"]
deny_paths = ["C:/tmp/vouch_boundary_walltest/**"]
"#;
    let cfg = vouch::config::load(text).expect("wall config parses");
    let (plain, _) = decision_at(&cfg, "echo x > C:/tmp/vouch_boundary_walltest/f", OUTSIDE);
    let (dotted, _) = decision_at(&cfg, "echo x > C:/tmp/vouch_boundary_walltest./f", OUTSIDE);
    assert_eq!(plain, "deny");
    assert_eq!(dotted, "allow");
}

/// A PowerShell/cmd drive-relative destination (`C:name`) must never be
/// rewritten to the drive root — resolved against the run place on that
/// drive, or unresolvable, but not silently the root.
#[test]
fn m2_131_drive_relative_never_resolves_to_drive_root() {
    let cfg = common::realistic_config();
    let (decision, reason) = decision_at(&cfg, "echo x > C:name", OUTSIDE);
    assert_eq!(decision, "ask");
    assert!(
        !reason.contains("C:/name"),
        "a drive-relative destination must not be silently read as the drive root: {reason}"
    );
}

/// CORRECTED against the design it encodes (§6.2.3), which says the global
/// remote-spec skip is REPLACED by per-entry data and that "for everyone
/// else a destination reaching that branch is judged as a write to the
/// pre-colon base path". This pin previously asserted the opposite — that
/// `cp a file:stream` ALLOWS, i.e. that the skip applies to every program —
/// which is the defect M2.131.4 names: on NTFS that spelling writes an
/// alternate data stream attached to `file`, a real local write, and `cp`
/// is not a program whose destinations are ever remote.
///
/// So the claim is: judged, not skipped, and judged as a write to the file
/// the stream hangs off — which is also the path an operator could add to an
/// allow list, unlike a spelling with a stream suffix on the end.
#[test]
fn m2_131_colon_destination_is_judged_for_a_local_writer() {
    let cfg = common::realistic_config();
    let (decision, reason) = decision_at(&cfg, "cp a file:stream", OUTSIDE);
    assert_eq!(decision, "ask", "{reason}");
    assert!(
        reason.contains("C:/outside/of/every/allowed/tree/file")
            && !reason.contains("file:stream"),
        "the write is judged against the file the stream hangs off: {reason}"
    );
}

/// `scp`'s own declared-remote destination (`host:d`, no `user@`) must keep
/// being read as remote and skipped, not composed as a local relative path.
#[test]
fn m2_131_scp_declared_remote_destination() {
    let cfg = common::realistic_config();
    assert_verdict(&cfg, OUTSIDE, "scp f host:d", "allow", None);
}
