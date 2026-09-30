//! Tests for container volume bind mount path evaluation.

mod common;

use common::{realistic_config, realistic_config_with};
use vouch::engine::decide_command_in;
use vouch::guards::{in_effect, written_paths_in};
use vouch::protocol::Decision;
use vouch::shell::parse;

fn parse_first_cmd(cmd_str: &str) -> vouch::shell::Cmd {
    parse(cmd_str).expect("shell parses").commands.into_iter().next().expect("has command")
}

#[test]
fn container_volume_derives_host_paths_from_short_flag() {
    let kb = in_effect();
    let cmd = parse_first_cmd("docker run -v /tmp/scratch:/workspace:rw alpine touch /workspace/file");

    let targets = written_paths_in(kb, &cmd, "bash");
    assert_eq!(targets.paths, vec!["/tmp/scratch".to_string()]);
}

#[test]
fn container_volume_ignores_readonly_mounts_from_writes() {
    let kb = in_effect();
    let cmd = parse_first_cmd("docker run -v /etc/hosts:/etc/hosts:ro alpine cat /etc/hosts");

    let targets = written_paths_in(kb, &cmd, "bash");
    assert!(targets.paths.is_empty(), "readonly mount should not derive write paths");
}

#[test]
fn container_volume_ignores_named_volumes() {
    let kb = in_effect();
    let cmd = parse_first_cmd("docker run -v my_named_volume:/app alpine ls");

    let targets = written_paths_in(kb, &cmd, "bash");
    assert!(targets.paths.is_empty(), "named volume should not derive host write paths");
}

#[test]
fn container_volume_parses_mount_flag_syntax() {
    let kb = in_effect();
    let cmd = parse_first_cmd("docker run --mount type=bind,source=/tmp/scratch,target=/app alpine touch /app/test");

    let targets = written_paths_in(kb, &cmd, "bash");
    assert_eq!(targets.paths, vec!["/tmp/scratch".to_string()]);
}

#[test]
fn container_volume_podman_parity() {
    let kb = in_effect();
    let cmd = parse_first_cmd("podman run -v /tmp/scratch:/data alpine echo hi");

    let targets = written_paths_in(kb, &cmd, "bash");
    assert_eq!(targets.paths, vec!["/tmp/scratch".to_string()]);
}

#[test]
fn container_volume_engine_allows_allowed_path() {
    let cfg = realistic_config();
    let scratch = common::t("/tmp/scratch");
    let cmd = format!("docker run -v {scratch}:/app:rw alpine touch /app/x");
    let decision = decide_command_in(
        &cfg,
        "bash",
        &cmd,
        Some("C:/Users/dev"),
        None,
    );
    assert!(
        matches!(decision, Decision::Allow(_)),
        "expected allow on {scratch} mount, got: {decision:?}"
    );
}

#[test]
fn container_volume_engine_halts_on_protected_path() {
    let cfg = realistic_config_with("[protected]\npaths = [\"C:/Users/dev/.config/vouch/config.toml\"]\n");
    let decision = decide_command_in(
        &cfg,
        "bash",
        "docker run -v C:/Users/dev/.config/vouch/config.toml:/vouch/config.toml:rw alpine touch /vouch/config.toml",
        Some("C:/Users/dev"),
        None,
    );
    match decision {
        Decision::Ask(explanation) => {
            assert!(
                explanation.contains("protected") || explanation.contains("config.toml") || explanation.contains("vouch"),
                "expected protected path ask, got: {explanation}"
            );
        }
        other => panic!("expected ask on protected path, got: {other:?}"),
    }
}
