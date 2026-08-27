//! On-demand, counts-only census for program-location recognition (M2.71).
//!
//! The real corpus is private. This example therefore prints a fixed list of
//! aggregate keys and decimal counts only: never command text, program names,
//! cwd values, executable paths, journal payloads, environment values, or
//! samples. Classification comes from the engine's actual scanner, wrapper
//! expansion, run-place timeline, existing-file resolver, and retained
//! `ProgramTrustAnswer`; no regex or verdict proxy participates.
//!
//! With no override, it uses the standing replay config and should report zero
//! matches because that config deliberately has no `run.trust_program` rule.
//! For a private positive probe, set `VOUCH_PROGRAM_LOCATION_CONFIG` to a
//! scratch TOML file. Its path and contents are never printed.
//! `VOUCH_PROGRAM_LOCATION_ONLY_ASKS=1` limits the same fixed report to corpus
//! rows whose recorded verdict was ask; the verdict and source never print.
//!
//! Run: cargo run --release --example count_program_location_shapes

#[path = "../tests/common/mod.rs"]
mod common;

use vouch::engine::ProgramLocationMeasurement;

pub fn render_counts(
    cfg: &vouch::config::Config,
    commands: &[String],
    home: &str,
    project_root: Option<&str>,
    cwd: Option<&str>,
) -> String {
    let mut total = ProgramLocationMeasurement::default();
    for command in commands {
        total.add(vouch::engine::measure_program_locations(
            cfg,
            "bash",
            command,
            home,
            project_root,
            cwd,
        ));
    }
    format!(
        concat!(
            "rows_total={}\n",
            "rows_scanned={}\n",
            "eligible_path_spelled_occurrences={}\n",
            "proven_existing_files={}\n",
            "matching_both_clauses={}\n",
            "unproven_unresolved_head={}\n",
            "unproven_unknown_run_place={}\n",
            "unproven_no_run_directory={}\n",
            "unproven_missing_file={}\n",
            "unproven_not_regular_file={}\n",
            "unproven_canonicalization_failed={}\n",
            "unresolved_residual={}\n",
        ),
        total.rows_total,
        total.rows_scanned,
        total.eligible_path_spelled_occurrences,
        total.proven_existing_files,
        total.matching_both_clauses,
        total.unproven_unresolved_head,
        total.unproven_unknown_run_place,
        total.unproven_no_run_directory,
        total.unproven_missing_file,
        total.unproven_not_regular_file,
        total.unproven_canonicalization_failed,
        total.unresolved_residual,
    )
}

fn measurement_config() -> vouch::config::Config {
    let Some(path) = std::env::var_os("VOUCH_PROGRAM_LOCATION_CONFIG") else {
        return common::realistic_config();
    };
    let text = std::fs::read_to_string(path).unwrap_or_else(|_| {
        panic!("VOUCH_PROGRAM_LOCATION_CONFIG could not be read; its value is withheld")
    });
    vouch::config::load(&text).unwrap_or_else(|_| {
        panic!(
            "VOUCH_PROGRAM_LOCATION_CONFIG did not contain valid config; its contents are withheld"
        )
    })
}

fn main() {
    let only_asks = std::env::var("VOUCH_PROGRAM_LOCATION_ONLY_ASKS").as_deref() == Ok("1");
    let rows = common::rows_for_measurement();
    let commands: Vec<String> = rows
        .into_iter()
        .filter(|row| !only_asks || row.verdict.eq_ignore_ascii_case("ask"))
        .map(|row| row.cmd)
        .collect();
    let project_root = std::env::var("CARGO_MANIFEST_DIR").ok();
    print!(
        "{}",
        render_counts(
            &measurement_config(),
            &commands,
            common::HOOK_HOME,
            project_root.as_deref(),
            None,
        )
    );
}
