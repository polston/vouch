//! Tests for automated grammar-driven synthetic shape permutations.
//!
//! Verifies panic-freedom, Section 5 prompt-names-setting invariant, and
//! guard firing consistency across generated structural permutations.

mod common;

use common::generator::SyntheticGenerator;
use common::realistic_config;
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;

#[test]
fn generate_and_verify_synthetic_grammar_corpus_fixture() {
    let mut gen = SyntheticGenerator::new(42);
    let rows = gen.generate_batch(500);

    // Verify fixture output
    assert_eq!(rows.len(), 500);
    for r in &rows {
        assert!(!r.cmd.is_empty(), "command cannot be empty");
        assert!(r.verdict == "allow" || r.verdict == "ask");
    }

    // Write fixture if not present or during test generation
    let fixture_path = common::repo_path("tests/fixtures/synthetic_grammar_corpus.json");
    let json = serde_json::to_string_pretty(&rows).expect("serialize rows");
    std::fs::write(&fixture_path, json).expect("write synthetic grammar corpus fixture");
}

#[test]
fn synthetic_permutations_never_panic() {
    let cfg = realistic_config();
    let mut gen = SyntheticGenerator::new(1337);
    let batch = gen.generate_batch(1000);

    for item in batch {
        let cwd = item.cwd.as_deref().unwrap_or("C:/Users/dev");
        let _ = decide_command_in(&cfg, "bash", &item.cmd, Some(cwd), None);
    }
}

#[test]
fn synthetic_permutations_every_ask_names_setting() {
    let cfg = realistic_config();
    let mut gen = SyntheticGenerator::new(2026);
    let batch = gen.generate_batch(500);

    for item in batch {
        let cwd = item.cwd.as_deref().unwrap_or("C:/Users/dev");
        let decision = decide_command_in(&cfg, "bash", &item.cmd, Some(cwd), None);
        if let Decision::Ask(explanation) = decision {
            assert!(
                explanation.contains("setting: ") || explanation.contains("what that means: "),
                "Ask decision on `{}` must explain cause or name setting: {}",
                item.cmd,
                explanation
            );
        }
    }
}

#[test]
fn synthetic_guard_permutations_consistently_fire() {
    let cfg = realistic_config();
    let mut gen = SyntheticGenerator::new(9999);

    // Generate destructive guard commands specifically
    for _ in 0..100 {
        let cmd = gen.generate_one();
        if cmd.cmd.starts_with("rm -") || cmd.cmd.starts_with("git reset --hard") || cmd.cmd.starts_with("git push --force") {
            let cwd = cmd.cwd.as_deref().unwrap_or("C:/Users/dev");
            let decision = decide_command_in(&cfg, "bash", &cmd.cmd, Some(cwd), None);
            match decision {
                Decision::Ask(explanation) => {
                    assert!(
                        explanation.contains("guard") || explanation.contains("history_rewrite") || explanation.contains("delete_recursive"),
                        "Command `{}` must trigger guard, got explanation: {}",
                        cmd.cmd,
                        explanation
                    );
                }
                Decision::Deny(reason) => {
                    // Deny is also an acceptable protective outcome
                    assert!(!reason.is_empty());
                }
                Decision::Allow(_) | Decision::Abstain => {
                    panic!("Destructive command `{}` must not be Allowed or Abstained!", cmd.cmd);
                }
            }
        }
    }
}
