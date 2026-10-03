//! Interactive Terminal UI & Policy Guided Correction (`vouch tui` / `vouch review --interactive`).
//!
//! Provides interactive terminal navigation for journal decisions, candidate rule inspection,
//! side-by-side TOML delta previews, and single-keystroke policy approval.

pub mod app;
pub mod backend;
pub mod engine;

pub use app::{AppStatus, TuiApp, ViewTab};
pub use backend::{ConsoleBackend, MockTerminalBackend, TerminalBackend, TerminalEvent, KeyCode};
pub use engine::{DecisionItem, ReviewCandidate, TuiEngine};

/// Launch interactive review session on the active terminal.
pub fn launch_interactive(home_dir: &str) -> Result<(), String> {
    let engine = TuiEngine::load(home_dir);
    let mut app = TuiApp::new(engine);
    let backend = ConsoleBackend::stdout();
    app.run_loop(backend)
}
