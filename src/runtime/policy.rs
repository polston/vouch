//! Policy evaluation for runtime filesystem events (M5.3).

use crate::config::Config;
use crate::paths::glob_match;
use super::{ExecutionTrace, FilesystemEvent};

/// Evaluates a sequence of captured runtime filesystem events against policy.
pub fn evaluate_trace(events: &[FilesystemEvent], cfg: &Config) -> ExecutionTrace {
    let mut unpermitted_writes = Vec::new();
    let allow_patterns = &cfg.write.allow_paths;
    let protected_patterns = &cfg.protected;

    for ev in events {
        if !ev.is_write {
            continue;
        }

        let path_str = ev.path.to_string_lossy();

        // 1. Protected paths take precedence over everything
        let is_protected = protected_patterns.iter().any(|pat| {
            glob_match(pat, &path_str) || path_str.starts_with(pat)
        });

        if is_protected {
            unpermitted_writes.push(ev.path.clone());
            continue;
        }

        // 2. Allow paths verification
        let is_allowed = allow_patterns.iter().any(|pat| {
            glob_match(pat, &path_str)
        });

        if !is_allowed {
            unpermitted_writes.push(ev.path.clone());
        }
    }

    let passed = unpermitted_writes.is_empty();
    ExecutionTrace {
        events: events.to_vec(),
        unpermitted_writes,
        passed,
    }
}
