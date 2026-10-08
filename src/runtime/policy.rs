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

/// Evaluates a single borrowed trace event directly against policy without heap allocations.
pub fn evaluate_event_borrowed(ev: &super::ebpf::BorrowedTraceEvent<'_>, cfg: &Config) -> bool {
    if !ev.is_write {
        return true;
    }

    let path_str = ev.filename;
    let protected_patterns = &cfg.protected;
    let allow_patterns = &cfg.write.allow_paths;

    // 1. Protected paths take precedence over everything
    let is_protected = protected_patterns.iter().any(|pat| {
        glob_match(pat, path_str) || path_str.starts_with(pat)
    });

    if is_protected {
        return false;
    }

    // 2. Allow paths verification
    let is_allowed = allow_patterns.iter().any(|pat| {
        glob_match(pat, path_str)
    });

    is_allowed
}

/// Evaluates an iterator of borrowed trace events against policy.
pub fn evaluate_trace_zero_copy<'a, I>(events: I, cfg: &Config) -> ExecutionTrace
where
    I: IntoIterator<Item = super::ebpf::BorrowedTraceEvent<'a>>,
{
    let mut unpermitted_writes = Vec::new();
    let mut fs_events = Vec::new();

    for ev in events {
        let is_allowed = evaluate_event_borrowed(&ev, cfg);
        let path = std::path::PathBuf::from(ev.filename);
        if !is_allowed {
            unpermitted_writes.push(path.clone());
        }
        fs_events.push(FilesystemEvent {
            pid: ev.pid,
            syscall: match ev.syscall_nr {
                257 | 56 => "openat".to_string(),
                263 | 35 => "unlinkat".to_string(),
                264 | 38 | 316 | 276 => "renameat".to_string(),
                _ => "unknown".to_string(),
            },
            path,
            is_write: ev.is_write,
        });
    }

    let passed = unpermitted_writes.is_empty();
    ExecutionTrace {
        events: fs_events,
        unpermitted_writes,
        passed,
    }
}
