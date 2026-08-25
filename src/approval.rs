//! One-time human approval for Codex hosts that cannot return `ask` from a
//! PreToolUse hook.
//!
//! The first attempt is blocked and creates a redacted request. The approval
//! broker runs only after Codex's native MCP approval, then one
//! byte-for-byte-equivalent call in the same session and turn may consume the
//! grant. Nothing reusable is minted.

use crate::journal::{append_outcome, OutcomeRecord};
use crate::outcome::Outcome;
use crate::protocol::HookInput;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const GRANT_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResult {
    Pending { request_id: String },
    Granted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAction {
    Accept,
    Decline,
    Cancel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRequest {
    request_id: String,
    fingerprint: String,
    original_id: String,
    created_at: u64,
    tool: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Grant {
    fingerprint: String,
    original_id: String,
    accepted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestSummary {
    pub request_id: String,
    pub tool: String,
    pub reason: String,
    pub created_at: u64,
}

fn approvals_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("approvals")
}

fn hash(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn fingerprint(input: &HookInput) -> String {
    let tool_input = serde_json::to_string(&input.tool_input.extra).unwrap_or_default();
    hash(&[
        &input.session_id,
        &input.turn_id,
        &input.cwd,
        &input.tool_name,
        input.tool_input.command.as_deref().unwrap_or_default(),
        input.tool_input.file_path.as_deref().unwrap_or_default(),
        input.tool_input.url.as_deref().unwrap_or_default(),
        &tool_input,
    ])
}

fn pending_path(dir: &Path, request_id: &str) -> PathBuf {
    dir.join(format!("pending-{request_id}.json"))
}

fn validate_request_id(request_id: &str) -> Result<(), String> {
    let suffix = request_id
        .strip_prefix("vouch-")
        .ok_or_else(|| "invalid request id".to_string())?;
    if suffix.len() != 20
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid request id".into());
    }
    Ok(())
}

fn grant_path(dir: &Path, fingerprint: &str) -> PathBuf {
    dir.join(format!("grant-{fingerprint}.json"))
}

fn alias_path(dir: &Path, retry_id: &str) -> PathBuf {
    dir.join(format!("alias-{}.json", hash(&[retry_id])))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("approval state path has no parent")?;
    fs::create_dir_all(parent).map_err(|e| format!("could not create approval state: {e}"))?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    fs::write(&tmp, bytes).map_err(|e| format!("could not write approval state: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("could not commit approval state: {e}"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|e| format!("could not read approval state: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("approval state is invalid: {e}"))
}

fn reason_summary(reason: &str) -> String {
    reason
        .lines()
        .next()
        .unwrap_or("vouch requested approval")
        .chars()
        .take(160)
        .collect()
}

/// Check for one exact grant, consuming it when present; otherwise create a
/// redacted request for the broker. The input itself is only hashed.
pub fn gate(
    state_dir: &Path,
    input: &HookInput,
    reason: &str,
    now: u64,
) -> Result<GateResult, String> {
    if input.session_id.trim().is_empty() {
        return Err("Codex approval requires a non-empty session_id".into());
    }
    if input.turn_id.trim().is_empty() {
        return Err("Codex approval requires a non-empty turn_id".into());
    }
    let dir = approvals_dir(state_dir);
    fs::create_dir_all(&dir).map_err(|e| format!("could not create approval state: {e}"))?;
    let fingerprint = fingerprint(input);
    let grant_file = grant_path(&dir, &fingerprint);
    if grant_file.exists() {
        let grant: Grant = read_json(&grant_file)?;
        let fresh = now >= grant.accepted_at && now - grant.accepted_at <= GRANT_TTL_SECS;
        if grant.fingerprint == fingerprint && fresh {
            fs::remove_file(&grant_file)
                .map_err(|e| format!("could not consume approval grant: {e}"))?;
            write_json(&alias_path(&dir, &input.tool_use_id), &grant.original_id)?;
            return Ok(GateResult::Granted);
        }
        let _ = fs::remove_file(&grant_file);
    }

    let request_id = format!("vouch-{}", &fingerprint[..20]);
    let request = PendingRequest {
        request_id: request_id.clone(),
        fingerprint,
        original_id: input.tool_use_id.clone(),
        created_at: now,
        tool: input.tool_name.clone(),
        reason: reason_summary(reason),
    };
    write_json(&pending_path(&dir, &request_id), &request)?;
    Ok(GateResult::Pending { request_id })
}

pub fn request_summary(state_dir: &Path, request_id: &str) -> Result<RequestSummary, String> {
    validate_request_id(request_id)?;
    let request: PendingRequest = read_json(&pending_path(&approvals_dir(state_dir), request_id))?;
    Ok(RequestSummary {
        request_id: request.request_id,
        tool: request.tool,
        reason: request.reason,
        created_at: request.created_at,
    })
}

/// Resolve one pending request. Accept creates an expiring exact-retry grant;
/// decline records a real denied outcome for the original blocked attempt.
pub fn respond(
    state_dir: &Path,
    request_id: &str,
    action: ApprovalAction,
    now: u64,
) -> Result<(), String> {
    validate_request_id(request_id)?;
    let dir = approvals_dir(state_dir);
    let path = pending_path(&dir, request_id);
    let request: PendingRequest = read_json(&path)?;
    match action {
        ApprovalAction::Accept => write_json(
            &grant_path(&dir, &request.fingerprint),
            &Grant {
                fingerprint: request.fingerprint,
                original_id: request.original_id,
                accepted_at: now,
            },
        )?,
        ApprovalAction::Decline => append_outcome(
            state_dir,
            &OutcomeRecord {
                id: request.original_id,
                outcome: Outcome::Denied,
                detail: "declined through the Codex approval broker".into(),
                host: "codex".into(),
            },
        )
        .map_err(|e| format!("could not record declined approval: {e}"))?,
        ApprovalAction::Cancel => {}
    }
    fs::remove_file(path).map_err(|e| format!("could not close approval request: {e}"))
}

/// Return and remove the original blocked call id associated with a granted
/// retry, so PostToolUse can close both journal rows with the same outcome.
pub fn take_outcome_alias(state_dir: &Path, retry_id: &str) -> Result<Option<String>, String> {
    let path = alias_path(&approvals_dir(state_dir), retry_id);
    if !path.exists() {
        return Ok(None);
    }
    let original: String = read_json(&path)?;
    fs::remove_file(path).map_err(|e| format!("could not consume outcome alias: {e}"))?;
    Ok(Some(original))
}
