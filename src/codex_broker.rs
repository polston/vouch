//! MCP server invoked after Codex's native tool approval to turn a redacted
//! pending vouch request into an exact one-use retry grant. It cannot create
//! policy or widen a call; [`crate::approval`] validates and binds the grant.

use std::path::PathBuf;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router, ErrorData};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::approval::{respond, ApprovalAction};

#[derive(Debug, Deserialize, JsonSchema)]
struct ApprovalParameters {
    /// The opaque request id printed by vouch's blocked hook response.
    request_id: String,
}

#[derive(Debug, Clone)]
pub struct ApprovalServer {
    state_dir: PathBuf,
}

impl ApprovalServer {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }
}

#[tool_router(server_handler)]
impl ApprovalServer {
    #[tool(
        name = "request_approval",
        description = "Approve one exact retry of the tool call named by the preceding vouch block"
    )]
    async fn request_approval(
        &self,
        Parameters(ApprovalParameters { request_id }): Parameters<ApprovalParameters>,
    ) -> Result<String, ErrorData> {
        let now = crate::journal::now_epoch_secs()
            .parse::<u64>()
            .unwrap_or_default();
        respond(&self.state_dir, &request_id, ApprovalAction::Accept, now)
            .map_err(|error| ErrorData::invalid_params(error, None))?;

        Ok("approved one exact retry; retry the unchanged tool call now".into())
    }
}
