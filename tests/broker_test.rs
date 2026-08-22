use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientInfo, Implementation};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::json;
use vouch::approval::{gate, GateResult};
use vouch::protocol::parse_input;

#[derive(Clone, Default)]
struct NativeApprovalClient;

impl ClientHandler for NativeApprovalClient {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("vouch-test-client", "0.0.0"),
        )
    }
}

#[tokio::test]
async fn native_tool_approval_mints_only_the_pending_exact_retry_without_elicitation() {
    let dir = std::env::temp_dir().join(format!("vouch_broker_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let first = parse_input(
        r#"{"session_id":"test-session","turn_id":"test-turn","tool_use_id":"first","cwd":"C:/Users/dev","tool_name":"Bash","tool_input":{"command":"Remove-Item notes.txt"}}"#,
    )
    .unwrap();
    let now = vouch::journal::now_epoch_secs().parse::<u64>().unwrap();
    let request_id = match gate(&dir, &first, "vouch stopped on: write", now).unwrap() {
        GateResult::Pending { request_id } => request_id,
        other => panic!("got {other:?}"),
    };

    let (server_transport, client_transport) = tokio::io::duplex(4096);
    let server_dir = dir.clone();
    let server = tokio::spawn(async move {
        vouch::codex_broker::ApprovalServer::new(server_dir)
            .serve(server_transport)
            .await
            .unwrap()
            .waiting()
            .await
            .unwrap();
    });
    let client = NativeApprovalClient.serve(client_transport).await.unwrap();
    let mut arguments = serde_json::Map::new();
    arguments.insert("request_id".into(), json!(request_id));
    let result = client
        .call_tool(CallToolRequestParams::new("request_approval").with_arguments(arguments))
        .await
        .unwrap();
    let text = result.content[0].as_text().unwrap().text.to_string();
    assert!(text.contains("approved"), "got: {text}");

    let retry = parse_input(
        r#"{"session_id":"test-session","turn_id":"test-turn","tool_use_id":"retry","cwd":"C:/Users/dev","tool_name":"Bash","tool_input":{"command":"Remove-Item notes.txt"}}"#,
    )
    .unwrap();
    assert!(matches!(
        gate(&dir, &retry, "vouch stopped on: write", now + 1).unwrap(),
        GateResult::Granted
    ));
    client.cancel().await.unwrap();
    server.await.unwrap();
}
