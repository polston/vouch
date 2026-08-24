use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--version" {
        println!("vouch-codex-broker {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if !args.is_empty() {
        return Err("usage: vouch-codex-broker [--version]".into());
    }
    let service = vouch::codex_broker::ApprovalServer::new(vouch::journal::state_dir())
        .serve(rmcp::transport::stdio())
        .await?;
    service.waiting().await?;
    Ok(())
}
