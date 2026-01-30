//! RMA Language Server
//!
//! Provides real-time code analysis feedback to IDEs via the Language Server Protocol.

use anyhow::Result;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod backend;
mod diagnostics;

use backend::RmaBackend;

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging to stderr (stdout is used for LSP communication)
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting RMA Language Server");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| RmaBackend::new(client));
    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
