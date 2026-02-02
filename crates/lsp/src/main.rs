//! RMA Language Server
//!
//! Provides real-time code analysis feedback to IDEs via the Language Server Protocol.
//!
//! # Usage
//!
//! The LSP server communicates over stdio (stdin/stdout). Configure your editor
//! to spawn this binary as a language server.
//!
//! ## VS Code
//!
//! Add to `.vscode/settings.json`:
//! ```json
//! {
//!   "rma.server.path": "/path/to/rma-lsp"
//! }
//! ```
//!
//! ## Neovim (with nvim-lspconfig)
//!
//! ```lua
//! require('lspconfig').rma.setup({
//!   cmd = { '/path/to/rma-lsp' },
//!   filetypes = { 'rust', 'javascript', 'typescript', 'python', 'go', 'java' },
//! })
//! ```
//!
//! # Performance
//!
//! Analysis is debounced to `textDocument/didSave` events to avoid excessive
//! CPU usage during editing. Diagnostics are updated when files are opened
//! or saved.

use anyhow::Result;
use tower_lsp::{LspService, Server};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;

mod backend;
mod diagnostics;

use backend::RmaBackend;

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging to stderr (stdout is used for LSP JSON-RPC communication)
    // Use RUST_LOG env var to control log level (default: info)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("rma_lsp=info,tower_lsp=warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_ansi(false) // Disable colors for log files
        .init();

    info!(
        "Starting RMA Language Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(RmaBackend::new);
    Server::new(stdin, stdout, socket).serve(service).await;

    info!("RMA Language Server stopped");
    Ok(())
}
