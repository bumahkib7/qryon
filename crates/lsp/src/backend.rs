//! LSP Backend implementation

use crate::diagnostics;
use rma_analyzer::AnalyzerEngine;
use rma_common::RmaConfig;
use rma_parser::ParserEngine;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};
use tracing::{debug, info, warn};

/// Document state for open files
struct DocumentState {
    content: String,
    version: i32,
}

/// RMA Language Server Backend
pub struct RmaBackend {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, DocumentState>>>,
    parser: Arc<ParserEngine>,
    analyzer: Arc<AnalyzerEngine>,
}

impl RmaBackend {
    pub fn new(client: Client) -> Self {
        let config = RmaConfig::default();
        Self {
            client,
            documents: Arc::new(RwLock::new(HashMap::new())),
            parser: Arc::new(ParserEngine::new(config.clone())),
            analyzer: Arc::new(AnalyzerEngine::new(config)),
        }
    }

    /// Analyze a document and publish diagnostics
    async fn analyze_document(&self, uri: &Url) {
        let documents = self.documents.read().await;

        if let Some(doc) = documents.get(uri) {
            let path = PathBuf::from(uri.path());

            // Parse the document
            match self.parser.parse_file(&path, &doc.content) {
                Ok(parsed) => {
                    // Analyze
                    match self.analyzer.analyze_file(&parsed) {
                        Ok(analysis) => {
                            // Convert findings to diagnostics
                            let diagnostics = diagnostics::findings_to_diagnostics(&analysis.findings);

                            self.client
                                .publish_diagnostics(uri.clone(), diagnostics, Some(doc.version))
                                .await;

                            debug!(
                                "Published {} diagnostics for {}",
                                analysis.findings.len(),
                                uri
                            );
                        }
                        Err(e) => {
                            warn!("Analysis failed for {}: {}", uri, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Parse failed for {}: {}", uri, e);
                }
            }
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for RmaBackend {
    async fn initialize(&self, _params: InitializeParams) -> LspResult<InitializeResult> {
        info!("RMA LSP initializing");

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(true),
                        })),
                        ..Default::default()
                    },
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(
                    DiagnosticOptions {
                        identifier: Some("rma".to_string()),
                        inter_file_dependencies: false,
                        workspace_diagnostics: false,
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                    },
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "RMA Language Server".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        info!("RMA LSP initialized");
        self.client
            .log_message(MessageType::INFO, "RMA Language Server ready")
            .await;
    }

    async fn shutdown(&self) -> LspResult<()> {
        info!("RMA LSP shutting down");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        info!("Document opened: {}", uri);

        {
            let mut documents = self.documents.write().await;
            documents.insert(
                uri.clone(),
                DocumentState {
                    content: params.text_document.text,
                    version: params.text_document.version,
                },
            );
        }

        self.analyze_document(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        {
            let mut documents = self.documents.write().await;
            if let Some(doc) = documents.get_mut(&uri) {
                // Full sync - take the last change
                if let Some(change) = params.content_changes.into_iter().last() {
                    doc.content = change.text;
                    doc.version = params.text_document.version;
                }
            }
        }

        self.analyze_document(&uri).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        info!("Document saved: {}", uri);

        if let Some(text) = params.text {
            let mut documents = self.documents.write().await;
            if let Some(doc) = documents.get_mut(&uri) {
                doc.content = text;
            }
        }

        self.analyze_document(&uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        info!("Document closed: {}", uri);

        {
            let mut documents = self.documents.write().await;
            documents.remove(&uri);
        }

        // Clear diagnostics
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let documents = self.documents.read().await;
        if let Some(_doc) = documents.get(uri) {
            // Could provide hover info about findings at this position
            // For now, return None
            return Ok(None);
        }

        Ok(None)
    }

    async fn code_action(&self, params: CodeActionParams) -> LspResult<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;
        let range = params.range;

        // Get diagnostics in range
        let diagnostics: Vec<_> = params
            .context
            .diagnostics
            .iter()
            .filter(|d| {
                d.range.start.line >= range.start.line && d.range.end.line <= range.end.line
            })
            .collect();

        if diagnostics.is_empty() {
            return Ok(None);
        }

        let mut actions = Vec::new();

        for diagnostic in diagnostics {
            // Add quick fix for unwrap
            if diagnostic.code == Some(NumberOrString::String("rust/unwrap-used".to_string())) {
                actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                    title: "Replace with ? operator".to_string(),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(vec![diagnostic.clone()]),
                    edit: None, // Would need proper text edit
                    command: None,
                    is_preferred: Some(true),
                    disabled: None,
                    data: None,
                }));
            }
        }

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(actions))
        }
    }
}
