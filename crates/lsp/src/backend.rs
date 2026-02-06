//! LSP Backend implementation
//!
//! This module implements the Language Server Protocol backend for RMA,
//! providing real-time code analysis feedback to editors.
//!
//! # Performance Design
//!
//! Analysis is **debounced to `did_save` events** rather than running on every
//! keystroke (`did_change`). This prevents excessive CPU usage during editing
//! while still providing timely feedback when the user saves.

use crate::diagnostics;
use dashmap::DashMap;
use rma_analyzer::AnalyzerEngine;
use rma_common::{Finding, RmaConfig};
use rma_parser::ParserEngine;
use std::path::PathBuf;
use std::sync::Arc;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};
use tracing::{debug, info, warn};

/// Document state for open files
#[derive(Debug, Clone)]
struct DocumentState {
    content: String,
    version: i32,
    /// Cached findings for code actions
    findings: Vec<Finding>,
}

/// RMA Language Server Backend
///
/// Uses `DashMap` for lock-free concurrent access to document state,
/// enabling parallel analysis without blocking the main LSP event loop.
pub struct RmaBackend {
    client: Client,
    /// Thread-safe document storage with lock-free reads
    documents: Arc<DashMap<Url, DocumentState>>,
    parser: Arc<ParserEngine>,
    analyzer: Arc<AnalyzerEngine>,
}

impl RmaBackend {
    pub fn new(client: Client) -> Self {
        let config = RmaConfig::default();
        Self {
            client,
            documents: Arc::new(DashMap::new()),
            parser: Arc::new(ParserEngine::new(config.clone())),
            analyzer: Arc::new(AnalyzerEngine::new(config)),
        }
    }

    /// Analyze a document and publish diagnostics
    ///
    /// This is called on `did_open` and `did_save` events (debounced).
    /// NOT called on `did_change` to avoid excessive analysis during editing.
    async fn analyze_document(&self, uri: &Url) {
        // Get document content (lock-free read via DashMap)
        let (content, version) = {
            match self.documents.get(uri) {
                Some(doc) => (doc.content.clone(), doc.version),
                None => {
                    warn!("Document not found for analysis: {}", uri);
                    return;
                }
            }
        };

        let path = PathBuf::from(uri.path());

        // Parse the document
        match self.parser.parse_file(&path, &content) {
            Ok(parsed) => {
                // Analyze
                match self.analyzer.analyze_file(&parsed) {
                    Ok(analysis) => {
                        // Store findings for code actions
                        if let Some(mut doc) = self.documents.get_mut(uri) {
                            doc.findings = analysis.findings.clone();
                        }

                        // Convert findings to diagnostics
                        let diagnostics = diagnostics::findings_to_diagnostics(&analysis.findings);

                        self.client
                            .publish_diagnostics(uri.clone(), diagnostics, Some(version))
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
                // For unsupported languages, just clear diagnostics silently
                if e.to_string().contains("Unsupported language") {
                    debug!("Skipping unsupported file: {}", uri);
                } else {
                    warn!("Parse failed for {}: {}", uri, e);
                }
                // Clear any stale diagnostics
                self.client
                    .publish_diagnostics(uri.clone(), vec![], Some(version))
                    .await;
            }
        }
    }

    /// Generate a suppression comment for the given language
    fn suppression_comment(rule_id: &str, path: &std::path::Path) -> String {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "rs" => format!("// rma-ignore[{}]", rule_id),
            "py" => format!("# rma-ignore[{}]", rule_id),
            "js" | "ts" | "tsx" | "jsx" | "mjs" | "cjs" => {
                format!("// rma-ignore[{}]", rule_id)
            }
            "go" => format!("// rma-ignore[{}]", rule_id),
            "java" => format!("// rma-ignore[{}]", rule_id),
            _ => format!("// rma-ignore[{}]", rule_id),
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
                        // Full sync for simplicity - content is replaced on each change
                        change: Some(TextDocumentSyncKind::FULL),
                        save: Some(TextDocumentSyncSaveOptions::SaveOptions(SaveOptions {
                            include_text: Some(true),
                        })),
                        ..Default::default()
                    },
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                code_action_provider: Some(CodeActionProviderCapability::Options(
                    CodeActionOptions {
                        code_action_kinds: Some(vec![
                            CodeActionKind::QUICKFIX,
                            CodeActionKind::SOURCE,
                        ]),
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                        resolve_provider: Some(false),
                    },
                )),
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

        // Store document state
        self.documents.insert(
            uri.clone(),
            DocumentState {
                content: params.text_document.text,
                version: params.text_document.version,
                findings: Vec::new(),
            },
        );

        // Analyze on open to show initial diagnostics
        self.analyze_document(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();

        // Update document content but DO NOT analyze
        // Analysis is debounced to did_save for performance
        if let Some(mut doc) = self.documents.get_mut(&uri)
            && let Some(change) = params.content_changes.into_iter().last()
        {
            doc.content = change.text;
            doc.version = params.text_document.version;
        }

        // NOTE: We intentionally do NOT call analyze_document here.
        // This is the debouncing strategy - only analyze on save.
        debug!("Document changed (analysis deferred to save): {}", uri);
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        info!("Document saved: {}", uri);

        // Update content if provided
        if let Some(text) = params.text
            && let Some(mut doc) = self.documents.get_mut(&uri)
        {
            doc.content = text;
        }

        // Analyze on save - this is where the work happens
        self.analyze_document(&uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        info!("Document closed: {}", uri);

        // Remove document state
        self.documents.remove(&uri);

        // Clear diagnostics
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        // Check if we have findings at this position
        if let Some(doc) = self.documents.get(uri) {
            for finding in &doc.findings {
                let start_line = finding.location.start_line.saturating_sub(1) as u32;
                let end_line = finding.location.end_line.saturating_sub(1) as u32;

                if position.line >= start_line && position.line <= end_line {
                    let mut content = format!("**{}**: {}", finding.rule_id, finding.message);

                    if let Some(suggestion) = &finding.suggestion {
                        content.push_str(&format!("\n\n**Suggestion**: {}", suggestion));
                    }

                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: content,
                        }),
                        range: Some(Range {
                            start: Position {
                                line: start_line,
                                character: finding.location.start_column.saturating_sub(1) as u32,
                            },
                            end: Position {
                                line: end_line,
                                character: finding.location.end_column.saturating_sub(1) as u32,
                            },
                        }),
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn code_action(&self, params: CodeActionParams) -> LspResult<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;
        let range = params.range;

        // Get diagnostics in range from the request context
        let diagnostics_in_range: Vec<_> = params
            .context
            .diagnostics
            .iter()
            .filter(|d| d.source.as_deref() == Some("rma"))
            .filter(|d| {
                // Check if diagnostic overlaps with requested range
                !(d.range.end.line < range.start.line || d.range.start.line > range.end.line)
            })
            .collect();

        if diagnostics_in_range.is_empty() {
            return Ok(None);
        }

        let mut actions = Vec::new();
        let path = PathBuf::from(uri.path());

        for diagnostic in diagnostics_in_range {
            let rule_id = match &diagnostic.code {
                Some(NumberOrString::String(s)) => s.clone(),
                _ => continue,
            };

            // Action 1: Suppress this finding with inline comment
            let suppression_comment = Self::suppression_comment(&rule_id, &path);
            let suppress_line = diagnostic.range.start.line;

            // Insert suppression comment on the line above
            let edit = TextEdit {
                range: Range {
                    start: Position {
                        line: suppress_line,
                        character: 0,
                    },
                    end: Position {
                        line: suppress_line,
                        character: 0,
                    },
                },
                new_text: format!("{}\n", suppression_comment),
            };

            let mut changes = std::collections::HashMap::new();
            changes.insert(uri.clone(), vec![edit]);

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title: format!("Suppress '{}' for this line", rule_id),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: Some(vec![diagnostic.clone()]),
                edit: Some(WorkspaceEdit {
                    changes: Some(changes),
                    document_changes: None,
                    change_annotations: None,
                }),
                command: None,
                is_preferred: Some(false),
                disabled: None,
                data: None,
            }));

            // Action 2: For specific rules, provide auto-fix suggestions
            if rule_id == "rust/unwrap-used" {
                actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                    title: "Replace .unwrap() with ? operator".to_string(),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(vec![diagnostic.clone()]),
                    edit: None, // Would need precise AST info for proper replacement
                    command: None,
                    is_preferred: Some(true),
                    disabled: Some(CodeActionDisabled {
                        reason: "Requires manual replacement - replace .unwrap() with ?"
                            .to_string(),
                    }),
                    data: None,
                }));
            }

            // Action 3: For console.log in JS/TS, offer removal
            if rule_id == "js/no-console-log" || rule_id == "javascript/console-log" {
                // Get the content to determine what to remove
                if let Some(doc) = self.documents.get(uri) {
                    let lines: Vec<&str> = doc.content.lines().collect();
                    let line_idx = diagnostic.range.start.line as usize;
                    if line_idx < lines.len() {
                        let line = lines[line_idx];
                        // Remove the entire line if it's just a console.log
                        if line.trim().starts_with("console.log") {
                            let edit = TextEdit {
                                range: Range {
                                    start: Position {
                                        line: diagnostic.range.start.line,
                                        character: 0,
                                    },
                                    end: Position {
                                        line: diagnostic.range.start.line + 1,
                                        character: 0,
                                    },
                                },
                                new_text: String::new(),
                            };

                            let mut changes = std::collections::HashMap::new();
                            changes.insert(uri.clone(), vec![edit]);

                            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                                title: "Remove console.log statement".to_string(),
                                kind: Some(CodeActionKind::QUICKFIX),
                                diagnostics: Some(vec![diagnostic.clone()]),
                                edit: Some(WorkspaceEdit {
                                    changes: Some(changes),
                                    document_changes: None,
                                    change_annotations: None,
                                }),
                                command: None,
                                is_preferred: Some(true),
                                disabled: None,
                                data: None,
                            }));
                        }
                    }
                }
            }
        }

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(actions))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suppression_comment_rust() {
        let comment =
            RmaBackend::suppression_comment("rust/unsafe-block", std::path::Path::new("test.rs"));
        assert_eq!(comment, "// rma-ignore[rust/unsafe-block]");
    }

    #[test]
    fn test_suppression_comment_python() {
        let comment =
            RmaBackend::suppression_comment("python/exec-used", std::path::Path::new("test.py"));
        assert_eq!(comment, "# rma-ignore[python/exec-used]");
    }

    #[test]
    fn test_suppression_comment_javascript() {
        let comment =
            RmaBackend::suppression_comment("js/no-eval", std::path::Path::new("test.js"));
        assert_eq!(comment, "// rma-ignore[js/no-eval]");
    }
}
