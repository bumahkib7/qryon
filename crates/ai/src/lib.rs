//! AI-Powered Vulnerability Detection for Qryon
//!
//! This crate provides AI integration for sophisticated security analysis,
//! supporting multiple AI providers (Claude, OpenAI, local models).

pub mod prompts;
pub mod providers;

use anyhow::Result;
use async_trait::async_trait;
use rma_common::{Finding, Language, Severity, SourceLocation};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors from AI analysis
#[derive(Error, Debug)]
pub enum AiError {
    #[error("AI provider error: {0}")]
    ProviderError(String),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("Request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Configuration for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// AI provider to use
    pub provider: AiProvider,

    /// API key (from env var if not set)
    pub api_key: Option<String>,

    /// Model to use
    pub model: String,

    /// Maximum tokens per request
    pub max_tokens: usize,

    /// Temperature for generation
    pub temperature: f32,

    /// Enable/disable AI analysis
    pub enabled: bool,

    /// Maximum file size to analyze (bytes)
    pub max_file_size: usize,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Claude,
            api_key: None,
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 4096,
            temperature: 0.0,
            enabled: false,
            max_file_size: 100_000, // 100KB
        }
    }
}

/// Supported AI providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    Claude,
    OpenAi,
    Local,
}

/// Request sent to AI for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub source_code: String,
    pub file_path: String,
    pub language: String,
    pub context: Option<String>,
}

/// Response from AI analysis
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisResponse {
    pub findings: Vec<AiFinding>,
    pub summary: Option<String>,
    pub confidence: f32,
}

/// AI-generated finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFinding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub start_line: usize,
    pub end_line: usize,
    pub category: String,
    pub cwe_id: Option<String>,
    pub fix_suggestion: Option<String>,
    pub confidence: f32,
}

impl AiFinding {
    pub fn to_finding(&self, file_path: PathBuf, language: Language) -> Finding {
        // Map AI confidence (0.0-1.0) to Confidence enum
        let confidence = if self.confidence >= 0.8 {
            rma_common::Confidence::High
        } else if self.confidence >= 0.5 {
            rma_common::Confidence::Medium
        } else {
            rma_common::Confidence::Low
        };

        // Map category string to enum
        let category = match self.category.to_lowercase().as_str() {
            "security" => rma_common::FindingCategory::Security,
            "performance" => rma_common::FindingCategory::Performance,
            "style" => rma_common::FindingCategory::Style,
            _ => rma_common::FindingCategory::Quality,
        };

        let mut finding = Finding {
            id: format!("ai-{}-{}", self.rule_id, self.start_line),
            rule_id: format!("ai/{}", self.rule_id),
            message: format!("{}: {}", self.title, self.description),
            severity: match self.severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" | "error" => Severity::Error,
                "medium" | "warning" => Severity::Warning,
                _ => Severity::Info,
            },
            location: SourceLocation::new(file_path, self.start_line, 1, self.end_line, 1),
            language,
            snippet: None,
            suggestion: self.fix_suggestion.clone(),
            fix: None,
            confidence,
            category,
            subcategory: None,
            technology: None,
            impact: None,
            likelihood: None,
            source: rma_common::FindingSource::Ai,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
            ai_verdict: None,
            ai_explanation: None,
            ai_confidence: None,
        };
        finding.compute_fingerprint();
        finding
    }
}

/// Trait for AI providers
#[async_trait]
pub trait AiAnalyzer: Send + Sync {
    /// Analyze source code for vulnerabilities
    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, AiError>;

    /// Check if the provider is available
    async fn health_check(&self) -> Result<bool, AiError>;

    /// Get the provider name
    fn provider_name(&self) -> &str;
}

/// Main AI analysis engine
pub struct AiEngine {
    config: AiConfig,
    provider: Box<dyn AiAnalyzer>,
}

impl AiEngine {
    /// Create a new AI engine with the given configuration
    pub async fn new(config: AiConfig) -> Result<Self> {
        let provider: Box<dyn AiAnalyzer> = match config.provider {
            AiProvider::Claude => {
                let api_key = config
                    .api_key
                    .clone()
                    .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                    .ok_or_else(|| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;

                Box::new(providers::claude::ClaudeProvider::new(
                    api_key,
                    config.model.clone(),
                    config.max_tokens,
                ))
            }
            AiProvider::OpenAi => {
                let api_key = config
                    .api_key
                    .clone()
                    .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                    .ok_or_else(|| anyhow::anyhow!("OPENAI_API_KEY not set"))?;

                Box::new(providers::openai::OpenAiProvider::new(
                    api_key,
                    config.model.clone(),
                    config.max_tokens,
                ))
            }
            AiProvider::Local => {
                let endpoint = std::env::var("QRYON_LOCAL_AI_ENDPOINT")
                    .or_else(|_| std::env::var("RMA_LOCAL_AI_ENDPOINT"))
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());

                Box::new(providers::local::LocalProvider::new(
                    endpoint,
                    config.model.clone(),
                ))
            }
        };

        Ok(Self { config, provider })
    }

    /// Analyze a source file
    pub async fn analyze_file(
        &self,
        source: &str,
        file_path: &str,
        language: Language,
    ) -> Result<Vec<Finding>> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        if source.len() > self.config.max_file_size {
            debug!("File {} exceeds max size, skipping AI analysis", file_path);
            return Ok(vec![]);
        }

        let request = AnalysisRequest {
            source_code: source.to_string(),
            file_path: file_path.to_string(),
            language: language.to_string(),
            context: None,
        };

        info!("Running AI analysis on {}", file_path);

        let response = self.provider.analyze(request).await?;

        let findings: Vec<Finding> = response
            .findings
            .into_iter()
            .filter(|f| f.confidence >= 0.7) // Only high-confidence findings
            .map(|f| f.to_finding(PathBuf::from(file_path), language))
            .collect();

        info!("AI found {} findings in {}", findings.len(), file_path);

        Ok(findings)
    }

    /// Check if AI provider is available
    pub async fn is_available(&self) -> bool {
        self.provider.health_check().await.unwrap_or(false)
    }

    /// Get provider name
    pub fn provider_name(&self) -> &str {
        self.provider.provider_name()
    }

    /// Triage a single static analysis finding using AI
    ///
    /// Sends the finding + surrounding code context to the AI provider
    /// and asks it to confirm/reject the finding with an explanation.
    pub async fn triage_finding(
        &self,
        finding: &Finding,
        code_context: &str,
        language: Language,
    ) -> Result<TriageResult, AiError> {
        let system_prompt = prompts::triage_system_prompt();
        let user_prompt = prompts::format_triage_prompt(finding, code_context, language);

        let request = AnalysisRequest {
            source_code: user_prompt,
            file_path: finding.location.file.to_string_lossy().to_string(),
            language: language.to_string(),
            context: Some(system_prompt.clone()),
        };

        // Retry with exponential backoff on rate limiting
        let mut attempt = 0;
        let max_retries = 3;
        let base_delay = std::time::Duration::from_secs(2);

        loop {
            match self.provider.analyze(request.clone()).await {
                Ok(response) => {
                    break Ok(TriageResult::from_analysis_response(&response));
                }
                Err(AiError::RateLimited) if attempt < max_retries => {
                    attempt += 1;
                    let delay = base_delay * 2u32.pow(attempt as u32 - 1);
                    warn!(
                        "Rate limited, retrying in {:?} (attempt {}/{})",
                        delay, attempt, max_retries
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => break Err(e),
            }
        }
    }
}

/// Result of AI triage on a single static analysis finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    /// "true_positive", "false_positive", or "needs_review"
    pub verdict: String,
    /// AI's confidence in its verdict (0.0-1.0)
    pub confidence: f32,
    /// Explanation of why the finding is/isn't a real issue
    pub explanation: String,
    /// Concrete fix suggestion (if true positive)
    pub fix_suggestion: Option<String>,
    /// Severity adjustment if the static tool's severity is wrong
    pub severity_adjustment: Option<String>,
}

impl TriageResult {
    /// Build a TriageResult from the AnalysisResponse returned by providers.
    ///
    /// When we send a triage prompt, the AI may still return an AnalysisResponse
    /// format. We interpret it:
    /// - If findings are empty → false_positive
    /// - If findings exist with high confidence → true_positive
    /// - Otherwise → needs_review
    pub fn from_analysis_response(response: &AnalysisResponse) -> Self {
        if response.findings.is_empty() {
            return Self {
                verdict: "false_positive".to_string(),
                confidence: response.confidence,
                explanation: response
                    .summary
                    .clone()
                    .unwrap_or_else(|| "AI determined this is likely a false positive.".to_string()),
                fix_suggestion: None,
                severity_adjustment: None,
            };
        }

        let finding = &response.findings[0];
        let verdict = if finding.confidence >= 0.7 {
            "true_positive"
        } else if finding.confidence >= 0.4 {
            "needs_review"
        } else {
            "false_positive"
        };

        Self {
            verdict: verdict.to_string(),
            confidence: finding.confidence,
            explanation: finding.description.clone(),
            fix_suggestion: finding.fix_suggestion.clone(),
            severity_adjustment: Some(finding.severity.clone()),
        }
    }
}

/// Extract code context around a finding location.
///
/// Returns `context_lines` lines above and below the finding, with line numbers.
pub fn extract_code_context(
    source: &str,
    start_line: usize,
    end_line: usize,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let total = lines.len();
    let ctx_start = start_line.saturating_sub(context_lines).max(1);
    let ctx_end = (end_line + context_lines).min(total);

    let mut result = String::with_capacity(2048);
    for (idx, line) in lines.iter().enumerate() {
        let line_num = idx + 1;
        if line_num >= ctx_start && line_num <= ctx_end {
            // Mark the finding lines with an arrow
            let marker = if line_num >= start_line && line_num <= end_line {
                ">>>"
            } else {
                "   "
            };
            result.push_str(&format!("{} {:>4} | {}\n", marker, line_num, line));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_finding_to_finding() {
        let ai_finding = AiFinding {
            rule_id: "sql-injection".to_string(),
            title: "SQL Injection".to_string(),
            description: "User input used in SQL query".to_string(),
            severity: "critical".to_string(),
            start_line: 10,
            end_line: 12,
            category: "security".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            fix_suggestion: Some("Use parameterized queries".to_string()),
            confidence: 0.95,
        };

        let finding = ai_finding.to_finding(PathBuf::from("test.rs"), Language::Rust);

        assert_eq!(finding.rule_id, "ai/sql-injection");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.suggestion.is_some());
    }
}
