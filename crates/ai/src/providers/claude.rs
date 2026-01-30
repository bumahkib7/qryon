//! Claude AI Provider (Anthropic)

use crate::{AiAnalyzer, AiError, AnalysisRequest, AnalysisResponse, prompts};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";

/// Claude AI Provider
pub struct ClaudeProvider {
    client: Client,
    api_key: String,
    model: String,
    max_tokens: usize,
}

impl ClaudeProvider {
    pub fn new(api_key: String, model: String, max_tokens: usize) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
            max_tokens,
        }
    }
}

#[derive(Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: usize,
    messages: Vec<ClaudeMessage>,
    system: String,
}

#[derive(Serialize)]
struct ClaudeMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Deserialize)]
struct ClaudeContent {
    text: String,
}

#[async_trait]
impl AiAnalyzer for ClaudeProvider {
    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, AiError> {
        let system_prompt = prompts::security_analysis_system_prompt();
        let user_prompt = prompts::format_analysis_prompt(&request);

        let claude_request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            messages: vec![ClaudeMessage {
                role: "user".to_string(),
                content: user_prompt,
            }],
            system: system_prompt,
        };

        debug!("Sending request to Claude API");

        let response = self
            .client
            .post(CLAUDE_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&claude_request)
            .send()
            .await?;

        if response.status() == 429 {
            return Err(AiError::RateLimited);
        }

        if response.status() == 401 {
            return Err(AiError::InvalidApiKey);
        }

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AiError::ProviderError(format!(
                "Claude API error: {}",
                error_text
            )));
        }

        let claude_response: ClaudeResponse = response.json().await?;

        let text = claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        // Parse JSON response from Claude
        prompts::parse_analysis_response(&text)
    }

    async fn health_check(&self) -> Result<bool, AiError> {
        // Simple check - try to access the API
        let response = self
            .client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "claude"
    }
}
