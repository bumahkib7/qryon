//! OpenAI Provider

use crate::{AiAnalyzer, AiError, AnalysisRequest, AnalysisResponse, prompts};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";

/// OpenAI Provider
pub struct OpenAiProvider {
    client: Client,
    api_key: String,
    model: String,
    max_tokens: usize,
}

impl OpenAiProvider {
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
struct OpenAiRequest {
    model: String,
    max_tokens: usize,
    messages: Vec<OpenAiMessage>,
    temperature: f32,
}

#[derive(Serialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiResponseMessage,
}

#[derive(Deserialize)]
struct OpenAiResponseMessage {
    content: String,
}

#[async_trait]
impl AiAnalyzer for OpenAiProvider {
    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, AiError> {
        let system_prompt = prompts::security_analysis_system_prompt();
        let user_prompt = prompts::format_analysis_prompt(&request);

        let openai_request = OpenAiRequest {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            messages: vec![
                OpenAiMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                OpenAiMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            temperature: 0.0,
        };

        debug!("Sending request to OpenAI API");

        let response = self
            .client
            .post(OPENAI_API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
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
                "OpenAI API error: {}",
                error_text
            )));
        }

        let openai_response: OpenAiResponse = response.json().await?;

        let text = openai_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        prompts::parse_analysis_response(&text)
    }

    async fn health_check(&self) -> Result<bool, AiError> {
        let response = self
            .client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await?;

        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "openai"
    }
}
