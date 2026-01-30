//! Local AI Provider (Ollama, etc.)

use crate::{AiAnalyzer, AiError, AnalysisRequest, AnalysisResponse, prompts};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Local AI Provider (Ollama-compatible)
pub struct LocalProvider {
    client: Client,
    endpoint: String,
    model: String,
}

impl LocalProvider {
    pub fn new(endpoint: String, model: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            model,
        }
    }
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

#[async_trait]
impl AiAnalyzer for LocalProvider {
    async fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResponse, AiError> {
        let system_prompt = prompts::security_analysis_system_prompt();
        let user_prompt = prompts::format_analysis_prompt(&request);

        let full_prompt = format!(
            "System: {}\n\nUser: {}\n\nAssistant:",
            system_prompt, user_prompt
        );

        let ollama_request = OllamaRequest {
            model: self.model.clone(),
            prompt: full_prompt,
            stream: false,
        };

        debug!("Sending request to local AI at {}", self.endpoint);

        let url = format!("{}/api/generate", self.endpoint);
        let response = self
            .client
            .post(&url)
            .json(&ollama_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AiError::ProviderError(format!(
                "Local AI error: {}",
                error_text
            )));
        }

        let ollama_response: OllamaResponse = response.json().await?;

        prompts::parse_analysis_response(&ollama_response.response)
    }

    async fn health_check(&self) -> Result<bool, AiError> {
        let url = format!("{}/api/tags", self.endpoint);
        let response = self.client.get(&url).send().await?;
        Ok(response.status().is_success())
    }

    fn provider_name(&self) -> &str {
        "local"
    }
}
