//! Prompts for AI security analysis

use crate::{AiError, AiFinding, AnalysisRequest, AnalysisResponse};

/// System prompt for security analysis
pub fn security_analysis_system_prompt() -> String {
    r#"You are an expert code security analyzer. Your task is to analyze source code for security vulnerabilities, bugs, and potential issues.

For each issue found, provide:
1. A unique rule_id (e.g., "sql-injection", "buffer-overflow")
2. A short title
3. A detailed description
4. Severity: "critical", "high", "medium", or "low"
5. Start and end line numbers
6. Category: "security", "reliability", "performance", or "maintainability"
7. CWE ID if applicable (e.g., "CWE-89")
8. A suggested fix
9. Confidence score (0.0 to 1.0)

Focus on:
- Injection vulnerabilities (SQL, command, XSS)
- Authentication/authorization issues
- Cryptographic weaknesses
- Memory safety issues
- Race conditions
- Information disclosure
- Input validation
- Error handling

Respond with valid JSON only, in this format:
{
  "findings": [
    {
      "rule_id": "string",
      "title": "string",
      "description": "string",
      "severity": "critical|high|medium|low",
      "start_line": number,
      "end_line": number,
      "category": "string",
      "cwe_id": "string or null",
      "fix_suggestion": "string or null",
      "confidence": number
    }
  ],
  "summary": "Brief summary of findings",
  "confidence": 0.0-1.0
}

If no issues are found, return {"findings": [], "summary": "No issues found", "confidence": 1.0}"#.to_string()
}

/// Format the analysis prompt with source code
pub fn format_analysis_prompt(request: &AnalysisRequest) -> String {
    format!(
        r#"Analyze the following {} code for security vulnerabilities:

File: {}

```{}
{}
```

{}

Provide your analysis as JSON."#,
        request.language,
        request.file_path,
        request.language.to_lowercase(),
        request.source_code,
        request.context.as_deref().unwrap_or("")
    )
}

/// Parse the AI response into structured findings
pub fn parse_analysis_response(text: &str) -> Result<AnalysisResponse, AiError> {
    // Try to extract JSON from the response
    let json_str = extract_json(text);

    serde_json::from_str(&json_str).map_err(|e| {
        AiError::ParseError(format!("Failed to parse AI response: {} - Response: {}", e, text))
    })
}

/// Extract JSON from text that might contain markdown or other formatting
fn extract_json(text: &str) -> String {
    // Try to find JSON block in markdown code fence
    if let Some(start) = text.find("```json") {
        if let Some(end) = text[start + 7..].find("```") {
            return text[start + 7..start + 7 + end].trim().to_string();
        }
    }

    // Try to find JSON block without language specifier
    if let Some(start) = text.find("```") {
        let after_start = &text[start + 3..];
        if let Some(end) = after_start.find("```") {
            let content = &after_start[..end];
            // Skip language identifier if present
            let json_start = content.find('{').unwrap_or(0);
            return content[json_start..].trim().to_string();
        }
    }

    // Try to find raw JSON object
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return text[start..=end].to_string();
        }
    }

    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_from_markdown() {
        let text = r#"Here is the analysis:

```json
{"findings": [], "summary": "No issues", "confidence": 1.0}
```

Done."#;

        let json = extract_json(text);
        assert!(json.contains("findings"));
    }

    #[test]
    fn test_extract_raw_json() {
        let text = r#"{"findings": [], "summary": "No issues", "confidence": 1.0}"#;
        let json = extract_json(text);
        assert_eq!(json, text);
    }

    #[test]
    fn test_parse_analysis_response() {
        let json = r#"{"findings": [], "summary": "No issues found", "confidence": 1.0}"#;
        let response = parse_analysis_response(json);
        assert!(response.is_ok());
        assert!(response.unwrap().findings.is_empty());
    }
}
