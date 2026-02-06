//! Maps Pysa taint annotations to our internal `FrameworkKnowledge` types.

use crate::{
    FrameworkKnowledge, SanitizerEntry, SanitizerKindTag, SeverityTag, SinkEntry, SinkKindTag,
    SourceEntry, SourceKindTag,
};

use super::PysaEntry;
use std::collections::BTreeMap;

/// Map a list of Pysa entries into framework knowledge, grouped by framework.
pub fn map_pysa_entries(entries: &[PysaEntry]) -> Vec<FrameworkKnowledge> {
    let mut frameworks: BTreeMap<String, FrameworkKnowledge> = BTreeMap::new();

    for entry in entries {
        let (_qualified_name, framework_id, package) = match entry {
            PysaEntry::Source { qualified_name, .. } => {
                let id = infer_framework_id(qualified_name);
                let pkg = top_level_package(qualified_name);
                (qualified_name.as_str(), id, pkg)
            }
            PysaEntry::Sink { qualified_name, .. } => {
                let id = infer_framework_id(qualified_name);
                let pkg = top_level_package(qualified_name);
                (qualified_name.as_str(), id, pkg)
            }
            PysaEntry::Sanitizer { qualified_name } => {
                let id = infer_framework_id(qualified_name);
                let pkg = top_level_package(qualified_name);
                (qualified_name.as_str(), id, pkg)
            }
        };

        if framework_id.is_empty() {
            continue;
        }

        let fk = frameworks
            .entry(framework_id.clone())
            .or_insert_with(|| FrameworkKnowledge {
                id: framework_id.clone(),
                display_name: package.clone(),
                language: "python".to_string(),
                import_patterns: vec![package.clone()],
                sources: Vec::new(),
                sinks: Vec::new(),
                sanitizers: Vec::new(),
                safe_patterns: Vec::new(),
                resource_types: Vec::new(),
            });

        if !fk.import_patterns.contains(&package) {
            fk.import_patterns.push(package.clone());
        }

        match entry {
            PysaEntry::Source {
                qualified_name,
                taint_kind,
            } => {
                let source = map_source(qualified_name, taint_kind);
                if !fk.sources.iter().any(|s| s.name == source.name) {
                    fk.sources.push(source);
                }
            }
            PysaEntry::Sink {
                qualified_name,
                taint_kind,
                ..
            } => {
                let sink = map_sink(qualified_name, taint_kind);
                if !fk.sinks.iter().any(|s| s.name == sink.name) {
                    fk.sinks.push(sink);
                }
            }
            PysaEntry::Sanitizer { qualified_name } => {
                let sanitizer = map_sanitizer(qualified_name);
                if !fk.sanitizers.iter().any(|s| s.name == sanitizer.name) {
                    fk.sanitizers.push(sanitizer);
                }
            }
        }
    }

    frameworks.into_values().collect()
}

fn map_source(qualified_name: &str, taint_kind: &str) -> SourceEntry {
    let kind = if qualified_name.contains('(') || !qualified_name.contains('.') {
        SourceKindTag::FunctionCall
    } else {
        SourceKindTag::MemberAccess
    };

    SourceEntry {
        name: qualified_name.to_string(),
        pattern: qualified_name.to_string(),
        kind,
        taint_label: map_pysa_taint_kind_to_label(taint_kind),
        description: format!("Pysa source: {qualified_name} (kind: {taint_kind})"),
    }
}

fn map_sink(qualified_name: &str, taint_kind: &str) -> SinkEntry {
    let (severity, cwe) = map_pysa_sink_severity(taint_kind);

    SinkEntry {
        name: qualified_name.to_string(),
        pattern: qualified_name.to_string(),
        kind: SinkKindTag::FunctionCall,
        rule_id: format!(
            "python/gen-pysa-{}",
            taint_kind.to_lowercase().replace(' ', "-")
        ),
        severity,
        description: format!("Pysa sink: {qualified_name} (kind: {taint_kind})"),
        cwe: Some(cwe.to_string()),
    }
}

fn map_sanitizer(qualified_name: &str) -> SanitizerEntry {
    let sanitizes = infer_sanitization_type(qualified_name);

    SanitizerEntry {
        name: qualified_name.to_string(),
        pattern: qualified_name.to_string(),
        kind: SanitizerKindTag::Function,
        sanitizes,
        description: format!("Pysa sanitizer: {qualified_name}"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn top_level_package(qualified_name: &str) -> String {
    qualified_name
        .split('.')
        .next()
        .unwrap_or(qualified_name)
        .to_string()
}

fn infer_framework_id(qualified_name: &str) -> String {
    let top = top_level_package(qualified_name).to_lowercase();

    match top.as_str() {
        "flask" | "werkzeug" | "markupsafe" | "jinja2" => "flask".to_string(),
        "django" => "django".to_string(),
        "fastapi" | "starlette" => "fastapi".to_string(),
        "requests" | "urllib" | "urllib3" | "httpx" | "aiohttp" => "python_http".to_string(),
        "subprocess" | "os" | "shutil" | "tempfile" | "io" | "socket" | "ftplib" | "smtplib" => {
            "python_stdlib".to_string()
        }
        "sqlalchemy" => "sqlalchemy".to_string(),
        "paramiko" => "paramiko".to_string(),
        "cryptography" | "hashlib" | "hmac" => "python_crypto".to_string(),
        "yaml" | "pyyaml" => "pyyaml".to_string(),
        _ => {
            let id = top.replace('-', "_");
            if id.is_empty() {
                return String::new();
            }
            id
        }
    }
}

fn map_pysa_taint_kind_to_label(kind: &str) -> String {
    match kind {
        "UserControlled" => "user_input".to_string(),
        "Cookies" => "user_input".to_string(),
        "Headers" => "user_input".to_string(),
        "URL" => "user_input".to_string(),
        "Demo" => "user_input".to_string(),
        "GetAttr" => "user_input".to_string(),
        _ => "user_input".to_string(),
    }
}

fn map_pysa_sink_severity(kind: &str) -> (SeverityTag, &'static str) {
    match kind {
        "RemoteCodeExecution" => (SeverityTag::Critical, "CWE-78"),
        "CodeExecution" => (SeverityTag::Critical, "CWE-94"),
        "SQL" | "SQLInjection" => (SeverityTag::Critical, "CWE-89"),
        "XSS" => (SeverityTag::Critical, "CWE-79"),
        "SSRF" | "ServerSideRequestForgery" => (SeverityTag::Critical, "CWE-918"),
        "PathTraversal" | "FileSystem_ReadWrite" => (SeverityTag::Critical, "CWE-22"),
        "XMLInjection" | "XXE" => (SeverityTag::Critical, "CWE-611"),
        "Deserialization" => (SeverityTag::Critical, "CWE-502"),
        "HeaderInjection" => (SeverityTag::Error, "CWE-113"),
        "Redirect" | "OpenRedirect" => (SeverityTag::Error, "CWE-601"),
        "LogInjection" => (SeverityTag::Warning, "CWE-117"),
        "RegexInjection" => (SeverityTag::Error, "CWE-1333"),
        "TemplateInjection" => (SeverityTag::Critical, "CWE-94"),
        "LDAPInjection" => (SeverityTag::Critical, "CWE-90"),
        _ => (SeverityTag::Error, "CWE-74"),
    }
}

fn infer_sanitization_type(qualified_name: &str) -> String {
    let lower = qualified_name.to_lowercase();
    if lower.contains("html") || lower.contains("escape") || lower.contains("markup") {
        "html".to_string()
    } else if lower.contains("sql") || lower.contains("query") {
        "sql".to_string()
    } else if lower.contains("url") || lower.contains("uri") || lower.contains("quote") {
        "url".to_string()
    } else if lower.contains("path") || lower.contains("file") || lower.contains("secure_filename")
    {
        "path".to_string()
    } else if lower.contains("shell") || lower.contains("shlex") {
        "shell".to_string()
    } else {
        "general".to_string()
    }
}
