//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static OKHTTP3_GEN_SOURCES: &[SourceDef] = &[];

static OKHTTP3_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "okhttp3.OkHttpClient.newCall",
        pattern: SinkKind::FunctionCall("okhttp3.OkHttpClient.newCall"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: okhttp3.OkHttpClient.newCall (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "okhttp3.OkHttpClient.newWebSocket",
        pattern: SinkKind::FunctionCall("okhttp3.OkHttpClient.newWebSocket"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: okhttp3.OkHttpClient.newWebSocket (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "okhttp3.Request.Request",
        pattern: SinkKind::FunctionCall("okhttp3.Request.Request"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: okhttp3.Request.Request (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "okhttp3.Request$Builder.url",
        pattern: SinkKind::FunctionCall("okhttp3.Request$Builder.url"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: okhttp3.Request$Builder.url (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static OKHTTP3_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.addEncodedPathSegment",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.addEncodedPathSegment"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.addEncodedPathSegment",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.addEncodedPathSegments",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.addEncodedPathSegments"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.addEncodedPathSegments",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.addEncodedQueryParameter",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.addEncodedQueryParameter"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.addEncodedQueryParameter",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.encodedFragment",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.encodedFragment"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.encodedFragment",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.encodedPassword",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.encodedPassword"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.encodedPassword",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.encodedPath",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.encodedPath"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.encodedPath",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.encodedQuery",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.encodedQuery"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.encodedQuery",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.encodedUsername",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.encodedUsername"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.encodedUsername",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.removeAllEncodedQueryParameters",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.removeAllEncodedQueryParameters"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.removeAllEncodedQueryParameters",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.setEncodedPathSegment",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.setEncodedPathSegment"),
        sanitizes: "url",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.setEncodedPathSegment",
    },
    SanitizerDef {
        name: "okhttp3.HttpUrl$Builder.setEncodedQueryParameter",
        pattern: SanitizerKind::Function("okhttp3.HttpUrl$Builder.setEncodedQueryParameter"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: okhttp3.HttpUrl$Builder.setEncodedQueryParameter",
    },
];

static OKHTTP3_GEN_IMPORTS: &[&str] = &["okhttp3"];

pub static OKHTTP3_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "okhttp3_generated",
    description: "Generated profile for okhttp3 from CodeQL/Pysa",
    detect_imports: OKHTTP3_GEN_IMPORTS,
    sources: OKHTTP3_GEN_SOURCES,
    sinks: OKHTTP3_GEN_SINKS,
    sanitizers: OKHTTP3_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
