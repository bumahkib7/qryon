//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PYTHON_HTTP_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "aiohttp.web_response.StreamResponse.headers",
        pattern: SourceKind::MemberAccess("aiohttp.web_response.StreamResponse.headers"),
        taint_label: "user_input",
        description: "Pysa source: aiohttp.web_response.StreamResponse.headers (kind: HeaderData)",
    },
    SourceDef {
        name: "aiohttp.web_response.StreamResponse.cookies",
        pattern: SourceKind::MemberAccess("aiohttp.web_response.StreamResponse.cookies"),
        taint_label: "user_input",
        description: "Pysa source: aiohttp.web_response.StreamResponse.cookies (kind: Cookies)",
    },
    SourceDef {
        name: "aiohttp.web_ws.WebSocketResponse.__aiter__",
        pattern: SourceKind::MemberAccess("aiohttp.web_ws.WebSocketResponse.__aiter__"),
        taint_label: "user_input",
        description: "Pysa source: aiohttp.web_ws.WebSocketResponse.__aiter__ (kind: UserControlled)",
    },
    SourceDef {
        name: "urllib.request.urlopen",
        pattern: SourceKind::MemberAccess("urllib.request.urlopen"),
        taint_label: "user_input",
        description: "Pysa source: urllib.request.urlopen (kind: DataFromInternet)",
    },
    SourceDef {
        name: "urllib.request.urlretrieve",
        pattern: SourceKind::MemberAccess("urllib.request.urlretrieve"),
        taint_label: "user_input",
        description: "Pysa source: urllib.request.urlretrieve (kind: DataFromInternet)",
    },
    SourceDef {
        name: "urllib.request.URLopener.open",
        pattern: SourceKind::MemberAccess("urllib.request.URLopener.open"),
        taint_label: "user_input",
        description: "Pysa source: urllib.request.URLopener.open (kind: DataFromInternet)",
    },
    SourceDef {
        name: "urllib.request.URLopener.open_unknown",
        pattern: SourceKind::MemberAccess("urllib.request.URLopener.open_unknown"),
        taint_label: "user_input",
        description: "Pysa source: urllib.request.URLopener.open_unknown (kind: DataFromInternet)",
    },
    SourceDef {
        name: "urllib.request.URLopener.retrieve",
        pattern: SourceKind::MemberAccess("urllib.request.URLopener.retrieve"),
        taint_label: "user_input",
        description: "Pysa source: urllib.request.URLopener.retrieve (kind: DataFromInternet)",
    },
];

static PYTHON_HTTP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "aiohttp.web_response.Response.text",
        pattern: SinkKind::FunctionCall("aiohttp.web_response.Response.text"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: aiohttp.web_response.Response.text (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "urllib.request.urlretrieve",
        pattern: SinkKind::FunctionCall("urllib.request.urlretrieve"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: urllib.request.urlretrieve (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "requests.models.Request.__init__",
        pattern: SinkKind::FunctionCall("requests.models.Request.__init__"),
        rule_id: "python/gen-pysa-authentication",
        severity: Severity::Error,
        description: "Pysa sink: requests.models.Request.__init__ (kind: Authentication)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "requests.models.PreparedRequest.prepare",
        pattern: SinkKind::FunctionCall("requests.models.PreparedRequest.prepare"),
        rule_id: "python/gen-pysa-authentication",
        severity: Severity::Error,
        description: "Pysa sink: requests.models.PreparedRequest.prepare (kind: Authentication)",
        cwe: Some("CWE-74"),
    },
];

static PYTHON_HTTP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PYTHON_HTTP_GEN_IMPORTS: &[&str] = &["aiohttp", "urllib", "requests"];

pub static PYTHON_HTTP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "python_http_generated",
    description: "Generated profile for aiohttp from CodeQL/Pysa",
    detect_imports: PYTHON_HTTP_GEN_IMPORTS,
    sources: PYTHON_HTTP_GEN_SOURCES,
    sinks: PYTHON_HTTP_GEN_SINKS,
    sanitizers: PYTHON_HTTP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
