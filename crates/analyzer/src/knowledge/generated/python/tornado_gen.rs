//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TORNADO_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "tornado.httputil.HTTPServerRequest.path",
        pattern: SourceKind::MemberAccess("tornado.httputil.HTTPServerRequest.path"),
        taint_label: "user_input",
        description: "Pysa source: tornado.httputil.HTTPServerRequest.path (kind: URL)",
    },
    SourceDef {
        name: "tornado.httputil.HTTPServerRequest.uri",
        pattern: SourceKind::MemberAccess("tornado.httputil.HTTPServerRequest.uri"),
        taint_label: "user_input",
        description: "Pysa source: tornado.httputil.HTTPServerRequest.uri (kind: URL)",
    },
];

static TORNADO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "tornado.web.RequestHandler.write",
        pattern: SinkKind::FunctionCall("tornado.web.RequestHandler.write"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: tornado.web.RequestHandler.write (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "tornado.web.RequestHandler.set_header",
        pattern: SinkKind::FunctionCall("tornado.web.RequestHandler.set_header"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: tornado.web.RequestHandler.set_header (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "tornado.web.RequestHandler.add_header",
        pattern: SinkKind::FunctionCall("tornado.web.RequestHandler.add_header"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: tornado.web.RequestHandler.add_header (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "tornado.web.RequestHandler.redirect",
        pattern: SinkKind::FunctionCall("tornado.web.RequestHandler.redirect"),
        rule_id: "python/gen-pysa-redirect",
        severity: Severity::Error,
        description: "Pysa sink: tornado.web.RequestHandler.redirect (kind: Redirect)",
        cwe: Some("CWE-601"),
    },
];

static TORNADO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TORNADO_GEN_IMPORTS: &[&str] = &["tornado"];

pub static TORNADO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "tornado_generated",
    description: "Generated profile for tornado from CodeQL/Pysa",
    detect_imports: TORNADO_GEN_IMPORTS,
    sources: TORNADO_GEN_SOURCES,
    sinks: TORNADO_GEN_SINKS,
    sanitizers: TORNADO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
