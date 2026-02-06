//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GOPKG_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "gopkg.in/macaron.Context.AllParams",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.AllParams"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.AllParams (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.GetCookie",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.GetCookie"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.GetCookie (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.GetSecureCookie",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.GetSecureCookie"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.GetSecureCookie (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.GetSuperSecureCookie",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.GetSuperSecureCookie"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.GetSuperSecureCookie (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.GetFile",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.GetFile"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.GetFile (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.Params",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.Params"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.Params (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.ParamsEscape",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.ParamsEscape"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.ParamsEscape (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.Query",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.Query"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.Query (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.QueryEscape",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.QueryEscape"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.QueryEscape (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.Context.QueryStrings",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.Context.QueryStrings"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.Context.QueryStrings (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.RequestBody.Bytes",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.RequestBody.Bytes"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.RequestBody.Bytes (kind: manual)",
    },
    SourceDef {
        name: "gopkg.in/macaron.RequestBody.String",
        pattern: SourceKind::MemberAccess("gopkg.in/macaron.RequestBody.String"),
        taint_label: "user_input",
        description: "CodeQL source: gopkg.in/macaron.RequestBody.String (kind: manual)",
    },
];

static GOPKG_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "gopkg.in/macaron.Context.Redirect",
    pattern: SinkKind::FunctionCall("gopkg.in/macaron.Context.Redirect"),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: gopkg.in/macaron.Context.Redirect (kind: manual)",
    cwe: Some("CWE-74"),
}];

static GOPKG_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "gopkg.in/yaml.Encoder.Encode",
        pattern: SanitizerKind::Function("gopkg.in/yaml.Encoder.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: gopkg.in/yaml.Encoder.Encode",
    },
    SanitizerDef {
        name: "gopkg.in/yaml.Node.Encode",
        pattern: SanitizerKind::Function("gopkg.in/yaml.Node.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: gopkg.in/yaml.Node.Encode",
    },
];

static GOPKG_GEN_IMPORTS: &[&str] = &["gopkg.in/macaron", "gopkg.in/yaml"];

pub static GOPKG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "gopkg_generated",
    description: "Generated profile for gopkg.in/macaron from CodeQL/Pysa",
    detect_imports: GOPKG_GEN_IMPORTS,
    sources: GOPKG_GEN_SOURCES,
    sinks: GOPKG_GEN_SINKS,
    sanitizers: GOPKG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
