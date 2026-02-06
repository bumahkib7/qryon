//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ENCODING_JSON_GEN_SOURCES: &[SourceDef] = &[];

static ENCODING_JSON_GEN_SINKS: &[SinkDef] = &[];

static ENCODING_JSON_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "encoding/json.HTMLEscape",
        pattern: SanitizerKind::Function("encoding/json..HTMLEscape"),
        sanitizes: "html",
        description: "CodeQL sanitizer: encoding/json..HTMLEscape",
    },
    SanitizerDef {
        name: "encoding/json.Encoder.Encode",
        pattern: SanitizerKind::Function("encoding/json.Encoder.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/json.Encoder.Encode",
    },
    SanitizerDef {
        name: "encoding/json.Encoder.SetIndent",
        pattern: SanitizerKind::Function("encoding/json.Encoder.SetIndent"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/json.Encoder.SetIndent",
    },
];

static ENCODING_JSON_GEN_IMPORTS: &[&str] = &["encoding/json"];

pub static ENCODING_JSON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "encoding_json_generated",
    description: "Generated profile for encoding/json from CodeQL/Pysa",
    detect_imports: ENCODING_JSON_GEN_IMPORTS,
    sources: ENCODING_JSON_GEN_SOURCES,
    sinks: ENCODING_JSON_GEN_SINKS,
    sanitizers: ENCODING_JSON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
