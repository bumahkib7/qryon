//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ENCODING_PEM_GEN_SOURCES: &[SourceDef] = &[];

static ENCODING_PEM_GEN_SINKS: &[SinkDef] = &[];

static ENCODING_PEM_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "encoding/pem.Encode",
        pattern: SanitizerKind::Function("encoding/pem..Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/pem..Encode",
    },
    SanitizerDef {
        name: "encoding/pem.EncodeToMemory",
        pattern: SanitizerKind::Function("encoding/pem..EncodeToMemory"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/pem..EncodeToMemory",
    },
];

static ENCODING_PEM_GEN_IMPORTS: &[&str] = &["encoding/pem"];

pub static ENCODING_PEM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "encoding_pem_generated",
    description: "Generated profile for encoding/pem from CodeQL/Pysa",
    detect_imports: ENCODING_PEM_GEN_IMPORTS,
    sources: ENCODING_PEM_GEN_SOURCES,
    sinks: ENCODING_PEM_GEN_SINKS,
    sanitizers: ENCODING_PEM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
