//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ENCODING_GOB_GEN_SOURCES: &[SourceDef] = &[];

static ENCODING_GOB_GEN_SINKS: &[SinkDef] = &[];

static ENCODING_GOB_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "encoding/gob.Encoder.Encode",
        pattern: SanitizerKind::Function("encoding/gob.Encoder.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/gob.Encoder.Encode",
    },
    SanitizerDef {
        name: "encoding/gob.Encoder.EncodeValue",
        pattern: SanitizerKind::Function("encoding/gob.Encoder.EncodeValue"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/gob.Encoder.EncodeValue",
    },
    SanitizerDef {
        name: "encoding/gob.GobEncoder.GobEncode",
        pattern: SanitizerKind::Function("encoding/gob.GobEncoder.GobEncode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/gob.GobEncoder.GobEncode",
    },
];

static ENCODING_GOB_GEN_IMPORTS: &[&str] = &["encoding/gob"];

pub static ENCODING_GOB_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "encoding_gob_generated",
    description: "Generated profile for encoding/gob from CodeQL/Pysa",
    detect_imports: ENCODING_GOB_GEN_IMPORTS,
    sources: ENCODING_GOB_GEN_SOURCES,
    sinks: ENCODING_GOB_GEN_SINKS,
    sanitizers: ENCODING_GOB_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
