//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ENCODING_XML_GEN_SOURCES: &[SourceDef] = &[];

static ENCODING_XML_GEN_SINKS: &[SinkDef] = &[];

static ENCODING_XML_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "encoding/xml.Escape",
        pattern: SanitizerKind::Function("encoding/xml..Escape"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml..Escape",
    },
    SanitizerDef {
        name: "encoding/xml.EscapeText",
        pattern: SanitizerKind::Function("encoding/xml..EscapeText"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml..EscapeText",
    },
    SanitizerDef {
        name: "encoding/xml.Encoder.Encode",
        pattern: SanitizerKind::Function("encoding/xml.Encoder.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml.Encoder.Encode",
    },
    SanitizerDef {
        name: "encoding/xml.Encoder.EncodeElement",
        pattern: SanitizerKind::Function("encoding/xml.Encoder.EncodeElement"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml.Encoder.EncodeElement",
    },
    SanitizerDef {
        name: "encoding/xml.Encoder.EncodeToken",
        pattern: SanitizerKind::Function("encoding/xml.Encoder.EncodeToken"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml.Encoder.EncodeToken",
    },
    SanitizerDef {
        name: "encoding/xml.Encoder.Indent",
        pattern: SanitizerKind::Function("encoding/xml.Encoder.Indent"),
        sanitizes: "general",
        description: "CodeQL sanitizer: encoding/xml.Encoder.Indent",
    },
];

static ENCODING_XML_GEN_IMPORTS: &[&str] = &["encoding/xml"];

pub static ENCODING_XML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "encoding_xml_generated",
    description: "Generated profile for encoding/xml from CodeQL/Pysa",
    detect_imports: ENCODING_XML_GEN_IMPORTS,
    sources: ENCODING_XML_GEN_SOURCES,
    sinks: ENCODING_XML_GEN_SINKS,
    sanitizers: ENCODING_XML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
