//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<reqwest::blocking::multipart::Form>::file.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SINKS: &[SinkDef] = &[];

static REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_IMPORTS: &[&str] =
    &["<reqwest::blocking::multipart::Form>::file"];

pub static REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<reqwest::blocking::multipart::form>::file_generated",
    description: "Generated profile for <reqwest::blocking::multipart::Form>::file from CodeQL/Pysa",
    detect_imports: REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_IMPORTS,
    sources: REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SOURCES,
    sinks: REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SINKS,
    sanitizers: REQWEST_BLOCKING_MULTIPART_FORM_FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
