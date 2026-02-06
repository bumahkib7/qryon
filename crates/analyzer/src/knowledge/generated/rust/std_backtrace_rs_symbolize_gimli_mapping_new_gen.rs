//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::backtrace_rs::symbolize::gimli::Mapping>::new.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::backtrace_rs::symbolize::gimli::Mapping>::new.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_IMPORTS: &[&str] =
    &["<std::backtrace_rs::symbolize::gimli::Mapping>::new"];

pub static STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::backtrace_rs::symbolize::gimli::mapping>::new_generated",
        description: "Generated profile for <std::backtrace_rs::symbolize::gimli::Mapping>::new from CodeQL/Pysa",
        detect_imports: STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_IMPORTS,
        sources: STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SOURCES,
        sinks: STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SINKS,
        sanitizers: STD_BACKTRACE_RS_SYMBOLIZE_GIMLI_MAPPING_NEW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
