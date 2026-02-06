//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SOURCES:
    &[SourceDef] = &[];

static SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<serde::__private::ser::content::SerializeStructVariantAsMapValue>::new.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    }];

static SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_IMPORTS: &[&str] =
    &["<serde::__private::ser::content::SerializeStructVariantAsMapValue>::new"];

pub static SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<serde::__private::ser::content::serializestructvariantasmapvalue>::new_generated",
    description: "Generated profile for <serde::__private::ser::content::SerializeStructVariantAsMapValue>::new from CodeQL/Pysa",
    detect_imports: SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_IMPORTS,
    sources: SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SOURCES,
    sinks: SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SINKS,
    sanitizers: SERDE___PRIVATE_SER_CONTENT_SERIALIZESTRUCTVARIANTASMAPVALUE_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
