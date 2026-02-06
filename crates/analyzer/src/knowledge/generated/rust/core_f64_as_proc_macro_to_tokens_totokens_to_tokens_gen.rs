//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SOURCES: &[SourceDef] = &[];

static CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::f64 as proc_macro::to_tokens::ToTokens>::to_tokens.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_IMPORTS: &[&str] =
    &["<core::f64 as proc_macro::to_tokens::ToTokens>::to_tokens"];

pub static CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::f64 as proc_macro::to_tokens::totokens>::to_tokens_generated",
        description: "Generated profile for <core::f64 as proc_macro::to_tokens::ToTokens>::to_tokens from CodeQL/Pysa",
        detect_imports: CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_IMPORTS,
        sources: CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SOURCES,
        sinks: CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SINKS,
        sanitizers: CORE_F64_AS_PROC_MACRO_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
