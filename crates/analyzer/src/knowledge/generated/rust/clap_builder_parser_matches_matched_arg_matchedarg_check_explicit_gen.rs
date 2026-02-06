//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SOURCES:
    &[SourceDef] = &[];

static CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<clap_builder::parser::matches::matched_arg::MatchedArg>::check_explicit.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_IMPORTS: &[&str] =
    &["<clap_builder::parser::matches::matched_arg::MatchedArg>::check_explicit"];

pub static CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<clap_builder::parser::matches::matched_arg::matchedarg>::check_explicit_generated",
    description: "Generated profile for <clap_builder::parser::matches::matched_arg::MatchedArg>::check_explicit from CodeQL/Pysa",
    detect_imports: CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_IMPORTS,
    sources: CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SOURCES,
    sinks: CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SINKS,
    sanitizers: CLAP_BUILDER_PARSER_MATCHES_MATCHED_ARG_MATCHEDARG_CHECK_EXPLICIT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
