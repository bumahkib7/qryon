//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SOURCES: &[SourceDef] =
    &[];

static CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<clap_builder::parser::matches::arg_matches::ArgMatches>::contains_id.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_IMPORTS: &[&str] =
    &["<clap_builder::parser::matches::arg_matches::ArgMatches>::contains_id"];

pub static CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<clap_builder::parser::matches::arg_matches::argmatches>::contains_id_generated",
    description: "Generated profile for <clap_builder::parser::matches::arg_matches::ArgMatches>::contains_id from CodeQL/Pysa",
    detect_imports: CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_IMPORTS,
    sources: CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SOURCES,
    sinks: CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SINKS,
    sanitizers: CLAP_BUILDER_PARSER_MATCHES_ARG_MATCHES_ARGMATCHES_CONTAINS_ID_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
