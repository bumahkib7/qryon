//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES:
    &[SourceDef] = &[];

static TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<typed-derive::Args as clap_builder::derive::FromArgMatches>::from_arg_matches_mut.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS:
    &[&str] =
    &["<typed-derive::Args as clap_builder::derive::FromArgMatches>::from_arg_matches_mut"];

pub static TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<typed_derive::args as clap_builder::derive::fromargmatches>::from_arg_matches_mut_generated",
    description: "Generated profile for <typed-derive::Args as clap_builder::derive::FromArgMatches>::from_arg_matches_mut from CodeQL/Pysa",
    detect_imports: TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS,
    sources: TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES,
    sinks: TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS,
    sanitizers: TYPED_DERIVE_ARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
