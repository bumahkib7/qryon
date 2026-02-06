//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES: &[SourceDef] = &[
];

static ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<escaped-positional-derive::Cli as clap_builder::derive::FromArgMatches>::from_arg_matches_mut.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS: &[&str] = &[
    "<escaped-positional-derive::Cli as clap_builder::derive::FromArgMatches>::from_arg_matches_mut",
];

pub static ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<escaped_positional_derive::cli as clap_builder::derive::fromargmatches>::from_arg_matches_mut_generated",
    description: "Generated profile for <escaped-positional-derive::Cli as clap_builder::derive::FromArgMatches>::from_arg_matches_mut from CodeQL/Pysa",
    detect_imports: ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS,
    sources: ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES,
    sinks: ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS,
    sanitizers: ESCAPED_POSITIONAL_DERIVE_CLI_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
