//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES: &[SourceDef] = &[
];

static INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<interop_hand_subcommand::AddArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS: &[&str] = &[
    "<interop_hand_subcommand::AddArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut",
];

pub static INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<interop_hand_subcommand::addargs as clap_builder::derive::fromargmatches>::from_arg_matches_mut_generated",
    description: "Generated profile for <interop_hand_subcommand::AddArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut from CodeQL/Pysa",
    detect_imports: INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS,
    sources: INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES,
    sinks: INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS,
    sanitizers: INTEROP_HAND_SUBCOMMAND_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
