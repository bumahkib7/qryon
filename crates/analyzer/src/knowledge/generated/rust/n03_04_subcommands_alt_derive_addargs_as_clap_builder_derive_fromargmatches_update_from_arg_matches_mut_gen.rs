//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SOURCES: &[SourceDef] = &[
];

static N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<03_04_subcommands_alt_derive::AddArgs as clap_builder::derive::FromArgMatches>::update_from_arg_matches_mut.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_IMPORTS: &[&str] = &[
    "<03_04_subcommands_alt_derive::AddArgs as clap_builder::derive::FromArgMatches>::update_from_arg_matches_mut",
];

pub static N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<03_04_subcommands_alt_derive::addargs as clap_builder::derive::fromargmatches>::update_from_arg_matches_mut_generated",
    description: "Generated profile for <03_04_subcommands_alt_derive::AddArgs as clap_builder::derive::FromArgMatches>::update_from_arg_matches_mut from CodeQL/Pysa",
    detect_imports: N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_IMPORTS,
    sources: N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SOURCES,
    sinks: N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SINKS,
    sanitizers: N03_04_SUBCOMMANDS_ALT_DERIVE_ADDARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_UPDATE_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
