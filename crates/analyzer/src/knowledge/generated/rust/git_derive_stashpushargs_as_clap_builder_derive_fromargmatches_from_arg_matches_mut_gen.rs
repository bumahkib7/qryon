//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES: &[SourceDef] = &[
];

static GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<git-derive::StashPushArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS: &[&str] = &[
    "<git-derive::StashPushArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut",
];

pub static GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<git_derive::stashpushargs as clap_builder::derive::fromargmatches>::from_arg_matches_mut_generated",
    description: "Generated profile for <git-derive::StashPushArgs as clap_builder::derive::FromArgMatches>::from_arg_matches_mut from CodeQL/Pysa",
    detect_imports: GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_IMPORTS,
    sources: GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SOURCES,
    sinks: GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SINKS,
    sanitizers: GIT_DERIVE_STASHPUSHARGS_AS_CLAP_BUILDER_DERIVE_FROMARGMATCHES_FROM_ARG_MATCHES_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
