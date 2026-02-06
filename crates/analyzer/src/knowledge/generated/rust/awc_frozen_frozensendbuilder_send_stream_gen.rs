//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SOURCES: &[SourceDef] = &[];

static AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<awc::frozen::FrozenSendBuilder>::send_stream.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_IMPORTS: &[&str] =
    &["<awc::frozen::FrozenSendBuilder>::send_stream"];

pub static AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<awc::frozen::frozensendbuilder>::send_stream_generated",
        description: "Generated profile for <awc::frozen::FrozenSendBuilder>::send_stream from CodeQL/Pysa",
        detect_imports: AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_IMPORTS,
        sources: AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SOURCES,
        sinks: AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SINKS,
        sanitizers: AWC_FROZEN_FROZENSENDBUILDER_SEND_STREAM_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
