//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SOURCES: &[SourceDef] = &[
];

static ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<alloc::vec::Vec as tokio_stream::stream_ext::collect::sealed::FromStreamPriv>::initialize.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_IMPORTS: &[&str] = &[
    "<alloc::vec::Vec as tokio_stream::stream_ext::collect::sealed::FromStreamPriv>::initialize",
];

pub static ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<alloc::vec::vec as tokio_stream::stream_ext::collect::sealed::fromstreampriv>::initialize_generated",
    description: "Generated profile for <alloc::vec::Vec as tokio_stream::stream_ext::collect::sealed::FromStreamPriv>::initialize from CodeQL/Pysa",
    detect_imports: ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_IMPORTS,
    sources: ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SOURCES,
    sinks: ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SINKS,
    sanitizers: ALLOC_VEC_VEC_AS_TOKIO_STREAM_STREAM_EXT_COLLECT_SEALED_FROMSTREAMPRIV_INITIALIZE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
