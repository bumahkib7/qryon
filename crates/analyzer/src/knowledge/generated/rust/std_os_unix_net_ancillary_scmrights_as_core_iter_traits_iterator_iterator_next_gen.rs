//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES: &[SourceDef] = &[
];

static STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<std::os::unix::net::ancillary::ScmRights as core::iter::traits::iterator::Iterator>::next.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS: &[&str] = &[
    "<std::os::unix::net::ancillary::ScmRights as core::iter::traits::iterator::Iterator>::next",
];

pub static STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::os::unix::net::ancillary::scmrights as core::iter::traits::iterator::iterator>::next_generated",
    description: "Generated profile for <std::os::unix::net::ancillary::ScmRights as core::iter::traits::iterator::Iterator>::next from CodeQL/Pysa",
    detect_imports: STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS,
    sources: STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES,
    sinks: STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS,
    sanitizers: STD_OS_UNIX_NET_ANCILLARY_SCMRIGHTS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
