//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SOURCES: &[SourceDef] = &[];

static RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<rand::seq::index_::IndexVec>::into_vec.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_IMPORTS: &[&str] =
    &["<rand::seq::index_::IndexVec>::into_vec"];

pub static RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<rand::seq::index_::indexvec>::into_vec_generated",
    description: "Generated profile for <rand::seq::index_::IndexVec>::into_vec from CodeQL/Pysa",
    detect_imports: RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_IMPORTS,
    sources: RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SOURCES,
    sinks: RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SINKS,
    sanitizers: RAND_SEQ_INDEX_INDEXVEC_INTO_VEC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
