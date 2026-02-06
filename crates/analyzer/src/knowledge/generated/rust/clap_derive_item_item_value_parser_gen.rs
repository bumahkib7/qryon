//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SOURCES: &[SourceDef] = &[];

static CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<clap_derive::item::Item>::value_parser.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_IMPORTS: &[&str] =
    &["<clap_derive::item::Item>::value_parser"];

pub static CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<clap_derive::item::item>::value_parser_generated",
    description: "Generated profile for <clap_derive::item::Item>::value_parser from CodeQL/Pysa",
    detect_imports: CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_IMPORTS,
    sources: CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SOURCES,
    sinks: CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SINKS,
    sanitizers: CLAP_DERIVE_ITEM_ITEM_VALUE_PARSER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
