//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SOURCES: &[SourceDef] = &[
];

static CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<clap_builder::builder::value_parser::PathBufValueParser as clap_builder::builder::value_parser::TypedValueParser>::parse.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_IMPORTS: &[&str] = &[
    "<clap_builder::builder::value_parser::PathBufValueParser as clap_builder::builder::value_parser::TypedValueParser>::parse",
];

pub static CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<clap_builder::builder::value_parser::pathbufvalueparser as clap_builder::builder::value_parser::typedvalueparser>::parse_generated",
    description: "Generated profile for <clap_builder::builder::value_parser::PathBufValueParser as clap_builder::builder::value_parser::TypedValueParser>::parse from CodeQL/Pysa",
    detect_imports: CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_IMPORTS,
    sources: CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SOURCES,
    sinks: CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SINKS,
    sanitizers: CLAP_BUILDER_BUILDER_VALUE_PARSER_PATHBUFVALUEPARSER_AS_CLAP_BUILDER_BUILDER_VALUE_PARSER_TYPEDVALUEPARSER_PARSE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
