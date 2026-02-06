//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STRCONV_GEN_SOURCES: &[SourceDef] = &[];

static STRCONV_GEN_SINKS: &[SinkDef] = &[];

static STRCONV_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "strconv.AppendQuote",
        pattern: SanitizerKind::Function("strconv..AppendQuote"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..AppendQuote",
    },
    SanitizerDef {
        name: "strconv.AppendQuoteToASCII",
        pattern: SanitizerKind::Function("strconv..AppendQuoteToASCII"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..AppendQuoteToASCII",
    },
    SanitizerDef {
        name: "strconv.AppendQuoteToGraphic",
        pattern: SanitizerKind::Function("strconv..AppendQuoteToGraphic"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..AppendQuoteToGraphic",
    },
    SanitizerDef {
        name: "strconv.Quote",
        pattern: SanitizerKind::Function("strconv..Quote"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..Quote",
    },
    SanitizerDef {
        name: "strconv.QuoteToASCII",
        pattern: SanitizerKind::Function("strconv..QuoteToASCII"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..QuoteToASCII",
    },
    SanitizerDef {
        name: "strconv.QuoteToGraphic",
        pattern: SanitizerKind::Function("strconv..QuoteToGraphic"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..QuoteToGraphic",
    },
    SanitizerDef {
        name: "strconv.QuotedPrefix",
        pattern: SanitizerKind::Function("strconv..QuotedPrefix"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..QuotedPrefix",
    },
    SanitizerDef {
        name: "strconv.Unquote",
        pattern: SanitizerKind::Function("strconv..Unquote"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..Unquote",
    },
    SanitizerDef {
        name: "strconv.UnquoteChar",
        pattern: SanitizerKind::Function("strconv..UnquoteChar"),
        sanitizes: "general",
        description: "CodeQL sanitizer: strconv..UnquoteChar",
    },
];

static STRCONV_GEN_IMPORTS: &[&str] = &["strconv"];

pub static STRCONV_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "strconv_generated",
    description: "Generated profile for strconv from CodeQL/Pysa",
    detect_imports: STRCONV_GEN_IMPORTS,
    sources: STRCONV_GEN_SOURCES,
    sinks: STRCONV_GEN_SINKS,
    sanitizers: STRCONV_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
