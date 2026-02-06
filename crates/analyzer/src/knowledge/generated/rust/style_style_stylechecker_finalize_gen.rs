//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<style::style::StyleChecker>::finalize.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<style::style::StyleChecker>::finalize.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[self] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_IMPORTS: &[&str] =
    &["<style::style::StyleChecker>::finalize"];

pub static STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<style::style::stylechecker>::finalize_generated",
    description: "Generated profile for <style::style::StyleChecker>::finalize from CodeQL/Pysa",
    detect_imports: STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_IMPORTS,
    sources: STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SOURCES,
    sinks: STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SINKS,
    sanitizers: STYLE_STYLE_STYLECHECKER_FINALIZE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
