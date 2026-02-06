//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<style::style::StyleChecker>::check_file.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<style::style::StyleChecker>::check_file.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_IMPORTS: &[&str] =
    &["<style::style::StyleChecker>::check_file"];

pub static STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<style::style::stylechecker>::check_file_generated",
    description: "Generated profile for <style::style::StyleChecker>::check_file from CodeQL/Pysa",
    detect_imports: STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_IMPORTS,
    sources: STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SOURCES,
    sinks: STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SINKS,
    sanitizers: STYLE_STYLE_STYLECHECKER_CHECK_FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
