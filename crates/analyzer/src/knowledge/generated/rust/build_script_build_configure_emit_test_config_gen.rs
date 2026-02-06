//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SOURCES: &[SourceDef] = &[];

static BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "build-script-build::configure::emit_test_config.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_IMPORTS: &[&str] =
    &["build-script-build::configure::emit_test_config"];

pub static BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "build_script_build::configure::emit_test_config_generated",
        description: "Generated profile for build-script-build::configure::emit_test_config from CodeQL/Pysa",
        detect_imports: BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_IMPORTS,
        sources: BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SOURCES,
        sinks: BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SINKS,
        sanitizers: BUILD_SCRIPT_BUILD_CONFIGURE_EMIT_TEST_CONFIG_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
