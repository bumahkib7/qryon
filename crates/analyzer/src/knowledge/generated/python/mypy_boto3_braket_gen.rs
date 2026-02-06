//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_BRAKET_GEN_SOURCES: &[SourceDef] = &[];

static MYPY_BOTO3_BRAKET_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "mypy_boto3_braket.client.BraketClient.create_quantum_task",
    pattern: SinkKind::FunctionCall("mypy_boto3_braket.client.BraketClient.create_quantum_task"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: mypy_boto3_braket.client.BraketClient.create_quantum_task (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static MYPY_BOTO3_BRAKET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_BRAKET_GEN_IMPORTS: &[&str] = &["mypy_boto3_braket"];

pub static MYPY_BOTO3_BRAKET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_braket_generated",
    description: "Generated profile for mypy_boto3_braket from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_BRAKET_GEN_IMPORTS,
    sources: MYPY_BOTO3_BRAKET_GEN_SOURCES,
    sinks: MYPY_BOTO3_BRAKET_GEN_SINKS,
    sanitizers: MYPY_BOTO3_BRAKET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
