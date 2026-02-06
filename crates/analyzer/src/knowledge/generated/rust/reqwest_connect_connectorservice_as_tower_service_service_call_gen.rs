//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SOURCES: &[SourceDef] =
    &[];

static REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<reqwest::connect::ConnectorService as tower_service::Service>::call.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_IMPORTS: &[&str] =
    &["<reqwest::connect::ConnectorService as tower_service::Service>::call"];

pub static REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<reqwest::connect::connectorservice as tower_service::service>::call_generated",
    description: "Generated profile for <reqwest::connect::ConnectorService as tower_service::Service>::call from CodeQL/Pysa",
    detect_imports: REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_IMPORTS,
    sources: REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SOURCES,
    sinks: REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SINKS,
    sanitizers: REQWEST_CONNECT_CONNECTORSERVICE_AS_TOWER_SERVICE_SERVICE_CALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
