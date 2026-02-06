//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SOFTWARE_GEN_SOURCES: &[SourceDef] = &[];

static SOFTWARE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.serializeToFile",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.serializeToFile",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.serializeToFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.DownloadFileRequest$Builder.destination",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.DownloadFileRequest$Builder.destination",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.DownloadFileRequest$Builder.destination (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.UploadFileRequest$Builder.source",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.UploadFileRequest$Builder.source",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.UploadFileRequest$Builder.source (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.DownloadDirectoryRequest$Builder.destination",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.DownloadDirectoryRequest$Builder.destination",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.DownloadDirectoryRequest$Builder.destination (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.fromFile",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.fromFile",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.fromFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.serializeToFile",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.serializeToFile",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.ResumableFileDownload.serializeToFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.fromFile",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.fromFile",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.ResumableFileUpload.fromFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "software.amazon.awssdk.transfer.s3.model.UploadDirectoryRequest$Builder.source",
        pattern: SinkKind::FunctionCall(
            "software.amazon.awssdk.transfer.s3.model.UploadDirectoryRequest$Builder.source",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: software.amazon.awssdk.transfer.s3.model.UploadDirectoryRequest$Builder.source (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static SOFTWARE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SOFTWARE_GEN_IMPORTS: &[&str] = &["software.amazon.awssdk.transfer.s3.model"];

pub static SOFTWARE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "software_generated",
    description: "Generated profile for software.amazon.awssdk.transfer.s3.model from CodeQL/Pysa",
    detect_imports: SOFTWARE_GEN_IMPORTS,
    sources: SOFTWARE_GEN_SOURCES,
    sinks: SOFTWARE_GEN_SINKS,
    sanitizers: SOFTWARE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
