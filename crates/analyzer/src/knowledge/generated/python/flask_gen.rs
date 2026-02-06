//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FLASK_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "werkzeug.wrappers.BaseResponse.get_data",
        pattern: SourceKind::MemberAccess("werkzeug.wrappers.BaseResponse.get_data"),
        taint_label: "user_input",
        description: "Pysa source: werkzeug.wrappers.BaseResponse.get_data (kind: ResponseData)",
    },
    SourceDef {
        name: "werkzeug.wrappers.CommonResponseDescriptorsMixin.location",
        pattern: SourceKind::MemberAccess(
            "werkzeug.wrappers.CommonResponseDescriptorsMixin.location",
        ),
        taint_label: "user_input",
        description: "Pysa source: werkzeug.wrappers.CommonResponseDescriptorsMixin.location (kind: URL)",
    },
    SourceDef {
        name: "werkzeug.wrappers.response.Response.get_data",
        pattern: SourceKind::MemberAccess("werkzeug.wrappers.response.Response.get_data"),
        taint_label: "user_input",
        description: "Pysa source: werkzeug.wrappers.response.Response.get_data (kind: ResponseData)",
    },
    SourceDef {
        name: "werkzeug.wrappers.response.Response.get_json",
        pattern: SourceKind::MemberAccess("werkzeug.wrappers.response.Response.get_json"),
        taint_label: "user_input",
        description: "Pysa source: werkzeug.wrappers.response.Response.get_json (kind: ResponseData)",
    },
    SourceDef {
        name: "flask.globals.session",
        pattern: SourceKind::MemberAccess("flask.globals.session"),
        taint_label: "user_input",
        description: "Pysa source: flask.globals.session (kind: UserControlled)",
    },
];

static FLASK_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "jinja2.filters.do_mark_safe",
        pattern: SinkKind::FunctionCall("jinja2.filters.do_mark_safe"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: jinja2.filters.do_mark_safe (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "markupsafe.Markup.__new__",
        pattern: SinkKind::FunctionCall("markupsafe.Markup.__new__"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: markupsafe.Markup.__new__ (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "jinja2.environment.Template.__new__",
        pattern: SinkKind::FunctionCall("jinja2.environment.Template.__new__"),
        rule_id: "python/gen-pysa-serversidetemplateinjection",
        severity: Severity::Error,
        description: "Pysa sink: jinja2.environment.Template.__new__ (kind: ServerSideTemplateInjection)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "werkzeug.utils.redirect",
        pattern: SinkKind::FunctionCall("werkzeug.utils.redirect"),
        rule_id: "python/gen-pysa-redirect",
        severity: Severity::Error,
        description: "Pysa sink: werkzeug.utils.redirect (kind: Redirect)",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "flask.json.jsonify",
        pattern: SinkKind::FunctionCall("flask.json.jsonify"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: flask.json.jsonify (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "werkzeug.utils.secure_filename",
        pattern: SinkKind::FunctionCall("werkzeug.utils.secure_filename"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: werkzeug.utils.secure_filename (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "flask.helpers.send_from_directory",
        pattern: SinkKind::FunctionCall("flask.helpers.send_from_directory"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: flask.helpers.send_from_directory (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
];

static FLASK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FLASK_GEN_IMPORTS: &[&str] = &["jinja2", "markupsafe", "werkzeug", "flask"];

pub static FLASK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "flask_generated",
    description: "Generated profile for jinja2 from CodeQL/Pysa",
    detect_imports: FLASK_GEN_IMPORTS,
    sources: FLASK_GEN_SOURCES,
    sinks: FLASK_GEN_SINKS,
    sanitizers: FLASK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
