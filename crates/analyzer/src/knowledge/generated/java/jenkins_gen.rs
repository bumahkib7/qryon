//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static JENKINS_GEN_SOURCES: &[SourceDef] = &[];

static JENKINS_GEN_SINKS: &[SinkDef] = &[];

static JENKINS_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "jenkins.model.ParameterizedJobMixIn$ParameterizedJob.scheduleBuild2",
        pattern: SanitizerKind::Function(
            "jenkins.model.ParameterizedJobMixIn$ParameterizedJob.scheduleBuild2",
        ),
        sanitizes: "sql",
        description: "CodeQL sanitizer: jenkins.model.ParameterizedJobMixIn$ParameterizedJob.scheduleBuild2",
    },
    SanitizerDef {
        name: "jenkins.model.ParameterizedJobMixIn.extendSearchIndex",
        pattern: SanitizerKind::Function("jenkins.model.ParameterizedJobMixIn.extendSearchIndex"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: jenkins.model.ParameterizedJobMixIn.extendSearchIndex",
    },
    SanitizerDef {
        name: "jenkins.model.ParameterizedJobMixIn.getTrigger",
        pattern: SanitizerKind::Function("jenkins.model.ParameterizedJobMixIn.getTrigger"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: jenkins.model.ParameterizedJobMixIn.getTrigger",
    },
    SanitizerDef {
        name: "jenkins.model.ParameterizedJobMixIn.scheduleBuild2",
        pattern: SanitizerKind::Function("jenkins.model.ParameterizedJobMixIn.scheduleBuild2"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: jenkins.model.ParameterizedJobMixIn.scheduleBuild2",
    },
    SanitizerDef {
        name: "jenkins.org.apache.commons.validator.routines.RegexValidator.validate",
        pattern: SanitizerKind::Function(
            "jenkins.org.apache.commons.validator.routines.RegexValidator.validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: jenkins.org.apache.commons.validator.routines.RegexValidator.validate",
    },
];

static JENKINS_GEN_IMPORTS: &[&str] = &[
    "jenkins.diagnosis",
    "jenkins.fingerprints",
    "jenkins.install",
    "jenkins.management",
    "jenkins.model.item_category",
    "jenkins.model.labels",
    "jenkins.model.lazy",
    "jenkins.model.queue",
    "jenkins.model",
    "jenkins.mvn",
    "jenkins.org.apache.commons.validator.routines",
    "jenkins.plugins",
    "jenkins.security.apitoken",
    "jenkins.security.seed",
    "jenkins.security.stapler",
    "jenkins.security",
    "jenkins.slaves",
    "jenkins.tasks.filters.impl",
    "jenkins.tasks.filters",
    "jenkins.tasks",
    "jenkins.telemetry",
    "jenkins.triggers",
    "jenkins.util.antlr",
    "jenkins.util.groovy",
    "jenkins.util.io",
    "jenkins.util.xml",
    "jenkins.util.xstream",
    "jenkins.util",
    "jenkins.websocket",
    "jenkins.widgets",
    "jenkins",
    "jenkins.agents",
    "jenkins.diagnostics",
    "jenkins.formelementpath",
    "jenkins.model.identity",
    "jenkins.monitor",
    "jenkins.scm",
    "jenkins.security.csrf",
    "jenkins.security.s2m",
    "jenkins.slaves.restarter",
    "jenkins.slaves.systemInfo",
    "jenkins.telemetry.impl",
    "jenkins.tools",
    "jenkins.util.java",
    "jenkins.views",
];

pub static JENKINS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "jenkins_generated",
    description: "Generated profile for jenkins.diagnosis from CodeQL/Pysa",
    detect_imports: JENKINS_GEN_IMPORTS,
    sources: JENKINS_GEN_SOURCES,
    sinks: JENKINS_GEN_SINKS,
    sanitizers: JENKINS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
