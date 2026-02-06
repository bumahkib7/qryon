//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static UNDERSCORE_GEN_SOURCES: &[SourceDef] = &[];

static UNDERSCORE_GEN_SINKS: &[SinkDef] = &[];

static UNDERSCORE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "'underscore.string'.Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,strip,lstrip,rstrip,camelcase]",
        pattern: SanitizerKind::Function(
            "Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,strip,lstrip,rstrip,camelcase]",
        ),
        sanitizes: "html",
        description: "CodeQL sanitizer: Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,strip,lstrip,rstrip,camelcase]",
    },
    SanitizerDef {
        name: "'underscore.string'.Member[surround,quote,q]",
        pattern: SanitizerKind::Function("Member[surround,quote,q]"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Member[surround,quote,q]",
    },
    SanitizerDef {
        name: "'underscore.string'.Wrapper.Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,value,strip,lstrip,rstrip,camelcase]",
        pattern: SanitizerKind::Function(
            "Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,value,strip,lstrip,rstrip,camelcase]",
        ),
        sanitizes: "html",
        description: "CodeQL sanitizer: Member[slugify,capitalize,decapitalize,clean,cleanDiacritics,swapCase,escapeHTML,unescapeHTML,wrap,dedent,reverse,pred,succ,titleize,camelize,classify,underscored,dasherize,humanize,trim,ltrim,rtrim,truncate,sprintf,strRight,strRightBack,strLeft,strLeftBack,stripTags,unquote,value,strip,lstrip,rstrip,camelcase]",
    },
    SanitizerDef {
        name: "'underscore.string'.Wrapper.Member[insert,replaceAll,join,splice,prune,pad,lpad,rpad,repeat,surround,quote,q,rjust,ljust]",
        pattern: SanitizerKind::Function(
            "Member[insert,replaceAll,join,splice,prune,pad,lpad,rpad,repeat,surround,quote,q,rjust,ljust]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Member[insert,replaceAll,join,splice,prune,pad,lpad,rpad,repeat,surround,quote,q,rjust,ljust]",
    },
    SanitizerDef {
        name: "'underscore.string'.Wrapper.Member[surround,quote,q]",
        pattern: SanitizerKind::Function("Member[surround,quote,q]"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Member[surround,quote,q]",
    },
];

static UNDERSCORE_GEN_IMPORTS: &[&str] = &["'underscore.string'.Wrapper", "'underscore.string'"];

pub static UNDERSCORE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "'underscore_generated",
    description: "Generated profile for 'underscore.string'.Wrapper from CodeQL/Pysa",
    detect_imports: UNDERSCORE_GEN_IMPORTS,
    sources: UNDERSCORE_GEN_SOURCES,
    sinks: UNDERSCORE_GEN_SINKS,
    sanitizers: UNDERSCORE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
