//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static DJANGO_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "django.http.request.HttpRequest.COOKIES",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.COOKIES"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.COOKIES (kind: Cookies)",
    },
    SourceDef {
        name: "django.http.request.HttpRequest.get_signed_cookie",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.get_signed_cookie"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.get_signed_cookie (kind: Cookies)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.cookies",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase.cookies"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.cookies (kind: Cookies)",
    },
    SourceDef {
        name: "django.http.request.HttpRequest.META",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.META"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.META (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.request.HttpRequest.__repr__",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.__repr__"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.__repr__ (kind: HeaderData)",
    },
    SourceDef {
        name: "django.core.handlers.wsgi.WSGIRequest.environ",
        pattern: SourceKind::MemberAccess("django.core.handlers.wsgi.WSGIRequest.environ"),
        taint_label: "user_input",
        description: "Pysa source: django.core.handlers.wsgi.WSGIRequest.environ (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.request.HttpRequest.get_full_path",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.get_full_path"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.get_full_path (kind: URL)",
    },
    SourceDef {
        name: "django.http.request.HttpRequest.build_absolute_uri",
        pattern: SourceKind::MemberAccess("django.http.request.HttpRequest.build_absolute_uri"),
        taint_label: "user_input",
        description: "Pysa source: django.http.request.HttpRequest.build_absolute_uri (kind: URL)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase._headers",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase._headers"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase._headers (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.serialize_headers",
        pattern: SourceKind::MemberAccess(
            "django.http.response.HttpResponseBase.serialize_headers",
        ),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.serialize_headers (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.__bytes__",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase.__bytes__"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.__bytes__ (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.items",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase.items"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.items (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.get",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase.get"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.get (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponseBase.__getitem__",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponseBase.__getitem__"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponseBase.__getitem__ (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponse.serialize",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponse.serialize"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponse.serialize (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponse.__bytes__",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponse.__bytes__"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponse.__bytes__ (kind: HeaderData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponse.content",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponse.content"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponse.content (kind: ResponseData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponse.__iter__",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponse.__iter__"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponse.__iter__ (kind: ResponseData)",
    },
    SourceDef {
        name: "django.http.response.HttpResponse.getvalue",
        pattern: SourceKind::MemberAccess("django.http.response.HttpResponse.getvalue"),
        taint_label: "user_input",
        description: "Pysa source: django.http.response.HttpResponse.getvalue (kind: ResponseData)",
    },
    SourceDef {
        name: "django.core.cache.backends.base.BaseCache.get",
        pattern: SourceKind::MemberAccess("django.core.cache.backends.base.BaseCache.get"),
        taint_label: "user_input",
        description: "Pysa source: django.core.cache.backends.base.BaseCache.get (kind: MemCache)",
    },
    SourceDef {
        name: "django.core.cache.backends.base.BaseCache.get_many",
        pattern: SourceKind::MemberAccess("django.core.cache.backends.base.BaseCache.get_many"),
        taint_label: "user_input",
        description: "Pysa source: django.core.cache.backends.base.BaseCache.get_many (kind: MemCache)",
    },
    SourceDef {
        name: "django.contrib.sessions.backends.base.SessionBase.session_key",
        pattern: SourceKind::MemberAccess(
            "django.contrib.sessions.backends.base.SessionBase.session_key",
        ),
        taint_label: "user_input",
        description: "Pysa source: django.contrib.sessions.backends.base.SessionBase.session_key (kind: UserSecrets)",
    },
    SourceDef {
        name: "django.contrib.sessions.backends.base.SessionBase._session_key",
        pattern: SourceKind::MemberAccess(
            "django.contrib.sessions.backends.base.SessionBase._session_key",
        ),
        taint_label: "user_input",
        description: "Pysa source: django.contrib.sessions.backends.base.SessionBase._session_key (kind: UserSecrets)",
    },
];

static DJANGO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "django.template.engine.Engine.from_string",
        pattern: SinkKind::FunctionCall("django.template.engine.Engine.from_string"),
        rule_id: "python/gen-pysa-serversidetemplateinjection",
        severity: Severity::Error,
        description: "Pysa sink: django.template.engine.Engine.from_string (kind: ServerSideTemplateInjection)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.template.base.Template.__init__",
        pattern: SinkKind::FunctionCall("django.template.base.Template.__init__"),
        rule_id: "python/gen-pysa-serversidetemplateinjection",
        severity: Severity::Error,
        description: "Pysa sink: django.template.base.Template.__init__ (kind: ServerSideTemplateInjection)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.http.response.HttpResponseBase.__setitem__",
        pattern: SinkKind::FunctionCall("django.http.response.HttpResponseBase.__setitem__"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: django.http.response.HttpResponseBase.__setitem__ (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.http.response.HttpResponseBase.setdefault",
        pattern: SinkKind::FunctionCall("django.http.response.HttpResponseBase.setdefault"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: django.http.response.HttpResponseBase.setdefault (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.http.response.HttpResponseRedirect.__init__",
        pattern: SinkKind::FunctionCall("django.http.response.HttpResponseRedirect.__init__"),
        rule_id: "python/gen-pysa-redirect",
        severity: Severity::Error,
        description: "Pysa sink: django.http.response.HttpResponseRedirect.__init__ (kind: Redirect)",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "django.shortcuts.redirect",
        pattern: SinkKind::FunctionCall("django.shortcuts.redirect"),
        rule_id: "python/gen-pysa-redirect",
        severity: Severity::Error,
        description: "Pysa sink: django.shortcuts.redirect (kind: Redirect)",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "django.shortcuts.render",
        pattern: SinkKind::FunctionCall("django.shortcuts.render"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: django.shortcuts.render (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "django.core.cache.backends.base.BaseCache.set",
        pattern: SinkKind::FunctionCall("django.core.cache.backends.base.BaseCache.set"),
        rule_id: "python/gen-pysa-memcachesink",
        severity: Severity::Error,
        description: "Pysa sink: django.core.cache.backends.base.BaseCache.set (kind: MemcacheSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.core.cache.backends.base.BaseCache.set_many",
        pattern: SinkKind::FunctionCall("django.core.cache.backends.base.BaseCache.set_many"),
        rule_id: "python/gen-pysa-memcachesink",
        severity: Severity::Error,
        description: "Pysa sink: django.core.cache.backends.base.BaseCache.set_many (kind: MemcacheSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "django.db.models.manager.Manager.raw",
        pattern: SinkKind::FunctionCall("django.db.models.manager.Manager.raw"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: django.db.models.manager.Manager.raw (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "django.db.backends.utils.CursorWrapper.execute",
        pattern: SinkKind::FunctionCall("django.db.backends.utils.CursorWrapper.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: django.db.backends.utils.CursorWrapper.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "django.db.backends.utils.CursorWrapper.executemany",
        pattern: SinkKind::FunctionCall("django.db.backends.utils.CursorWrapper.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: django.db.backends.utils.CursorWrapper.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "django.db.backends.mysql.base.CursorWrapper.execute",
        pattern: SinkKind::FunctionCall("django.db.backends.mysql.base.CursorWrapper.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: django.db.backends.mysql.base.CursorWrapper.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "django.db.backends.mysql.base.CursorWrapper.executemany",
        pattern: SinkKind::FunctionCall("django.db.backends.mysql.base.CursorWrapper.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: django.db.backends.mysql.base.CursorWrapper.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "django.utils.html.format_html",
        pattern: SinkKind::FunctionCall("django.utils.html.format_html"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: django.utils.html.format_html (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "django.utils.html.format_html_join",
        pattern: SinkKind::FunctionCall("django.utils.html.format_html_join"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: django.utils.html.format_html_join (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "django.http.response.HttpResponse.content",
        pattern: SinkKind::FunctionCall("django.http.response.HttpResponse.content"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: django.http.response.HttpResponse.content (kind: XSS)",
        cwe: Some("CWE-79"),
    },
];

static DJANGO_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "django.http.request.HttpRequest.is_secure",
    pattern: SanitizerKind::Function("django.http.request.HttpRequest.is_secure"),
    sanitizes: "general",
    description: "Pysa sanitizer: django.http.request.HttpRequest.is_secure",
}];

static DJANGO_GEN_IMPORTS: &[&str] = &["django"];

pub static DJANGO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "django_generated",
    description: "Generated profile for django from CodeQL/Pysa",
    detect_imports: DJANGO_GEN_IMPORTS,
    sources: DJANGO_GEN_SOURCES,
    sinks: DJANGO_GEN_SINKS,
    sanitizers: DJANGO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
