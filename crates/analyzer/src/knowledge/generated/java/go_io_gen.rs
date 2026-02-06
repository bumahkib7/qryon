//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GO_IO_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "io.netty.handler.codec.ByteToMessageDecoder.callDecode",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.ByteToMessageDecoder.callDecode"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.ByteToMessageDecoder.callDecode (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.ByteToMessageDecoder.decode",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.ByteToMessageDecoder.decode"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.ByteToMessageDecoder.decode (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.ByteToMessageDecoder.decodeLast",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.ByteToMessageDecoder.decodeLast"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.ByteToMessageDecoder.decodeLast (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.ByteToMessageCodec.decode",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.ByteToMessageCodec.decode"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.ByteToMessageCodec.decode (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.ByteToMessageCodec.decodeLast",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.ByteToMessageCodec.decodeLast"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.ByteToMessageCodec.decodeLast (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.MessageToMessageDecoder.acceptInboundMessage",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.MessageToMessageDecoder.acceptInboundMessage",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.MessageToMessageDecoder.acceptInboundMessage (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.MessageToMessageDecoder.decode",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.MessageToMessageDecoder.decode"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.MessageToMessageDecoder.decode (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.MessageToMessageCodec.acceptInboundMessage",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.MessageToMessageCodec.acceptInboundMessage",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.MessageToMessageCodec.acceptInboundMessage (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.MessageToMessageCodec.decode",
        pattern: SourceKind::MemberAccess("io.netty.handler.codec.MessageToMessageCodec.decode"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.MessageToMessageCodec.decode (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.http2.Http2FrameListener.onDataRead",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.http2.Http2FrameListener.onDataRead",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.http2.Http2FrameListener.onDataRead (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.http2.Http2FrameListener.onHeadersRead",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.http2.Http2FrameListener.onHeadersRead",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.http2.Http2FrameListener.onHeadersRead (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.http2.Http2FrameListener.onPushPromiseRead",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.http2.Http2FrameListener.onPushPromiseRead",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.http2.Http2FrameListener.onPushPromiseRead (kind: manual)",
    },
    SourceDef {
        name: "io.netty.handler.codec.http2.Http2FrameListener.onUnknownFrame",
        pattern: SourceKind::MemberAccess(
            "io.netty.handler.codec.http2.Http2FrameListener.onUnknownFrame",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.handler.codec.http2.Http2FrameListener.onUnknownFrame (kind: manual)",
    },
    SourceDef {
        name: "io.netty.channel.ChannelInboundHandler.channelRead",
        pattern: SourceKind::MemberAccess("io.netty.channel.ChannelInboundHandler.channelRead"),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.channel.ChannelInboundHandler.channelRead (kind: manual)",
    },
    SourceDef {
        name: "io.netty.channel.SimpleChannelInboundHandler.channelRead0",
        pattern: SourceKind::MemberAccess(
            "io.netty.channel.SimpleChannelInboundHandler.channelRead0",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.netty.channel.SimpleChannelInboundHandler.channelRead0 (kind: manual)",
    },
    SourceDef {
        name: "io.jsonwebtoken.SigningKeyResolver.resolveSigningKey",
        pattern: SourceKind::MemberAccess("io.jsonwebtoken.SigningKeyResolver.resolveSigningKey"),
        taint_label: "user_input",
        description: "CodeQL source: io.jsonwebtoken.SigningKeyResolver.resolveSigningKey (kind: manual)",
    },
    SourceDef {
        name: "io.jsonwebtoken.SigningKeyResolverAdapter.resolveSigningKeyBytes",
        pattern: SourceKind::MemberAccess(
            "io.jsonwebtoken.SigningKeyResolverAdapter.resolveSigningKeyBytes",
        ),
        taint_label: "user_input",
        description: "CodeQL source: io.jsonwebtoken.SigningKeyResolverAdapter.resolveSigningKeyBytes (kind: manual)",
    },
];

static GO_IO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "io.netty.handler.codec.http.multipart.HttpPostRequestEncoder.addBodyFileUpload",
        pattern: SinkKind::FunctionCall(
            "io.netty.handler.codec.http.multipart.HttpPostRequestEncoder.addBodyFileUpload",
        ),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.codec.http.multipart.HttpPostRequestEncoder.addBodyFileUpload (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.bootstrap.Bootstrap.connect",
        pattern: SinkKind::FunctionCall("io.netty.bootstrap.Bootstrap.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.bootstrap.Bootstrap.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.undertow.server.handlers.resource.PathResourceManager.getResource",
        pattern: SinkKind::FunctionCall(
            "io.undertow.server.handlers.resource.PathResourceManager.getResource",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.undertow.server.handlers.resource.PathResourceManager.getResource (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.ssl.OpenSslServerContext.OpenSslServerContext",
        pattern: SinkKind::FunctionCall(
            "io.netty.handler.ssl.OpenSslServerContext.OpenSslServerContext",
        ),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.ssl.OpenSslServerContext.OpenSslServerContext (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.ssl.SslContextBuilder.forServer",
        pattern: SinkKind::FunctionCall("io.netty.handler.ssl.SslContextBuilder.forServer"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.ssl.SslContextBuilder.forServer (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.ssl.SslContextBuilder.trustManager",
        pattern: SinkKind::FunctionCall("io.netty.handler.ssl.SslContextBuilder.trustManager"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.ssl.SslContextBuilder.trustManager (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.util.internal.PlatformDependent.createTempFile",
        pattern: SinkKind::FunctionCall("io.netty.util.internal.PlatformDependent.createTempFile"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.util.internal.PlatformDependent.createTempFile (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.util.internal.SocketUtils.connect",
        pattern: SinkKind::FunctionCall("io.netty.util.internal.SocketUtils.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.util.internal.SocketUtils.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.codec.http.DefaultFullHttpRequest.DefaultFullHttpRequest",
        pattern: SinkKind::FunctionCall(
            "io.netty.handler.codec.http.DefaultFullHttpRequest.DefaultFullHttpRequest",
        ),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.codec.http.DefaultFullHttpRequest.DefaultFullHttpRequest (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.codec.http.DefaultHttpRequest.DefaultHttpRequest",
        pattern: SinkKind::FunctionCall(
            "io.netty.handler.codec.http.DefaultHttpRequest.DefaultHttpRequest",
        ),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.codec.http.DefaultHttpRequest.DefaultHttpRequest (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.codec.http.HttpRequest.setUri",
        pattern: SinkKind::FunctionCall("io.netty.handler.codec.http.HttpRequest.setUri"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.codec.http.HttpRequest.setUri (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.channel.Channel$Unsafe.connect",
        pattern: SinkKind::FunctionCall("io.netty.channel.Channel$Unsafe.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.channel.Channel$Unsafe.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.channel.ChannelDuplexHandler.connect",
        pattern: SinkKind::FunctionCall("io.netty.channel.ChannelDuplexHandler.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.channel.ChannelDuplexHandler.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.channel.ChannelOutboundHandlerAdapter.connect",
        pattern: SinkKind::FunctionCall("io.netty.channel.ChannelOutboundHandlerAdapter.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.channel.ChannelOutboundHandlerAdapter.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.channel.ChannelOutboundInvoker.connect",
        pattern: SinkKind::FunctionCall("io.netty.channel.ChannelOutboundInvoker.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.channel.ChannelOutboundInvoker.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.channel.DefaultChannelPipeline.connect",
        pattern: SinkKind::FunctionCall("io.netty.channel.DefaultChannelPipeline.connect"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.channel.DefaultChannelPipeline.connect (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io.netty.handler.stream.ChunkedFile.ChunkedFile",
        pattern: SinkKind::FunctionCall("io.netty.handler.stream.ChunkedFile.ChunkedFile"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io.netty.handler.stream.ChunkedFile.ChunkedFile (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
];

static GO_IO_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "io.netty.handler.codec.base64.Base64.encode",
        pattern: SanitizerKind::Function("io.netty.handler.codec.base64.Base64.encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: io.netty.handler.codec.base64.Base64.encode",
    },
    SanitizerDef {
        name: "io.netty.handler.codec.http.QueryStringEncoder.QueryStringEncoder",
        pattern: SanitizerKind::Function(
            "io.netty.handler.codec.http.QueryStringEncoder.QueryStringEncoder",
        ),
        sanitizes: "sql",
        description: "CodeQL sanitizer: io.netty.handler.codec.http.QueryStringEncoder.QueryStringEncoder",
    },
    SanitizerDef {
        name: "io.netty.buffer.ByteBufUtil.encodeString",
        pattern: SanitizerKind::Function("io.netty.buffer.ByteBufUtil.encodeString"),
        sanitizes: "general",
        description: "CodeQL sanitizer: io.netty.buffer.ByteBufUtil.encodeString",
    },
    SanitizerDef {
        name: "io.netty.handler.codec.http.cookie.ServerCookieEncoder.encode",
        pattern: SanitizerKind::Function(
            "io.netty.handler.codec.http.cookie.ServerCookieEncoder.encode",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: io.netty.handler.codec.http.cookie.ServerCookieEncoder.encode",
    },
];

static GO_IO_GEN_IMPORTS: &[&str] = &[
    "io.netty.handler.codec.base64",
    "io.netty.resolver",
    "io.netty.handler.codec",
    "io.netty.handler.codec.http.multipart",
    "io.netty.bootstrap",
    "io.undertow.server.handlers.resource",
    "io.netty.handler.ssl",
    "io.netty.util.internal",
    "io.netty.handler.codec.http.websocketx",
    "io.netty.handler.codec.http2",
    "io.netty.handler.codec.http",
    "io.netty.buffer",
    "io.netty.channel",
    "io.netty.handler.stream",
    "io.jsonwebtoken",
    "io.netty.handler.codec.http.cookie",
    "io.netty.util",
];

pub static GO_IO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "go_io_generated",
    description: "Generated profile for io.netty.handler.codec.base64 from CodeQL/Pysa",
    detect_imports: GO_IO_GEN_IMPORTS,
    sources: GO_IO_GEN_SOURCES,
    sinks: GO_IO_GEN_SINKS,
    sanitizers: GO_IO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
