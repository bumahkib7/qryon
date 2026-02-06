//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MICROSOFT_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "Microsoft.Extensions.DependencyModel.Resolution.DotNetReferenceAssembliesPathResolver.Resolve",
        pattern: SourceKind::MemberAccess(
            "Microsoft.Extensions.DependencyModel.Resolution.DotNetReferenceAssembliesPathResolver.Resolve",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Extensions.DependencyModel.Resolution.DotNetReferenceAssembliesPathResolver.Resolve (kind: df-generated)",
    },
    SourceDef {
        name: "Microsoft.Extensions.Configuration.UserSecrets.PathHelper.GetSecretsPathFromSecretsId",
        pattern: SourceKind::MemberAccess(
            "Microsoft.Extensions.Configuration.UserSecrets.PathHelper.GetSecretsPathFromSecretsId",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Extensions.Configuration.UserSecrets.PathHelper.GetSecretsPathFromSecretsId (kind: df-generated)",
    },
    SourceDef {
        name: "Microsoft.Extensions.Configuration.EnvironmentVariablesExtensions.AddEnvironmentVariables",
        pattern: SourceKind::MemberAccess(
            "Microsoft.Extensions.Configuration.EnvironmentVariablesExtensions.AddEnvironmentVariables",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Extensions.Configuration.EnvironmentVariablesExtensions.AddEnvironmentVariables (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.AspNetCore.Components.NavigationManager.get_BaseUri",
        pattern: SourceKind::MemberAccess(
            "Microsoft.AspNetCore.Components.NavigationManager.get_BaseUri",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.AspNetCore.Components.NavigationManager.get_BaseUri (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.AspNetCore.Components.NavigationManager.get_Uri",
        pattern: SourceKind::MemberAccess(
            "Microsoft.AspNetCore.Components.NavigationManager.get_Uri",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.AspNetCore.Components.NavigationManager.get_Uri (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute",
        pattern: SourceKind::MemberAccess(
            "Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute",
        pattern: SourceKind::MemberAccess(
            "Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.Win32.Registry.GetValue",
        pattern: SourceKind::MemberAccess("Microsoft.Win32.Registry.GetValue"),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Win32.Registry.GetValue (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.Win32.RegistryKey.GetSubKeyNames",
        pattern: SourceKind::MemberAccess("Microsoft.Win32.RegistryKey.GetSubKeyNames"),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Win32.RegistryKey.GetSubKeyNames (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.Win32.RegistryKey.GetValue",
        pattern: SourceKind::MemberAccess("Microsoft.Win32.RegistryKey.GetValue"),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Win32.RegistryKey.GetValue (kind: manual)",
    },
    SourceDef {
        name: "Microsoft.Win32.RegistryKey.GetValueNames",
        pattern: SourceKind::MemberAccess("Microsoft.Win32.RegistryKey.GetValueNames"),
        taint_label: "user_input",
        description: "CodeQL source: Microsoft.Win32.RegistryKey.GetValueNames (kind: manual)",
    },
];

static MICROSOFT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "Microsoft.AspNetCore.Components.MarkupString.MarkupString",
        pattern: SinkKind::FunctionCall(
            "Microsoft.AspNetCore.Components.MarkupString.MarkupString",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.AspNetCore.Components.MarkupString.MarkupString (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.AspNetCore.Components.MarkupString.op_Explicit",
        pattern: SinkKind::FunctionCall("Microsoft.AspNetCore.Components.MarkupString.op_Explicit"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.AspNetCore.Components.MarkupString.op_Explicit (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.Data.SqlClient.SqlCommand.SqlCommand",
        pattern: SinkKind::FunctionCall("Microsoft.Data.SqlClient.SqlCommand.SqlCommand"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.Data.SqlClient.SqlCommand.SqlCommand (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.Data.SqlClient.SqlDataAdapter.SqlDataAdapter",
        pattern: SinkKind::FunctionCall("Microsoft.Data.SqlClient.SqlDataAdapter.SqlDataAdapter"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.Data.SqlClient.SqlDataAdapter.SqlDataAdapter (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw",
        pattern: SinkKind::FunctionCall(
            "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRawAsync",
        pattern: SinkKind::FunctionCall(
            "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRawAsync",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRawAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw<TEntity>",
        pattern: SinkKind::FunctionCall(
            "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw<TEntity>",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw<TEntity> (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteDataset",
        pattern: SinkKind::FunctionCall(
            "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteDataset",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteDataset (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteNonQuery",
        pattern: SinkKind::FunctionCall(
            "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteNonQuery",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteNonQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteReader",
        pattern: SinkKind::FunctionCall("Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteReader"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteReader (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteScalar",
        pattern: SinkKind::FunctionCall("Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteScalar"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteScalar (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteXmlReader",
        pattern: SinkKind::FunctionCall(
            "Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteXmlReader",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.ApplicationBlocks.Data.SqlHelper.ExecuteXmlReader (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.JSInterop.JSRuntimeExtensions.InvokeAsync<TValue>",
        pattern: SinkKind::FunctionCall(
            "Microsoft.JSInterop.JSRuntimeExtensions.InvokeAsync<TValue>",
        ),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.JSInterop.JSRuntimeExtensions.InvokeAsync<TValue> (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Microsoft.JSInterop.JSRuntimeExtensions.InvokeVoidAsync",
        pattern: SinkKind::FunctionCall("Microsoft.JSInterop.JSRuntimeExtensions.InvokeVoidAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Microsoft.JSInterop.JSRuntimeExtensions.InvokeVoidAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static MICROSOFT_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "Microsoft.Win32.SafeHandles.SafeFileHandle.SafeFileHandle",
        pattern: SanitizerKind::Function(
            "Microsoft.Win32.SafeHandles.SafeFileHandle.SafeFileHandle",
        ),
        sanitizes: "path",
        description: "CodeQL sanitizer: Microsoft.Win32.SafeHandles.SafeFileHandle.SafeFileHandle",
    },
    SanitizerDef {
        name: "Microsoft.Win32.SafeHandles.SafeWaitHandle.SafeWaitHandle",
        pattern: SanitizerKind::Function(
            "Microsoft.Win32.SafeHandles.SafeWaitHandle.SafeWaitHandle",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Win32.SafeHandles.SafeWaitHandle.SafeWaitHandle",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.DataAnnotationValidateOptions<TOptions>.DataAnnotationValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.DataAnnotationValidateOptions<TOptions>.DataAnnotationValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.DataAnnotationValidateOptions<TOptions>.DataAnnotationValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4,TDep5>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4,TDep5>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4,TDep5>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3,TDep4>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2,TDep3>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep1,TDep2>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.OptionsBuilder<TOptions>.Validate<TDep>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4,TDep5>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3,TDep4>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2,TDep3>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep1,TDep2>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions,TDep>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions>.Validate",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions>.Validate",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions>.Validate",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptions<TOptions>.ValidateOptions",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptions<TOptions>.ValidateOptions",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptions<TOptions>.ValidateOptions",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptionsResult.Fail",
        pattern: SanitizerKind::Function("Microsoft.Extensions.Options.ValidateOptionsResult.Fail"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptionsResult.Fail",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddError",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddError",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddError",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResult",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResult",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResult",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResults",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResults",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptionsResultBuilder.AddResults",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.Build",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.Options.ValidateOptionsResultBuilder.Build",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.Options.ValidateOptionsResultBuilder.Build",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.DependencyInjection.OptionsBuilderDataAnnotationsExtensions.ValidateDataAnnotations<TOptions>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.DependencyInjection.OptionsBuilderDataAnnotationsExtensions.ValidateDataAnnotations<TOptions>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.DependencyInjection.OptionsBuilderDataAnnotationsExtensions.ValidateDataAnnotations<TOptions>",
    },
    SanitizerDef {
        name: "Microsoft.Extensions.DependencyInjection.OptionsBuilderExtensions.ValidateOnStart<TOptions>",
        pattern: SanitizerKind::Function(
            "Microsoft.Extensions.DependencyInjection.OptionsBuilderExtensions.ValidateOnStart<TOptions>",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Extensions.DependencyInjection.OptionsBuilderExtensions.ValidateOnStart<TOptions>",
    },
    SanitizerDef {
        name: "Microsoft.Interop.ContainingSyntaxContext.WrapMemberInContainingSyntaxWithUnsafeModifier",
        pattern: SanitizerKind::Function(
            "Microsoft.Interop.ContainingSyntaxContext.WrapMemberInContainingSyntaxWithUnsafeModifier",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Interop.ContainingSyntaxContext.WrapMemberInContainingSyntaxWithUnsafeModifier",
    },
    SanitizerDef {
        name: "Microsoft.Interop.MarshallerHelpers.ValidateCountInfoAvailableAtCall",
        pattern: SanitizerKind::Function(
            "Microsoft.Interop.MarshallerHelpers.ValidateCountInfoAvailableAtCall",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Microsoft.Interop.MarshallerHelpers.ValidateCountInfoAvailableAtCall",
    },
];

static MICROSOFT_GEN_IMPORTS: &[&str] = &[
    "Microsoft.Extensions.FileSystemGlobbing.Internal.PathSegments",
    "Microsoft.Extensions.Hosting.Systemd",
    "Microsoft.Extensions.Configuration.Xml",
    "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Logging.TraceSource",
    "Microsoft.Extensions.Logging.Abstractions",
    "Microsoft.Interop.Analyzers",
    "Microsoft.Extensions.Caching.Memory",
    "Microsoft.Extensions.Configuration.EnvironmentVariables",
    "Microsoft.Extensions.Logging.Console",
    "Microsoft.NET.Build.Tasks",
    "Microsoft.Extensions.Configuration.CommandLine",
    "Microsoft.VisualBasic",
    "Microsoft.DotNet.Build.Tasks",
    "Microsoft.Extensions.DependencyInjection.Extensions",
    "Microsoft.Win32.SafeHandles",
    "Microsoft.Diagnostics.JitTrace",
    "Microsoft.DotNet.PlatformAbstractions",
    "Microsoft.Extensions.FileProviders.Physical",
    "Microsoft.Extensions.DependencyModel",
    "Microsoft.Extensions.FileProviders",
    "Microsoft.VisualBasic.CompilerServices",
    "Microsoft.Extensions.Logging.Configuration",
    "Microsoft.CSharp.RuntimeBinder",
    "Microsoft.Extensions.FileSystemGlobbing.Abstractions",
    "Microsoft.Extensions.FileSystemGlobbing.Internal.PatternContexts",
    "Microsoft.Extensions.Configuration.Memory",
    "Microsoft.Extensions.Hosting.Internal",
    "Microsoft.Win32",
    "Microsoft.Extensions.Configuration.Binder.SourceGeneration",
    "Microsoft.Extensions.DependencyInjection.Specification",
    "Microsoft.Extensions.FileSystemGlobbing.Internal.Patterns",
    "Microsoft.Extensions.Caching.Hybrid",
    "Microsoft.Extensions.Primitives",
    "Microsoft.Extensions.FileSystemGlobbing",
    "Microsoft.Extensions.Caching.Distributed",
    "Microsoft.Interop.JavaScript",
    "Microsoft.Extensions.DependencyModel.Resolution",
    "Microsoft.Extensions.FileSystemGlobbing.Internal",
    "Microsoft.Extensions.Options",
    "Microsoft.Extensions.Hosting.WindowsServices",
    "Microsoft.Extensions.FileProviders.Composite",
    "Microsoft.Extensions.Logging.EventSource",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Http",
    "Microsoft.Extensions.FileProviders.Internal",
    "Microsoft.Extensions.Diagnostics.Metrics",
    "Microsoft.Extensions.Options.Generators",
    "Microsoft.Extensions.Configuration.UserSecrets",
    "Microsoft.Extensions.Logging.Debug",
    "Microsoft.Extensions.Logging",
    "Microsoft.Interop",
    "Microsoft.Extensions.DependencyInjection.Specification.Fakes",
    "Microsoft.VisualBasic.FileIO",
    "Microsoft.Diagnostics.Tools.Pgo.TypeRefTypeSystem",
    "Microsoft.Extensions.Logging.Generators",
    "Microsoft.Extensions.Configuration.Json",
    "Microsoft.Extensions.Hosting",
    "Microsoft.Extensions.Internal",
    "Microsoft.Extensions.Configuration.Ini",
    "Microsoft.NETCore.Platforms",
    "Microsoft.Extensions.Logging.EventLog",
    "Microsoft.CSharp",
    "Microsoft.Extensions.Http.Logging",
    "Microsoft.Diagnostics.Tools.Pgo",
    "Microsoft.Extensions.Diagnostics.Metrics.Configuration",
    "Microsoft.AspNetCore.Mvc",
    "Microsoft.AspNetCore.Components",
    "Microsoft.Data.SqlClient",
    "Microsoft.EntityFrameworkCore",
    "Microsoft.AspNetCore.Components.CompilerServices",
    "Microsoft.ApplicationBlocks.Data",
    "Microsoft.AspNetCore.Http",
    "Microsoft.AspNetCore.WebUtilities",
    "Microsoft.JSInterop",
];

pub static MICROSOFT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "microsoft_generated",
    description: "Generated profile for Microsoft.Extensions.FileSystemGlobbing.Internal.PathSegments from CodeQL/Pysa",
    detect_imports: MICROSOFT_GEN_IMPORTS,
    sources: MICROSOFT_GEN_SOURCES,
    sinks: MICROSOFT_GEN_SINKS,
    sanitizers: MICROSOFT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
