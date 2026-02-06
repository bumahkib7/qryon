//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ANDROIDX_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "androidx.slice.SliceProvider.onBindSlice",
        pattern: SourceKind::MemberAccess("androidx.slice.SliceProvider.onBindSlice"),
        taint_label: "user_input",
        description: "CodeQL source: androidx.slice.SliceProvider.onBindSlice (kind: manual)",
    },
    SourceDef {
        name: "androidx.slice.SliceProvider.onCreatePermissionRequest",
        pattern: SourceKind::MemberAccess("androidx.slice.SliceProvider.onCreatePermissionRequest"),
        taint_label: "user_input",
        description: "CodeQL source: androidx.slice.SliceProvider.onCreatePermissionRequest (kind: manual)",
    },
    SourceDef {
        name: "androidx.slice.SliceProvider.onMapIntentToUri",
        pattern: SourceKind::MemberAccess("androidx.slice.SliceProvider.onMapIntentToUri"),
        taint_label: "user_input",
        description: "CodeQL source: androidx.slice.SliceProvider.onMapIntentToUri (kind: manual)",
    },
    SourceDef {
        name: "androidx.slice.SliceProvider.onSlicePinned",
        pattern: SourceKind::MemberAccess("androidx.slice.SliceProvider.onSlicePinned"),
        taint_label: "user_input",
        description: "CodeQL source: androidx.slice.SliceProvider.onSlicePinned (kind: manual)",
    },
    SourceDef {
        name: "androidx.slice.SliceProvider.onSliceUnpinned",
        pattern: SourceKind::MemberAccess("androidx.slice.SliceProvider.onSliceUnpinned"),
        taint_label: "user_input",
        description: "CodeQL source: androidx.slice.SliceProvider.onSliceUnpinned (kind: manual)",
    },
];

static ANDROIDX_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "androidx.fragment.app.FragmentTransaction.add",
        pattern: SinkKind::FunctionCall("androidx.fragment.app.FragmentTransaction.add"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.fragment.app.FragmentTransaction.add (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.fragment.app.FragmentTransaction.attach",
        pattern: SinkKind::FunctionCall("androidx.fragment.app.FragmentTransaction.attach"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.fragment.app.FragmentTransaction.attach (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.fragment.app.FragmentTransaction.replace",
        pattern: SinkKind::FunctionCall("androidx.fragment.app.FragmentTransaction.replace"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.fragment.app.FragmentTransaction.replace (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.AlarmManagerCompat.setAlarmClock",
        pattern: SinkKind::FunctionCall("androidx.core.app.AlarmManagerCompat.setAlarmClock"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.AlarmManagerCompat.setAlarmClock (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.AlarmManagerCompat.setAndAllowWhileIdle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.AlarmManagerCompat.setAndAllowWhileIdle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.AlarmManagerCompat.setAndAllowWhileIdle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.AlarmManagerCompat.setExact",
        pattern: SinkKind::FunctionCall("androidx.core.app.AlarmManagerCompat.setExact"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.AlarmManagerCompat.setExact (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.AlarmManagerCompat.setExactAndAllowWhileIdle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.AlarmManagerCompat.setExactAndAllowWhileIdle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.AlarmManagerCompat.setExactAndAllowWhileIdle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Action.Action",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Action.Action"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Action.Action (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Action$Builder.Builder",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Action$Builder.Builder",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Action$Builder.Builder (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Action$Builder.addExtras",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Action$Builder.addExtras",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Action$Builder.addExtras (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigPictureStyle.setBigContentTitle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigPictureStyle.setBigContentTitle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigPictureStyle.setBigContentTitle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigPictureStyle.setContentDescription",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigPictureStyle.setContentDescription",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigPictureStyle.setContentDescription (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigPictureStyle.setSummaryText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigPictureStyle.setSummaryText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigPictureStyle.setSummaryText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigTextStyle.bigText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigTextStyle.bigText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigTextStyle.bigText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigTextStyle.setBigContentTitle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigTextStyle.setBigContentTitle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigTextStyle.setBigContentTitle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$BigTextStyle.setSummaryText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$BigTextStyle.setSummaryText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$BigTextStyle.setSummaryText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.addAction",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.addAction"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.addAction (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.addExtras",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.addExtras"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.addExtras (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setCategory",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setCategory"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setCategory (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setChannelId",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setChannelId",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setChannelId (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setContent",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setContent"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setContent (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setContentInfo",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setContentInfo",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setContentInfo (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setContentText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setContentText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setContentText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setContentTitle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setContentTitle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setContentTitle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setCustomBigContentView",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setCustomBigContentView",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setCustomBigContentView (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setCustomContentView",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setCustomContentView",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setCustomContentView (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setCustomHeadsUpContentView",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setCustomHeadsUpContentView",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setCustomHeadsUpContentView (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setExtras",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setExtras"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setExtras (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setGroup",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setGroup"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setGroup (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setRemoteInputHistory",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setRemoteInputHistory",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setRemoteInputHistory (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setSettingsText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$Builder.setSettingsText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setSettingsText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setSortKey",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setSortKey"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setSortKey (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setSubText",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setSubText"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setSubText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$Builder.setTicker",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$Builder.setTicker"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$Builder.setTicker (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$CallStyle.setVerificationText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$CallStyle.setVerificationText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$CallStyle.setVerificationText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$InboxStyle.addLine",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationCompat$InboxStyle.addLine"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$InboxStyle.addLine (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$InboxStyle.setBigContentTitle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$InboxStyle.setBigContentTitle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$InboxStyle.setBigContentTitle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$InboxStyle.setSummaryText",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$InboxStyle.setSummaryText",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$InboxStyle.setSummaryText (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$MessagingStyle.addMessage",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$MessagingStyle.addMessage",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$MessagingStyle.addMessage (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$MessagingStyle.setConversationTitle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$MessagingStyle.setConversationTitle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$MessagingStyle.setConversationTitle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$MessagingStyle.MessagingStyle",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$MessagingStyle.MessagingStyle",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$MessagingStyle.MessagingStyle (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationCompat$MessagingStyle$Message.Message",
        pattern: SinkKind::FunctionCall(
            "androidx.core.app.NotificationCompat$MessagingStyle$Message.Message",
        ),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationCompat$MessagingStyle$Message.Message (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.core.app.NotificationManagerCompat.notify",
        pattern: SinkKind::FunctionCall("androidx.core.app.NotificationManagerCompat.notify"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.core.app.NotificationManagerCompat.notify (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.slice.SliceProvider.onBindSlice",
        pattern: SinkKind::FunctionCall("androidx.slice.SliceProvider.onBindSlice"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.slice.SliceProvider.onBindSlice (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "androidx.slice.SliceProvider.onCreatePermissionRequest",
        pattern: SinkKind::FunctionCall("androidx.slice.SliceProvider.onCreatePermissionRequest"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: androidx.slice.SliceProvider.onCreatePermissionRequest (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static ANDROIDX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ANDROIDX_GEN_IMPORTS: &[&str] = &[
    "androidx.fragment.app",
    "androidx.core.app",
    "androidx.slice.builders",
    "androidx.slice",
];

pub static ANDROIDX_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "androidx_generated",
    description: "Generated profile for androidx.fragment.app from CodeQL/Pysa",
    detect_imports: ANDROIDX_GEN_IMPORTS,
    sources: ANDROIDX_GEN_SOURCES,
    sinks: ANDROIDX_GEN_SINKS,
    sanitizers: ANDROIDX_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
