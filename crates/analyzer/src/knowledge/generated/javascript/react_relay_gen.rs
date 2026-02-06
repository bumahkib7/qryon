//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REACT_RELAY_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "react-relay.Member[useFragment].ReturnValue",
        pattern: SourceKind::MemberAccess("useFragment"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useFragment].ReturnValue (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[useLazyLoadQuery].ReturnValue",
        pattern: SourceKind::MemberAccess("useLazyLoadQuery"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useLazyLoadQuery].ReturnValue (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[usePreloadedQuery].ReturnValue",
        pattern: SourceKind::MemberAccess("usePreloadedQuery"),
        taint_label: "user_input",
        description: "CodeQL source: Member[usePreloadedQuery].ReturnValue (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[useClientQuery].ReturnValue",
        pattern: SourceKind::MemberAccess("useClientQuery"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useClientQuery].ReturnValue (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[useRefetchableFragment].ReturnValue.Member[0]",
        pattern: SourceKind::MemberAccess("useRefetchableFragment.0"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useRefetchableFragment].ReturnValue.Member[0] (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[usePaginationFragment].ReturnValue.Member[data]",
        pattern: SourceKind::MemberAccess("usePaginationFragment.data"),
        taint_label: "user_input",
        description: "CodeQL source: Member[usePaginationFragment].ReturnValue.Member[data] (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[useMutation].ReturnValue.Member[0].Argument[0].Member[onCompleted].Parameter[0]",
        pattern: SourceKind::MemberAccess("useMutation.0.onCompleted.Parameter[0]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useMutation].ReturnValue.Member[0].Argument[0].Member[onCompleted].Parameter[0] (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[useSubscription].Argument[0].Member[onNext].Parameter[0]",
        pattern: SourceKind::MemberAccess("useSubscription.onNext.Parameter[0]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[useSubscription].Argument[0].Member[onNext].Parameter[0] (kind: response)",
    },
    SourceDef {
        name: "react-relay.Member[fetchQuery].ReturnValue.Member[subscribe].Argument[0].Member[next].Parameter[0]",
        pattern: SourceKind::MemberAccess("fetchQuery.subscribe.next.Parameter[0]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[fetchQuery].ReturnValue.Member[subscribe].Argument[0].Member[next].Parameter[0] (kind: response)",
    },
];

static REACT_RELAY_GEN_SINKS: &[SinkDef] = &[];

static REACT_RELAY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REACT_RELAY_GEN_IMPORTS: &[&str] = &["react-relay"];

pub static REACT_RELAY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "react_relay_generated",
    description: "Generated profile for react-relay from CodeQL/Pysa",
    detect_imports: REACT_RELAY_GEN_IMPORTS,
    sources: REACT_RELAY_GEN_SOURCES,
    sinks: REACT_RELAY_GEN_SINKS,
    sanitizers: REACT_RELAY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
