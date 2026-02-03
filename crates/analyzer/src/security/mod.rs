//! Security module - DEPRECATED
//!
//! All security scanning is now done through the embedded Semgrep rule engine.
//! The 647+ community-vetted rules provide comprehensive coverage.
//!
//! This module is kept for backwards compatibility but contains no active rules.
//! Analysis engines (taint, typestate, CFG) are in the `flow` module.

// NOTE: All hardcoded rules have been removed in favor of the Semgrep rule engine.
// The following modules are deprecated and will be removed in a future version:
//
// - rust.rs - Use semgrep rust/* rules
// - javascript.rs - Use semgrep javascript/* rules
// - python.rs - Use semgrep python/* rules
// - java.rs - Use semgrep java/* rules
// - go.rs - Use semgrep go/* rules
// - generic.rs - Use semgrep generic/* rules
// - typestate_rules.rs - Typestate analysis moved to flow module
// - dataflow_rules.rs - Dataflow analysis moved to flow module
// - xss_taint.rs - XSS detection via semgrep rules
// - null_pointer.rs - Null checks via semgrep rules
// - resource_leak.rs - Resource leaks via semgrep rules
