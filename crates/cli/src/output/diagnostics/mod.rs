//! Rich diagnostic output for rustc-style error messages
//!
//! This module provides beautiful, context-rich diagnostic output similar to
//! what rustc produces. It includes:
//! - Error codes (QRYON-S001, QRYON-Q001, etc.)
//! - Source code context with line numbers
//! - Underline highlighting for the problematic span
//! - Notes and help messages

#![allow(dead_code)] // Many items are part of the public API for future use

pub mod codes;
pub mod renderer;
pub mod source;
pub mod spans;

// Re-exports for public API
#[allow(unused_imports)]
pub use codes::{Category, DiagnosticCode, DiagnosticCodeRegistry, REGISTRY};
#[allow(unused_imports)]
pub use renderer::{RichDiagnosticConfig, RichDiagnosticRenderer};
#[allow(unused_imports)]
pub use source::{SourceCache, SourceFile, SourceLine};
#[allow(unused_imports)]
pub use spans::SpanRenderer;

use rma_common::Finding;

/// Trait for rendering diagnostics
pub trait DiagnosticRenderer {
    /// Render a single finding as a diagnostic string
    fn render(&self, finding: &Finding, cache: &mut SourceCache) -> String;

    /// Render multiple findings
    fn render_all(&self, findings: &[Finding], cache: &mut SourceCache) -> String {
        findings
            .iter()
            .map(|f| self.render(f, cache))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
