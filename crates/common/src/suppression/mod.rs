//! Database-backed suppression system for managing false positives
//!
//! This module provides a persistent suppression system using Sled for storage,
//! enabling teams to manage false positives without modifying source code.
//!
//! ## Features
//!
//! - **Persistent Storage**: Suppressions stored in `.rma/suppressions.db`
//! - **Audit Trail**: Full history of who, when, and why for each suppression
//! - **Team Sharing**: Export to JSON for version control
//! - **Staleness Detection**: Detect when suppressed code has changed
//! - **Expiration**: Automatic expiration with configurable defaults
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rma_common::suppression::{SuppressionStore, SuppressionEntry, SuppressionStatus};
//!
//! // Open the store
//! let store = SuppressionStore::open_project(".")?;
//!
//! // Check if a finding is suppressed
//! if let Some(entry) = store.is_suppressed("sha256:abc123...")? {
//!     println!("Suppressed by {} on {}", entry.suppressed_by, entry.created_at);
//! }
//!
//! // Add a new suppression
//! let entry = SuppressionEntry::new(
//!     "sha256:abc123...",
//!     "generic/hardcoded-secret",
//!     "src/test.rs",
//!     "admin",
//!     "Test fixture, not a real key",
//! );
//! store.suppress(entry)?;
//!
//! // Export for team sharing
//! let json = store.export()?;
//! std::fs::write(".rma/suppressions.json", json)?;
//! ```

mod audit;
mod entry;
mod store;

pub use audit::{AuditAction, AuditContext, AuditEvent, AuditQuery, AuditSeverity, FieldChange};
pub use entry::{
    Approval, ApprovalInfo, Rejection, RevocationSchedule, SuppressionEntry, SuppressionStatus,
    hash_snippet,
};
pub use store::{StoreStats, SuppressionExport, SuppressionFilter, SuppressionStore};

/// Default path for the suppression database within a project
pub const DEFAULT_DB_PATH: &str = ".rma/suppressions.db";

/// Default path for exported suppressions JSON
pub const DEFAULT_EXPORT_PATH: &str = ".rma/suppressions.json";

/// Default expiration period for suppressions (90 days)
pub const DEFAULT_EXPIRATION_DAYS: u32 = 90;

/// Maximum allowed expiration period (365 days)
pub const MAX_EXPIRATION_DAYS: u32 = 365;
