//! Suppression entry data structures with enterprise features
//!
//! Includes:
//! - Approval workflows
//! - Groups and tags
//! - Scheduled auto-revocation
//! - Policy compliance

use crate::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Status of a suppression entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionStatus {
    /// Suppression is active
    Active,
    /// Suppression has expired
    Expired,
    /// Suppression was manually revoked
    Revoked,
    /// The underlying code has changed (suppression may no longer apply)
    Stale,
    /// Pending approval
    PendingApproval,
    /// Approval was rejected
    Rejected,
    /// Scheduled for auto-revocation
    ScheduledRevocation,
}

impl Default for SuppressionStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for SuppressionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuppressionStatus::Active => write!(f, "active"),
            SuppressionStatus::Expired => write!(f, "expired"),
            SuppressionStatus::Revoked => write!(f, "revoked"),
            SuppressionStatus::Stale => write!(f, "stale"),
            SuppressionStatus::PendingApproval => write!(f, "pending-approval"),
            SuppressionStatus::Rejected => write!(f, "rejected"),
            SuppressionStatus::ScheduledRevocation => write!(f, "scheduled-revocation"),
        }
    }
}

/// Approval status for a suppression
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalInfo {
    /// Whether approval is required
    pub required: bool,
    /// List of required approvers (usernames or email patterns)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_approvers: Vec<String>,
    /// Approvals received
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<Approval>,
    /// Minimum number of approvals required
    #[serde(default = "default_min_approvals")]
    pub min_approvals: usize,
    /// Rejection info if rejected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<Rejection>,
}

fn default_min_approvals() -> usize {
    1
}

/// An approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Who approved
    pub approver: String,
    /// When approved (ISO 8601)
    pub approved_at: String,
    /// Optional comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A rejection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    /// Who rejected
    pub rejector: String,
    /// When rejected (ISO 8601)
    pub rejected_at: String,
    /// Reason for rejection
    pub reason: String,
}

impl ApprovalInfo {
    /// Check if the suppression has sufficient approvals
    pub fn is_approved(&self) -> bool {
        if !self.required {
            return true;
        }
        self.approvals.len() >= self.min_approvals
    }

    /// Check if it was rejected
    pub fn is_rejected(&self) -> bool {
        self.rejection.is_some()
    }

    /// Add an approval
    pub fn add_approval(&mut self, approver: impl Into<String>, comment: Option<String>) {
        self.approvals.push(Approval {
            approver: approver.into(),
            approved_at: chrono::Utc::now().to_rfc3339(),
            comment,
        });
    }

    /// Reject the suppression
    pub fn reject(&mut self, rejector: impl Into<String>, reason: impl Into<String>) {
        self.rejection = Some(Rejection {
            rejector: rejector.into(),
            rejected_at: chrono::Utc::now().to_rfc3339(),
            reason: reason.into(),
        });
    }
}

/// Auto-revocation schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationSchedule {
    /// When the auto-revocation is scheduled (ISO 8601)
    pub scheduled_at: String,
    /// Reason for scheduled revocation
    pub reason: String,
    /// Who scheduled the revocation
    pub scheduled_by: String,
    /// Whether to notify before revocation
    #[serde(default)]
    pub notify_before: bool,
    /// Days before revocation to send notification
    #[serde(default = "default_notify_days")]
    pub notify_days_before: u32,
    /// Grace period after scheduled time before actual revocation (hours)
    #[serde(default)]
    pub grace_period_hours: u32,
}

fn default_notify_days() -> u32 {
    7
}

impl RevocationSchedule {
    /// Create a new revocation schedule
    pub fn new(
        scheduled_at: impl Into<String>,
        reason: impl Into<String>,
        scheduled_by: impl Into<String>,
    ) -> Self {
        Self {
            scheduled_at: scheduled_at.into(),
            reason: reason.into(),
            scheduled_by: scheduled_by.into(),
            notify_before: true,
            notify_days_before: 7,
            grace_period_hours: 24,
        }
    }

    /// Check if the scheduled time has passed
    pub fn is_due(&self) -> bool {
        if let Ok(scheduled) = chrono::DateTime::parse_from_rfc3339(&self.scheduled_at) {
            let grace = chrono::Duration::hours(self.grace_period_hours as i64);
            return chrono::Utc::now() >= scheduled + grace;
        }
        false
    }

    /// Check if notification should be sent
    pub fn should_notify(&self) -> bool {
        if !self.notify_before {
            return false;
        }
        if let Ok(scheduled) = chrono::DateTime::parse_from_rfc3339(&self.scheduled_at) {
            let notify_time =
                scheduled - chrono::Duration::days(self.notify_days_before as i64);
            let now = chrono::Utc::now();
            return now >= notify_time && now < scheduled;
        }
        false
    }
}

/// A suppression entry representing a finding that should be ignored
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionEntry {
    /// Unique identifier for this suppression (UUID)
    pub id: String,

    /// SHA256 fingerprint of the finding being suppressed
    pub fingerprint: String,

    /// Rule ID that generated the finding (e.g., "generic/hardcoded-secret")
    pub rule_id: String,

    /// Path to the file containing the suppressed finding
    pub file_path: PathBuf,

    /// Hash of the code snippet for staleness detection (security: no raw code stored)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_hash: Option<String>,

    /// Hash of surrounding context for additional staleness detection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_hash: Option<String>,

    /// Who created this suppression
    pub suppressed_by: String,

    /// When this suppression was created (ISO 8601)
    pub created_at: String,

    /// When this suppression expires (ISO 8601, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Reason for the suppression
    pub reason: String,

    /// Reference to a ticket/issue (e.g., "JIRA-456")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<String>,

    /// Current status of the suppression
    #[serde(default)]
    pub status: SuppressionStatus,

    /// Original severity of the finding
    #[serde(default)]
    pub original_severity: Severity,

    // ========== Enterprise Features ==========
    /// Tags for categorization
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<String>,

    /// Groups this suppression belongs to
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub groups: HashSet<String>,

    /// Approval workflow info
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalInfo>,

    /// Scheduled auto-revocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_revocation: Option<RevocationSchedule>,

    /// Policy that created this suppression (if from policy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,

    /// Priority level (1-5, 1 being highest)
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Additional metadata
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, String>,

    /// Version number for optimistic locking
    #[serde(default)]
    pub version: u32,

    /// Last modified timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,

    /// Last modified by
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

fn default_priority() -> u8 {
    3
}

impl SuppressionEntry {
    /// Create a new active suppression entry
    pub fn new(
        fingerprint: impl Into<String>,
        rule_id: impl Into<String>,
        file_path: impl Into<PathBuf>,
        suppressed_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid_v4(),
            fingerprint: fingerprint.into(),
            rule_id: rule_id.into(),
            file_path: file_path.into(),
            snippet_hash: None,
            context_hash: None,
            suppressed_by: suppressed_by.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            reason: reason.into(),
            ticket_ref: None,
            status: SuppressionStatus::Active,
            original_severity: Severity::Warning,
            tags: HashSet::new(),
            groups: HashSet::new(),
            approval: None,
            scheduled_revocation: None,
            policy_id: None,
            priority: 3,
            metadata: std::collections::HashMap::new(),
            version: 1,
            updated_at: None,
            updated_by: None,
        }
    }

    /// Set the snippet hash for staleness detection (from raw snippet)
    pub fn with_snippet(mut self, snippet: impl AsRef<str>) -> Self {
        self.snippet_hash = Some(hash_snippet(snippet.as_ref()));
        self
    }

    /// Set the snippet hash directly
    pub fn with_snippet_hash(mut self, hash: impl Into<String>) -> Self {
        self.snippet_hash = Some(hash.into());
        self
    }

    /// Set the context hash for additional staleness detection
    pub fn with_context_hash(mut self, hash: impl Into<String>) -> Self {
        self.context_hash = Some(hash.into());
        self
    }

    /// Set an expiration date
    pub fn with_expiration(mut self, expires_at: impl Into<String>) -> Self {
        self.expires_at = Some(expires_at.into());
        self
    }

    /// Set expiration from a duration string (e.g., "90d", "30d", "7d")
    pub fn with_expiration_days(mut self, days: u32) -> Self {
        let expires = chrono::Utc::now() + chrono::Duration::days(days as i64);
        self.expires_at = Some(expires.to_rfc3339());
        self
    }

    /// Set a ticket reference
    pub fn with_ticket(mut self, ticket: impl Into<String>) -> Self {
        self.ticket_ref = Some(ticket.into());
        self
    }

    /// Set the original severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.original_severity = severity;
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }

    /// Add multiple tags
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        for tag in tags {
            self.tags.insert(tag.into());
        }
        self
    }

    /// Add to a group
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.groups.insert(group.into());
        self
    }

    /// Set priority (1-5)
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority.clamp(1, 5);
        self
    }

    /// Set policy ID
    pub fn with_policy(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    /// Require approval
    pub fn require_approval(mut self, min_approvals: usize) -> Self {
        self.approval = Some(ApprovalInfo {
            required: true,
            required_approvers: Vec::new(),
            approvals: Vec::new(),
            min_approvals,
            rejection: None,
        });
        self.status = SuppressionStatus::PendingApproval;
        self
    }

    /// Require approval from specific approvers
    pub fn require_approval_from(
        mut self,
        approvers: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.approval = Some(ApprovalInfo {
            required: true,
            required_approvers: approvers.into_iter().map(|a| a.into()).collect(),
            approvals: Vec::new(),
            min_approvals: 1,
            rejection: None,
        });
        self.status = SuppressionStatus::PendingApproval;
        self
    }

    /// Schedule auto-revocation
    pub fn schedule_revocation(
        mut self,
        scheduled_at: impl Into<String>,
        reason: impl Into<String>,
        scheduled_by: impl Into<String>,
    ) -> Self {
        self.scheduled_revocation = Some(RevocationSchedule::new(
            scheduled_at,
            reason,
            scheduled_by,
        ));
        self
    }

    /// Schedule auto-revocation in N days
    pub fn schedule_revocation_days(
        mut self,
        days: u32,
        reason: impl Into<String>,
        scheduled_by: impl Into<String>,
    ) -> Self {
        let scheduled = chrono::Utc::now() + chrono::Duration::days(days as i64);
        self.scheduled_revocation = Some(RevocationSchedule::new(
            scheduled.to_rfc3339(),
            reason,
            scheduled_by,
        ));
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if the suppression has expired
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires_at) = self.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                return expiry < chrono::Utc::now();
            }
        }
        false
    }

    /// Check if the suppression is active (not expired, revoked, or stale)
    pub fn is_active(&self) -> bool {
        matches!(self.status, SuppressionStatus::Active) && !self.is_expired()
    }

    /// Check if approval is pending
    pub fn is_pending_approval(&self) -> bool {
        self.status == SuppressionStatus::PendingApproval
    }

    /// Check if the suppression has been approved
    pub fn is_approved(&self) -> bool {
        self.approval.as_ref().map(|a| a.is_approved()).unwrap_or(true)
    }

    /// Approve the suppression
    pub fn approve(&mut self, approver: impl Into<String>, comment: Option<String>) {
        if let Some(ref mut approval) = self.approval {
            approval.add_approval(approver, comment);
            if approval.is_approved() {
                self.status = SuppressionStatus::Active;
            }
        }
        self.touch("approver");
    }

    /// Reject the suppression
    pub fn reject(&mut self, rejector: impl Into<String>, reason: impl Into<String>) {
        if let Some(ref mut approval) = self.approval {
            approval.reject(rejector.into(), reason);
        }
        self.status = SuppressionStatus::Rejected;
        self.touch("rejector");
    }

    /// Mark the suppression as revoked
    pub fn revoke(&mut self) {
        self.status = SuppressionStatus::Revoked;
    }

    /// Mark the suppression as stale
    pub fn mark_stale(&mut self) {
        self.status = SuppressionStatus::Stale;
    }

    /// Reactivate the suppression
    pub fn reactivate(&mut self, actor: impl Into<String>) {
        self.status = SuppressionStatus::Active;
        self.touch(actor);
    }

    /// Schedule auto-revocation (mutable version)
    pub fn set_scheduled_revocation(
        &mut self,
        scheduled_at: impl Into<String>,
        reason: impl Into<String>,
        scheduled_by: impl Into<String>,
    ) {
        self.scheduled_revocation = Some(RevocationSchedule::new(
            scheduled_at,
            reason,
            scheduled_by.into(),
        ));
        self.status = SuppressionStatus::ScheduledRevocation;
    }

    /// Cancel scheduled revocation
    pub fn cancel_scheduled_revocation(&mut self) {
        self.scheduled_revocation = None;
        if self.status == SuppressionStatus::ScheduledRevocation {
            self.status = SuppressionStatus::Active;
        }
    }

    /// Add an approval (convenience method for mutable operations)
    pub fn add_approval(&mut self, approver: impl Into<String>, comment: Option<&str>) {
        if let Some(ref mut approval) = self.approval {
            approval.add_approval(approver, comment.map(|s| s.to_string()));
            if approval.is_approved() {
                self.status = SuppressionStatus::Active;
            }
        }
        self.touch("approver");
    }

    /// Update the modification timestamp
    fn touch(&mut self, actor: impl Into<String>) {
        self.updated_at = Some(chrono::Utc::now().to_rfc3339());
        self.updated_by = Some(actor.into());
        self.version += 1;
    }

    /// Check if the code has changed (staleness detection)
    pub fn is_stale(&self, current_snippet: Option<&str>) -> bool {
        match (&self.snippet_hash, current_snippet) {
            (Some(original_hash), Some(current)) => {
                let current_hash = hash_snippet(current);
                original_hash != &current_hash
            }
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Check if the code has changed using a pre-computed hash
    pub fn is_stale_by_hash(&self, current_snippet_hash: Option<&str>) -> bool {
        match (&self.snippet_hash, current_snippet_hash) {
            (Some(original), Some(current)) => original != current,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// Check if scheduled revocation is due
    pub fn is_revocation_due(&self) -> bool {
        self.scheduled_revocation
            .as_ref()
            .map(|s| s.is_due())
            .unwrap_or(false)
    }

    /// Get a human-readable description of time until expiration
    pub fn time_until_expiry(&self) -> Option<String> {
        if let Some(ref expires_at) = self.expires_at {
            if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                let now = chrono::Utc::now();
                if expiry < now {
                    return Some("expired".to_string());
                }
                let duration = expiry.signed_duration_since(now);
                let days = duration.num_days();
                if days > 0 {
                    return Some(format!("{}d", days));
                }
                let hours = duration.num_hours();
                if hours > 0 {
                    return Some(format!("{}h", hours));
                }
                return Some("< 1h".to_string());
            }
        }
        None
    }

    /// Check if this suppression has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Check if this suppression is in a specific group
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.contains(group)
    }

    /// Get all tags as a sorted vector
    pub fn tags_sorted(&self) -> Vec<&str> {
        let mut tags: Vec<_> = self.tags.iter().map(|s| s.as_str()).collect();
        tags.sort();
        tags
    }

    /// Get all groups as a sorted vector
    pub fn groups_sorted(&self) -> Vec<&str> {
        let mut groups: Vec<_> = self.groups.iter().map(|s| s.as_str()).collect();
        groups.sort();
        groups
    }
}

/// Generate a simple UUID v4 (random)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&timestamp, &mut hasher);
    std::hash::Hash::hash(&std::process::id(), &mut hasher);
    let random = std::hash::Hasher::finish(&hasher);

    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (timestamp & 0xFFFFFFFF) as u32,
        ((timestamp >> 32) & 0xFFFF) as u16,
        (random & 0xFFF) as u16,
        ((random >> 12) & 0x3FFF | 0x8000) as u16,
        (random >> 26) & 0xFFFFFFFFFFFF
    )
}

/// Hash a code snippet for secure storage (no raw code in DB)
pub fn hash_snippet(snippet: &str) -> String {
    use sha2::{Digest, Sha256};

    // Normalize whitespace before hashing
    let normalized: String = snippet.split_whitespace().collect::<Vec<_>>().join(" ");

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let result = hasher.finalize();

    format!("{:x}", result)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_suppression() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "generic/hardcoded-secret",
            "src/test.rs",
            "admin",
            "Test fixture",
        );

        assert!(!entry.id.is_empty());
        assert_eq!(entry.fingerprint, "sha256:abc123");
        assert_eq!(entry.rule_id, "generic/hardcoded-secret");
        assert_eq!(entry.file_path, PathBuf::from("src/test.rs"));
        assert_eq!(entry.suppressed_by, "admin");
        assert_eq!(entry.reason, "Test fixture");
        assert_eq!(entry.status, SuppressionStatus::Active);
        assert!(entry.is_active());
        assert!(entry.snippet_hash.is_none());
    }

    #[test]
    fn test_expiration() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .with_expiration_days(30);

        assert!(!entry.is_expired());
        assert!(entry.is_active());
        assert!(entry.expires_at.is_some());
        assert!(entry.time_until_expiry().is_some());
    }

    #[test]
    fn test_staleness_detection() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .with_snippet("let password = \"secret\";");

        assert!(entry.snippet_hash.is_some());
        assert!(!entry.is_stale(Some("let password = \"secret\";")));
        assert!(!entry.is_stale(Some("let  password  =  \"secret\";")));
        assert!(entry.is_stale(Some("let password = \"different\";")));
        assert!(entry.is_stale(None));
    }

    #[test]
    fn test_hash_snippet() {
        let hash1 = hash_snippet("let x = 1;");
        let hash2 = hash_snippet("let x = 1;");
        let hash3 = hash_snippet("let  x  =  1;");
        let hash4 = hash_snippet("let y = 2;");

        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_revoke() {
        let mut entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        );

        assert!(entry.is_active());
        entry.revoke();
        assert!(!entry.is_active());
        assert_eq!(entry.status, SuppressionStatus::Revoked);
    }

    #[test]
    fn test_tags_and_groups() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .with_tag("security")
        .with_tag("false-positive")
        .with_group("team-backend");

        assert!(entry.has_tag("security"));
        assert!(entry.has_tag("false-positive"));
        assert!(!entry.has_tag("other"));
        assert!(entry.in_group("team-backend"));
        assert!(!entry.in_group("team-frontend"));
    }

    #[test]
    fn test_approval_workflow() {
        let mut entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .require_approval(2);

        assert!(entry.is_pending_approval());
        assert!(!entry.is_approved());

        entry.approve("approver1", Some("Looks good".to_string()));
        assert!(entry.is_pending_approval()); // Still needs 1 more

        entry.approve("approver2", None);
        assert!(entry.is_approved());
        assert!(entry.is_active());
    }

    #[test]
    fn test_approval_rejection() {
        let mut entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .require_approval(1);

        entry.reject("security-team", "This is a real vulnerability");
        assert_eq!(entry.status, SuppressionStatus::Rejected);
        assert!(!entry.is_active());
    }

    #[test]
    fn test_scheduled_revocation() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .schedule_revocation_days(30, "Temporary suppression", "admin");

        assert!(entry.scheduled_revocation.is_some());
        assert!(!entry.is_revocation_due());
    }

    #[test]
    fn test_priority() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .with_priority(1);

        assert_eq!(entry.priority, 1);

        let entry2 = entry.with_priority(10); // Should clamp to 5
        assert_eq!(entry2.priority, 5);
    }

    #[test]
    fn test_metadata() {
        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "rule",
            "file.rs",
            "user",
            "reason",
        )
        .with_metadata("custom_field", "custom_value")
        .with_metadata("another", "value");

        assert_eq!(entry.metadata.get("custom_field"), Some(&"custom_value".to_string()));
        assert_eq!(entry.metadata.get("another"), Some(&"value".to_string()));
    }
}
