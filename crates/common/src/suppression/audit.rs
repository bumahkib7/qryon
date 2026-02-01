//! Enhanced audit trail for suppression operations
//!
//! Provides comprehensive audit logging with full context, diffs, and metadata tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Actions that can be audited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Suppression was created
    Created,
    /// Suppression expired automatically
    Expired,
    /// Suppression was manually revoked
    Revoked,
    /// Suppression expiration was extended
    Extended,
    /// Suppression was marked as stale
    MarkedStale,
    /// Suppression was reactivated (e.g., after code fix)
    Reactivated,
    /// Suppression was imported from JSON
    Imported,
    /// Suppression metadata was updated
    Updated,
    /// Suppression was submitted for approval
    SubmittedForApproval,
    /// Suppression was approved
    Approved,
    /// Suppression approval was rejected
    Rejected,
    /// Suppression was added to a group
    AddedToGroup,
    /// Suppression was removed from a group
    RemovedFromGroup,
    /// Tag was added
    TagAdded,
    /// Tag was removed
    TagRemoved,
    /// Scheduled for auto-revocation
    ScheduledRevocation,
    /// Auto-revocation was cancelled
    RevocationCancelled,
    /// Bulk operation applied
    BulkOperation,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::Created => write!(f, "created"),
            AuditAction::Expired => write!(f, "expired"),
            AuditAction::Revoked => write!(f, "revoked"),
            AuditAction::Extended => write!(f, "extended"),
            AuditAction::MarkedStale => write!(f, "marked-stale"),
            AuditAction::Reactivated => write!(f, "reactivated"),
            AuditAction::Imported => write!(f, "imported"),
            AuditAction::Updated => write!(f, "updated"),
            AuditAction::SubmittedForApproval => write!(f, "submitted-for-approval"),
            AuditAction::Approved => write!(f, "approved"),
            AuditAction::Rejected => write!(f, "rejected"),
            AuditAction::AddedToGroup => write!(f, "added-to-group"),
            AuditAction::RemovedFromGroup => write!(f, "removed-from-group"),
            AuditAction::TagAdded => write!(f, "tag-added"),
            AuditAction::TagRemoved => write!(f, "tag-removed"),
            AuditAction::ScheduledRevocation => write!(f, "scheduled-revocation"),
            AuditAction::RevocationCancelled => write!(f, "revocation-cancelled"),
            AuditAction::BulkOperation => write!(f, "bulk-operation"),
        }
    }
}

/// Severity level of an audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational event
    #[default]
    Info,
    /// Warning event
    Warning,
    /// Important event requiring attention
    Important,
    /// Critical security event
    Critical,
}

/// A field change in an audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Name of the field that changed
    pub field: String,
    /// Previous value (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_value: Option<String>,
    /// New value (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
}

impl FieldChange {
    pub fn new(field: impl Into<String>, old: Option<String>, new: Option<String>) -> Self {
        Self {
            field: field.into(),
            old_value: old,
            new_value: new,
        }
    }
}

/// Context about the environment when the audit event occurred
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditContext {
    /// Git commit hash (if in a git repo)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Git branch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Hostname where the action occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// CI/CD pipeline identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_pipeline: Option<String>,
    /// CI/CD job identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_job: Option<String>,
    /// Additional context metadata
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl AuditContext {
    /// Create context from current environment
    pub fn from_environment() -> Self {
        let git_commit = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let git_branch = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .ok();

        let working_dir = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        let ci_pipeline = std::env::var("CI_PIPELINE_ID")
            .or_else(|_| std::env::var("GITHUB_RUN_ID"))
            .or_else(|_| std::env::var("BUILD_ID"))
            .ok();

        let ci_job = std::env::var("CI_JOB_ID")
            .or_else(|_| std::env::var("GITHUB_JOB"))
            .or_else(|_| std::env::var("JOB_NAME"))
            .ok();

        Self {
            git_commit,
            git_branch,
            hostname,
            working_dir,
            ci_pipeline,
            ci_job,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// An enhanced audit event with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// When this event occurred (ISO 8601)
    pub timestamp: String,
    /// ID of the suppression this event relates to
    pub suppression_id: String,
    /// What action was taken
    pub action: AuditAction,
    /// Severity of this event
    #[serde(default)]
    pub severity: AuditSeverity,
    /// Who performed the action
    pub actor: String,
    /// Actor's email (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_email: Option<String>,
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Detailed reason for the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Fields that changed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<FieldChange>,
    /// Environment context
    #[serde(default, skip_serializing_if = "is_default_context")]
    pub context: AuditContext,
    /// Related event IDs (for linked actions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_events: Vec<String>,
    /// Tags for categorization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

fn is_default_context(ctx: &AuditContext) -> bool {
    ctx.git_commit.is_none()
        && ctx.git_branch.is_none()
        && ctx.hostname.is_none()
        && ctx.working_dir.is_none()
        && ctx.ci_pipeline.is_none()
        && ctx.ci_job.is_none()
        && ctx.metadata.is_empty()
}

impl AuditEvent {
    /// Create a new audit event with auto-generated ID and timestamp
    pub fn new(
        suppression_id: impl Into<String>,
        action: AuditAction,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            id: generate_event_id(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            suppression_id: suppression_id.into(),
            action,
            severity: AuditSeverity::Info,
            actor: actor.into(),
            actor_email: None,
            description: None,
            reason: None,
            changes: Vec::new(),
            context: AuditContext::default(),
            related_events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Create with full environment context
    pub fn with_context(
        suppression_id: impl Into<String>,
        action: AuditAction,
        actor: impl Into<String>,
    ) -> Self {
        let mut event = Self::new(suppression_id, action, actor);
        event.context = AuditContext::from_environment();
        event
    }

    /// Set severity
    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set reason
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Add a field change
    pub fn add_change(mut self, change: FieldChange) -> Self {
        self.changes.push(change);
        self
    }

    /// Add a related event
    pub fn add_related(mut self, event_id: impl Into<String>) -> Self {
        self.related_events.push(event_id.into());
        self
    }

    /// Add a tag
    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set actor email
    pub fn actor_email(mut self, email: impl Into<String>) -> Self {
        self.actor_email = Some(email.into());
        self
    }

    /// Parse timestamp to chrono DateTime
    pub fn parsed_timestamp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.timestamp)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }

    /// Get a human-readable relative time (e.g., "2 hours ago")
    pub fn relative_time(&self) -> String {
        if let Some(timestamp) = self.parsed_timestamp() {
            let now = chrono::Utc::now();
            let duration = now.signed_duration_since(timestamp);

            let days = duration.num_days();
            if days > 0 {
                return format!("{} day{} ago", days, if days == 1 { "" } else { "s" });
            }

            let hours = duration.num_hours();
            if hours > 0 {
                return format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" });
            }

            let minutes = duration.num_minutes();
            if minutes > 0 {
                return format!(
                    "{} minute{} ago",
                    minutes,
                    if minutes == 1 { "" } else { "s" }
                );
            }

            return "just now".to_string();
        }
        self.timestamp.clone()
    }

    /// Format for display
    pub fn format_summary(&self) -> String {
        let mut summary = format!("{} by {}", self.action, self.actor);
        if let Some(ref desc) = self.description {
            summary.push_str(&format!(": {}", desc));
        }
        summary
    }
}

/// Generate a unique event ID
fn generate_event_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&timestamp, &mut hasher);
    std::hash::Hash::hash(&std::process::id(), &mut hasher);
    std::hash::Hash::hash(&std::thread::current().id(), &mut hasher);
    let random = std::hash::Hasher::finish(&hasher);

    format!("evt_{:016x}{:08x}", timestamp as u64, random as u32)
}

/// Audit log query builder
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Filter by suppression ID
    pub suppression_id: Option<String>,
    /// Filter by actor
    pub actor: Option<String>,
    /// Filter by action
    pub action: Option<AuditAction>,
    /// Filter by minimum severity
    pub min_severity: Option<AuditSeverity>,
    /// Filter by start time
    pub from: Option<String>,
    /// Filter by end time
    pub to: Option<String>,
    /// Filter by tags
    pub tags: Vec<String>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: usize,
}

impl AuditQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_suppression(id: impl Into<String>) -> Self {
        Self {
            suppression_id: Some(id.into()),
            ..Default::default()
        }
    }

    pub fn by_actor(actor: impl Into<String>) -> Self {
        Self {
            actor: Some(actor.into()),
            ..Default::default()
        }
    }

    pub fn with_action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Check if an event matches this query
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(ref id) = self.suppression_id
            && event.suppression_id != *id
        {
            return false;
        }

        if let Some(ref actor) = self.actor
            && event.actor != *actor
        {
            return false;
        }

        if let Some(action) = self.action
            && event.action != action
        {
            return false;
        }

        if !self.tags.is_empty() && !self.tags.iter().any(|t| event.tags.contains(t)) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event() {
        let event = AuditEvent::new("suppression-123", AuditAction::Created, "admin");

        assert_eq!(event.suppression_id, "suppression-123");
        assert_eq!(event.action, AuditAction::Created);
        assert_eq!(event.actor, "admin");
        assert!(event.description.is_none());
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_audit_event_with_details() {
        let event = AuditEvent::new("suppression-123", AuditAction::Revoked, "admin")
            .severity(AuditSeverity::Important)
            .reason("False positive confirmed")
            .add_change(FieldChange::new(
                "status",
                Some("active".to_string()),
                Some("revoked".to_string()),
            ));

        assert_eq!(event.action, AuditAction::Revoked);
        assert_eq!(event.severity, AuditSeverity::Important);
        assert_eq!(event.reason, Some("False positive confirmed".to_string()));
        assert_eq!(event.changes.len(), 1);
    }

    #[test]
    fn test_audit_context() {
        let ctx = AuditContext::from_environment().with_metadata("custom_key", "custom_value");

        // Context should capture working dir at minimum
        assert!(ctx.working_dir.is_some());
        assert_eq!(
            ctx.metadata.get("custom_key"),
            Some(&"custom_value".to_string())
        );
    }

    #[test]
    fn test_audit_query() {
        let event = AuditEvent::new("supp-1", AuditAction::Created, "user1").add_tag("security");

        let query1 = AuditQuery::for_suppression("supp-1");
        assert!(query1.matches(&event));

        let query2 = AuditQuery::for_suppression("supp-2");
        assert!(!query2.matches(&event));

        let query3 = AuditQuery::new().with_tag("security");
        assert!(query3.matches(&event));

        let query4 = AuditQuery::new().with_tag("other");
        assert!(!query4.matches(&event));
    }

    #[test]
    fn test_relative_time() {
        let event = AuditEvent::new("id", AuditAction::Created, "user");
        let relative = event.relative_time();
        assert!(
            relative.contains("just now")
                || relative.contains("second")
                || relative.contains("minute")
        );
    }
}
