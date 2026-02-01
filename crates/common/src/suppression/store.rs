//! Sled-backed suppression store

use super::{AuditAction, AuditEvent, SuppressionEntry, SuppressionStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Filter criteria for listing suppressions
#[derive(Debug, Clone, Default)]
pub struct SuppressionFilter {
    /// Filter by rule ID (exact match or prefix with wildcard)
    pub rule_id: Option<String>,
    /// Filter by file path (exact match or contains)
    pub file_path: Option<PathBuf>,
    /// Filter by status
    pub status: Option<SuppressionStatus>,
    /// Include all statuses (not just active)
    pub include_all: bool,
    /// Limit number of results
    pub limit: Option<usize>,
}

impl SuppressionFilter {
    /// Create a filter for active suppressions only
    pub fn active_only() -> Self {
        Self {
            status: Some(SuppressionStatus::Active),
            ..Default::default()
        }
    }

    /// Create a filter that includes all suppressions
    pub fn all() -> Self {
        Self {
            include_all: true,
            ..Default::default()
        }
    }

    /// Filter by rule ID
    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    /// Filter by file path
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Limit results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Export format for suppressions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionExport {
    /// Version of the export format
    pub version: String,
    /// When the export was created
    pub exported_at: String,
    /// Who created the export
    pub exported_by: String,
    /// The suppression entries
    pub suppressions: Vec<SuppressionEntry>,
}

impl SuppressionExport {
    /// Create a new export
    pub fn new(suppressions: Vec<SuppressionEntry>, exported_by: impl Into<String>) -> Self {
        Self {
            version: "1.0".to_string(),
            exported_at: chrono::Utc::now().to_rfc3339(),
            exported_by: exported_by.into(),
            suppressions,
        }
    }
}

/// Sled-backed store for suppressions
///
/// ## Sled Layout
///
/// - `by_id`: Primary store, key=id, value=SuppressionEntry JSON
/// - `by_fingerprint`: Index fingerprint -> id for fast lookup
/// - `by_rule`: Index rule_id:id -> () for filtering by rule
/// - `by_file`: Index file_path:id -> () for filtering by file
/// - `audit_log`: key=timestamp-id, value=AuditEvent JSON
pub struct SuppressionStore {
    /// The Sled database
    db: sled::Db,
    /// Primary store: id -> SuppressionEntry
    by_id: sled::Tree,
    /// Index: fingerprint -> id
    by_fingerprint: sled::Tree,
    /// Index: rule_id:id -> () for fast rule filtering
    by_rule: sled::Tree,
    /// Index: file_path:id -> () for fast file filtering
    by_file: sled::Tree,
    /// Tree for audit log (key: timestamp-id, value: AuditEvent)
    audit_log: sled::Tree,
}

impl SuppressionStore {
    /// Open or create a suppression store at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path.as_ref()).with_context(|| {
            format!("Failed to open suppression database at {:?}", path.as_ref())
        })?;

        let by_id = db.open_tree("by_id").context("Failed to open by_id tree")?;
        let by_fingerprint = db
            .open_tree("by_fingerprint")
            .context("Failed to open by_fingerprint tree")?;
        let by_rule = db
            .open_tree("by_rule")
            .context("Failed to open by_rule tree")?;
        let by_file = db
            .open_tree("by_file")
            .context("Failed to open by_file tree")?;
        let audit_log = db
            .open_tree("audit_log")
            .context("Failed to open audit_log tree")?;

        Ok(Self {
            db,
            by_id,
            by_fingerprint,
            by_rule,
            by_file,
            audit_log,
        })
    }

    /// Get the database path
    pub fn db_path(&self) -> Option<PathBuf> {
        // sled doesn't expose the path directly, but we can get it from config
        None // Would need to store it separately
    }

    /// Get the entry count
    pub fn entry_count(&self) -> usize {
        self.by_id.len()
    }

    /// Open or create a suppression store for a project
    ///
    /// Uses `.rma/suppressions.db` within the project root
    pub fn open_project(project_root: impl AsRef<Path>) -> Result<Self> {
        let db_path = project_root.as_ref().join(".rma").join("suppressions.db");

        // Create .rma directory if it doesn't exist
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        Self::open(&db_path)
    }

    /// Check if a fingerprint is suppressed
    ///
    /// Returns the suppression entry if found and active
    pub fn is_suppressed(&self, fingerprint: &str) -> Result<Option<SuppressionEntry>> {
        // Look up the suppression ID from the fingerprint index
        if let Some(id_bytes) = self.by_fingerprint.get(fingerprint.as_bytes())? {
            let id = String::from_utf8_lossy(&id_bytes);

            // Get the suppression entry
            if let Some(entry_bytes) = self.by_id.get(id.as_bytes())? {
                let mut entry: SuppressionEntry = serde_json::from_slice(&entry_bytes)
                    .context("Failed to deserialize suppression entry")?;

                // Check if expired
                if entry.is_expired() && entry.status == SuppressionStatus::Active {
                    entry.status = SuppressionStatus::Expired;
                    // Update the stored entry
                    let _ = self.update_entry(&entry);
                }

                // Only return if active
                if entry.is_active() {
                    return Ok(Some(entry));
                }
            }
        }

        Ok(None)
    }

    /// Add a new suppression
    ///
    /// Returns the suppression ID
    pub fn suppress(&self, entry: SuppressionEntry) -> Result<String> {
        let id = entry.id.clone();
        let entry_json =
            serde_json::to_vec(&entry).context("Failed to serialize suppression entry")?;

        // Store the suppression in primary tree
        self.by_id.insert(entry.id.as_bytes(), entry_json)?;

        // Update indexes
        self.by_fingerprint
            .insert(entry.fingerprint.as_bytes(), entry.id.as_bytes())?;

        // rule:id index for fast rule filtering
        let rule_key = format!("{}:{}", entry.rule_id, entry.id);
        self.by_rule.insert(rule_key.as_bytes(), &[])?;

        // file:id index for fast file filtering
        let file_key = format!("{}:{}", entry.file_path.display(), entry.id);
        self.by_file.insert(file_key.as_bytes(), &[])?;

        // Log the audit event
        self.log_audit(AuditEvent::new(
            &entry.id,
            AuditAction::Created,
            &entry.suppressed_by,
        ))?;

        // Flush to disk
        self.db.flush()?;

        Ok(id)
    }

    /// Revoke a suppression by ID
    pub fn revoke(&self, id: &str, actor: &str) -> Result<bool> {
        self.revoke_with_reason(id, actor, None)
    }

    /// Revoke a suppression by ID with optional reason
    pub fn revoke_with_reason(&self, id: &str, actor: &str, reason: Option<&str>) -> Result<bool> {
        if let Some(entry_bytes) = self.by_id.get(id.as_bytes())? {
            let mut entry: SuppressionEntry = serde_json::from_slice(&entry_bytes)?;
            entry.revoke();

            let entry_json = serde_json::to_vec(&entry)?;
            self.by_id.insert(id.as_bytes(), entry_json)?;

            // Remove from fingerprint index
            self.by_fingerprint.remove(entry.fingerprint.as_bytes())?;

            // Remove from rule index
            let rule_key = format!("{}:{}", entry.rule_id, entry.id);
            self.by_rule.remove(rule_key.as_bytes())?;

            // Remove from file index
            let file_key = format!("{}:{}", entry.file_path.display(), entry.id);
            self.by_file.remove(file_key.as_bytes())?;

            // Log the audit event
            let event = if let Some(r) = reason {
                AuditEvent::new(id, AuditAction::Revoked, actor).reason(r)
            } else {
                AuditEvent::new(id, AuditAction::Revoked, actor)
            };
            self.log_audit(event)?;

            self.db.flush()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Get a suppression by ID
    pub fn get(&self, id: &str) -> Result<Option<SuppressionEntry>> {
        if let Some(entry_bytes) = self.by_id.get(id.as_bytes())? {
            let entry: SuppressionEntry = serde_json::from_slice(&entry_bytes)?;
            return Ok(Some(entry));
        }
        Ok(None)
    }

    /// List suppressions with optional filtering
    pub fn list(&self, filter: SuppressionFilter) -> Result<Vec<SuppressionEntry>> {
        let mut results = Vec::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let mut entry: SuppressionEntry = serde_json::from_slice(&value)?;

            // Update expired status
            if entry.is_expired() && entry.status == SuppressionStatus::Active {
                entry.status = SuppressionStatus::Expired;
            }

            // Apply filters
            if !filter.include_all
                && !entry.is_active()
                && (filter.status.is_none() || filter.status != Some(entry.status))
            {
                continue;
            }

            if let Some(ref status) = filter.status
                && entry.status != *status
            {
                continue;
            }

            if let Some(ref rule_id) = filter.rule_id {
                if rule_id.ends_with('*') {
                    let prefix = rule_id.trim_end_matches('*');
                    if !entry.rule_id.starts_with(prefix) {
                        continue;
                    }
                } else if entry.rule_id != *rule_id {
                    continue;
                }
            }

            if let Some(ref file_path) = filter.file_path
                && !entry
                    .file_path
                    .to_string_lossy()
                    .contains(file_path.to_string_lossy().as_ref())
            {
                continue;
            }

            results.push(entry);

            if let Some(limit) = filter.limit
                && results.len() >= limit
            {
                break;
            }
        }

        // Sort by created_at descending
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(results)
    }

    /// Export all active suppressions to JSON
    pub fn export(&self, actor: &str) -> Result<String> {
        let entries = self.list(SuppressionFilter::active_only())?;
        let export = SuppressionExport::new(entries, actor);
        serde_json::to_string_pretty(&export).context("Failed to serialize export")
    }

    /// Import suppressions from JSON
    pub fn import(&self, json: &str, actor: &str) -> Result<usize> {
        let export: SuppressionExport =
            serde_json::from_str(json).context("Failed to parse import JSON")?;

        let mut imported = 0;

        for entry in export.suppressions {
            // Check if this fingerprint already has an active suppression
            if self.is_suppressed(&entry.fingerprint)?.is_some() {
                continue;
            }

            // Create a new entry with a fresh ID
            let new_entry = SuppressionEntry::new(
                &entry.fingerprint,
                &entry.rule_id,
                &entry.file_path,
                actor,
                &entry.reason,
            )
            .with_severity(entry.original_severity);

            // Preserve optional fields
            let new_entry = if let Some(snippet_hash) = entry.snippet_hash {
                new_entry.with_snippet_hash(snippet_hash)
            } else {
                new_entry
            };

            let new_entry = if let Some(context_hash) = entry.context_hash {
                new_entry.with_context_hash(context_hash)
            } else {
                new_entry
            };

            let new_entry = if let Some(ticket) = entry.ticket_ref {
                new_entry.with_ticket(ticket)
            } else {
                new_entry
            };

            let new_entry = if let Some(expires_at) = entry.expires_at {
                new_entry.with_expiration(expires_at)
            } else {
                new_entry
            };

            self.suppress(new_entry)?;

            // Log import audit event
            self.log_audit(
                AuditEvent::new(&entry.id, AuditAction::Imported, actor)
                    .description(format!("Imported from export by {}", export.exported_by)),
            )?;

            imported += 1;
        }

        Ok(imported)
    }

    /// Check for stale suppressions based on current findings
    ///
    /// Returns a list of suppressions that no longer match their original code
    pub fn check_staleness<F>(&self, get_snippet: F) -> Result<Vec<SuppressionEntry>>
    where
        F: Fn(&SuppressionEntry) -> Option<String>,
    {
        let mut stale = Vec::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let entry: SuppressionEntry = serde_json::from_slice(&value)?;

            if entry.status != SuppressionStatus::Active {
                continue;
            }

            let current_snippet = get_snippet(&entry);
            if entry.is_stale(current_snippet.as_deref()) {
                stale.push(entry);
            }
        }

        Ok(stale)
    }

    /// Clean up expired suppressions
    ///
    /// Returns the number of suppressions cleaned up
    pub fn cleanup_expired(&self, actor: &str) -> Result<usize> {
        let mut cleaned = 0;

        for item in self.by_id.iter() {
            let (key, value) = item?;
            let mut entry: SuppressionEntry = serde_json::from_slice(&value)?;

            if entry.status == SuppressionStatus::Active && entry.is_expired() {
                entry.status = SuppressionStatus::Expired;
                let entry_json = serde_json::to_vec(&entry)?;
                self.by_id.insert(&key, entry_json)?;

                // Remove from fingerprint index
                self.by_fingerprint.remove(entry.fingerprint.as_bytes())?;

                // Log audit event
                self.log_audit(AuditEvent::new(&entry.id, AuditAction::Expired, actor))?;

                cleaned += 1;
            }
        }

        self.db.flush()?;
        Ok(cleaned)
    }

    /// Get the audit log for a specific suppression
    pub fn get_audit_log(&self, suppression_id: &str) -> Result<Vec<AuditEvent>> {
        let mut events = Vec::new();

        for item in self.audit_log.iter() {
            let (_, value) = item?;
            let event: AuditEvent = serde_json::from_slice(&value)?;
            if event.suppression_id == suppression_id {
                events.push(event);
            }
        }

        // Sort by timestamp descending
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(events)
    }

    /// Get recent audit events
    pub fn get_recent_audit(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut events = Vec::new();

        for item in self.audit_log.iter().rev() {
            let (_, value) = item?;
            let event: AuditEvent = serde_json::from_slice(&value)?;
            events.push(event);

            if events.len() >= limit {
                break;
            }
        }

        Ok(events)
    }

    /// Get statistics about the store
    pub fn stats(&self) -> Result<StoreStats> {
        let mut total = 0;
        let mut active = 0;
        let mut expired = 0;
        let mut revoked = 0;
        let mut stale = 0;
        let mut pending_approval = 0;
        let mut rejected = 0;
        let mut scheduled_revocation = 0;

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let mut entry: SuppressionEntry = serde_json::from_slice(&value)?;

            // Update expired status
            if entry.is_expired() && entry.status == SuppressionStatus::Active {
                entry.status = SuppressionStatus::Expired;
            }

            total += 1;
            match entry.status {
                SuppressionStatus::Active => active += 1,
                SuppressionStatus::Expired => expired += 1,
                SuppressionStatus::Revoked => revoked += 1,
                SuppressionStatus::Stale => stale += 1,
                SuppressionStatus::PendingApproval => pending_approval += 1,
                SuppressionStatus::Rejected => rejected += 1,
                SuppressionStatus::ScheduledRevocation => scheduled_revocation += 1,
            }
        }

        Ok(StoreStats {
            total,
            active,
            expired,
            revoked,
            stale,
            pending_approval,
            rejected,
            scheduled_revocation,
        })
    }

    /// Update an existing entry (public version with audit logging)
    pub fn update(&self, entry: &SuppressionEntry, actor: &str) -> Result<()> {
        self.update_entry(entry)?;
        self.log_audit(
            AuditEvent::new(&entry.id, AuditAction::Updated, actor).description("Entry updated"),
        )?;
        self.db.flush()?;
        Ok(())
    }

    /// Submit a suppression for approval
    pub fn submit_for_approval(&self, id: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            entry.status = SuppressionStatus::PendingApproval;
            self.update_entry(&entry)?;
            self.log_audit(
                AuditEvent::new(id, AuditAction::SubmittedForApproval, actor)
                    .description("Submitted for approval"),
            )?;
            self.db.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Approve a suppression
    pub fn approve(&self, id: &str, approver: &str, comment: Option<&str>) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.status != SuppressionStatus::PendingApproval {
                anyhow::bail!("Suppression is not pending approval");
            }

            entry.add_approval(approver, comment);

            // Check if we have enough approvals
            if entry.is_approved() {
                entry.status = SuppressionStatus::Active;
            }

            self.update_entry(&entry)?;

            let event = AuditEvent::new(id, AuditAction::Approved, approver);
            let event = if let Some(c) = comment {
                event.description(c)
            } else {
                event
            };
            self.log_audit(event)?;

            self.db.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Reject a suppression
    pub fn reject(&self, id: &str, rejector: &str, reason: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.status != SuppressionStatus::PendingApproval {
                anyhow::bail!("Suppression is not pending approval");
            }

            entry.reject(rejector, reason);
            self.update_entry(&entry)?;

            self.log_audit(AuditEvent::new(id, AuditAction::Rejected, rejector).reason(reason))?;

            self.db.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Add a tag to a suppression
    pub fn add_tag(&self, id: &str, tag: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.tags.insert(tag.to_string()) {
                self.update_entry(&entry)?;
                self.log_audit(
                    AuditEvent::new(id, AuditAction::TagAdded, actor)
                        .description(format!("Added tag: {}", tag)),
                )?;
                self.db.flush()?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Remove a tag from a suppression
    pub fn remove_tag(&self, id: &str, tag: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.tags.remove(tag) {
                self.update_entry(&entry)?;
                self.log_audit(
                    AuditEvent::new(id, AuditAction::TagRemoved, actor)
                        .description(format!("Removed tag: {}", tag)),
                )?;
                self.db.flush()?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Add a suppression to a group
    pub fn add_to_group(&self, id: &str, group: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.groups.insert(group.to_string()) {
                self.update_entry(&entry)?;
                self.log_audit(
                    AuditEvent::new(id, AuditAction::AddedToGroup, actor)
                        .description(format!("Added to group: {}", group)),
                )?;
                self.db.flush()?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Remove a suppression from a group
    pub fn remove_from_group(&self, id: &str, group: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            if entry.groups.remove(group) {
                self.update_entry(&entry)?;
                self.log_audit(
                    AuditEvent::new(id, AuditAction::RemovedFromGroup, actor)
                        .description(format!("Removed from group: {}", group)),
                )?;
                self.db.flush()?;
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Schedule a suppression for auto-revocation
    pub fn schedule_revocation(
        &self,
        id: &str,
        scheduled_for: &str,
        actor: &str,
        reason: &str,
    ) -> Result<bool> {
        if let Some(mut entry) = self.get(id)? {
            entry.set_scheduled_revocation(scheduled_for, reason, actor);
            self.update_entry(&entry)?;
            self.log_audit(
                AuditEvent::new(id, AuditAction::ScheduledRevocation, actor)
                    .description(format!("Scheduled for revocation on {}", scheduled_for))
                    .reason(reason),
            )?;
            self.db.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Cancel a scheduled revocation
    pub fn cancel_revocation(&self, id: &str, actor: &str) -> Result<bool> {
        if let Some(mut entry) = self.get(id)?
            && entry.status == SuppressionStatus::ScheduledRevocation
        {
            entry.cancel_scheduled_revocation();
            self.update_entry(&entry)?;
            self.log_audit(AuditEvent::new(id, AuditAction::RevocationCancelled, actor))?;
            self.db.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Process scheduled revocations that are due
    pub fn process_scheduled_revocations(&self, actor: &str) -> Result<Vec<String>> {
        let mut revoked = Vec::new();
        let now = chrono::Utc::now().to_rfc3339();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let mut entry: SuppressionEntry = serde_json::from_slice(&value)?;

            if entry.status == SuppressionStatus::ScheduledRevocation
                && let Some(ref schedule) = entry.scheduled_revocation
                && schedule.scheduled_at <= now
            {
                entry.revoke();
                self.update_entry(&entry)?;

                // Remove from indexes
                self.by_fingerprint.remove(entry.fingerprint.as_bytes())?;
                let rule_key = format!("{}:{}", entry.rule_id, entry.id);
                self.by_rule.remove(rule_key.as_bytes())?;
                let file_key = format!("{}:{}", entry.file_path.display(), entry.id);
                self.by_file.remove(file_key.as_bytes())?;

                self.log_audit(
                    AuditEvent::new(&entry.id, AuditAction::Revoked, actor)
                        .description("Auto-revoked as scheduled"),
                )?;
                revoked.push(entry.id.clone());
            }
        }

        if !revoked.is_empty() {
            self.db.flush()?;
        }

        Ok(revoked)
    }

    /// List suppressions by tag
    pub fn list_by_tag(&self, tag: &str) -> Result<Vec<SuppressionEntry>> {
        let mut results = Vec::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let entry: SuppressionEntry = serde_json::from_slice(&value)?;

            if entry.tags.contains(tag) {
                results.push(entry);
            }
        }

        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(results)
    }

    /// List suppressions by group
    pub fn list_by_group(&self, group: &str) -> Result<Vec<SuppressionEntry>> {
        let mut results = Vec::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let entry: SuppressionEntry = serde_json::from_slice(&value)?;

            if entry.groups.contains(group) {
                results.push(entry);
            }
        }

        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(results)
    }

    /// List all unique tags in the store
    pub fn list_tags(&self) -> Result<Vec<String>> {
        let mut tags = std::collections::HashSet::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let entry: SuppressionEntry = serde_json::from_slice(&value)?;
            tags.extend(entry.tags);
        }

        let mut tags: Vec<_> = tags.into_iter().collect();
        tags.sort();
        Ok(tags)
    }

    /// List all unique groups in the store
    pub fn list_groups(&self) -> Result<Vec<String>> {
        let mut groups = std::collections::HashSet::new();

        for item in self.by_id.iter() {
            let (_, value) = item?;
            let entry: SuppressionEntry = serde_json::from_slice(&value)?;
            groups.extend(entry.groups);
        }

        let mut groups: Vec<_> = groups.into_iter().collect();
        groups.sort();
        Ok(groups)
    }

    /// Bulk add tag to multiple suppressions
    pub fn bulk_add_tag(&self, ids: &[&str], tag: &str, actor: &str) -> Result<usize> {
        let mut count = 0;
        for id in ids {
            if self.add_tag(id, tag, actor)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Bulk revoke suppressions
    pub fn bulk_revoke(&self, ids: &[&str], actor: &str, reason: Option<&str>) -> Result<usize> {
        let mut count = 0;
        for id in ids {
            if self.revoke_with_reason(id, actor, reason)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Update an existing entry (internal)
    fn update_entry(&self, entry: &SuppressionEntry) -> Result<()> {
        let entry_json = serde_json::to_vec(entry)?;
        self.by_id.insert(entry.id.as_bytes(), entry_json)?;
        Ok(())
    }

    /// Log an audit event
    fn log_audit(&self, event: AuditEvent) -> Result<()> {
        // Use timestamp + id as key for ordering
        let key = format!("{}-{}", event.timestamp, event.suppression_id);
        let value = serde_json::to_vec(&event)?;
        self.audit_log.insert(key.as_bytes(), value)?;
        Ok(())
    }
}

/// Statistics about the suppression store
#[derive(Debug, Clone, Default)]
pub struct StoreStats {
    pub total: usize,
    pub active: usize,
    pub expired: usize,
    pub revoked: usize,
    pub stale: usize,
    pub pending_approval: usize,
    pub rejected: usize,
    pub scheduled_revocation: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (SuppressionStore, TempDir) {
        let temp = TempDir::new().unwrap();
        let store = SuppressionStore::open(temp.path().join("test.db")).unwrap();
        (store, temp)
    }

    #[test]
    fn test_suppress_and_lookup() {
        let (store, _temp) = create_test_store();

        let entry = SuppressionEntry::new(
            "sha256:abc123",
            "generic/hardcoded-secret",
            "src/test.rs",
            "admin",
            "Test fixture",
        );

        store.suppress(entry).unwrap();

        let found = store.is_suppressed("sha256:abc123").unwrap();
        assert!(found.is_some());

        let found = found.unwrap();
        assert_eq!(found.rule_id, "generic/hardcoded-secret");
        assert_eq!(found.reason, "Test fixture");
    }

    #[test]
    fn test_revoke() {
        let (store, _temp) = create_test_store();

        let entry = SuppressionEntry::new("sha256:abc123", "rule", "file.rs", "user", "reason");
        store.suppress(entry).unwrap();

        assert!(store.is_suppressed("sha256:abc123").unwrap().is_some());

        store
            .revoke(
                &store.list(SuppressionFilter::all()).unwrap()[0].id,
                "admin",
            )
            .unwrap();

        assert!(store.is_suppressed("sha256:abc123").unwrap().is_none());
    }

    #[test]
    fn test_export_import() {
        let (store1, _temp1) = create_test_store();
        let (store2, _temp2) = create_test_store();

        // Create suppressions in store1
        store1
            .suppress(SuppressionEntry::new(
                "sha256:111",
                "rule1",
                "file1.rs",
                "user",
                "reason1",
            ))
            .unwrap();
        store1
            .suppress(SuppressionEntry::new(
                "sha256:222",
                "rule2",
                "file2.rs",
                "user",
                "reason2",
            ))
            .unwrap();

        // Export
        let json = store1.export("exporter").unwrap();

        // Import into store2
        let imported = store2.import(&json, "importer").unwrap();
        assert_eq!(imported, 2);

        // Verify
        assert!(store2.is_suppressed("sha256:111").unwrap().is_some());
        assert!(store2.is_suppressed("sha256:222").unwrap().is_some());
    }

    #[test]
    fn test_list_with_filter() {
        let (store, _temp) = create_test_store();

        store
            .suppress(SuppressionEntry::new(
                "fp1",
                "security/sql-injection",
                "file1.rs",
                "user",
                "reason",
            ))
            .unwrap();
        store
            .suppress(SuppressionEntry::new(
                "fp2",
                "security/xss",
                "file2.rs",
                "user",
                "reason",
            ))
            .unwrap();
        store
            .suppress(SuppressionEntry::new(
                "fp3",
                "quality/long-function",
                "file3.rs",
                "user",
                "reason",
            ))
            .unwrap();

        // Filter by rule prefix
        let security_only = store
            .list(SuppressionFilter::all().with_rule("security/*"))
            .unwrap();
        assert_eq!(security_only.len(), 2);

        // Filter by file
        let file1_only = store
            .list(SuppressionFilter::all().with_file("file1"))
            .unwrap();
        assert_eq!(file1_only.len(), 1);
    }

    #[test]
    fn test_audit_log() {
        let (store, _temp) = create_test_store();

        let entry = SuppressionEntry::new("sha256:abc", "rule", "file.rs", "user1", "reason");
        let id = entry.id.clone();

        store.suppress(entry).unwrap();
        store.revoke(&id, "user2").unwrap();

        let log = store.get_audit_log(&id).unwrap();
        assert_eq!(log.len(), 2);

        // Most recent first
        assert_eq!(log[0].action, AuditAction::Revoked);
        assert_eq!(log[0].actor, "user2");
        assert_eq!(log[1].action, AuditAction::Created);
        assert_eq!(log[1].actor, "user1");
    }

    #[test]
    fn test_stats() {
        let (store, _temp) = create_test_store();

        store
            .suppress(SuppressionEntry::new("fp1", "r1", "f1.rs", "u", "r"))
            .unwrap();
        store
            .suppress(SuppressionEntry::new("fp2", "r2", "f2.rs", "u", "r"))
            .unwrap();

        let id = store.list(SuppressionFilter::all()).unwrap()[0].id.clone();
        store.revoke(&id, "admin").unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.revoked, 1);
    }

    #[test]
    fn test_suppression_engine_with_store() {
        use crate::config::{RulesConfig, SuppressionEngine, SuppressionSource};
        use std::path::PathBuf;

        let (store, _temp) = create_test_store();

        // Create a suppression
        store
            .suppress(SuppressionEntry::new(
                "sha256:known_fingerprint",
                "security/sql-injection",
                "src/database.rs",
                "security-team",
                "Verified false positive - parameterized query",
            ))
            .unwrap();

        // Create suppression engine with the store
        let engine = SuppressionEngine::new(&RulesConfig::default(), false).with_store(store);

        // Check that a finding with the known fingerprint is suppressed
        let result = engine.check(
            "security/sql-injection",
            &PathBuf::from("src/database.rs"),
            42,
            &[],
            Some("sha256:known_fingerprint"),
        );

        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::Database));
        assert!(result.reason.is_some());
        assert!(result.location.unwrap().starts_with("database:"));

        // Check that a finding with unknown fingerprint is NOT suppressed
        let result = engine.check(
            "security/sql-injection",
            &PathBuf::from("src/database.rs"),
            42,
            &[],
            Some("sha256:unknown_fingerprint"),
        );

        assert!(!result.suppressed);
    }
}
