//! Suppress command implementation
//!
//! Manages database-backed suppressions for findings.

use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use colored::Colorize;
use rma_common::suppression::{SuppressionEntry, SuppressionFilter, SuppressionStore};
use rma_common::{RmaTomlConfig, Severity, parse_expiration_days};
use std::io::Write;
use std::path::PathBuf;

/// Suppress subcommand action
#[derive(Debug, Clone)]
pub enum SuppressAction {
    /// Add a new suppression
    Add {
        /// Fingerprint of the finding to suppress
        fingerprint: Option<String>,
        /// Interactive mode - select from scan results
        interactive: bool,
        /// Reason for suppression
        reason: Option<String>,
        /// Ticket reference
        ticket: Option<String>,
        /// Expiration (e.g., "90d", "30d")
        expires: Option<String>,
        /// Rule ID (for interactive filtering)
        rule: Option<String>,
        /// File path (for interactive filtering)
        file: Option<PathBuf>,
    },
    /// List suppressions
    List {
        /// Filter by rule ID
        rule: Option<String>,
        /// Filter by file path
        file: Option<PathBuf>,
        /// Include all statuses (not just active)
        all: bool,
        /// Limit number of results
        limit: Option<usize>,
    },
    /// Remove a suppression by ID
    Remove {
        /// Suppression ID to remove
        id: String,
    },
    /// Show suppression details
    Show {
        /// Suppression ID to show
        id: String,
        /// Include audit history
        history: bool,
    },
    /// Export suppressions to JSON
    Export {
        /// Output file path
        output: PathBuf,
    },
    /// Import suppressions from JSON
    Import {
        /// Input file path
        input: PathBuf,
    },
    /// Check for stale suppressions
    Check {
        /// Prune stale suppressions
        prune: bool,
    },
    /// Show audit log
    Log {
        /// Limit number of entries
        limit: usize,
    },
}

pub struct SuppressArgs {
    pub action: SuppressAction,
    pub path: PathBuf,
    pub quiet: bool,
}

/// Get current username for audit trail
fn get_current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn run(args: SuppressArgs) -> Result<()> {
    // Get project root
    let project_root = if args.path.is_absolute() {
        args.path.clone()
    } else {
        std::env::current_dir()?.join(&args.path)
    };

    // Discover configuration
    let toml_config = RmaTomlConfig::discover(&project_root);

    // Get database path from config or use default
    let db_path = toml_config
        .as_ref()
        .map(|(_, c)| project_root.join(&c.suppressions.database))
        .unwrap_or_else(|| project_root.join(".rma/suppressions.db"));

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    // Open the store
    let store = SuppressionStore::open(&db_path)
        .with_context(|| format!("Failed to open suppression database at {:?}", db_path))?;

    let actor = get_current_user();

    match args.action {
        SuppressAction::Add {
            fingerprint,
            interactive,
            reason,
            ticket,
            expires,
            rule,
            file,
        } => {
            if interactive {
                run_add_interactive(&store, &project_root, &actor, reason, ticket, expires, rule, file, args.quiet)
            } else if let Some(fp) = fingerprint {
                run_add(&store, &fp, reason, ticket, expires, &actor, args.quiet, toml_config.as_ref().map(|(_, c)| c))
            } else {
                anyhow::bail!("Either --fingerprint or --interactive is required")
            }
        }
        SuppressAction::List { rule, file, all, limit } => {
            run_list(&store, &db_path, rule, file, all, limit, args.quiet)
        }
        SuppressAction::Remove { id } => {
            run_remove(&store, &id, &actor, args.quiet)
        }
        SuppressAction::Show { id, history } => {
            run_show(&store, &id, history, args.quiet)
        }
        SuppressAction::Export { output } => {
            run_export(&store, &output, &actor, args.quiet)
        }
        SuppressAction::Import { input } => {
            run_import(&store, &input, &actor, args.quiet)
        }
        SuppressAction::Check { prune } => {
            run_check(&store, &project_root, prune, &actor, args.quiet)
        }
        SuppressAction::Log { limit } => {
            run_log(&store, limit, args.quiet)
        }
    }
}

fn run_add(
    store: &SuppressionStore,
    fingerprint: &str,
    reason: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,
    actor: &str,
    quiet: bool,
    config: Option<&RmaTomlConfig>,
) -> Result<()> {
    // Check if already suppressed
    if let Some(existing) = store.is_suppressed(fingerprint)? {
        if !quiet {
            println!(
                "{} Fingerprint already suppressed (ID: {})",
                Theme::warning_mark(),
                existing.id.yellow()
            );
        }
        return Ok(());
    }

    // Get reason (required)
    let reason = reason.ok_or_else(|| anyhow::anyhow!("--reason is required"))?;

    // Check if ticket is required
    if config.is_some_and(|c| c.suppressions.require_ticket) && ticket.is_none() {
        anyhow::bail!("Ticket reference is required (config: suppressions.require_ticket = true)");
    }

    // Parse expiration
    let expires_days = expires
        .as_ref()
        .and_then(|e| parse_expiration_days(e))
        .or_else(|| {
            config.and_then(|c| parse_expiration_days(&c.suppressions.default_expiration))
        });

    // Check max expiration
    if let Some(days) = expires_days {
        if let Some(max_days) = config.and_then(|c| parse_expiration_days(&c.suppressions.max_expiration)) {
            if days > max_days {
                anyhow::bail!(
                    "Expiration {} days exceeds maximum allowed {} days",
                    days,
                    max_days
                );
            }
        }
    }

    // Create the entry
    let mut entry = SuppressionEntry::new(
        fingerprint,
        "unknown", // We don't have rule_id from fingerprint alone
        "unknown", // We don't have file_path from fingerprint alone
        actor,
        &reason,
    );

    if let Some(days) = expires_days {
        entry = entry.with_expiration_days(days);
    }

    if let Some(ref t) = ticket {
        entry = entry.with_ticket(t);
    }

    // Store the suppression
    store.suppress(entry.clone())?;

    if !quiet {
        println!();
        println!("{} Suppression added!", Theme::success_mark());
        println!();
        println!("  {} ID: {}", Theme::bullet(), entry.id.cyan());
        println!("  {} Fingerprint: {}", Theme::bullet(), fingerprint.dimmed());
        println!("  {} Reason: {}", Theme::bullet(), reason.bright_white());
        if let Some(t) = ticket {
            println!("  {} Ticket: {}", Theme::bullet(), t.yellow());
        }
        if let Some(ref exp) = entry.time_until_expiry() {
            println!("  {} Expires in: {}", Theme::bullet(), exp.yellow());
        }
        println!();
    }

    Ok(())
}

fn run_add_interactive(
    store: &SuppressionStore,
    project_root: &PathBuf,
    actor: &str,
    reason: Option<String>,
    ticket: Option<String>,
    expires: Option<String>,
    rule_filter: Option<String>,
    file_filter: Option<PathBuf>,
    quiet: bool,
) -> Result<()> {
    use dialoguer::{MultiSelect, Input};
    use rma_analyzer::AnalyzerEngine;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;

    if !quiet {
        println!();
        println!("{}", Theme::header("Interactive Suppression"));
        println!("{}", Theme::separator(50));
        println!();
        println!("  {} Scanning for findings...", Theme::info_mark());
    }

    // Run a quick scan
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = AnalyzerEngine::new(config);

    let (parsed_files, _) = parser.parse_directory(project_root)?;
    let (results, _) = analyzer.analyze_files(&parsed_files)?;

    // Collect findings that aren't already suppressed
    let mut findings: Vec<(String, String, String, Severity, String)> = Vec::new();

    for result in &results {
        for finding in &result.findings {
            // Compute fingerprint if not present
            let fingerprint = finding.fingerprint.clone().unwrap_or_else(|| {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(finding.rule_id.as_bytes());
                hasher.update(result.path.as_bytes());
                if let Some(ref snippet) = finding.snippet {
                    let normalized: String = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
                    hasher.update(normalized.as_bytes());
                }
                let hash = hasher.finalize();
                format!("sha256:{:x}", hash)[..23].to_string()
            });

            // Check if already suppressed
            if store.is_suppressed(&fingerprint)?.is_some() {
                continue;
            }

            // Apply filters
            if let Some(ref rule) = rule_filter {
                if !finding.rule_id.contains(rule) {
                    continue;
                }
            }

            if let Some(ref file) = file_filter {
                if !result.path.contains(&file.to_string_lossy().as_ref()) {
                    continue;
                }
            }

            findings.push((
                fingerprint,
                finding.rule_id.clone(),
                result.path.clone(),
                finding.severity,
                finding.snippet.clone().unwrap_or_default(),
            ));
        }
    }

    if findings.is_empty() {
        if !quiet {
            println!("  {} No new findings to suppress", Theme::info_mark());
        }
        return Ok(());
    }

    if !quiet {
        println!("  {} Found {} findings", Theme::info_mark(), findings.len().to_string().yellow());
        println!();
    }

    // Create selection items
    let items: Vec<String> = findings
        .iter()
        .enumerate()
        .map(|(_, (_, rule_id, file, severity, snippet))| {
            let severity_str = match severity {
                Severity::Critical => "CRIT".red(),
                Severity::Error => "ERR".bright_red(),
                Severity::Warning => "WARN".yellow(),
                Severity::Info => "INFO".blue(),
            };
            let snippet_preview = if snippet.len() > 40 {
                format!("{}...", &snippet[..40])
            } else {
                snippet.clone()
            };
            format!(
                "[{}] {} {} - {}",
                severity_str,
                rule_id.cyan(),
                file.dimmed(),
                snippet_preview.dimmed()
            )
        })
        .collect();

    // Multi-select
    let selections = MultiSelect::new()
        .with_prompt("Select findings to suppress (Space to toggle, Enter to confirm)")
        .items(&items)
        .interact()?;

    if selections.is_empty() {
        if !quiet {
            println!("  {} No findings selected", Theme::info_mark());
        }
        return Ok(());
    }

    // Get reason if not provided
    let reason = if let Some(r) = reason {
        r
    } else {
        Input::new()
            .with_prompt("Reason for suppression")
            .interact_text()?
    };

    // Get ticket if not provided
    let ticket = if let Some(t) = ticket {
        Some(t)
    } else {
        let t: String = Input::new()
            .with_prompt("Ticket reference (optional, press Enter to skip)")
            .allow_empty(true)
            .interact_text()?;
        if t.is_empty() { None } else { Some(t) }
    };

    // Parse expiration
    let expires_days = expires.as_ref().and_then(|e| parse_expiration_days(e));

    // Suppress each selected finding
    let mut suppressed = 0;
    for idx in selections {
        let (fingerprint, rule_id, file_path, severity, snippet) = &findings[idx];

        let mut entry = SuppressionEntry::new(
            fingerprint,
            rule_id,
            file_path,
            actor,
            &reason,
        )
        .with_severity(*severity)
        .with_snippet(snippet);

        if let Some(days) = expires_days {
            entry = entry.with_expiration_days(days);
        }

        if let Some(ref t) = ticket {
            entry = entry.with_ticket(t);
        }

        store.suppress(entry)?;
        suppressed += 1;
    }

    if !quiet {
        println!();
        println!("{} Suppressed {} findings!", Theme::success_mark(), suppressed.to_string().green());
        println!();
    }

    Ok(())
}

fn run_list(
    store: &SuppressionStore,
    db_path: &PathBuf,
    rule: Option<String>,
    file: Option<PathBuf>,
    all: bool,
    limit: Option<usize>,
    quiet: bool,
) -> Result<()> {
    let mut filter = if all {
        SuppressionFilter::all()
    } else {
        SuppressionFilter::active_only()
    };

    if let Some(r) = rule {
        filter = filter.with_rule(r);
    }

    if let Some(f) = file {
        filter = filter.with_file(f);
    }

    if let Some(l) = limit {
        filter = filter.with_limit(l);
    }

    let entries = store.list(filter)?;

    if quiet {
        // Just print IDs
        for entry in &entries {
            println!("{}", entry.id);
        }
        return Ok(());
    }

    println!();
    println!("{}", Theme::header("Suppressions"));
    println!("{}", Theme::separator(80));
    println!("  {} Database: {}", Theme::info_mark(), db_path.display().to_string().cyan());
    println!("  {} Total entries: {}", Theme::info_mark(), store.entry_count().to_string().yellow());
    println!();

    if entries.is_empty() {
        println!("  {} No suppressions found", Theme::info_mark());
        println!();
        return Ok(());
    }

    for entry in &entries {
        let status_color = match entry.status {
            rma_common::suppression::SuppressionStatus::Active => entry.status.to_string().green(),
            rma_common::suppression::SuppressionStatus::Expired => entry.status.to_string().yellow(),
            rma_common::suppression::SuppressionStatus::Revoked => entry.status.to_string().red(),
            rma_common::suppression::SuppressionStatus::Stale => entry.status.to_string().magenta(),
            rma_common::suppression::SuppressionStatus::PendingApproval => entry.status.to_string().blue(),
            rma_common::suppression::SuppressionStatus::Rejected => entry.status.to_string().red().bold(),
            rma_common::suppression::SuppressionStatus::ScheduledRevocation => entry.status.to_string().yellow().italic(),
        };

        println!("  {} {}", Theme::bullet(), entry.id.cyan());
        println!("    Status: {}", status_color);
        println!("    Rule: {}", entry.rule_id.bright_white());
        println!("    File: {}", entry.file_path.display().to_string().dimmed());
        println!("    Reason: {}", entry.reason);
        if let Some(ref ticket) = entry.ticket_ref {
            println!("    Ticket: {}", ticket.yellow());
        }
        if let Some(exp) = entry.time_until_expiry() {
            println!("    Expires: {}", exp.yellow());
        }
        println!("    By: {} on {}", entry.suppressed_by.dimmed(), entry.created_at.dimmed());
        println!();
    }

    let stats = store.stats()?;
    println!("{}", Theme::separator(80));
    println!(
        "  Total: {} | Active: {} | Expired: {} | Revoked: {}",
        stats.total.to_string().bright_white(),
        stats.active.to_string().green(),
        stats.expired.to_string().yellow(),
        stats.revoked.to_string().red()
    );
    println!();

    Ok(())
}

fn run_remove(store: &SuppressionStore, id: &str, actor: &str, quiet: bool) -> Result<()> {
    let removed = store.revoke(id, actor)?;

    if !quiet {
        println!();
        if removed {
            println!("{} Suppression {} removed", Theme::success_mark(), id.cyan());
        } else {
            println!("{} Suppression {} not found", Theme::warning_mark(), id.yellow());
        }
        println!();
    }

    Ok(())
}

fn run_show(store: &SuppressionStore, id: &str, history: bool, quiet: bool) -> Result<()> {
    let entry = store.get(id)?
        .ok_or_else(|| anyhow::anyhow!("Suppression {} not found", id))?;

    if quiet {
        println!("{}", serde_json::to_string(&entry)?);
        return Ok(());
    }

    println!();
    println!("{}", Theme::header("Suppression Details"));
    println!("{}", Theme::separator(60));
    println!();

    println!("  ID:          {}", entry.id.cyan());
    println!("  Status:      {}", entry.status.to_string().bright_white());
    println!("  Fingerprint: {}", entry.fingerprint.dimmed());
    println!("  Rule:        {}", entry.rule_id.bright_white());
    println!("  File:        {}", entry.file_path.display());
    println!("  Severity:    {}", entry.original_severity);
    println!("  Reason:      {}", entry.reason);

    if let Some(ref ticket) = entry.ticket_ref {
        println!("  Ticket:      {}", ticket.yellow());
    }

    if let Some(ref hash) = entry.snippet_hash {
        println!("  Snippet Hash: {}", hash.dimmed());
    }

    println!("  Created:     {} by {}", entry.created_at, entry.suppressed_by);

    if let Some(ref exp) = entry.expires_at {
        let status = if entry.is_expired() { "(expired)".red() } else { "".normal() };
        println!("  Expires:     {} {}", exp, status);
    }

    if history {
        println!();
        println!("{}", "  Audit History:".cyan());
        println!("{}", Theme::separator(60));

        let events = store.get_audit_log(id)?;
        for event in events {
            println!(
                "    {} {} by {} {}",
                event.action.to_string().bright_white(),
                event.relative_time().dimmed(),
                event.actor.yellow(),
                event.description.as_deref().unwrap_or("").dimmed()
            );
        }
    }

    println!();

    Ok(())
}

fn run_export(store: &SuppressionStore, output: &PathBuf, actor: &str, quiet: bool) -> Result<()> {
    let json = store.export(actor)?;

    let mut file = std::fs::File::create(output)
        .with_context(|| format!("Failed to create file {:?}", output))?;
    file.write_all(json.as_bytes())?;

    if !quiet {
        let entries = store.list(SuppressionFilter::active_only())?;
        println!();
        println!("{} Exported {} suppressions to {}",
            Theme::success_mark(),
            entries.len().to_string().green(),
            output.display().to_string().cyan()
        );
        println!();
        println!("  {}", "Next steps:".cyan());
        println!("  {} git add {}", Theme::bullet(), output.display());
        println!("  {} git commit -m \"Export suppressions\"", Theme::bullet());
        println!();
    }

    Ok(())
}

fn run_import(store: &SuppressionStore, input: &PathBuf, actor: &str, quiet: bool) -> Result<()> {
    let json = std::fs::read_to_string(input)
        .with_context(|| format!("Failed to read file {:?}", input))?;

    let imported = store.import(&json, actor)?;

    if !quiet {
        println!();
        println!("{} Imported {} suppressions from {}",
            Theme::success_mark(),
            imported.to_string().green(),
            input.display().to_string().cyan()
        );
        println!();
    }

    Ok(())
}

fn run_check(
    store: &SuppressionStore,
    _project_root: &PathBuf,
    prune: bool,
    actor: &str,
    quiet: bool,
) -> Result<()> {
    if !quiet {
        println!();
        println!("{}", Theme::header("Checking Suppressions"));
        println!("{}", Theme::separator(50));
        println!();
    }

    // First, cleanup expired
    let expired = store.cleanup_expired(actor)?;
    if !quiet && expired > 0 {
        println!("  {} Cleaned up {} expired suppressions", Theme::info_mark(), expired.to_string().yellow());
    }

    // Check for stale suppressions
    // Note: Since we only store snippet_hash (not raw content), staleness detection
    // requires re-running a scan and comparing fingerprints. For MVP, we just
    // report entries that have a snippet_hash but the file no longer exists.
    if !quiet {
        println!("  {} Checking for stale suppressions...", Theme::info_mark());
    }

    let stale = store.check_staleness(|entry| {
        // For now, just check if the file still exists
        // Full staleness detection would require re-scanning and computing hashes
        if entry.file_path.exists() {
            // File exists - we can't easily detect staleness without re-scanning
            // Return the stored hash to indicate "not stale"
            entry.snippet_hash.clone()
        } else {
            // File deleted - definitely stale
            None
        }
    })?;

    if stale.is_empty() {
        if !quiet {
            println!("  {} No stale suppressions found", Theme::success_mark());
            println!();
        }
        return Ok(());
    }

    if !quiet {
        println!();
        println!("  {} Found {} stale suppressions:", Theme::warning_mark(), stale.len().to_string().yellow());
        println!();

        for entry in &stale {
            println!("    {} {}", Theme::bullet(), entry.id.cyan());
            println!("      Rule: {}", entry.rule_id);
            println!("      File: {}", entry.file_path.display());
            println!();
        }
    }

    if prune {
        // Mark stale suppressions
        for entry in &stale {
            store.revoke(&entry.id, actor)?;
        }

        if !quiet {
            println!("  {} Pruned {} stale suppressions", Theme::success_mark(), stale.len().to_string().green());
            println!();
        }
    } else if !quiet {
        println!("  {} Run with --prune to remove stale suppressions", Theme::info_mark());
        println!();
    }

    Ok(())
}

fn run_log(store: &SuppressionStore, limit: usize, quiet: bool) -> Result<()> {
    let events = store.get_recent_audit(limit)?;

    if quiet {
        for event in &events {
            println!("{}\t{}\t{}\t{}",
                event.timestamp,
                event.action,
                event.suppression_id,
                event.actor
            );
        }
        return Ok(());
    }

    println!();
    println!("{}", Theme::header("Audit Log"));
    println!("{}", Theme::separator(80));
    println!();

    if events.is_empty() {
        println!("  {} No audit events found", Theme::info_mark());
        println!();
        return Ok(());
    }

    for event in &events {
        let action_color = match event.action {
            rma_common::suppression::AuditAction::Created => event.action.to_string().green(),
            rma_common::suppression::AuditAction::Revoked => event.action.to_string().red(),
            rma_common::suppression::AuditAction::Expired => event.action.to_string().yellow(),
            rma_common::suppression::AuditAction::Extended => event.action.to_string().cyan(),
            rma_common::suppression::AuditAction::MarkedStale => event.action.to_string().magenta(),
            rma_common::suppression::AuditAction::Reactivated => event.action.to_string().green(),
            rma_common::suppression::AuditAction::Imported => event.action.to_string().blue(),
            rma_common::suppression::AuditAction::Updated => event.action.to_string().cyan(),
            rma_common::suppression::AuditAction::SubmittedForApproval => event.action.to_string().blue(),
            rma_common::suppression::AuditAction::Approved => event.action.to_string().green().bold(),
            rma_common::suppression::AuditAction::Rejected => event.action.to_string().red().bold(),
            rma_common::suppression::AuditAction::AddedToGroup => event.action.to_string().cyan(),
            rma_common::suppression::AuditAction::RemovedFromGroup => event.action.to_string().yellow(),
            rma_common::suppression::AuditAction::TagAdded => event.action.to_string().cyan(),
            rma_common::suppression::AuditAction::TagRemoved => event.action.to_string().yellow(),
            rma_common::suppression::AuditAction::ScheduledRevocation => event.action.to_string().yellow().italic(),
            rma_common::suppression::AuditAction::RevocationCancelled => event.action.to_string().green(),
            rma_common::suppression::AuditAction::BulkOperation => event.action.to_string().bright_white(),
        };

        println!(
            "  {} {} {} by {}",
            event.relative_time().dimmed(),
            action_color,
            event.suppression_id.cyan(),
            event.actor.yellow()
        );
        if let Some(ref desc) = event.description {
            println!("    {}", desc.dimmed());
        }
    }

    println!();

    Ok(())
}
