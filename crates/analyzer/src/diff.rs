//! Diff-aware analysis for PR workflows
//!
//! This module provides functionality to filter findings to only those
//! affecting lines changed in a PR/diff. This is useful for:
//! - PR workflows where you only want to see new issues
//! - Incremental analysis to reduce noise
//! - CI pipelines that focus on changed code

use anyhow::{Context, Result};
use rma_common::Finding;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process::Command;

/// Map of file paths to the set of line numbers that were changed
pub type ChangedLines = HashMap<PathBuf, HashSet<usize>>;

/// Get changed lines by running `git diff` against a base reference
///
/// This runs `git diff --unified=0` to get a minimal diff showing only
/// the exact lines that changed.
///
/// # Arguments
/// * `project_root` - The root directory of the git repository
/// * `base_ref` - The git reference to compare against (e.g., "origin/main")
///
/// # Returns
/// A map of file paths to the set of changed line numbers
pub fn get_changed_lines_from_git(project_root: &PathBuf, base_ref: &str) -> Result<ChangedLines> {
    // Run git diff with unified=0 to get exact changed lines
    let output = Command::new("git")
        .args(["diff", "--unified=0", base_ref])
        .current_dir(project_root)
        .output()
        .context("Failed to run git diff")?;

    if !output.status.success() {
        // Try fetching the remote first
        let _ = Command::new("git")
            .args(["fetch", "origin"])
            .current_dir(project_root)
            .output();

        // Retry the diff
        let output = Command::new("git")
            .args(["diff", "--unified=0", base_ref])
            .current_dir(project_root)
            .output()
            .context("Failed to run git diff after fetch")?;

        if !output.status.success() {
            anyhow::bail!(
                "git diff failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let diff_text = String::from_utf8_lossy(&output.stdout);
        return parse_unified_diff(&diff_text, Some(project_root));
    }

    let diff_text = String::from_utf8_lossy(&output.stdout);
    parse_unified_diff(&diff_text, Some(project_root))
}

/// Get changed lines from unified diff text read from stdin
///
/// This is useful for piping diff output from other sources.
///
/// # Returns
/// A map of file paths to the set of changed line numbers
pub fn get_changed_lines_from_stdin() -> Result<ChangedLines> {
    let stdin = io::stdin();
    let mut diff_text = String::new();

    for line in stdin.lock().lines() {
        let line = line.context("Failed to read line from stdin")?;
        diff_text.push_str(&line);
        diff_text.push('\n');
    }

    parse_unified_diff(&diff_text, None)
}

/// Parse a unified diff and extract the changed line numbers for each file
///
/// Handles standard git unified diff format:
/// ```text
/// diff --git a/file.rs b/file.rs
/// --- a/file.rs
/// +++ b/file.rs
/// @@ -10,3 +10,5 @@ fn example() {
///  unchanged
/// +added line 1
/// +added line 2
///  unchanged
/// ```
///
/// # Arguments
/// * `diff_text` - The unified diff text
/// * `project_root` - Optional project root to resolve relative paths
///
/// # Returns
/// A map of file paths to the set of changed line numbers (in the new version)
pub fn parse_unified_diff(diff_text: &str, project_root: Option<&PathBuf>) -> Result<ChangedLines> {
    let mut changed_lines: ChangedLines = HashMap::new();
    let mut current_file: Option<PathBuf> = None;

    for line in diff_text.lines() {
        // Handle file header: +++ b/path/to/file
        if line.starts_with("+++ ") {
            let path_str = line
                .strip_prefix("+++ ")
                .unwrap()
                .strip_prefix("b/")
                .unwrap_or(line.strip_prefix("+++ ").unwrap());

            // Handle /dev/null for new files
            if path_str == "/dev/null" {
                current_file = None;
                continue;
            }

            let file_path = if let Some(root) = project_root {
                root.join(path_str)
            } else {
                PathBuf::from(path_str)
            };

            current_file = Some(file_path);
        }
        // Handle hunk header: @@ -old_start,old_count +new_start,new_count @@
        else if line.starts_with("@@ ")
            && let Some(ref file) = current_file
            && let Some((new_start, new_count)) = parse_hunk_header(line)
        {
            let lines = changed_lines.entry(file.clone()).or_default();
            // Add all lines in the new range
            for line_num in new_start..new_start + new_count {
                lines.insert(line_num);
            }
        }
    }

    Ok(changed_lines)
}

/// Parse a hunk header to extract the new file line range
///
/// Format: @@ -old_start,old_count +new_start,new_count @@ optional context
/// Or:     @@ -old_start +new_start,new_count @@
/// Or:     @@ -old_start,old_count +new_start @@
///
/// Returns (new_start, new_count) where count defaults to 1 if not specified
fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    // Extract the part between @@ markers
    let parts: Vec<&str> = line.split("@@").collect();
    if parts.len() < 2 {
        return None;
    }

    let range_part = parts[1].trim();

    // Find the + part (new file range)
    for part in range_part.split_whitespace() {
        if part.starts_with('+') {
            let range_str = part.strip_prefix('+')?;

            // Parse "start,count" or just "start"
            if let Some((start_str, count_str)) = range_str.split_once(',') {
                let start = start_str.parse().ok()?;
                let count = count_str.parse().ok()?;
                return Some((start, count));
            } else {
                let start = range_str.parse().ok()?;
                // If no count specified, it means 1 line changed
                return Some((start, 1));
            }
        }
    }

    None
}

/// Filter findings to only include those on changed lines
///
/// This compares each finding's location against the changed lines map
/// and keeps only findings that are on lines that were modified.
///
/// # Arguments
/// * `findings` - The list of findings to filter
/// * `changed_lines` - Map of file paths to changed line numbers
///
/// # Returns
/// A filtered vector containing only findings on changed lines
pub fn filter_findings_by_diff(
    findings: Vec<Finding>,
    changed_lines: &ChangedLines,
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|finding| {
            let file_path = &finding.location.file;

            // Check if this file has any changed lines
            if let Some(lines) = changed_lines.get(file_path) {
                // Check if any line in the finding's range is changed
                for line in finding.location.start_line..=finding.location.end_line {
                    if lines.contains(&line) {
                        return true;
                    }
                }
                false
            } else {
                // Try matching with just the filename for relative path handling
                let file_name = file_path.file_name();
                for (changed_path, lines) in changed_lines.iter() {
                    // Check if paths match (handling relative vs absolute)
                    let paths_match = changed_path == file_path
                        || changed_path.ends_with(file_path)
                        || file_path.ends_with(changed_path)
                        || (file_name.is_some() && changed_path.file_name() == file_name);

                    if paths_match {
                        for line in finding.location.start_line..=finding.location.end_line {
                            if lines.contains(&line) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
        })
        .collect()
}

/// Check if a file is in the changed files set (regardless of line numbers)
///
/// This is useful for filtering files before analysis.
pub fn is_file_changed(file_path: &PathBuf, changed_lines: &ChangedLines) -> bool {
    if changed_lines.contains_key(file_path) {
        return true;
    }

    // Try matching with just the filename for relative path handling
    let file_name = file_path.file_name();
    for changed_path in changed_lines.keys() {
        if changed_path.ends_with(file_path)
            || file_path.ends_with(changed_path)
            || (file_name.is_some() && changed_path.file_name() == file_name)
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{Language, Severity, SourceLocation};

    #[test]
    fn test_parse_hunk_header_basic() {
        // Standard format: @@ -10,3 +10,5 @@
        let result = parse_hunk_header("@@ -10,3 +10,5 @@");
        assert_eq!(result, Some((10, 5)));
    }

    #[test]
    fn test_parse_hunk_header_no_count() {
        // Single line change: @@ -10 +10 @@
        let result = parse_hunk_header("@@ -10 +10 @@");
        assert_eq!(result, Some((10, 1)));
    }

    #[test]
    fn test_parse_hunk_header_with_context() {
        // With function context: @@ -10,3 +10,5 @@ fn example() {
        let result = parse_hunk_header("@@ -10,3 +10,5 @@ fn example() {");
        assert_eq!(result, Some((10, 5)));
    }

    #[test]
    fn test_parse_hunk_header_single_line_new_count() {
        // @@ -5,0 +6,2 @@ - adding 2 lines after line 5
        let result = parse_hunk_header("@@ -5,0 +6,2 @@");
        assert_eq!(result, Some((6, 2)));
    }

    #[test]
    fn test_parse_hunk_header_deletion_only() {
        // @@ -10,3 +10,0 @@ - removing 3 lines
        // This represents 0 lines in the new file at position 10
        let result = parse_hunk_header("@@ -10,3 +10,0 @@");
        assert_eq!(result, Some((10, 0)));
    }

    #[test]
    fn test_parse_unified_diff_simple() {
        let diff = r#"diff --git a/src/main.rs b/src/main.rs
index abc123..def456 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -10,3 +10,5 @@ fn main() {
 unchanged
+added line 1
+added line 2
 unchanged
"#;

        let result = parse_unified_diff(diff, None).unwrap();
        assert!(result.contains_key(&PathBuf::from("src/main.rs")));

        let lines = result.get(&PathBuf::from("src/main.rs")).unwrap();
        // Lines 10-14 are in the hunk (5 lines starting at 10)
        assert!(lines.contains(&10));
        assert!(lines.contains(&11));
        assert!(lines.contains(&12));
        assert!(lines.contains(&13));
        assert!(lines.contains(&14));
    }

    #[test]
    fn test_parse_unified_diff_multiple_hunks() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -5,2 +5,3 @@
 line
+new line at 6
 line
@@ -20,1 +21,2 @@
 old
+new line at 22
"#;

        let result = parse_unified_diff(diff, None).unwrap();
        let lines = result.get(&PathBuf::from("src/lib.rs")).unwrap();

        // First hunk: lines 5-7 (3 lines starting at 5)
        assert!(lines.contains(&5));
        assert!(lines.contains(&6));
        assert!(lines.contains(&7));

        // Second hunk: lines 21-22 (2 lines starting at 21)
        assert!(lines.contains(&21));
        assert!(lines.contains(&22));
    }

    #[test]
    fn test_parse_unified_diff_new_file() {
        let diff = r#"diff --git a/src/new_file.rs b/src/new_file.rs
new file mode 100644
index 0000000..abc123
--- /dev/null
+++ b/src/new_file.rs
@@ -0,0 +1,10 @@
+fn new_function() {
+    println!("hello");
+}
"#;

        let result = parse_unified_diff(diff, None).unwrap();
        assert!(result.contains_key(&PathBuf::from("src/new_file.rs")));

        let lines = result.get(&PathBuf::from("src/new_file.rs")).unwrap();
        // All 10 lines are new (lines 1-10)
        for i in 1..=10 {
            assert!(lines.contains(&i), "Line {} should be marked as changed", i);
        }
    }

    #[test]
    fn test_parse_unified_diff_deleted_file() {
        let diff = r#"diff --git a/src/old_file.rs b/src/old_file.rs
deleted file mode 100644
index abc123..0000000
--- a/src/old_file.rs
+++ /dev/null
@@ -1,10 +0,0 @@
-fn old_function() {
-    println!("goodbye");
-}
"#;

        let result = parse_unified_diff(diff, None).unwrap();
        // Deleted files have no changed lines in the new version
        assert!(!result.contains_key(&PathBuf::from("src/old_file.rs")));
    }

    #[test]
    fn test_parse_unified_diff_renamed_file() {
        let diff = r#"diff --git a/src/old_name.rs b/src/new_name.rs
similarity index 95%
rename from src/old_name.rs
rename to src/new_name.rs
index abc123..def456 100644
--- a/src/old_name.rs
+++ b/src/new_name.rs
@@ -5,1 +5,2 @@
 unchanged
+added in renamed file
"#;

        let result = parse_unified_diff(diff, None).unwrap();
        // The new file name should be tracked
        assert!(result.contains_key(&PathBuf::from("src/new_name.rs")));

        let lines = result.get(&PathBuf::from("src/new_name.rs")).unwrap();
        assert!(lines.contains(&5));
        assert!(lines.contains(&6));
    }

    #[test]
    fn test_filter_findings_by_diff_keeps_changed() {
        let mut changed_lines = ChangedLines::new();
        changed_lines.insert(
            PathBuf::from("src/main.rs"),
            vec![10, 11, 12].into_iter().collect(),
        );

        let findings = vec![
            create_test_finding("src/main.rs", 10, 10), // On changed line
            create_test_finding("src/main.rs", 5, 5),   // Not on changed line
            create_test_finding("src/main.rs", 11, 12), // Spans changed lines
        ];

        let filtered = filter_findings_by_diff(findings, &changed_lines);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].location.start_line, 10);
        assert_eq!(filtered[1].location.start_line, 11);
    }

    #[test]
    fn test_filter_findings_by_diff_removes_unchanged() {
        let mut changed_lines = ChangedLines::new();
        changed_lines.insert(
            PathBuf::from("src/main.rs"),
            vec![10, 11].into_iter().collect(),
        );

        let findings = vec![
            create_test_finding("src/main.rs", 5, 5), // Before changed area
            create_test_finding("src/main.rs", 20, 25), // After changed area
            create_test_finding("src/other.rs", 10, 10), // Different file
        ];

        let filtered = filter_findings_by_diff(findings, &changed_lines);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_findings_partial_overlap() {
        let mut changed_lines = ChangedLines::new();
        changed_lines.insert(
            PathBuf::from("src/main.rs"),
            vec![10, 11, 12].into_iter().collect(),
        );

        let findings = vec![
            create_test_finding("src/main.rs", 8, 10), // Starts before, ends on changed
            create_test_finding("src/main.rs", 12, 15), // Starts on changed, ends after
        ];

        let filtered = filter_findings_by_diff(findings, &changed_lines);
        assert_eq!(filtered.len(), 2); // Both have partial overlap
    }

    #[test]
    fn test_is_file_changed() {
        let mut changed_lines = ChangedLines::new();
        changed_lines.insert(PathBuf::from("src/main.rs"), vec![10].into_iter().collect());

        assert!(is_file_changed(
            &PathBuf::from("src/main.rs"),
            &changed_lines
        ));
        assert!(!is_file_changed(
            &PathBuf::from("src/other.rs"),
            &changed_lines
        ));
    }

    #[test]
    fn test_path_matching_relative_absolute() {
        let mut changed_lines = ChangedLines::new();
        changed_lines.insert(
            PathBuf::from("/project/src/main.rs"),
            vec![10].into_iter().collect(),
        );

        // Should match when finding has relative path
        let finding = create_test_finding("src/main.rs", 10, 10);
        let filtered = filter_findings_by_diff(vec![finding], &changed_lines);
        assert_eq!(filtered.len(), 1);
    }

    fn create_test_finding(file: &str, start_line: usize, end_line: usize) -> Finding {
        Finding {
            id: format!("test-{}-{}", file, start_line),
            rule_id: "test-rule".to_string(),
            message: "Test finding".to_string(),
            severity: Severity::Warning,
            location: SourceLocation {
                file: PathBuf::from(file),
                start_line,
                start_column: 1,
                end_line,
                end_column: 1,
            },
            language: Language::Rust,
            snippet: None,
            suggestion: None,
            fix: None,
            confidence: rma_common::Confidence::Medium,
            category: rma_common::FindingCategory::Security,
            source: Default::default(),
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }
}
