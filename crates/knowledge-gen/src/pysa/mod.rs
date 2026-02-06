//! Pysa taint stub parser
//!
//! Parses `.pysa` files from the pyre-check repository's `stubs/` directory.
//! These files define taint sources, sinks, and sanitizers using annotations like:
//!
//! ```text
//! def flask.request.args -> TaintSource[UserControlled]: ...
//! def subprocess.call(command: TaintSink[RemoteCodeExecution]): ...
//! def markupsafe.escape(text) -> Sanitize: ...
//! ```

mod mapper;

use crate::FrameworkKnowledge;
use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

/// A parsed Pysa annotation line.
#[derive(Debug)]
pub enum PysaEntry {
    Source {
        qualified_name: String,
        taint_kind: String,
    },
    Sink {
        qualified_name: String,
        #[allow(dead_code)]
        param_name: Option<String>,
        taint_kind: String,
    },
    Sanitizer {
        qualified_name: String,
    },
}

/// Parse all `.pysa` files in the given directory tree and produce `FrameworkKnowledge`.
pub fn parse_pysa_stubs(stubs_root: &Path) -> Result<Vec<FrameworkKnowledge>> {
    let pysa_files: Vec<_> = WalkDir::new(stubs_root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "pysa"))
        .collect();

    println!("  Found {} .pysa files", pysa_files.len());

    let mut all_entries = Vec::new();

    for entry in pysa_files {
        let path = entry.path();
        match parse_pysa_file(path) {
            Ok(entries) => all_entries.extend(entries),
            Err(e) => {
                eprintln!("  Warning: skipping {}: {e}", path.display());
            }
        }
    }

    println!("  Parsed {} taint annotations", all_entries.len());

    Ok(mapper::map_pysa_entries(&all_entries))
}

fn parse_pysa_file(path: &Path) -> Result<Vec<PysaEntry>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut entries = Vec::new();

    // Patterns for Pysa annotations
    let source_re =
        Regex::new(r"^def\s+([\w.]+)\s*(?:\([^)]*\))?\s*->\s*TaintSource\[(\w+)\]").unwrap();

    let sink_re =
        Regex::new(r"^def\s+([\w.]+)\s*\((?:.*?(\w+)\s*:\s*)?.*?TaintSink\[(\w+)\]").unwrap();

    let sanitize_re = Regex::new(r"^def\s+([\w.]+)\s*\([^)]*\)\s*->\s*Sanitize").unwrap();

    // Also match attribute-style annotations
    let attr_source_re = Regex::new(r"^([\w.]+)\s*:\s*TaintSource\[(\w+)\]").unwrap();

    let attr_sink_re = Regex::new(r"^([\w.]+)\s*:\s*TaintSink\[(\w+)\]").unwrap();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Try source patterns
        if let Some(caps) = source_re.captures(line) {
            entries.push(PysaEntry::Source {
                qualified_name: caps[1].to_string(),
                taint_kind: caps[2].to_string(),
            });
            continue;
        }

        // Try attribute source
        if let Some(caps) = attr_source_re.captures(line) {
            entries.push(PysaEntry::Source {
                qualified_name: caps[1].to_string(),
                taint_kind: caps[2].to_string(),
            });
            continue;
        }

        // Try sink patterns
        if let Some(caps) = sink_re.captures(line) {
            let param_name = caps.get(2).map(|m| m.as_str().to_string());
            entries.push(PysaEntry::Sink {
                qualified_name: caps[1].to_string(),
                param_name,
                taint_kind: caps[3].to_string(),
            });
            continue;
        }

        // Try attribute sink
        if let Some(caps) = attr_sink_re.captures(line) {
            entries.push(PysaEntry::Sink {
                qualified_name: caps[1].to_string(),
                param_name: None,
                taint_kind: caps[2].to_string(),
            });
            continue;
        }

        // Try sanitizer
        if let Some(caps) = sanitize_re.captures(line) {
            entries.push(PysaEntry::Sanitizer {
                qualified_name: caps[1].to_string(),
            });
        }
    }

    Ok(entries)
}
