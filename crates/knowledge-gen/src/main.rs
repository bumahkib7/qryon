//! Knowledge generator: parses CodeQL Models-as-Data YAML and Pysa taint stubs
//! to produce static Rust `FrameworkProfile` definitions for the analyzer.
//!
//! Usage:
//! ```bash
//! cargo run -p knowledge-gen -- \
//!   --codeql-dir external/codeql \
//!   --pysa-dir external/pysa-models/stubs \
//!   --output-dir crates/analyzer/src/knowledge/generated
//! ```

mod codegen;
mod codeql;
mod pysa;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "knowledge-gen",
    about = "Generate framework security knowledge from CodeQL and Pysa"
)]
struct Args {
    /// Path to the CodeQL repository root (contains python/, javascript/, java/, go/ dirs)
    #[arg(long)]
    codeql_dir: Option<PathBuf>,

    /// Path to the Pysa stubs directory (contains taint/ and third_party/ dirs)
    #[arg(long)]
    pysa_dir: Option<PathBuf>,

    /// Output directory for generated .rs files
    #[arg(long)]
    output_dir: PathBuf,
}

/// Collected knowledge for a single framework, ready for codegen.
#[derive(Debug, Clone)]
pub struct FrameworkKnowledge {
    /// Identifier used for the Rust constant names (e.g. "flask", "django")
    pub id: String,
    /// Human-readable name
    pub display_name: String,
    /// Language this framework belongs to
    pub language: String,
    /// Import patterns that detect the framework
    pub import_patterns: Vec<String>,
    /// Taint sources
    pub sources: Vec<SourceEntry>,
    /// Taint sinks
    pub sinks: Vec<SinkEntry>,
    /// Sanitizers
    pub sanitizers: Vec<SanitizerEntry>,
    /// Safe patterns (APIs that don't propagate taint)
    pub safe_patterns: Vec<SafePatternEntry>,
    /// Resource types (acquire/release lifecycle pairs)
    pub resource_types: Vec<ResourceTypeEntry>,
}

#[derive(Debug, Clone)]
pub struct SourceEntry {
    pub name: String,
    pub pattern: String,
    pub kind: SourceKindTag,
    pub taint_label: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum SourceKindTag {
    FunctionCall,
    MemberAccess,
}

#[derive(Debug, Clone)]
pub struct SinkEntry {
    pub name: String,
    pub pattern: String,
    pub kind: SinkKindTag,
    pub rule_id: String,
    pub severity: SeverityTag,
    pub description: String,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum SinkKindTag {
    FunctionCall,
    MethodCall,
}

#[derive(Debug, Clone, Copy)]
pub enum SeverityTag {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone)]
pub struct SanitizerEntry {
    pub name: String,
    pub pattern: String,
    pub kind: SanitizerKindTag,
    pub sanitizes: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum SanitizerKindTag {
    Function,
    MethodCall,
}

#[derive(Debug, Clone)]
pub struct SafePatternEntry {
    pub name: String,
    pub pattern: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ResourceTypeEntry {
    pub name: String,
    pub acquire_pattern: String,
    pub release_pattern: String,
    pub leak_consequence: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut all_knowledge: Vec<FrameworkKnowledge> = Vec::new();

    // Parse CodeQL Models-as-Data
    if let Some(codeql_dir) = &args.codeql_dir {
        let codeql_dir = codeql_dir
            .canonicalize()
            .with_context(|| format!("CodeQL directory not found: {}", codeql_dir.display()))?;
        println!("Parsing CodeQL MaD from: {}", codeql_dir.display());
        let codeql_knowledge = codeql::parse_codeql_mad(&codeql_dir)?;
        println!(
            "  Found {} framework(s) from CodeQL",
            codeql_knowledge.len()
        );
        for fk in &codeql_knowledge {
            println!(
                "    {} ({}): {} sources, {} sinks, {} sanitizers, {} safe, {} resources",
                fk.id,
                fk.language,
                fk.sources.len(),
                fk.sinks.len(),
                fk.sanitizers.len(),
                fk.safe_patterns.len(),
                fk.resource_types.len()
            );
        }
        all_knowledge.extend(codeql_knowledge);
    }

    // Parse Pysa taint stubs
    if let Some(pysa_dir) = &args.pysa_dir {
        let pysa_dir = pysa_dir
            .canonicalize()
            .with_context(|| format!("Pysa directory not found: {}", pysa_dir.display()))?;
        println!("Parsing Pysa stubs from: {}", pysa_dir.display());
        let pysa_knowledge = pysa::parse_pysa_stubs(&pysa_dir)?;
        println!("  Found {} framework(s) from Pysa", pysa_knowledge.len());
        for fk in &pysa_knowledge {
            println!(
                "    {} ({}): {} sources, {} sinks, {} sanitizers, {} safe, {} resources",
                fk.id,
                fk.language,
                fk.sources.len(),
                fk.sinks.len(),
                fk.sanitizers.len(),
                fk.safe_patterns.len(),
                fk.resource_types.len()
            );
        }
        all_knowledge.extend(pysa_knowledge);
    }

    if all_knowledge.is_empty() {
        println!("No knowledge sources provided. Use --codeql-dir and/or --pysa-dir.");
        return Ok(());
    }

    // Merge knowledge by (language, framework_id)
    let merged = merge_knowledge(all_knowledge);

    // Generate Rust code
    println!("\nGenerating Rust code to: {}", args.output_dir.display());
    codegen::generate(&merged, &args.output_dir)?;
    println!("Done! Generated {} framework profile(s).", merged.len());

    Ok(())
}

/// Merge knowledge entries that share the same (language, id) pair.
fn merge_knowledge(entries: Vec<FrameworkKnowledge>) -> Vec<FrameworkKnowledge> {
    use std::collections::BTreeMap;

    let mut map: BTreeMap<(String, String), FrameworkKnowledge> = BTreeMap::new();

    for entry in entries {
        let key = (entry.language.clone(), entry.id.clone());
        map.entry(key)
            .and_modify(|existing| {
                // Merge import patterns (dedup)
                for pat in &entry.import_patterns {
                    if !existing.import_patterns.contains(pat) {
                        existing.import_patterns.push(pat.clone());
                    }
                }
                // Merge sources (dedup by name)
                for src in &entry.sources {
                    if !existing.sources.iter().any(|s| s.name == src.name) {
                        existing.sources.push(src.clone());
                    }
                }
                // Merge sinks (dedup by name)
                for sink in &entry.sinks {
                    if !existing.sinks.iter().any(|s| s.name == sink.name) {
                        existing.sinks.push(sink.clone());
                    }
                }
                // Merge sanitizers (dedup by name)
                for san in &entry.sanitizers {
                    if !existing.sanitizers.iter().any(|s| s.name == san.name) {
                        existing.sanitizers.push(san.clone());
                    }
                }
                // Merge safe patterns (dedup by name)
                for sp in &entry.safe_patterns {
                    if !existing.safe_patterns.iter().any(|s| s.name == sp.name) {
                        existing.safe_patterns.push(sp.clone());
                    }
                }
                // Merge resource types (dedup by name)
                for rt in &entry.resource_types {
                    if !existing.resource_types.iter().any(|r| r.name == rt.name) {
                        existing.resource_types.push(rt.clone());
                    }
                }
            })
            .or_insert(entry);
    }

    map.into_values().collect()
}
