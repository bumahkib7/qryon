//! CodeQL Models-as-Data (MaD) YAML parser
//!
//! Parses the `extensions` YAML files found under `<lang>/ql/lib/ext/` in
//! the CodeQL repository. Each file contains `sourceModel`, `sinkModel`,
//! and `summaryModel` entries describing framework APIs.

mod mapper;

use crate::FrameworkKnowledge;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use walkdir::WalkDir;

/// Top-level YAML structure for CodeQL MaD extension files.
#[derive(Debug, Deserialize)]
pub struct MadFile {
    #[serde(default)]
    pub extensions: Vec<Extension>,
}

/// A single extension block (addsTo + data).
#[derive(Debug, Deserialize)]
pub struct Extension {
    #[serde(rename = "addsTo")]
    pub adds_to: AddsTo,
    #[serde(default)]
    pub data: Vec<Vec<serde_yaml::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct AddsTo {
    #[allow(dead_code)]
    pub pack: String,
    pub extensible: String,
}

/// Language directories we scan inside the CodeQL repo.
const LANGUAGE_DIRS: &[(&str, &str)] = &[
    ("python", "python/ql/lib/ext"),
    ("javascript", "javascript/ql/lib/ext"),
    ("java", "java/ql/lib/ext"),
    ("go", "go/ql/lib/ext"),
    ("cpp", "cpp/ql/lib/ext"),
    ("csharp", "csharp/ql/lib/ext"),
    ("rust", "rust/ql/lib/ext"),
    ("ruby", "ruby/ql/lib/ext"),
    ("swift", "swift/ql/lib/ext"),
];

/// Parse all CodeQL MaD YAML files and produce `FrameworkKnowledge` entries.
pub fn parse_codeql_mad(codeql_root: &Path) -> Result<Vec<FrameworkKnowledge>> {
    let mut results = Vec::new();

    for &(language, rel_path) in LANGUAGE_DIRS {
        let ext_dir = codeql_root.join(rel_path);
        if !ext_dir.exists() {
            println!("  Skipping {language}: {} not found", ext_dir.display());
            continue;
        }

        let yaml_files: Vec<_> = WalkDir::new(&ext_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
            })
            .collect();

        println!("  {language}: found {} YAML files", yaml_files.len());

        for entry in yaml_files {
            let path = entry.path();
            match parse_mad_file(path) {
                Ok(mad) => {
                    let knowledge = mapper::map_extensions(language, &mad.extensions, path);
                    results.extend(knowledge);
                }
                Err(e) => {
                    // Skip malformed files; some MaD files may use formats we don't handle
                    eprintln!("  Warning: skipping {}: {e}", path.display());
                }
            }
        }
    }

    Ok(results)
}

fn parse_mad_file(path: &Path) -> Result<MadFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mad: MadFile = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML: {}", path.display()))?;
    Ok(mad)
}
