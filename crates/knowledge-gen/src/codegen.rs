//! Rust code generator for framework security profiles.
//!
//! Emits `.rs` files with static `FrameworkProfile` definitions matching
//! the hand-coded profiles in `crates/analyzer/src/knowledge/`.

use crate::{FrameworkKnowledge, SanitizerKindTag, SeverityTag, SinkKindTag, SourceKindTag};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::path::Path;

/// Generate all `.rs` files from the collected knowledge.
pub fn generate(knowledge: &[FrameworkKnowledge], output_dir: &Path) -> Result<()> {
    // Group by language
    let mut by_language: BTreeMap<&str, Vec<&FrameworkKnowledge>> = BTreeMap::new();
    for fk in knowledge {
        by_language
            .entry(fk.language.as_str())
            .or_default()
            .push(fk);
    }

    // Clean output dir
    if output_dir.exists() {
        std::fs::remove_dir_all(output_dir)
            .with_context(|| format!("Failed to clean {}", output_dir.display()))?;
    }
    std::fs::create_dir_all(output_dir)?;

    // Generate per-language directories and files
    let mut language_mods = Vec::new();

    for (language, frameworks) in &by_language {
        let lang_dir = output_dir.join(language);
        std::fs::create_dir_all(&lang_dir)?;

        let mut framework_mods = Vec::new();
        let mut used_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        for fk in frameworks {
            // Skip frameworks with no useful content
            if fk.sources.is_empty()
                && fk.sinks.is_empty()
                && fk.sanitizers.is_empty()
                && fk.safe_patterns.is_empty()
                && fk.resource_types.is_empty()
            {
                continue;
            }

            let mut safe_id = sanitize_id(&fk.id);
            // Deduplicate: append numeric suffix on collision
            if used_ids.contains(&safe_id) {
                let mut n = 2;
                loop {
                    let candidate = format!("{safe_id}_{n}");
                    if !used_ids.contains(&candidate) {
                        safe_id = candidate;
                        break;
                    }
                    n += 1;
                }
            }
            used_ids.insert(safe_id.clone());
            let mod_name = format!("{safe_id}_gen");
            let file_name = format!("{mod_name}.rs");
            let content = generate_framework_file(fk, &safe_id)?;
            let file_path = lang_dir.join(&file_name);
            std::fs::write(&file_path, &content)
                .with_context(|| format!("Failed to write {}", file_path.display()))?;
            println!("  Wrote {}/{file_name}", language);
            framework_mods.push((mod_name, safe_id));
        }

        if !framework_mods.is_empty() {
            // Generate language mod.rs
            let lang_mod = generate_language_mod(language, &framework_mods)?;
            std::fs::write(lang_dir.join("mod.rs"), &lang_mod)?;
            language_mods.push(language.to_string());
        }
    }

    // Generate top-level mod.rs
    let top_mod = generate_top_mod(&language_mods)?;
    std::fs::write(output_dir.join("mod.rs"), &top_mod)?;

    Ok(())
}

/// Generate a single framework profile `.rs` file.
fn generate_framework_file(fk: &FrameworkKnowledge, safe_id: &str) -> Result<String> {
    let mut out = String::with_capacity(4096);
    let upper_id = safe_id.to_uppercase();

    writeln!(
        out,
        "//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs"
    )?;
    writeln!(
        out,
        "//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`"
    )?;
    writeln!(out)?;
    writeln!(out, "use crate::knowledge::types::{{")?;
    writeln!(
        out,
        "    FrameworkProfile, SourceDef, SourceKind, SinkDef, SinkKind,"
    )?;
    writeln!(
        out,
        "    SanitizerDef, SanitizerKind, SafePattern, ResourceType,"
    )?;
    writeln!(out, "}};")?;
    writeln!(out, "use rma_common::Severity;")?;
    writeln!(out)?;

    // Sources
    writeln!(out, "static {upper_id}_GEN_SOURCES: &[SourceDef] = &[")?;
    for src in &fk.sources {
        let kind_expr = match src.kind {
            SourceKindTag::FunctionCall => {
                format!("SourceKind::FunctionCall(\"{}\")", escape_str(&src.pattern))
            }
            SourceKindTag::MemberAccess => {
                format!("SourceKind::MemberAccess(\"{}\")", escape_str(&src.pattern))
            }
        };
        writeln!(out, "    SourceDef {{")?;
        writeln!(out, "        name: \"{}\",", escape_str(&src.name))?;
        writeln!(out, "        pattern: {kind_expr},")?;
        writeln!(
            out,
            "        taint_label: \"{}\",",
            escape_str(&src.taint_label)
        )?;
        writeln!(
            out,
            "        description: \"{}\",",
            escape_str(&src.description)
        )?;
        writeln!(out, "    }},")?;
    }
    writeln!(out, "];")?;
    writeln!(out)?;

    // Sinks
    writeln!(out, "static {upper_id}_GEN_SINKS: &[SinkDef] = &[")?;
    for sink in &fk.sinks {
        let kind_expr = match sink.kind {
            SinkKindTag::FunctionCall => {
                format!("SinkKind::FunctionCall(\"{}\")", escape_str(&sink.pattern))
            }
            SinkKindTag::MethodCall => {
                format!("SinkKind::MethodCall(\"{}\")", escape_str(&sink.pattern))
            }
        };
        let severity_expr = match sink.severity {
            SeverityTag::Info => "Severity::Info",
            SeverityTag::Warning => "Severity::Warning",
            SeverityTag::Error => "Severity::Error",
            SeverityTag::Critical => "Severity::Critical",
        };
        let cwe_expr = match &sink.cwe {
            Some(cwe) => format!("Some(\"{}\")", escape_str(cwe)),
            None => "None".to_string(),
        };
        writeln!(out, "    SinkDef {{")?;
        writeln!(out, "        name: \"{}\",", escape_str(&sink.name))?;
        writeln!(out, "        pattern: {kind_expr},")?;
        writeln!(out, "        rule_id: \"{}\",", escape_str(&sink.rule_id))?;
        writeln!(out, "        severity: {severity_expr},")?;
        writeln!(
            out,
            "        description: \"{}\",",
            escape_str(&sink.description)
        )?;
        writeln!(out, "        cwe: {cwe_expr},")?;
        writeln!(out, "    }},")?;
    }
    writeln!(out, "];")?;
    writeln!(out)?;

    // Sanitizers
    writeln!(
        out,
        "static {upper_id}_GEN_SANITIZERS: &[SanitizerDef] = &["
    )?;
    for san in &fk.sanitizers {
        let kind_expr = match san.kind {
            SanitizerKindTag::Function => {
                format!("SanitizerKind::Function(\"{}\")", escape_str(&san.pattern))
            }
            SanitizerKindTag::MethodCall => format!(
                "SanitizerKind::MethodCall(\"{}\")",
                escape_str(&san.pattern)
            ),
        };
        writeln!(out, "    SanitizerDef {{")?;
        writeln!(out, "        name: \"{}\",", escape_str(&san.name))?;
        writeln!(out, "        pattern: {kind_expr},")?;
        writeln!(
            out,
            "        sanitizes: \"{}\",",
            escape_str(&san.sanitizes)
        )?;
        writeln!(
            out,
            "        description: \"{}\",",
            escape_str(&san.description)
        )?;
        writeln!(out, "    }},")?;
    }
    writeln!(out, "];")?;
    writeln!(out)?;

    // Safe patterns
    if !fk.safe_patterns.is_empty() {
        writeln!(
            out,
            "static {upper_id}_GEN_SAFE_PATTERNS: &[SafePattern] = &["
        )?;
        for sp in &fk.safe_patterns {
            writeln!(out, "    SafePattern {{")?;
            writeln!(out, "        name: \"{}\",", escape_str(&sp.name))?;
            writeln!(out, "        pattern: \"{}\",", escape_str(&sp.pattern))?;
            writeln!(out, "        reason: \"{}\",", escape_str(&sp.reason))?;
            writeln!(out, "    }},")?;
        }
        writeln!(out, "];")?;
        writeln!(out)?;
    }

    // Resource types
    if !fk.resource_types.is_empty() {
        writeln!(
            out,
            "static {upper_id}_GEN_RESOURCE_TYPES: &[ResourceType] = &["
        )?;
        for rt in &fk.resource_types {
            writeln!(out, "    ResourceType {{")?;
            writeln!(out, "        name: \"{}\",", escape_str(&rt.name))?;
            writeln!(
                out,
                "        acquire_pattern: \"{}\",",
                escape_str(&rt.acquire_pattern)
            )?;
            writeln!(
                out,
                "        release_pattern: \"{}\",",
                escape_str(&rt.release_pattern)
            )?;
            writeln!(
                out,
                "        leak_consequence: \"{}\",",
                escape_str(&rt.leak_consequence)
            )?;
            writeln!(out, "    }},")?;
        }
        writeln!(out, "];")?;
        writeln!(out)?;
    }

    // Import patterns
    writeln!(out, "static {upper_id}_GEN_IMPORTS: &[&str] = &[")?;
    for pat in &fk.import_patterns {
        writeln!(out, "    \"{}\",", escape_str(pat))?;
    }
    writeln!(out, "];")?;
    writeln!(out)?;

    // Framework profile
    let safe_ref = if fk.safe_patterns.is_empty() {
        "&[]".to_string()
    } else {
        format!("{upper_id}_GEN_SAFE_PATTERNS")
    };
    let resource_ref = if fk.resource_types.is_empty() {
        "&[]".to_string()
    } else {
        format!("{upper_id}_GEN_RESOURCE_TYPES")
    };

    writeln!(
        out,
        "pub static {upper_id}_GEN_PROFILE: FrameworkProfile = FrameworkProfile {{"
    )?;
    writeln!(out, "    name: \"{}_generated\",", escape_str(&fk.id))?;
    writeln!(
        out,
        "    description: \"Generated profile for {} from CodeQL/Pysa\",",
        escape_str(&fk.display_name)
    )?;
    writeln!(out, "    detect_imports: {upper_id}_GEN_IMPORTS,")?;
    writeln!(out, "    sources: {upper_id}_GEN_SOURCES,")?;
    writeln!(out, "    sinks: {upper_id}_GEN_SINKS,")?;
    writeln!(out, "    sanitizers: {upper_id}_GEN_SANITIZERS,")?;
    writeln!(out, "    safe_patterns: {safe_ref},")?;
    writeln!(out, "    dangerous_patterns: &[], // Not auto-generated")?;
    writeln!(out, "    resource_types: {resource_ref},")?;
    writeln!(out, "}};")?;

    Ok(out)
}

/// Generate a language-level `mod.rs` that exposes all generated framework profiles.
fn generate_language_mod(language: &str, frameworks: &[(String, String)]) -> Result<String> {
    let mut out = String::with_capacity(512);

    writeln!(out, "//! Auto-generated {language} framework profiles")?;
    writeln!(
        out,
        "//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`"
    )?;
    writeln!(out)?;

    writeln!(out, "use crate::knowledge::types::FrameworkProfile;")?;
    writeln!(out)?;

    for (mod_name, _) in frameworks {
        writeln!(out, "mod {mod_name};")?;
    }
    writeln!(out)?;

    writeln!(out, "/// Get all generated {language} framework profiles.")?;
    writeln!(
        out,
        "pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {{"
    )?;
    writeln!(out, "    vec![")?;
    for (mod_name, id) in frameworks {
        let upper_id = id.to_uppercase();
        writeln!(out, "        &{mod_name}::{upper_id}_GEN_PROFILE,")?;
    }
    writeln!(out, "    ]")?;
    writeln!(out, "}}")?;

    Ok(out)
}

/// Generate the top-level `generated/mod.rs` that dispatches by language.
fn generate_top_mod(languages: &[String]) -> Result<String> {
    let mut out = String::with_capacity(512);

    writeln!(out, "//! Auto-generated framework security knowledge")?;
    writeln!(out, "//!")?;
    writeln!(
        out,
        "//! Generated from CodeQL Models-as-Data and Pysa taint stubs."
    )?;
    writeln!(
        out,
        "//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`"
    )?;
    writeln!(out)?;

    writeln!(out, "use crate::knowledge::types::FrameworkProfile;")?;
    writeln!(out, "use rma_common::Language;")?;
    writeln!(out)?;

    for lang in languages {
        writeln!(out, "mod {lang};")?;
    }
    writeln!(out)?;

    writeln!(
        out,
        "/// Get generated framework profiles for the given language."
    )?;
    writeln!(
        out,
        "pub fn profiles_for_language(language: Language) -> Vec<&'static FrameworkProfile> {{"
    )?;
    writeln!(out, "    match language {{")?;

    for lang in languages {
        let match_arm = match lang.as_str() {
            "python" => "Language::Python",
            "javascript" => "Language::JavaScript | Language::TypeScript",
            "java" => "Language::Java | Language::Kotlin | Language::Scala",
            "go" => "Language::Go",
            "cpp" => "Language::C | Language::Cpp",
            "csharp" => "Language::CSharp",
            "rust" => "Language::Rust",
            _ => continue,
        };
        writeln!(out, "        {match_arm} => {lang}::generated_profiles(),")?;
    }
    writeln!(out, "        _ => vec![],")?;
    writeln!(out, "    }}")?;
    writeln!(out, "}}")?;

    Ok(out)
}

/// Sanitize a framework ID into a valid Rust identifier.
///
/// Strips leading special characters, replaces non-alphanumeric chars with `_`,
/// collapses consecutive underscores, and ensures it starts with a letter or `_`.
fn sanitize_id(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_underscore = false;

    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            result.push(c);
            prev_underscore = c == '_';
        } else {
            // Replace special chars with underscore, but collapse consecutive ones
            if !prev_underscore && !result.is_empty() {
                result.push('_');
                prev_underscore = true;
            }
        }
    }

    // Trim trailing underscores
    let result = result.trim_end_matches('_').to_string();

    // Ensure doesn't start with a digit
    if result.starts_with(|c: char| c.is_ascii_digit()) {
        format!("n{result}")
    } else if result.is_empty() {
        "unknown".to_string()
    } else {
        result
    }
}

/// Escape a string for use in Rust string literals.
fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
