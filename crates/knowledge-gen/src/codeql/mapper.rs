//! Maps CodeQL Models-as-Data entries to our internal `FrameworkKnowledge` types.

use crate::{
    FrameworkKnowledge, ResourceTypeEntry, SafePatternEntry, SanitizerEntry, SanitizerKindTag,
    SeverityTag, SinkEntry, SinkKindTag, SourceEntry, SourceKindTag,
};

use super::Extension;
use std::collections::BTreeMap;
use std::path::Path;

/// Map a set of extensions from a single YAML file into framework knowledge entries.
/// Groups entries by the package/framework they belong to.
pub fn map_extensions(
    language: &str,
    extensions: &[Extension],
    _source_path: &Path,
) -> Vec<FrameworkKnowledge> {
    // Accumulate entries grouped by framework identifier
    let mut frameworks: BTreeMap<String, FrameworkKnowledge> = BTreeMap::new();

    // Collect alloc/dealloc entries for pairing after the loop
    let mut alloc_entries: Vec<(String, String)> = Vec::new(); // (namespace::function, framework_id)
    let mut dealloc_entries: Vec<(String, String)> = Vec::new();

    for ext in extensions {
        let model_type = &ext.adds_to.extensible;

        for row in &ext.data {
            // MaD rows have variable length. The first element is typically the package/namespace.
            if row.is_empty() {
                continue;
            }

            let package = value_to_string(&row[0]);
            let framework_id = normalize_framework_id(&package);

            if framework_id.is_empty() {
                continue;
            }

            let fk = frameworks
                .entry(framework_id.clone())
                .or_insert_with(|| FrameworkKnowledge {
                    id: framework_id.clone(),
                    display_name: package.clone(),
                    language: language.to_string(),
                    import_patterns: vec![package.clone()],
                    sources: Vec::new(),
                    sinks: Vec::new(),
                    sanitizers: Vec::new(),
                    safe_patterns: Vec::new(),
                    resource_types: Vec::new(),
                });

            // Ensure the package is in import patterns
            if !fk.import_patterns.contains(&package) {
                fk.import_patterns.push(package.clone());
            }

            match model_type.as_str() {
                "sourceModel" => {
                    if let Some(source) = map_source_row(row, &package)
                        && !fk.sources.iter().any(|s| s.name == source.name)
                    {
                        fk.sources.push(source);
                    }
                }
                "sinkModel" => {
                    if let Some(sink) = map_sink_row(row, &package, language)
                        && !fk.sinks.iter().any(|s| s.name == sink.name)
                    {
                        fk.sinks.push(sink);
                    }
                }
                "summaryModel" => {
                    if let Some(sanitizer) = map_summary_row(row, &package)
                        && !fk.sanitizers.iter().any(|s| s.name == sanitizer.name)
                    {
                        fk.sanitizers.push(sanitizer);
                    }
                }
                "neutralModel" => {
                    if let Some(sp) = map_neutral_row(row, &package)
                        && !fk.safe_patterns.iter().any(|s| s.name == sp.name)
                    {
                        fk.safe_patterns.push(sp);
                    }
                }
                "barrierModel" => {
                    if let Some(sp) = map_barrier_row(row, &package)
                        && !fk.safe_patterns.iter().any(|s| s.name == sp.name)
                    {
                        fk.safe_patterns.push(sp);
                    }
                }
                "allocationFunctionModel" => {
                    // Format: [namespace, class, is_instance, function, size_arg, count_arg, kind, creates_heap]
                    if row.len() >= 4 {
                        let namespace = value_to_string(&row[0]);
                        let function = value_to_string(&row[3]);
                        let qualified = if namespace.is_empty() {
                            function.clone()
                        } else {
                            format!("{namespace}::{function}")
                        };
                        alloc_entries.push((qualified, framework_id.clone()));
                    }
                }
                "deallocationFunctionModel" => {
                    // Format: [namespace, class, is_instance, function, ptr_arg]
                    if row.len() >= 4 {
                        let namespace = value_to_string(&row[0]);
                        let function = value_to_string(&row[3]);
                        let qualified = if namespace.is_empty() {
                            function.clone()
                        } else {
                            format!("{namespace}::{function}")
                        };
                        dealloc_entries.push((qualified, framework_id.clone()));
                    }
                }
                _ => {
                    // typeModel, etc. - skip
                }
            }
        }
    }

    // Pair alloc/dealloc entries into resource types
    pair_alloc_dealloc(&mut frameworks, &alloc_entries, &dealloc_entries);

    frameworks.into_values().collect()
}

/// Pair allocation and deallocation functions into ResourceTypeEntry.
fn pair_alloc_dealloc(
    frameworks: &mut BTreeMap<String, FrameworkKnowledge>,
    alloc_entries: &[(String, String)],
    dealloc_entries: &[(String, String)],
) {
    // Known pairs: alloc function name suffix -> dealloc function name suffix
    let known_pairs: &[(&str, &str)] = &[
        ("malloc", "free"),
        ("calloc", "free"),
        ("realloc", "free"),
        ("strdup", "free"),
        ("CoTaskMemAlloc", "CoTaskMemFree"),
        ("CoTaskMemRealloc", "CoTaskMemFree"),
        ("HeapAlloc", "HeapFree"),
        ("HeapReAlloc", "HeapFree"),
        ("LocalAlloc", "LocalFree"),
        ("LocalReAlloc", "LocalFree"),
        ("GlobalAlloc", "GlobalFree"),
        ("GlobalReAlloc", "GlobalFree"),
        ("VirtualAlloc", "VirtualFree"),
        ("VirtualAllocEx", "VirtualFree"),
        ("MapViewOfFile", "UnmapViewOfFile"),
        ("_aligned_malloc", "_aligned_free"),
        ("_aligned_realloc", "_aligned_free"),
    ];

    // Build dealloc lookup: function_name -> qualified_name
    let dealloc_lookup: BTreeMap<String, &str> = dealloc_entries
        .iter()
        .map(|(qualified, _)| {
            let func_name = qualified.rsplit("::").next().unwrap_or(qualified);
            (func_name.to_string(), qualified.as_str())
        })
        .collect();

    for (alloc_qualified, fw_id) in alloc_entries {
        let alloc_func = alloc_qualified
            .rsplit("::")
            .next()
            .unwrap_or(alloc_qualified);

        // Try known pairs first
        let mut matched_dealloc: Option<String> = None;
        for (alloc_suffix, dealloc_suffix) in known_pairs {
            if alloc_func.ends_with(alloc_suffix) || alloc_func == *alloc_suffix {
                if let Some(dealloc_q) = dealloc_lookup.get(*dealloc_suffix) {
                    matched_dealloc = Some(dealloc_q.to_string());
                } else {
                    // Use the dealloc name even if not in our entries
                    matched_dealloc = Some(dealloc_suffix.to_string());
                }
                break;
            }
        }

        // Heuristic fallback: *Alloc -> *Free
        if matched_dealloc.is_none() && alloc_func.contains("Alloc") {
            let dealloc_guess = alloc_func.replace("Alloc", "Free");
            if dealloc_lookup.contains_key(&dealloc_guess) {
                matched_dealloc = Some(dealloc_lookup.get(&dealloc_guess).unwrap().to_string());
            } else {
                matched_dealloc = Some(dealloc_guess);
            }
        }

        if let Some(release) = matched_dealloc
            && let Some(fk) = frameworks.get_mut(fw_id)
        {
            let rt = ResourceTypeEntry {
                name: alloc_func.to_string(),
                acquire_pattern: alloc_qualified.clone(),
                release_pattern: release,
                leak_consequence: "Heap memory leak".to_string(),
            };
            if !fk.resource_types.iter().any(|r| r.name == rt.name) {
                fk.resource_types.push(rt);
            }
        }
    }
}

/// Map a sourceModel row to a SourceEntry.
///
/// Typical CodeQL MaD source row format:
///   ["package", "type", "subtypes", "name", "signature", "ext", "input", "output", "kind"]
/// or shorter for some languages:
///   ["package", "access_path", "kind"]
fn map_source_row(row: &[serde_yaml::Value], package: &str) -> Option<SourceEntry> {
    // We need at minimum: package, some access info, and a kind
    if row.len() < 2 {
        return None;
    }

    let (access_path, kind_str) = if row.len() >= 9 {
        // Full MaD format: [package, type, subtypes, name, sig, ext, input, output, kind]
        let type_name = value_to_string(&row[1]);
        let method_name = value_to_string(&row[3]);
        let kind = value_to_string(&row[8]);
        let access = if method_name.is_empty() || method_name == "true" || method_name == "false" {
            format!("{package}.{type_name}")
        } else {
            format!("{package}.{type_name}.{method_name}")
        };
        (access, kind)
    } else if row.len() >= 3 {
        // Short format: [package, access_path, kind]
        (value_to_string(&row[1]), value_to_string(&row[2]))
    } else {
        (value_to_string(&row[1]), "remote".to_string())
    };

    let name = sanitize_name(&access_path, package);
    let (source_kind, pattern) = classify_source(&access_path);

    Some(SourceEntry {
        name,
        pattern,
        kind: source_kind,
        taint_label: map_source_kind_to_label(&kind_str),
        description: format!("CodeQL source: {access_path} (kind: {kind_str})"),
    })
}

/// Map a sinkModel row to a SinkEntry.
fn map_sink_row(row: &[serde_yaml::Value], package: &str, language: &str) -> Option<SinkEntry> {
    if row.len() < 2 {
        return None;
    }

    let (access_path, kind_str) = if row.len() >= 9 {
        let type_name = value_to_string(&row[1]);
        let method_name = value_to_string(&row[3]);
        let kind = value_to_string(&row[8]);
        let access = if method_name.is_empty() || method_name == "true" || method_name == "false" {
            format!("{package}.{type_name}")
        } else {
            format!("{package}.{type_name}.{method_name}")
        };
        (access, kind)
    } else if row.len() >= 3 {
        (value_to_string(&row[1]), value_to_string(&row[2]))
    } else {
        return None;
    };

    let name = sanitize_name(&access_path, package);
    let (sink_kind, pattern) = classify_sink(&access_path);
    let (severity, cwe) = map_sink_kind_to_severity(&kind_str);
    let rule_id = format!("{language}/gen-{}", kind_str.replace(' ', "-"));

    Some(SinkEntry {
        name,
        pattern,
        kind: sink_kind,
        rule_id,
        severity,
        description: format!("CodeQL sink: {access_path} (kind: {kind_str})"),
        cwe: Some(cwe.to_string()),
    })
}

/// Map a summaryModel row to a SanitizerEntry (if it looks like a sanitizer).
///
/// summaryModel describes taint propagation. We specifically look for
/// entries that transform/encode data (sanitizer-like behavior).
fn map_summary_row(row: &[serde_yaml::Value], package: &str) -> Option<SanitizerEntry> {
    if row.len() < 2 {
        return None;
    }

    let (access_path, kind_str) = if row.len() >= 9 {
        let type_name = value_to_string(&row[1]);
        let method_name = value_to_string(&row[3]);
        let kind = value_to_string(&row[8]);
        let access = if method_name.is_empty() || method_name == "true" || method_name == "false" {
            format!("{package}.{type_name}")
        } else {
            format!("{package}.{type_name}.{method_name}")
        };
        (access, kind)
    } else if row.len() >= 3 {
        (value_to_string(&row[1]), value_to_string(&row[2]))
    } else {
        return None;
    };

    // Only include entries that look like sanitizers
    let is_sanitizer = is_sanitizer_like(&access_path, &kind_str);
    if !is_sanitizer {
        return None;
    }

    let name = sanitize_name(&access_path, package);
    let sanitizes = infer_sanitization_type(&access_path, &kind_str);

    Some(SanitizerEntry {
        name,
        pattern: access_path.clone(),
        kind: SanitizerKindTag::Function,
        sanitizes,
        description: format!("CodeQL sanitizer: {access_path}"),
    })
}

/// Map a neutralModel row to a SafePatternEntry.
///
/// neutralModel row format (Java/C#):
///   ["package", "class", "method", "signature", "category", "provenance"]
fn map_neutral_row(row: &[serde_yaml::Value], package: &str) -> Option<SafePatternEntry> {
    if row.len() < 3 {
        return None;
    }

    let class = value_to_string(&row[1]);
    let method = if row.len() >= 4 {
        value_to_string(&row[3])
    } else {
        value_to_string(&row[2])
    };

    // Skip if class looks like a boolean (subtypes field) — shorter format
    let (class, method) = if class == "true" || class == "false" {
        // Short format: [package, subtypes, name, ...]
        (String::new(), value_to_string(&row[2]))
    } else {
        (class, method)
    };

    if method.is_empty() {
        return None;
    }

    let name = if class.is_empty() {
        format!("{package}.{method}")
    } else {
        format!("{package}.{class}.{method}")
    };

    let pattern = if class.is_empty() {
        format!("{method}()")
    } else {
        format!("{class}.{method}()")
    };

    Some(SafePatternEntry {
        name,
        pattern,
        reason: "CodeQL neutral: does not propagate taint".to_string(),
    })
}

/// Map a barrierModel row to a SafePatternEntry.
///
/// barrierModel row format:
///   ["package", "class", is_instance, "method", "signature", "ext", "output", "vuln_kind", "provenance"]
fn map_barrier_row(row: &[serde_yaml::Value], package: &str) -> Option<SafePatternEntry> {
    if row.len() < 8 {
        return None;
    }

    let class = value_to_string(&row[1]);
    let method = value_to_string(&row[3]);
    let vuln_kind = value_to_string(&row[7]);

    if method.is_empty() {
        return None;
    }

    let name = if class.is_empty() {
        format!("{package}.{method}")
    } else {
        format!("{package}.{class}.{method}")
    };

    let pattern = if class.is_empty() {
        format!("{method}()")
    } else {
        format!("{class}.{method}()")
    };

    Some(SafePatternEntry {
        name,
        pattern,
        reason: format!("CodeQL barrier: blocks {vuln_kind} taint"),
    })
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn value_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Normalize a package name to a valid Rust identifier used as framework ID.
fn normalize_framework_id(package: &str) -> String {
    let base = package.split('.').next().unwrap_or(package).to_lowercase();

    // Map common package prefixes to framework names
    match base.as_str() {
        "flask" | "werkzeug" | "markupsafe" | "jinja2" => "flask".to_string(),
        "django" => "django".to_string(),
        "fastapi" | "starlette" => "fastapi".to_string(),
        "express" => "express".to_string(),
        "react" | "react-dom" => "react".to_string(),
        "next" => "nextjs".to_string(),
        "vue" => "vue".to_string(),
        "spring" | "springframework" | "org" => {
            if package.contains("spring") {
                "spring".to_string()
            } else if package.contains("jakarta") {
                "jakarta".to_string()
            } else {
                base.replace('-', "_")
            }
        }
        "jakarta" | "javax" => "jakarta".to_string(),
        "gin" => "gin".to_string(),
        "net" => {
            if package.contains("net/http") {
                "net_http".to_string()
            } else {
                base.replace('-', "_")
            }
        }
        "subprocess" | "os" | "shutil" | "tempfile" => "python_stdlib".to_string(),
        "crypto" | "io" | "database" | "html" => {
            if package.contains("database/sql") {
                "database_sql".to_string()
            } else if package.contains("html/template") {
                "go_html_template".to_string()
            } else {
                format!("go_{base}")
            }
        }
        "child_process" | "fs" | "path" | "http" | "https" | "url" | "querystring" | "buffer" => {
            "node_core".to_string()
        }
        "lodash" | "underscore" => "lodash".to_string(),
        "jquery" => "jquery".to_string(),
        "requests" | "urllib" | "urllib3" | "httpx" | "aiohttp" => "python_http".to_string(),
        "sqlalchemy" => "sqlalchemy".to_string(),
        _ => {
            let id = base.replace(['-', '/'], "_");
            if id.is_empty() || id.chars().all(|c| c == '_') {
                return String::new();
            }
            id
        }
    }
}

fn sanitize_name(access_path: &str, package: &str) -> String {
    let name = access_path
        .replace(package, "")
        .trim_start_matches('.')
        .to_string();
    if name.is_empty() {
        access_path.to_string()
    } else {
        format!("{package}.{name}")
    }
}

fn classify_source(access_path: &str) -> (SourceKindTag, String) {
    // If it contains "Member[" or a dot-access pattern, it's a member access
    if access_path.contains("Member[") || access_path.contains('.') {
        (SourceKindTag::MemberAccess, clean_access_path(access_path))
    } else {
        (SourceKindTag::FunctionCall, clean_access_path(access_path))
    }
}

fn classify_sink(access_path: &str) -> (SinkKindTag, String) {
    // If the last segment looks like a method call (contains a dot before the last part)
    let parts: Vec<&str> = access_path.rsplitn(2, '.').collect();
    if parts.len() == 2 {
        // e.g., "subprocess.call" -> FunctionCall("subprocess.call")
        (SinkKindTag::FunctionCall, clean_access_path(access_path))
    } else {
        (SinkKindTag::FunctionCall, clean_access_path(access_path))
    }
}

/// Clean CodeQL access path notation (e.g., "Member[request].Argument[0]") to
/// a plain dotted path suitable for pattern matching.
fn clean_access_path(path: &str) -> String {
    let mut result = path.to_string();
    // Remove CodeQL MaD notation like Member[], Argument[], ReturnValue, etc.
    let re_member = regex::Regex::new(r"Member\[([^\]]+)\]").unwrap();
    result = re_member.replace_all(&result, "$1").to_string();

    let re_arg = regex::Regex::new(r"\.?Argument\[\d+\]").unwrap();
    result = re_arg.replace_all(&result, "").to_string();

    let re_ret = regex::Regex::new(r"\.?ReturnValue").unwrap();
    result = re_ret.replace_all(&result, "").to_string();

    // Clean up double dots
    while result.contains("..") {
        result = result.replace("..", ".");
    }
    result = result.trim_matches('.').to_string();

    result
}

fn map_source_kind_to_label(kind: &str) -> String {
    match kind {
        "remote" => "user_input".to_string(),
        "local" => "local_input".to_string(),
        "database" => "database_input".to_string(),
        "file" => "file_input".to_string(),
        "environment" => "env_input".to_string(),
        _ => "user_input".to_string(),
    }
}

fn map_sink_kind_to_severity(kind: &str) -> (SeverityTag, &'static str) {
    match kind {
        "command-injection" | "code-injection" => (SeverityTag::Critical, "CWE-78"),
        "sql-injection" => (SeverityTag::Critical, "CWE-89"),
        "nosql-injection" => (SeverityTag::Critical, "CWE-943"),
        "path-injection" | "path-traversal" => (SeverityTag::Critical, "CWE-22"),
        "ldap-injection" => (SeverityTag::Critical, "CWE-90"),
        "xpath-injection" => (SeverityTag::Critical, "CWE-643"),
        "log-injection" => (SeverityTag::Warning, "CWE-117"),
        "url-redirection" | "redirect" => (SeverityTag::Error, "CWE-601"),
        "xss" | "html-injection" => (SeverityTag::Critical, "CWE-79"),
        "xxe" | "xml-injection" => (SeverityTag::Critical, "CWE-611"),
        "ssrf" | "request-forgery" => (SeverityTag::Critical, "CWE-918"),
        "ssti" | "template-injection" => (SeverityTag::Critical, "CWE-94"),
        "unsafe-deserialization" => (SeverityTag::Critical, "CWE-502"),
        "regex-injection" => (SeverityTag::Error, "CWE-1333"),
        _ => (SeverityTag::Error, "CWE-74"),
    }
}

fn is_sanitizer_like(access_path: &str, kind: &str) -> bool {
    let lower = access_path.to_lowercase();
    let kind_lower = kind.to_lowercase();

    // Check for encoding/escaping function names
    lower.contains("escape")
        || lower.contains("encode")
        || lower.contains("sanitize")
        || lower.contains("clean")
        || lower.contains("purify")
        || lower.contains("quote")
        || lower.contains("safe")
        || lower.contains("secure")
        || lower.contains("validate")
        || lower.contains("parameterize")
        // Check kind
        || kind_lower.contains("sanitize")
        || kind_lower.contains("taint-step")
}

fn infer_sanitization_type(access_path: &str, _kind: &str) -> String {
    let lower = access_path.to_lowercase();
    if lower.contains("html") || lower.contains("xss") || lower.contains("markup") {
        "html".to_string()
    } else if lower.contains("sql") || lower.contains("query") || lower.contains("parameterize") {
        "sql".to_string()
    } else if lower.contains("url") || lower.contains("uri") {
        "url".to_string()
    } else if lower.contains("path") || lower.contains("file") {
        "path".to_string()
    } else if lower.contains("shell") || lower.contains("command") || lower.contains("shlex") {
        "shell".to_string()
    } else {
        "general".to_string()
    }
}
