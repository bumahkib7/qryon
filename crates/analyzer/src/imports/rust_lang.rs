//! Rust import resolution
//!
//! Handles:
//! - use crate::module::item;
//! - use super::item;
//! - use self::item;
//! - use module::{item1, item2};
//! - pub use re-exports
//! - mod declarations

use super::{
    Export, ExportKind, FileImports, ImportKind, ResolvedImport, UnresolvedImport, UnresolvedReason,
};
use std::path::{Path, PathBuf};

/// Extract imports and exports from a Rust file
pub fn extract_imports(
    tree: &tree_sitter::Tree,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
) -> FileImports {
    let mut file_imports = FileImports::default();
    let root = tree.root_node();

    extract_imports_recursive(root, source, file_path, project_root, &mut file_imports);

    file_imports
}

fn extract_imports_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    match node.kind() {
        "use_declaration" => {
            extract_use_declaration(node, source, file_path, project_root, file_imports);
        }
        "function_item" => {
            extract_function_export(node, source, file_imports);
        }
        "struct_item" => {
            extract_struct_export(node, source, file_imports);
        }
        "enum_item" => {
            extract_enum_export(node, source, file_imports);
        }
        "trait_item" => {
            extract_trait_export(node, source, file_imports);
        }
        "impl_item" => {
            // Skip impl blocks for now
        }
        "mod_item" => {
            extract_mod_declaration(node, source, file_imports);
        }
        "const_item" | "static_item" => {
            extract_const_export(node, source, file_imports);
        }
        "type_alias" => {
            extract_type_export(node, source, file_imports);
        }
        _ => {}
    }

    // Recurse into children (but not into function/impl bodies)
    if !matches!(node.kind(), "function_item" | "impl_item") {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_imports_recursive(child, source, file_path, project_root, file_imports);
        }
    }
}

/// Extract a use declaration
fn extract_use_declaration(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;
    let is_pub = has_visibility(node, source);

    // Find the use tree
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "use_tree" || child.kind() == "scoped_identifier" {
            extract_use_tree(
                child,
                source,
                file_path,
                project_root,
                file_imports,
                line,
                is_pub,
                "",
            );
        }
    }
}

/// Extract imports from a use tree (handles nesting like `use foo::{bar, baz}`)
#[allow(clippy::too_many_arguments)]
fn extract_use_tree(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
    line: usize,
    is_pub: bool,
    prefix: &str,
) {
    match node.kind() {
        "use_tree" => {
            // Check for use tree list: use foo::{bar, baz}
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "use_list" => {
                        // Get the path prefix
                        let path_node = node.child_by_field_name("path");
                        let path_prefix = path_node
                            .and_then(|p| p.utf8_text(source).ok())
                            .unwrap_or("");

                        let full_prefix = if prefix.is_empty() {
                            path_prefix.to_string()
                        } else {
                            format!("{}::{}", prefix, path_prefix)
                        };

                        // Process each item in the list
                        let mut list_cursor = child.walk();
                        for list_child in child.children(&mut list_cursor) {
                            if list_child.kind() == "use_tree" {
                                extract_use_tree(
                                    list_child,
                                    source,
                                    file_path,
                                    project_root,
                                    file_imports,
                                    line,
                                    is_pub,
                                    &full_prefix,
                                );
                            }
                        }
                    }
                    "scoped_identifier" | "identifier" => {
                        extract_use_tree(
                            child,
                            source,
                            file_path,
                            project_root,
                            file_imports,
                            line,
                            is_pub,
                            prefix,
                        );
                    }
                    _ => {}
                }
            }
        }
        "scoped_identifier" => {
            if let Ok(path) = node.utf8_text(source) {
                let full_path = if prefix.is_empty() {
                    path.to_string()
                } else {
                    format!("{}::{}", prefix, path)
                };
                add_rust_import(
                    file_imports,
                    &full_path,
                    line,
                    is_pub,
                    file_path,
                    project_root,
                );
            }
        }
        "identifier" => {
            if let Ok(name) = node.utf8_text(source) {
                let full_path = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{}::{}", prefix, name)
                };
                add_rust_import(
                    file_imports,
                    &full_path,
                    line,
                    is_pub,
                    file_path,
                    project_root,
                );
            }
        }
        _ => {}
    }
}

/// Add a Rust import
fn add_rust_import(
    file_imports: &mut FileImports,
    path: &str,
    line: usize,
    is_pub: bool,
    file_path: &Path,
    project_root: &Path,
) {
    let parts: Vec<&str> = path.split("::").collect();
    let local_name = parts.last().unwrap_or(&"").to_string();

    // Try to resolve the import
    let resolved = resolve_rust_import(path, file_path, project_root);

    if let Some(source_file) = resolved {
        file_imports.imports.push(ResolvedImport {
            local_name: local_name.clone(),
            source_file,
            exported_name: local_name,
            kind: ImportKind::Use,
            specifier: path.to_string(),
            line,
        });

        // If pub use, this is also an export (re-export)
        if is_pub {
            let name = parts.last().unwrap_or(&"");
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: 0,
                line,
                kind: ExportKind::Unknown,
            });
        }
    } else {
        let reason = if is_external_crate(path) {
            UnresolvedReason::ExternalPackage
        } else {
            UnresolvedReason::FileNotFound
        };

        file_imports.unresolved.push(UnresolvedImport {
            specifier: path.to_string(),
            local_name,
            line,
            reason,
        });
    }
}

/// Try to resolve a Rust import path to a file
fn resolve_rust_import(path: &str, file_path: &Path, project_root: &Path) -> Option<PathBuf> {
    let parts: Vec<&str> = path.split("::").collect();
    if parts.is_empty() {
        return None;
    }

    match parts[0] {
        "crate" => {
            // Resolve from crate root
            let crate_root = find_crate_root(file_path, project_root)?;
            resolve_from_root(&crate_root, &parts[1..])
        }
        "super" => {
            // Resolve from parent module
            let parent_dir = file_path.parent()?.parent()?;
            resolve_from_root(parent_dir, &parts[1..])
        }
        "self" => {
            // Resolve from current module
            let current_dir = file_path.parent()?;
            resolve_from_root(current_dir, &parts[1..])
        }
        _ => None, // External crate
    }
}

/// Find the crate root (directory containing Cargo.toml or src/lib.rs)
fn find_crate_root(file_path: &Path, project_root: &Path) -> Option<PathBuf> {
    let mut current = file_path.parent()?;

    while current.starts_with(project_root) {
        if current.join("Cargo.toml").exists() {
            // Found a crate, return its src directory
            let src = current.join("src");
            if src.exists() {
                return Some(src);
            }
            return Some(current.to_path_buf());
        }
        current = current.parent()?;
    }

    None
}

/// Resolve a path from a root directory
fn resolve_from_root(root: &Path, parts: &[&str]) -> Option<PathBuf> {
    if parts.is_empty() {
        return None;
    }

    let mut current = root.to_path_buf();

    // Navigate through module path
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // Last part - could be a file or a module
            // Try as file first
            let file_path = current.join(format!("{}.rs", part));
            if file_path.exists() {
                return Some(file_path.canonicalize().unwrap_or(file_path));
            }

            // Try as module directory
            let mod_path = current.join(part).join("mod.rs");
            if mod_path.exists() {
                return Some(mod_path.canonicalize().unwrap_or(mod_path));
            }
        } else {
            // Not the last part - must be a directory
            let dir_path = current.join(part);
            if dir_path.is_dir() {
                current = dir_path;
            } else {
                return None;
            }
        }
    }

    None
}

/// Check if a path refers to an external crate
fn is_external_crate(path: &str) -> bool {
    let first = path.split("::").next().unwrap_or("");
    !matches!(first, "crate" | "super" | "self")
}

/// Check if a node has pub visibility
fn has_visibility(node: tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier"
            && let Ok(text) = child.utf8_text(source)
        {
            return text.starts_with("pub");
        }
    }
    false
}

/// Extract function export
fn extract_function_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Function,
        });
    }
}

/// Extract struct export
fn extract_struct_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Type,
        });
    }
}

/// Extract enum export
fn extract_enum_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Type,
        });
    }
}

/// Extract trait export
fn extract_trait_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Type,
        });
    }
}

/// Extract const/static export
fn extract_const_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Variable,
        });
    }
}

/// Extract type alias export
fn extract_type_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Type,
        });
    }
}

/// Extract mod declaration
fn extract_mod_declaration(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !has_visibility(node, source) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Module,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rust(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_simple_use() {
        let code = "use std::collections::HashMap;";
        let tree = parse_rust(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/main.rs"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].specifier, "std::collections::HashMap");
    }

    #[test]
    fn test_pub_function() {
        let code = r#"
pub fn public_function() {}
fn private_function() {}
"#;
        let tree = parse_rust(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/lib.rs"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "public_function");
    }

    #[test]
    fn test_pub_struct() {
        let code = r#"
pub struct MyStruct {
    field: i32,
}
"#;
        let tree = parse_rust(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/lib.rs"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "MyStruct");
        assert!(matches!(imports.exports[0].kind, ExportKind::Type));
    }

    #[test]
    fn test_is_external_crate() {
        assert!(is_external_crate("std::io"));
        assert!(is_external_crate("serde::Serialize"));
        assert!(!is_external_crate("crate::module"));
        assert!(!is_external_crate("super::parent"));
        assert!(!is_external_crate("self::sibling"));
    }
}
