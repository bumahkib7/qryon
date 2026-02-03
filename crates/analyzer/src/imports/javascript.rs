//! JavaScript/TypeScript import resolution
//!
//! Handles:
//! - ES6 imports: import foo from './bar', import { foo } from './bar', import * as foo from './bar'
//! - CommonJS: const foo = require('./bar'), const { foo } = require('./bar')
//! - Exports: export default, export { foo }, module.exports

use super::{
    Export, ExportKind, FileImports, ImportKind, ResolvedImport, UnresolvedImport,
    UnresolvedReason, is_external_package, resolve_relative_import,
};
use std::path::{Path, PathBuf};

/// JavaScript/TypeScript file extensions to try when resolving imports
const JS_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs"];

/// Extract imports and exports from a JavaScript/TypeScript file
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
        "import_statement" => {
            extract_es6_import(node, source, file_path, project_root, file_imports);
        }
        "export_statement" => {
            extract_export(node, source, file_imports);
        }
        "call_expression" => {
            // Check for require() calls
            if let Some(func) = node.child_by_field_name("function")
                && func.kind() == "identifier"
                && let Ok(name) = func.utf8_text(source)
                && name == "require"
            {
                extract_require(node, source, file_path, project_root, file_imports);
            }
        }
        "assignment_expression" | "expression_statement" => {
            // Check for module.exports = ...
            extract_module_exports(node, source, file_imports);
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_imports_recursive(child, source, file_path, project_root, file_imports);
    }
}

/// Extract an ES6 import statement
fn extract_es6_import(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;

    // Get the import source (string after 'from')
    let source_node = node.child_by_field_name("source");
    let specifier = match source_node {
        Some(s) => {
            let text = s.utf8_text(source).unwrap_or("");
            // Remove quotes
            text.trim_matches(|c| c == '"' || c == '\'' || c == '`')
                .to_string()
        }
        None => return,
    };

    // Check if this is an external package
    if is_external_package(&specifier) {
        // Still extract the import info but mark as unresolved
        extract_import_names(node, source, &specifier, line, file_imports, None);
        return;
    }

    // Try to resolve the import
    let resolved_path = resolve_relative_import(&specifier, file_path, project_root, JS_EXTENSIONS);

    extract_import_names(node, source, &specifier, line, file_imports, resolved_path);
}

/// Extract import names from an import statement
fn extract_import_names(
    node: tree_sitter::Node,
    source: &[u8],
    specifier: &str,
    line: usize,
    file_imports: &mut FileImports,
    resolved_path: Option<PathBuf>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            // import foo from './bar' (default import)
            "import_clause" => {
                let mut clause_cursor = child.walk();
                for clause_child in child.children(&mut clause_cursor) {
                    match clause_child.kind() {
                        "identifier" => {
                            // Default import
                            if let Ok(name) = clause_child.utf8_text(source) {
                                add_import_or_unresolved(
                                    file_imports,
                                    name,
                                    "default",
                                    specifier,
                                    line,
                                    ImportKind::Default,
                                    &resolved_path,
                                );
                            }
                        }
                        "named_imports" => {
                            // import { foo, bar as baz } from './bar'
                            extract_named_imports(
                                clause_child,
                                source,
                                specifier,
                                line,
                                file_imports,
                                &resolved_path,
                            );
                        }
                        "namespace_import" => {
                            // import * as foo from './bar'
                            if let Some(name_node) = clause_child.child_by_field_name("name")
                                && let Ok(name) = name_node.utf8_text(source)
                            {
                                add_import_or_unresolved(
                                    file_imports,
                                    name,
                                    "*",
                                    specifier,
                                    line,
                                    ImportKind::Namespace,
                                    &resolved_path,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Extract named imports like { foo, bar as baz }
fn extract_named_imports(
    node: tree_sitter::Node,
    source: &[u8],
    specifier: &str,
    line: usize,
    file_imports: &mut FileImports,
    resolved_path: &Option<PathBuf>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "import_specifier" {
            let name_node = child.child_by_field_name("name");
            let alias_node = child.child_by_field_name("alias");

            if let Some(name) = name_node
                && let Ok(exported_name) = name.utf8_text(source)
            {
                let local_name = if let Some(alias) = alias_node {
                    alias.utf8_text(source).unwrap_or(exported_name)
                } else {
                    exported_name
                };

                add_import_or_unresolved(
                    file_imports,
                    local_name,
                    exported_name,
                    specifier,
                    line,
                    ImportKind::Named,
                    resolved_path,
                );
            }
        }
    }
}

/// Add an import to resolved or unresolved list
fn add_import_or_unresolved(
    file_imports: &mut FileImports,
    local_name: &str,
    exported_name: &str,
    specifier: &str,
    line: usize,
    kind: ImportKind,
    resolved_path: &Option<PathBuf>,
) {
    if let Some(path) = resolved_path {
        file_imports.imports.push(ResolvedImport {
            local_name: local_name.to_string(),
            source_file: path.clone(),
            exported_name: exported_name.to_string(),
            kind,
            specifier: specifier.to_string(),
            line,
        });
    } else {
        let reason = if is_external_package(specifier) {
            UnresolvedReason::ExternalPackage
        } else {
            UnresolvedReason::FileNotFound
        };

        file_imports.unresolved.push(UnresolvedImport {
            specifier: specifier.to_string(),
            local_name: local_name.to_string(),
            line,
            reason,
        });
    }
}

/// Extract require() calls
fn extract_require(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;

    // Get the argument to require()
    let args = node.child_by_field_name("arguments");
    let specifier = match args {
        Some(args_node) => {
            let mut cursor = args_node.walk();
            args_node
                .children(&mut cursor)
                .find(|c| c.kind() == "string")
                .and_then(|s| s.utf8_text(source).ok())
                .map(|t| t.trim_matches(|c| c == '"' || c == '\'').to_string())
        }
        None => None,
    };

    let specifier = match specifier {
        Some(s) => s,
        None => return,
    };

    // Try to get the variable name from parent
    let parent = node.parent();
    let local_name = parent
        .and_then(|p| {
            match p.kind() {
                "variable_declarator" => {
                    // const foo = require('./bar')
                    p.child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source).ok())
                        .map(|s| s.to_string())
                }
                "assignment_expression" => {
                    // foo = require('./bar')
                    p.child_by_field_name("left")
                        .and_then(|n| n.utf8_text(source).ok())
                        .map(|s| s.to_string())
                }
                _ => None,
            }
        })
        .unwrap_or_else(|| specifier.clone());

    // Check if external
    if is_external_package(&specifier) {
        file_imports.unresolved.push(UnresolvedImport {
            specifier,
            local_name,
            line,
            reason: UnresolvedReason::ExternalPackage,
        });
        return;
    }

    // Try to resolve
    let resolved = resolve_relative_import(&specifier, file_path, project_root, JS_EXTENSIONS);

    if let Some(path) = resolved {
        file_imports.imports.push(ResolvedImport {
            local_name,
            source_file: path,
            exported_name: "default".to_string(),
            kind: ImportKind::CommonJS,
            specifier,
            line,
        });
    } else {
        file_imports.unresolved.push(UnresolvedImport {
            specifier,
            local_name,
            line,
            reason: UnresolvedReason::FileNotFound,
        });
    }
}

/// Extract export statements
fn extract_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    let line = node.start_position().row + 1;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declaration" | "class_declaration" => {
                // export function foo() {} or export class Foo {}
                if let Some(name_node) = child.child_by_field_name("name")
                    && let Ok(name) = name_node.utf8_text(source)
                {
                    let kind = if child.kind() == "function_declaration" {
                        ExportKind::Function
                    } else {
                        ExportKind::Class
                    };
                    file_imports.exports.push(Export {
                        name: name.to_string(),
                        is_default: false,
                        node_id: child.id(),
                        line,
                        kind,
                    });
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                // export const foo = ...
                extract_variable_exports(child, source, line, file_imports);
            }
            "export_clause" => {
                // export { foo, bar }
                let mut clause_cursor = child.walk();
                for export_spec in child.children(&mut clause_cursor) {
                    if export_spec.kind() == "export_specifier"
                        && let Some(name_node) = export_spec.child_by_field_name("name")
                        && let Ok(name) = name_node.utf8_text(source)
                    {
                        let alias = export_spec
                            .child_by_field_name("alias")
                            .and_then(|a| a.utf8_text(source).ok());
                        let is_default = alias == Some("default");
                        file_imports.exports.push(Export {
                            name: alias.unwrap_or(name).to_string(),
                            is_default,
                            node_id: export_spec.id(),
                            line,
                            kind: ExportKind::Unknown,
                        });
                    }
                }
            }
            _ => {
                // Check for default export
                let node_text = node.utf8_text(source).unwrap_or("");
                if node_text.contains("default") {
                    // export default ...
                    let export_name = if let Some(name_child) = child.child_by_field_name("name") {
                        name_child
                            .utf8_text(source)
                            .unwrap_or("default")
                            .to_string()
                    } else {
                        "default".to_string()
                    };
                    file_imports.exports.push(Export {
                        name: export_name,
                        is_default: true,
                        node_id: node.id(),
                        line,
                        kind: ExportKind::Unknown,
                    });
                }
            }
        }
    }
}

/// Extract variable exports from variable declaration
fn extract_variable_exports(
    node: tree_sitter::Node,
    source: &[u8],
    line: usize,
    file_imports: &mut FileImports,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declarator"
            && let Some(name_node) = child.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(source)
        {
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: child.id(),
                line,
                kind: ExportKind::Variable,
            });
        }
    }
}

/// Extract module.exports assignments
fn extract_module_exports(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    let text = node.utf8_text(source).unwrap_or("");

    // module.exports = foo
    if text.starts_with("module.exports") || text.contains("module.exports =") {
        let line = node.start_position().row + 1;
        file_imports.exports.push(Export {
            name: "default".to_string(),
            is_default: true,
            node_id: node.id(),
            line,
            kind: ExportKind::Unknown,
        });
    }

    // module.exports.foo = ...
    if text.contains("module.exports.") {
        let line = node.start_position().row + 1;
        // Try to extract the property name
        if let Some(pos) = text.find("module.exports.") {
            let after = &text[pos + "module.exports.".len()..];
            if let Some(end) = after.find(|c: char| !c.is_alphanumeric() && c != '_') {
                let name = &after[..end];
                if !name.is_empty() {
                    file_imports.exports.push(Export {
                        name: name.to_string(),
                        is_default: false,
                        node_id: node.id(),
                        line,
                        kind: ExportKind::Unknown,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_es6_default_import() {
        let code = r#"import foo from './bar';"#;
        let tree = parse_js(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/handler.js"),
            Path::new("/project"),
        );

        // Won't resolve because file doesn't exist, but should be in unresolved
        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].local_name, "foo");
    }

    #[test]
    fn test_external_package() {
        let code = r#"import express from 'express';"#;
        let tree = parse_js(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/app.js"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert!(matches!(
            imports.unresolved[0].reason,
            UnresolvedReason::ExternalPackage
        ));
    }

    #[test]
    fn test_named_exports() {
        let code = r#"
export function sanitize(input) { return input; }
export const VERSION = '1.0.0';
export class Helper {}
"#;
        let tree = parse_js(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/utils.js"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 3);
        let names: Vec<_> = imports.exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"sanitize"));
        assert!(names.contains(&"VERSION"));
        assert!(names.contains(&"Helper"));
    }
}
