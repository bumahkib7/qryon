//! Java import resolution
//!
//! Handles:
//! - import package.Class;
//! - import package.*;
//! - import static package.Class.member;
//! - Package declarations
//! - Class/Interface/Enum exports

use super::{
    Export, ExportKind, FileImports, ImportKind, ResolvedImport, UnresolvedImport, UnresolvedReason,
};
use std::path::{Path, PathBuf};

/// Extract imports and exports from a Java file
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
        "import_declaration" => {
            extract_import_declaration(node, source, file_path, project_root, file_imports);
        }
        "class_declaration" => {
            extract_class_export(node, source, file_imports);
        }
        "interface_declaration" => {
            extract_interface_export(node, source, file_imports);
        }
        "enum_declaration" => {
            extract_enum_export(node, source, file_imports);
        }
        "record_declaration" => {
            extract_record_export(node, source, file_imports);
        }
        _ => {}
    }

    // Recurse into children (but not into class bodies for imports)
    if !matches!(node.kind(), "class_body" | "interface_body" | "enum_body") {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_imports_recursive(child, source, file_path, project_root, file_imports);
        }
    }
}

/// Extract an import declaration
fn extract_import_declaration(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;
    let text = node.utf8_text(source).unwrap_or("");

    // Check if static import
    let is_static = text.contains("static ");

    // Find the scoped identifier
    let mut cursor = node.walk();
    let mut import_path = String::new();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "scoped_identifier" => {
                if let Ok(path) = child.utf8_text(source) {
                    import_path = path.to_string();
                }
            }
            "asterisk" => {
                // Wildcard import
                if !import_path.is_empty() {
                    import_path.push_str(".*");
                }
            }
            _ => {}
        }
    }

    if import_path.is_empty() {
        return;
    }

    // Get the local name (last part of path)
    let local_name = if import_path.ends_with(".*") {
        "*".to_string()
    } else {
        import_path
            .rsplit('.')
            .next()
            .unwrap_or(&import_path)
            .to_string()
    };

    let kind = if is_static {
        ImportKind::Named // Static imports are like named imports
    } else if import_path.ends_with(".*") {
        ImportKind::Namespace
    } else {
        ImportKind::JavaImport
    };

    // Try to resolve the import
    let resolved = resolve_java_import(&import_path, file_path, project_root);

    if let Some(source_file) = resolved {
        file_imports.imports.push(ResolvedImport {
            local_name,
            source_file,
            exported_name: import_path.clone(),
            kind,
            specifier: import_path,
            line,
        });
    } else {
        let reason = if is_java_stdlib(&import_path) || is_external_java_package(&import_path) {
            UnresolvedReason::ExternalPackage
        } else {
            UnresolvedReason::FileNotFound
        };

        file_imports.unresolved.push(UnresolvedImport {
            specifier: import_path,
            local_name,
            line,
            reason,
        });
    }
}

/// Try to resolve a Java import to a file path
fn resolve_java_import(
    import_path: &str,
    _file_path: &Path,
    project_root: &Path,
) -> Option<PathBuf> {
    // Remove wildcard if present
    let class_path = import_path.trim_end_matches(".*");

    // Convert package.Class to package/Class.java
    let file_path = class_path.replace('.', "/") + ".java";

    // Common source directories to check
    let source_dirs = ["src/main/java", "src", "app/src/main/java", ""];

    for src_dir in source_dirs {
        let full_path = if src_dir.is_empty() {
            project_root.join(&file_path)
        } else {
            project_root.join(src_dir).join(&file_path)
        };

        if full_path.exists() {
            return Some(full_path.canonicalize().unwrap_or(full_path));
        }
    }

    None
}

/// Check if an import is from Java standard library
fn is_java_stdlib(import_path: &str) -> bool {
    let stdlib_prefixes = ["java.", "javax.", "sun.", "com.sun.", "jdk."];

    stdlib_prefixes
        .iter()
        .any(|prefix| import_path.starts_with(prefix))
}

/// Check if an import is from an external package
fn is_external_java_package(import_path: &str) -> bool {
    let external_prefixes = [
        "org.apache.",
        "org.springframework.",
        "com.google.",
        "org.junit.",
        "org.mockito.",
        "org.slf4j.",
        "org.hibernate.",
        "io.netty.",
        "com.fasterxml.",
        "org.json.",
        "okhttp3.",
        "retrofit2.",
    ];

    external_prefixes
        .iter()
        .any(|prefix| import_path.starts_with(prefix))
}

/// Check if a class has public visibility
fn is_public(node: tree_sitter::Node, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers"
            && let Ok(text) = child.utf8_text(source)
        {
            return text.contains("public");
        }
    }
    false
}

/// Extract class export
fn extract_class_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    // Only export public classes (or any top-level class for now)
    if !is_public(node, source) && !is_top_level(node) {
        return;
    }

    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: is_default_class(node),
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Class,
        });
    }
}

/// Extract interface export
fn extract_interface_export(
    node: tree_sitter::Node,
    source: &[u8],
    file_imports: &mut FileImports,
) {
    if !is_public(node, source) && !is_top_level(node) {
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
    if !is_public(node, source) && !is_top_level(node) {
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

/// Extract record export (Java 14+)
fn extract_record_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if !is_public(node, source) && !is_top_level(node) {
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

/// Check if a node is at the top level (not nested in another class)
fn is_top_level(node: tree_sitter::Node) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        if matches!(
            p.kind(),
            "class_declaration" | "interface_declaration" | "enum_declaration"
        ) {
            return false;
        }
        if p.kind() == "program" {
            return true;
        }
        parent = p.parent();
    }
    true
}

/// Check if a class is the "default" export (matches filename)
fn is_default_class(node: tree_sitter::Node) -> bool {
    // In Java, the public class name should match the filename
    // We can't easily check this without the filename, so return false
    // The caller can check this if needed
    node.parent().is_some_and(|p| p.kind() == "program")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_java(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_simple_import() {
        let code = r#"
package com.example;

import java.util.List;
"#;
        let tree = parse_java(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/main/java/com/example/Main.java"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].specifier, "java.util.List");
        assert_eq!(imports.unresolved[0].local_name, "List");
    }

    #[test]
    fn test_wildcard_import() {
        let code = r#"
import java.util.*;
"#;
        let tree = parse_java(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/Main.java"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert!(imports.unresolved[0].specifier.ends_with(".*"));
        assert_eq!(imports.unresolved[0].local_name, "*");
    }

    #[test]
    fn test_public_class_export() {
        let code = r#"
package com.example;

public class MyClass {
    public void method() {}
}

class PackagePrivate {}
"#;
        let tree = parse_java(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/MyClass.java"),
            Path::new("/project"),
        );

        // Both classes are exported (top-level)
        assert_eq!(imports.exports.len(), 2);
        let names: Vec<_> = imports.exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"MyClass"));
        assert!(names.contains(&"PackagePrivate"));
    }

    #[test]
    fn test_interface_export() {
        let code = r#"
public interface MyInterface {
    void method();
}
"#;
        let tree = parse_java(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/MyInterface.java"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "MyInterface");
        assert!(matches!(imports.exports[0].kind, ExportKind::Type));
    }

    #[test]
    fn test_is_java_stdlib() {
        assert!(is_java_stdlib("java.util.List"));
        assert!(is_java_stdlib("java.io.File"));
        assert!(is_java_stdlib("javax.swing.JFrame"));
        assert!(!is_java_stdlib("com.example.MyClass"));
        assert!(!is_java_stdlib("org.apache.commons.lang3.StringUtils"));
    }
}
