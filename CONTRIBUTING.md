# Contributing to RMA

Thank you for your interest in contributing to RMA (Rust Monorepo Analyzer)!

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/bumahkib7/rust-monorepo-analyzer.git
cd rust-monorepo-analyzer

# Build all crates
make build

# Run tests
make test

# Run the CLI
cargo run -p rma-cli -- scan .
```

## Development Workflow

### Branch Strategy

- `master` - stable release branch
- `develop` - development branch
- `feature/*` - feature branches
- `fix/*` - bug fix branches

### Making Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `make test`
5. Run lints: `make lint`
6. Format code: `make fmt`
7. Commit with a descriptive message
8. Push and create a Pull Request

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(analyzer): add SQL injection detection for Go
fix(parser): handle UTF-8 BOM in source files
docs(readme): update installation instructions
```

## Project Structure

```
crates/
├── common/    # Shared types (Language, Severity, Finding)
├── parser/    # Tree-sitter AST parsing
├── analyzer/  # Security rules and metrics
├── indexer/   # Tantivy full-text search
├── cli/       # Command-line interface
├── daemon/    # HTTP API server
├── plugins/   # WASM plugin system
├── lsp/       # Language Server Protocol
└── ai/        # AI-powered analysis
```

## Adding a New Security Rule

1. Add the rule in `crates/analyzer/src/rules.rs`:

```rust
pub fn check_my_rule(node: Node, source: &str, language: Language) -> Option<Finding> {
    if node.kind() == "dangerous_pattern" {
        return Some(Finding {
            rule_id: "lang/my-rule".to_string(),
            severity: Severity::Warning,
            message: "Dangerous pattern detected".to_string(),
            // ...
        });
    }
    None
}
```

2. Register the rule in the analyzer:

```rust
// In crates/analyzer/src/lib.rs
rules.push(check_my_rule);
```

3. Add tests in `crates/analyzer/tests/`.

4. Document the rule in `README.md`.

## Adding a New Language

1. Add the tree-sitter grammar to `Cargo.toml`:

```toml
tree-sitter-newlang = "0.23"
```

2. Update `Language` enum in `crates/common/src/lib.rs`:

```rust
pub enum Language {
    // ...
    NewLang,
}
```

3. Add parser support in `crates/parser/src/lib.rs`:

```rust
Language::NewLang => tree_sitter_newlang::LANGUAGE.into(),
```

4. Add language-specific rules in `crates/analyzer/`.

5. Update file extension mapping.

## Testing

### Unit Tests

```bash
cargo test --workspace
```

### Integration Tests

```bash
cargo test --workspace -- --ignored
```

### Benchmarks

```bash
cargo bench
```

### Coverage

```bash
make test-coverage
```

## Code Style

- Follow Rust standard style (rustfmt)
- Use `clippy` for linting
- Add doc comments for public APIs
- Prefer descriptive variable names

## Pull Request Checklist

- [ ] Tests pass (`make test`)
- [ ] Lints pass (`make lint`)
- [ ] Code is formatted (`make fmt`)
- [ ] Documentation updated if needed
- [ ] Changelog entry added (for features/fixes)
- [ ] Commit messages follow convention

## Reporting Issues

When reporting bugs, please include:

1. RMA version (`rma --version`)
2. Operating system and version
3. Steps to reproduce
4. Expected vs actual behavior
5. Error messages or logs

## Security Issues

For security vulnerabilities, please email security@example.com instead of creating a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT/Apache-2.0 dual license.

## Questions?

- Open a GitHub Discussion
- Check existing issues and PRs

Thank you for contributing!
