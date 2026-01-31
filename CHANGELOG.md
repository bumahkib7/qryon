# Changelog

All notable changes to RMA (Rust Monorepo Analyzer) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-31

### Added

- **8 New Security Rules**: Comprehensive vulnerability detection

  **Rust-specific:**
  - `rust/transmute-used` - Detects std::mem::transmute (type safety bypass)
  - `rust/raw-pointer-deref` - Detects raw pointer dereferences
  - `rust/command-injection` - Detects shell command execution patterns
  - `rust/sql-injection` - Detects SQL built with format!/string concatenation
  - `rust/unchecked-index` - Detects direct array indexing without bounds check
  - `rust/path-traversal` - Detects file paths with string interpolation

  **Generic (all languages):**
  - `generic/hardcoded-secret` - Detects API keys, AWS keys, GitHub tokens, private keys
  - `generic/insecure-crypto` - Detects MD5, SHA-1, DES, RC4, ECB mode usage

- **Automatic Homebrew Updates**: New workflow auto-updates tap on release
  - `.github/workflows/update-homebrew-tap.yml`
  - Computes SHA256 hashes automatically
  - Supports macOS + Linux (Intel + ARM)

### Changed

- Total security rules: 19 (was 11)
- Secret detection now redacts sensitive values in output
- Detection code patterns are automatically skipped to reduce false positives

## [0.2.0] - 2026-02-01

### Added

- **Config Versioning**: Added `config_version = 1` to rma.toml for future compatibility
  - Validates version on load, warns if missing, errors on unsupported versions
  
- **Stable Fingerprints**: New fingerprinting system for baseline comparisons
  - Survives line number changes, whitespace changes, path format differences
  - SHA-256 based with normalized inputs
  
- **Rulesets**: Named groups of rules for targeted scanning
  - Built-in: `security`, `maintainability`
  - Custom rulesets via `[rulesets]` in rma.toml
  - CLI: `--ruleset security`

- **Inline Suppression**: Suppress findings with comments
  - `// rma-ignore-next-line <rule_id> reason="..."`
  - `// rma-ignore <rule_id> reason="..."` (block-level)
  - Python: `# rma-ignore-next-line <rule_id> reason="..."`
  - Strict profile requires reason

- **Print Effective Config**: `rma config print-effective [--format json]`
  - Shows resolved configuration with precedence tracking
  - Displays where each value comes from (default, config-file, cli-flag)

- **Timer String Rule**: New `js/timer-string-eval` rule
  - Only flags setTimeout/setInterval with string arguments
  - Arrow functions, function references are NOT flagged
  - Default severity: Warning (not Critical)

- **GitHub Actions**: Composite action and reusable workflow
  - `.github/actions/rma-scan/action.yml`
  - `.github/workflows/rma-scan-reusable.yml`
  - Automatic SARIF upload to GitHub Security tab

- **New CLI Flags**:
  - `--ruleset <name>` - Use specific ruleset
  - `--include-suppressed` - Include suppressed findings
  - `--baseline-mode` - Only report new findings

### Changed

- **Edition 2024**: Updated Rust edition from 2021 to 2024
- **js/dynamic-code-execution**: Now only flags `eval()` and `Function()`, not timers

### Fixed

- Timer rule false positives for normal setTimeout/setInterval usage
- Config precedence now correctly applies CLI > config file > defaults

## [0.1.1] - 2025-12-15

### Added
- Initial GitHub release with pre-built binaries
- Docker images on GHCR
- Homebrew tap

## [0.1.0] - 2025-12-01

### Added
- Initial release
- Multi-language support: Rust, JavaScript, TypeScript, Python, Go, Java
- 10+ security and code quality rules
- SARIF output for GitHub Security tab
- Watch mode for real-time analysis
- HTTP API daemon
- WASM plugin system
- AI-powered analysis (optional)
- Configuration via rma.toml
- Profiles: fast, balanced, strict
- Baseline tracking for legacy code
