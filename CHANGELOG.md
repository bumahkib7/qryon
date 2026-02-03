# Changelog

All notable changes to RMA (Rust Monorepo Analyzer) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] - 2026-02-03

### Added

#### Enhanced Interactive TUI (`rma scan --interactive`)
- **Call Graph Statistics Panel**: Real-time overview showing total functions, edges, sources, sinks, sanitizers, and unresolved calls
- **Security Classification Badges**: Visual indicators for taint sources `[HTTP Handler]`, sinks `[SQL Injection]`, sanitizers `[SAN]`, and exported functions `⬆`
- **Source→Sink Flow Highlighting**: Dangerous flows marked with `⚠` icon and red highlighting
- **Source→Sink Filter** (press `x`): Toggle to show only potentially dangerous source-to-sink edges
- **Edge Detail Panel** (press `Enter`): Comprehensive view with:
  - Caller/callee function info with file paths and line numbers
  - Source classification type (HTTP Handler, File Input, etc.)
  - Sink vulnerability types (SQL Injection, XSS, Command Injection, etc.)
  - Sanitizer information if present
  - Classification confidence percentage
  - Security warning box for source→sink flows with remediation guidance
- **Enhanced Finding Detail View**: Full metadata display including rule ID, language, severity (color-coded), confidence, category, fingerprint, fix suggestions, and complete code snippets

#### Analysis Caching
- **Incremental Scan Cache**: Content-hash based caching for faster re-scans
- **`--no-cache` flag**: Force fresh analysis bypassing cache
- **Cache stored in `.rma/cache/analysis/`**: Per-file analysis results

#### Flows Command Enhancements
- **`rma flows --interactive`**: Launch TUI for browsing cross-file data flows
- **Test file filtering**: Flows from/to test files excluded by default

### Changed
- **Test Files Excluded by Default**: Tests are now excluded from scans by default across all languages
  - Use `--include-tests` to opt-in to scanning test files
  - Unified test pattern detection: 70+ patterns for JS/TS, Python, Go, Rust, Java, Kotlin
  - `--skip-tests` flag deprecated (tests excluded by default)
  - `security` command now uses same comprehensive patterns as `scan` command
- **Call Graph Test Filtering**: Call graph edges now exclude test files by default
- **TUI Status Bar**: Updated help text with available keyboard shortcuts

### Fixed
- **Zip crate dependency**: Updated from yanked 2.6 to stable 2.4
- **Clippy warnings**: Fixed trait object syntax and unused imports
- **Missing SystemTime import**: Fixed compilation error in OSV provider

## [0.15.1] - 2026-02-02

### Fixed
- **SARIF Validation**: Ensure line/column values are >= 1 (fixes GitHub upload errors)
- **Self-Scan False Positives**: Exclude rule definition patterns from self-scanning
- **Command Injection FP**: Suppress false positive for static npm command

### Changed
- **Faster CI Scans**: Download pre-built binary instead of building from source
- **Test Exclusion**: Add `--skip-tests-all` and `--exclude-rules` for cleaner self-scan


## [0.15.0] - 2026-02-02

### Added
- **SARIF Scanned Files Summary**: GitHub Code Scanning now displays scanned files and timing metrics
  - Added `artifacts` array with all analyzed files (path, language, LOC, complexity)
  - Added `invocations` array with execution timing and performance stats
  - Metrics include files/second throughput, total findings breakdown
- **Dedicated RMA Scan Workflow**: New `rma-scan.yml` workflow for GitHub Code Scanning integration
- **Open Source Community Files**:
  - `CODEOWNERS` for maintainer control
  - `CODE_OF_CONDUCT.md` (Contributor Covenant)
  - `SECURITY.md` vulnerability reporting policy
  - Issue templates (bug report, feature request)
  - Pull request template

### Fixed
- npm package URLs now point to correct repository
- GitHub Actions workflow permissions for code scanning
- README version references updated to current release

### Changed
- Branch protection configured for solo maintainer workflow
- GitHub Discussions enabled
- Repository topics added for discoverability

## [0.14.0] - 2026-02-02

### Added
- **Typestate Analysis Framework**: Track object state transitions through their lifecycle
  - `generic/file-typestate`: Detect use-after-close, unclosed files, double-open
  - `generic/lock-typestate`: Detect double-lock, double-unlock, unlock-without-lock
  - `generic/crypto-typestate`: Detect use of uninitialized ciphers
  - `generic/database-typestate`: Detect query-before-connect, query-after-close
  - `generic/iterator-typestate`: Detect iterator use after exhaustion
  - Language support: JavaScript, TypeScript, Python, Go, Java
  - Safe pattern recognition: `with`, `defer`, try-with-resources, RAII
  - FlowContext integration with `compute_typestate()` and `typestate_violations()` methods
  - `builtin_typestate_rules()` convenience function for all typestate rules
- **Interactive TUI**: Browse findings with keyboard navigation (`j/k`, `Enter` for details, `s` filter severity)
- **Smart Progress Display**: Real-time progress bar with ETA, file counts, and severity breakdown
- **Powerful Filtering**: `--severity`, `--rules`, `--exclude-rules`, `--files`, `--category`, `--search`
- **Output Limiting**: `--limit N` and `--group-by` (file/rule/severity) for large codebases

### Fixed
- **Database Typestate False Positives**: Rule now requires database imports in file before flagging
- **API Client Detection**: `cartApi.update()`, `userService.create()` no longer flagged as DB queries
- **Array.find() False Positives**: Removed generic `.find(` from DB patterns, use specific ORM patterns
- Compiler warnings eliminated across all crates

## [0.13.0] - 2026-02-02

### Added
- **Cross-File Analysis** (`--cross-file`): Import resolution and call graph construction
  - Tracks function calls across file boundaries
  - Detects taint flows through function parameters
  - Supports JS/TS, Python, Go, Rust, Java
- **20+ New Security Rules**:
  - Python: `unsafe-deserialization`, `ssti`, `unsafe-yaml`, `django-raw-sql`, `path-traversal`
  - Rust: `unwrap-on-user-input`, `missing-error-propagation`, `raw-sql-query`, `unwrap-in-handler`
  - Go: `defer-in-loop`, `goroutine-leak`, `missing-http-timeout`, `insecure-tls`
  - Java: `npe-prone-patterns`, `unclosed-resource`, `log-injection`, `spring-security-misconfig`
  - JS/TS: `prototype-pollution`, `redos`, `missing-security-headers`, `express-security`
- **Test File Exclusion Flags**:
  - `--skip-tests`: Skip test files (security rules still apply)
  - `--skip-tests-all`: Skip ALL findings in tests including security rules
  - 65+ test patterns: `*_test.go`, `*.test.ts`, `test_*.py`, `src/test/**`, `__tests__/**`, etc.
- **Auto-Fix Foundation**: `Fix` struct with replacement suggestions
- **Diff-Aware Analysis** (`--diff`): Only report findings on changed lines
- **HTML Reports**: Self-contained HTML report generation with embedded CSS/JS
- **GitHub Action**: `action.yml` for CI/CD integration with SARIF upload
- **LSP Enhancements**: Code actions, debounced diagnostics, concurrent access with DashMap

### Changed
- Security rules now properly registered in `register_default_rules()`
- `--mode pr` and `--mode ci` automatically skip test files
- Improved pattern matching for test directory detection

### Fixed
- Rules not triggering in CLI scan (missing rule registration)
- Clippy warnings for absurd comparisons in tests

## [0.12.0] - 2026-02-02

### Added
- Security audit command for comprehensive vulnerability assessment
- OSV provider for multi-language dependency scanning
- RustSec provider for Rust advisory database

## [0.7.0] - 2026-02-01

### Added
- **Native Oxc Integration**: JS/TS analysis using oxc crates directly (no external binaries)
  - `oxc/no-debugger` - Detect debugger statements
  - `oxc/no-eval` - Detect dangerous code execution
  - `oxc/no-alert` - Detect browser dialogs
  - `oxc/no-empty-pattern` - Detect empty destructuring
  - `oxc/no-with` - Detect deprecated with statements
- **Test File Exclusion**: Secret detection rules now skip test/fixture/example files
  - Skips `/test/`, `/tests/`, `/__tests__/`, `/fixtures/`, `/examples/` directories
  - Skips `*_test.go`, `*.test.js`, `*.spec.ts`, `conftest.py` files
- **Gosec Provider**: Go security analysis via gosec CLI integration
- **65 Total Rules**: Comprehensive coverage across all supported languages

### Changed
- **js/no-cond-assign**: Now only flags actual control flow statements (if/while/for/do)
  - Fixes false positives on ternaries in JSX template literals
  - Skips intentional patterns like `if ((x = getValue()) !== null)`
- **Go Security Scanner**: Single-pass AST traversal for maximum performance
  - Pre-compiled regex patterns with LazyLock
  - Quick content checks to skip unnecessary scanning

### Fixed
- False positive: Private keys in test files no longer flagged
- False positive: Ternary expressions in JSX className props
- Performance: Rule pre-filtering with HashMap for O(1) lookup
- Performance: HashSet for O(1) node kind lookups

## [0.6.0] - 2026-02-01

### Added
- WebSocket endpoint for real-time file watching (`/ws/watch`)
- Web dashboard for browser-based monitoring
- Initial scan on watch mode startup
- Interactive keyboard shortcuts in watch mode (q/c/r/s/e/p/?)

### Changed
- Categorized rules into high-confidence sinks vs review hints
- Reduced false positives in security rules

### Fixed
- Clippy warnings for Rust 2024 edition
- Normalized file paths in SARIF and GitHub output

## [0.5.0] - 2026-01-31

### Added
- Rich diagnostics with code snippets and suggestions
- GitHub Actions output format (`--format github`)

### Fixed
- Clippy warnings for Rust 2024 if-let chains

## [0.4.0] - 2026-01-31

### Added
- SARIF output improvements
- Better error messages

## [0.3.0] - 2026-01-31

### Added
- 8 new security rules for Rust, JS/TS, Python, Go, Java
- Automatic Homebrew tap update workflow
- Secret detection (API keys, AWS keys, GitHub tokens, private keys)
- Insecure crypto detection (MD5, SHA-1, DES, RC4, ECB)

## [0.2.0] - 2026-01-31

### Added
- Config versioning (`config_version = 1`)
- Stable fingerprints for baseline comparisons
- Rulesets (security, maintainability)
- Inline suppression (`// rma-ignore-next-line`)
- GitHub Actions integration
- Timer string rule for JS

### Changed
- Updated to Rust edition 2024

## [0.1.0] - 2026-01-31

### Added
- Initial release
- Multi-language support: Rust, JavaScript, TypeScript, Python, Go, Java
- Security and code quality rules
- SARIF output for GitHub Security tab
- Watch mode for real-time analysis
- HTTP API daemon
- Configuration via rma.toml
- Profiles: fast, balanced, strict
