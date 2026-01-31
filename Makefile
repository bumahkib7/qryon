# RMA - Rust Monorepo Analyzer
# Makefile for common development tasks

.PHONY: all build release install test check lint fmt clean help

# Default target
all: build

# Build debug binary
build:
	@echo "🔨 Building RMA (debug)..."
	cargo build -p rma-cli

# Build release binary
release:
	@echo "🚀 Building RMA (release)..."
	cargo build -p rma-cli --release

# Install locally
install: release
	@echo "📦 Installing RMA..."
	cargo install --path crates/cli

# Install with cargo
install-cargo:
	@echo "📦 Installing RMA via cargo..."
	cargo install --git https://github.com/bumahkib7/rust-monorepo-analyzer rma-cli

# Run tests
test:
	@echo "🧪 Running tests..."
	cargo test --workspace

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	cargo tarpaulin --workspace --out Html

# Check compilation
check:
	@echo "✓ Checking compilation..."
	cargo check --workspace

# Run clippy
lint:
	@echo "🔍 Running clippy..."
	cargo clippy --workspace --all-features -- -D warnings

# Format code
fmt:
	@echo "🎨 Formatting code..."
	cargo fmt --all

# Format check
fmt-check:
	@echo "🎨 Checking format..."
	cargo fmt --all -- --check

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	cargo clean
	rm -rf .rma

# Run the CLI
run:
	@echo "▶ Running RMA..."
	cargo run -p rma-cli -- $(ARGS)

# Run benchmarks
bench:
	@echo "⏱ Running benchmarks..."
	cargo bench

# Build documentation
docs:
	@echo "📚 Building documentation..."
	cargo doc --workspace --no-deps --open

# Full CI check (what CI runs)
ci: fmt-check lint test
	@echo "✅ All CI checks passed!"

# Quick scan of the project itself
self-scan: build
	@echo "🔍 Scanning RMA codebase..."
	./target/debug/rma scan ./crates --languages rust

# Watch mode on the project
self-watch: build
	@echo "👁 Watching RMA codebase..."
	./target/debug/rma watch ./crates

# Generate shell completions
completions: release
	@mkdir -p completions
	./target/release/rma completions bash > completions/rma.bash
	./target/release/rma completions zsh > completions/_rma
	./target/release/rma completions fish > completions/rma.fish
	@echo "✓ Generated shell completions in ./completions/"

# Help
help:
	@echo "RMA - Rust Monorepo Analyzer"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build debug binary"
	@echo "  release        Build release binary"
	@echo "  install        Install locally (release build)"
	@echo "  install-cargo  Install via cargo from GitHub"
	@echo "  test           Run tests"
	@echo "  test-coverage  Run tests with coverage report"
	@echo "  check          Check compilation"
	@echo "  lint           Run clippy"
	@echo "  fmt            Format code"
	@echo "  fmt-check      Check formatting"
	@echo "  clean          Clean build artifacts"
	@echo "  run ARGS=...   Run CLI with arguments"
	@echo "  bench          Run benchmarks"
	@echo "  docs           Build and open documentation"
	@echo "  ci             Run full CI checks"
	@echo "  self-scan      Scan RMA's own codebase"
	@echo "  self-watch     Watch RMA's codebase"
	@echo "  completions    Generate shell completions"
	@echo "  help           Show this help"
