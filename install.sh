#!/bin/bash
# RMA Installer - One command installation
# Usage: curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
REPO="bumahkib7/rust-monorepo-analyzer"
BINARY_NAME="rma"
INSTALL_DIR="${RMA_INSTALL_DIR:-$HOME/.local/bin}"

print_banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║     🔍 RMA - Rust Monorepo Analyzer       ║"
    echo "  ║         One-Command Installer              ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

# Detect OS and Architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux*)
            OS="unknown-linux-gnu"
            ;;
        darwin*)
            OS="apple-darwin"
            ;;
        msys*|mingw*|cygwin*)
            OS="pc-windows-msvc"
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="aarch64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    PLATFORM="${ARCH}-${OS}"
    info "Detected platform: ${BOLD}$PLATFORM${NC}"
}

# Check for required tools
check_requirements() {
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        error "curl or wget is required but not installed"
    fi

    if ! command -v tar &> /dev/null; then
        error "tar is required but not installed"
    fi
}

# Get latest release version
get_latest_version() {
    info "Fetching latest version..."

    if command -v curl &> /dev/null; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi

    if [ -z "$VERSION" ]; then
        warn "Could not fetch latest version, using 'latest'"
        VERSION="latest"
    else
        info "Latest version: ${BOLD}$VERSION${NC}"
    fi
}

# Download and install
install_binary() {
    local DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/rma-${PLATFORM}.tar.gz"
    local TMP_DIR=$(mktemp -d)
    local ARCHIVE="${TMP_DIR}/rma.tar.gz"

    info "Downloading from: $DOWNLOAD_URL"

    # Download
    if command -v curl &> /dev/null; then
        curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE" || {
            # If pre-built binary not available, fall back to cargo install
            warn "Pre-built binary not available for $PLATFORM"
            install_from_source
            return
        }
    else
        wget -q "$DOWNLOAD_URL" -O "$ARCHIVE" || {
            warn "Pre-built binary not available for $PLATFORM"
            install_from_source
            return
        }
    fi

    # Extract
    info "Extracting..."
    tar -xzf "$ARCHIVE" -C "$TMP_DIR"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    # Install binary
    mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    # Cleanup
    rm -rf "$TMP_DIR"

    success "Installed ${BINARY_NAME} to ${INSTALL_DIR}"
}

# Fallback: Install from source using cargo
install_from_source() {
    info "Installing from source using cargo..."

    if ! command -v cargo &> /dev/null; then
        error "Cargo is required for source installation. Install Rust: https://rustup.rs"
    fi

    cargo install --git "https://github.com/${REPO}" rma-cli

    success "Installed ${BINARY_NAME} via cargo"
}

# Add to PATH if needed
setup_path() {
    local SHELL_RC=""
    local PATH_LINE="export PATH=\"\$PATH:${INSTALL_DIR}\""

    # Check if already in PATH
    if echo "$PATH" | grep -q "$INSTALL_DIR"; then
        return
    fi

    # Detect shell config file
    if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ] || [ "$SHELL" = "/bin/bash" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            SHELL_RC="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            SHELL_RC="$HOME/.bash_profile"
        fi
    elif [ -f "$HOME/.profile" ]; then
        SHELL_RC="$HOME/.profile"
    fi

    if [ -n "$SHELL_RC" ]; then
        if ! grep -q "$INSTALL_DIR" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# RMA - Rust Monorepo Analyzer" >> "$SHELL_RC"
            echo "$PATH_LINE" >> "$SHELL_RC"
            success "Added ${INSTALL_DIR} to PATH in ${SHELL_RC}"
            warn "Run 'source ${SHELL_RC}' or restart your terminal"
        fi
    else
        warn "Could not detect shell config. Add this to your shell profile:"
        echo "  $PATH_LINE"
    fi
}

# Verify installation
verify_installation() {
    if [ -x "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        local VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
        success "RMA installed successfully! Version: $VERSION"
    else
        error "Installation verification failed"
    fi
}

# Print usage
print_usage() {
    echo ""
    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo -e "  ${CYAN}rma scan .${NC}              # Scan current directory"
    echo -e "  ${CYAN}rma scan ./src --ai${NC}     # Scan with AI analysis"
    echo -e "  ${CYAN}rma watch .${NC}             # Watch for changes"
    echo -e "  ${CYAN}rma --help${NC}              # Show all commands"
    echo ""
    echo -e "${BOLD}Documentation:${NC} https://github.com/${REPO}"
    echo ""
}

# Main
main() {
    print_banner
    check_requirements
    detect_platform
    get_latest_version
    install_binary
    setup_path
    verify_installation
    print_usage
}

main "$@"
