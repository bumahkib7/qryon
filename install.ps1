# RMA Installer for Windows
# Usage: iwr -useb https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.ps1 | iex

$ErrorActionPreference = 'Stop'

# Configuration
$repo = "bumahkib7/rust-monorepo-analyzer"
$binaryName = "rma.exe"
$installDir = "$env:USERPROFILE\.local\bin"

function Write-Color {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Show-Banner {
    Write-Color ""
    Write-Color "  ╔═══════════════════════════════════════════╗" "Cyan"
    Write-Color "  ║     🔍 RMA - Rust Monorepo Analyzer       ║" "Cyan"
    Write-Color "  ║         Windows Installer                  ║" "Cyan"
    Write-Color "  ╚═══════════════════════════════════════════╝" "Cyan"
    Write-Color ""
}

function Get-Platform {
    $arch = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "i686" }
    return "$arch-pc-windows-msvc"
}

function Get-LatestVersion {
    Write-Color "[INFO] Fetching latest version..." "Blue"
    try {
        $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
        $version = $releases.tag_name
        Write-Color "[INFO] Latest version: $version" "Blue"
        return $version
    } catch {
        Write-Color "[!] Could not fetch latest version, using 'latest'" "Yellow"
        return "latest"
    }
}

function Install-Binary {
    param([string]$Platform, [string]$Version)

    $downloadUrl = "https://github.com/$repo/releases/latest/download/rma-$Platform.zip"
    $tempDir = Join-Path $env:TEMP "rma-install"
    $zipFile = Join-Path $tempDir "rma.zip"

    # Create temp directory
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    Write-Color "[INFO] Downloading from: $downloadUrl" "Blue"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
    } catch {
        Write-Color "[!] Pre-built binary not available, installing via cargo..." "Yellow"
        Install-FromSource
        return
    }

    # Extract
    Write-Color "[INFO] Extracting..." "Blue"
    Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force

    # Create install directory
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir | Out-Null
    }

    # Copy binary
    $sourcePath = Join-Path $tempDir $binaryName
    $destPath = Join-Path $installDir $binaryName
    Copy-Item -Path $sourcePath -Destination $destPath -Force

    # Cleanup
    Remove-Item $tempDir -Recurse -Force

    Write-Color "[✓] Installed $binaryName to $installDir" "Green"
}

function Install-FromSource {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Color "[✗] Cargo is required. Install Rust from https://rustup.rs" "Red"
        exit 1
    }

    cargo install --git "https://github.com/$repo" rma-cli
    Write-Color "[✓] Installed via cargo" "Green"
}

function Add-ToPath {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")

    if ($currentPath -notlike "*$installDir*") {
        $newPath = "$currentPath;$installDir"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $env:Path = "$env:Path;$installDir"
        Write-Color "[✓] Added $installDir to PATH" "Green"
        Write-Color "[!] Restart your terminal for PATH changes to take effect" "Yellow"
    }
}

function Test-Installation {
    $rmaPath = Join-Path $installDir $binaryName
    if (Test-Path $rmaPath) {
        $version = & $rmaPath --version 2>$null
        Write-Color "[✓] RMA installed successfully! Version: $version" "Green"
    } else {
        Write-Color "[✗] Installation verification failed" "Red"
        exit 1
    }
}

function Show-Usage {
    Write-Color ""
    Write-Color "Quick Start:" "White"
    Write-Color ""
    Write-Color "  rma scan .              # Scan current directory" "Cyan"
    Write-Color "  rma scan ./src --ai     # Scan with AI analysis" "Cyan"
    Write-Color "  rma watch .             # Watch for changes" "Cyan"
    Write-Color "  rma --help              # Show all commands" "Cyan"
    Write-Color ""
    Write-Color "Documentation: https://github.com/$repo" "White"
    Write-Color ""
}

# Main
Show-Banner

$platform = Get-Platform
Write-Color "[INFO] Detected platform: $platform" "Blue"

$version = Get-LatestVersion
Install-Binary -Platform $platform -Version $version
Add-ToPath
Test-Installation
Show-Usage
