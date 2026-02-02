#!/usr/bin/env node

/**
 * RMA npm package installer
 * Downloads the pre-built binary for the current platform on npm install
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const os = require('os');

const REPO = 'bumahkib7/rust-monorepo-analyzer';
const BINARY_NAME = process.platform === 'win32' ? 'rma.exe' : 'rma';
const BIN_DIR = path.join(__dirname, 'bin');

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();

  const platforms = {
    'darwin-x64': 'x86_64-apple-darwin',
    'darwin-arm64': 'aarch64-apple-darwin',
    'linux-x64': 'x86_64-unknown-linux-gnu',
    'linux-arm64': 'aarch64-unknown-linux-gnu',
    'win32-x64': 'x86_64-pc-windows-msvc',
  };

  const key = `${platform}-${arch}`;
  const target = platforms[key];

  if (!target) {
    throw new Error(`Unsupported platform: ${key}. Supported: ${Object.keys(platforms).join(', ')}`);
  }

  return { target, ext: platform === 'win32' ? 'zip' : 'tar.gz' };
}

function getVersion() {
  const packageJson = require('./package.json');
  return packageJson.version;
}

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;

    client.get(url, { headers: { 'User-Agent': 'rma-npm-installer' } }, (response) => {
      // Handle redirects
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        return downloadFile(response.headers.location).then(resolve).catch(reject);
      }

      if (response.statusCode !== 200) {
        reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
        return;
      }

      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks)));
      response.on('error', reject);
    }).on('error', reject);
  });
}

function extractTarGz(buffer, destDir) {
  // Safe extraction using execFileSync with explicit arguments (no shell interpolation)
  const tmpFile = path.join(os.tmpdir(), `rma-${Date.now()}.tar.gz`);
  fs.writeFileSync(tmpFile, buffer);

  try {
    execFileSync('tar', ['-xzf', tmpFile, '-C', destDir], { stdio: 'pipe' });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  const tmpFile = path.join(os.tmpdir(), `rma-${Date.now()}.zip`);
  fs.writeFileSync(tmpFile, buffer);

  try {
    if (process.platform === 'win32') {
      execFileSync('powershell', [
        '-command',
        `Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}'`
      ], { stdio: 'pipe' });
    } else {
      execFileSync('unzip', ['-o', tmpFile, '-d', destDir], { stdio: 'pipe' });
    }
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function install() {
  console.log('Installing RMA binary...');

  const { target, ext } = getPlatform();
  const version = getVersion();

  console.log(`  Platform: ${target}`);
  console.log(`  Version: v${version}`);

  const downloadUrl = `https://github.com/${REPO}/releases/download/v${version}/rma-${target}.${ext}`;
  console.log(`  Downloading from: ${downloadUrl}`);

  // Ensure bin directory exists
  if (!fs.existsSync(BIN_DIR)) {
    fs.mkdirSync(BIN_DIR, { recursive: true });
  }

  try {
    const buffer = await downloadFile(downloadUrl);
    console.log(`  Downloaded ${(buffer.length / 1024 / 1024).toFixed(2)} MB`);

    if (ext === 'zip') {
      extractZip(buffer, BIN_DIR);
    } else {
      extractTarGz(buffer, BIN_DIR);
    }

    const binaryPath = path.join(BIN_DIR, BINARY_NAME);

    // Make executable on Unix
    if (process.platform !== 'win32') {
      fs.chmodSync(binaryPath, 0o755);
    }

    // Verify installation
    if (fs.existsSync(binaryPath)) {
      console.log(`  Binary installed: ${binaryPath}`);
      console.log('  RMA installed successfully!');
    } else {
      throw new Error(`Binary not found at ${binaryPath}`);
    }
  } catch (error) {
    console.error(`\nFailed to download pre-built binary: ${error.message}`);
    console.error('\nAlternative installation methods:');
    console.error('  1. cargo install rma-cli');
    console.error('  2. curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash');
    console.error('  3. brew install bumahkib7/tap/rma (macOS)');
    process.exit(1);
  }
}

install();
