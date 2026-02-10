#!/usr/bin/env node

/**
 * Qryon wrapper script for npm
 * Spawns the native Qryon binary with all arguments passed through
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const BINARY_NAME = process.platform === 'win32' ? 'qryon.exe' : 'qryon';
const binaryPath = path.join(__dirname, BINARY_NAME);

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('Error: Qryon binary not found.');
  console.error('Try reinstalling: npm install -g qryon');
  console.error('Or install directly: cargo install rma-cli');
  process.exit(1);
}

// Spawn the binary with all arguments
const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: true,
});

child.on('error', (err) => {
  console.error(`Failed to start Qryon: ${err.message}`);
  process.exit(1);
});

child.on('close', (code) => {
  process.exit(code || 0);
});
