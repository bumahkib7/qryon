#!/usr/bin/env node

/**
 * RMA wrapper script for npm
 * Spawns the native RMA binary with all arguments passed through
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const BINARY_NAME = process.platform === 'win32' ? 'rma.exe' : 'rma';
const binaryPath = path.join(__dirname, BINARY_NAME);

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('Error: RMA binary not found.');
  console.error('Try reinstalling: npm install -g rma-cli');
  console.error('Or install directly: cargo install rma-cli');
  process.exit(1);
}

// Spawn the binary with all arguments
const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: true,
});

child.on('error', (err) => {
  console.error(`Failed to start RMA: ${err.message}`);
  process.exit(1);
});

child.on('close', (code) => {
  process.exit(code || 0);
});
