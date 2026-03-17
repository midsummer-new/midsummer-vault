#!/usr/bin/env node

const { existsSync, mkdirSync, copyFileSync, chmodSync } = require("fs");
const { join } = require("path");

const PLATFORMS = {
  "darwin-arm64": "@midsummerai/vault-darwin-arm64",
  "darwin-x64": "@midsummerai/vault-darwin-x64",
  "linux-x64": "@midsummerai/vault-linux-x64",
  "linux-arm64": "@midsummerai/vault-linux-arm64",
  "win32-x64": "@midsummerai/vault-win32-x64",
};

const platform = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[platform];

if (!pkg) {
  console.error(`Unsupported platform: ${platform}`);
  process.exit(1);
}

try {
  const binaryName = process.platform === "win32" ? "vault.exe" : "vault";
  const sourcePath = join(
    require.resolve(`${pkg}/package.json`),
    "..",
    "bin",
    binaryName
  );

  if (!existsSync(sourcePath)) {
    console.error(`Binary not found: ${sourcePath}`);
    process.exit(1);
  }

  const binDir = join(__dirname, "bin");
  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: true });
  }

  const destPath = join(binDir, binaryName);
  copyFileSync(sourcePath, destPath);
  chmodSync(destPath, 0o755);
} catch (err) {
  console.error(`Failed to install vault binary: ${err.message}`);
  process.exit(1);
}
