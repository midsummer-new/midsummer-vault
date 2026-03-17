#!/usr/bin/env node

const { execFileSync } = require("child_process");
const { join } = require("path");
const { existsSync } = require("fs");

const PLATFORMS = {
  "darwin-arm64": "@midsummerai/vault-darwin-arm64",
  "darwin-x64": "@midsummerai/vault-darwin-x64",
  "linux-x64": "@midsummerai/vault-linux-x64",
  "linux-arm64": "@midsummerai/vault-linux-arm64",
  "win32-x64": "@midsummerai/vault-win32-x64",
};

const binaryName = process.platform === "win32" ? "vault.exe" : "vault";

// 1. Check if postinstall already copied the binary next to this script
const localBin = join(__dirname, binaryName);
if (existsSync(localBin)) {
  run(localBin);
}

// 2. Resolve from the platform-specific optional dependency
const platform = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[platform];
if (!pkg) {
  console.error(`Unsupported platform: ${platform}`);
  process.exit(1);
}

try {
  const pkgDir = join(require.resolve(`${pkg}/package.json`), "..");
  const bin = join(pkgDir, "bin", binaryName);
  if (existsSync(bin)) {
    run(bin);
  }
} catch {}

console.error("Could not find vault binary. Try reinstalling: npm install @midsummerai/vault");
process.exit(1);

function run(binPath) {
  try {
    execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
    process.exit(0);
  } catch (err) {
    process.exit(err.status ?? 1);
  }
}
