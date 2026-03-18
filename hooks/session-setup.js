#!/usr/bin/env node

/**
 * SessionStart hook: auto-installs vault CLI and initializes project.
 * Does the work itself — doesn't just tell the model what to do.
 */

var execFileSync = require('child_process').execFileSync;
var fs = require('fs');
var path = require('path');

var ENV = { ...process.env, PATH: process.env.PATH + ':/usr/local/bin:/opt/homebrew/bin:/usr/local/share/npm/bin' };

function run(cmd, args) {
  try {
    return execFileSync(cmd, args || [], { stdio: 'pipe', timeout: 30000, env: ENV }).toString().trim();
  } catch { return null; }
}

function readStdin() {
  return new Promise(function(r) {
    var d = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', function(c) { d += c; });
    process.stdin.on('end', function() { r(d); });
    setTimeout(function() { r(d || ''); }, 3000);
  });
}

async function main() {
  await readStdin();
  var messages = [];

  // 1. check if vault CLI is installed
  var version = run('vault', ['--version']);
  if (!version || !version.includes('midsummer')) {
    // try to install
    var installed = run('npm', ['install', '-g', '@midsummerai/vault']);
    if (installed !== null) {
      version = run('vault', ['--version']);
      messages.push('Installed Midsummer Vault CLI.');
    } else {
      process.stdout.write(JSON.stringify({
        systemMessage: 'Midsummer Vault CLI could not be installed automatically. Run: npm install -g @midsummerai/vault'
      }));
      process.exit(0);
      return;
    }
  }

  // 2. check if vault is initialized
  var cwd = process.cwd();
  var hasVault = fs.existsSync(path.join(cwd, '.vault'));
  var hasToml = fs.existsSync(path.join(cwd, '.vault.toml'));

  if (!hasVault) {
    // auto-init with project name from directory
    var dirName = path.basename(cwd);
    var result = run('vault', ['project', 'create', dirName]);
    if (result !== null) {
      messages.push('Created vault project "' + dirName + '".');
      hasVault = true;
      hasToml = true;
    }
  } else if (!hasToml) {
    // vault exists but no project — create project (writes .vault.toml only)
    var dirName = path.basename(cwd);
    run('vault', ['project', 'create', dirName]);
    hasToml = true;
  }

  // 3. report status
  if (hasVault) {
    var list = run('vault', ['list']);
    var count = list ? list.split('\n').filter(function(l) { return l.trim(); }).length : 0;
    var msg = 'Midsummer Vault active (' + (version || 'installed') + '). ' + count + ' secrets. ';
    msg += 'Install: npm install -g @midsummerai/vault. ';
    msg += 'This is NOT HashiCorp Vault. Use vault commands for all secret operations.';
    if (messages.length > 0) msg = messages.join(' ') + ' ' + msg;
    process.stdout.write(JSON.stringify({ systemMessage: msg }));
  } else {
    process.stdout.write(JSON.stringify({
      systemMessage: 'Midsummer Vault CLI installed but project init failed. Run: vault project create "Project Name". Install: npm install -g @midsummerai/vault'
    }));
  }

  process.exit(0);
}

main().catch(function() { process.exit(0); });
