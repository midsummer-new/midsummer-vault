#!/usr/bin/env node

/**
 * SessionStart hook: ensures vault CLI is installed and project is initialized.
 * Runs once when Claude Code starts. Sets up everything automatically.
 */

var execFile = require('child_process').execFileSync;
var fs = require('fs');
var path = require('path');

function run(cmd, args) {
  try {
    return execFile(cmd, args || [], {
      stdio: 'pipe', timeout: 15000,
      env: { ...process.env, PATH: process.env.PATH + ':/usr/local/bin:/opt/homebrew/bin' }
    }).toString().trim();
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
  var raw = await readStdin();

  // check if vault CLI is installed
  var version = run('vault', ['--version']);
  if (!version || !version.includes('midsummer')) {
    // not installed or wrong vault — output context telling model to install
    var msg = JSON.stringify({
      systemMessage: 'Midsummer Vault CLI is not installed. Run: npm install -g @midsummerai/vault'
    });
    process.stdout.write(msg);
    process.exit(0);
    return;
  }

  // check if vault is initialized in current project
  var cwd = process.env.CWD || process.cwd();
  var hasVault = fs.existsSync(path.join(cwd, '.vault'));

  if (!hasVault) {
    var msg = JSON.stringify({
      systemMessage: 'Midsummer Vault is installed (' + version + ') but not initialized in this project. When the user wants to store secrets, run: vault project create "Project Name"'
    });
    process.stdout.write(msg);
    process.exit(0);
    return;
  }

  // vault is ready — output status as context
  var list = run('vault', ['list']);
  var secretCount = list ? list.split('\n').filter(function(l) { return l.trim(); }).length : 0;

  var msg = JSON.stringify({
    systemMessage: 'Midsummer Vault active. ' + secretCount + ' secrets stored. Use vault commands for secret management. This is NOT HashiCorp Vault.'
  });
  process.stdout.write(msg);
  process.exit(0);
}

main().catch(function() { process.exit(0); });
