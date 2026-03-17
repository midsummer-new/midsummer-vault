#!/usr/bin/env node

/**
 * PostToolUse hook for Read: scans file content for known vault secrets
 * and replaces them with [vault:NAME] references before the model sees them.
 *
 * Also catches base64-encoded and URL-encoded forms of each secret.
 * If vault CLI is missing or uninitialized, silently passes through.
 */

const { execFileSync } = require('child_process');

// ─── Helpers ────────────────────────────────────────────────────────────────

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

/**
 * Load all secret name/value pairs from the local vault.
 * Returns Map<name, value> or empty map on failure.
 */
function loadSecrets() {
  const secrets = new Map();

  try {
    const namesRaw = execFileSync('vault', ['list'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000,
      encoding: 'utf8',
    });

    // vault list outputs one name per line, skip empty lines and header noise
    const names = namesRaw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith('─') && !l.startsWith('Name'));

    for (const name of names) {
      try {
        const value = execFileSync('vault', ['get', name], {
          stdio: ['pipe', 'pipe', 'pipe'],
          timeout: 5000,
          encoding: 'utf8',
        }).trim();

        // skip empty or very short values (avoid false positives)
        if (value.length >= 4) {
          secrets.set(name, value);
        }
      } catch {
        // individual secret fetch failed, skip it
      }
    }
  } catch {
    // vault CLI not found, not initialized, or errored — return empty
  }

  return secrets;
}

/**
 * Escape a string for use inside a RegExp.
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Build variant forms of a secret value for redaction:
 *   - raw value
 *   - base64-encoded
 *   - URL-encoded (percent-encoding)
 */
function secretVariants(value) {
  const variants = [value];

  // base64-encoded form
  try {
    const b64 = Buffer.from(value, 'utf8').toString('base64');
    if (b64 !== value) variants.push(b64);
  } catch {
    // ignore encoding errors
  }

  // URL-encoded form
  try {
    const urlEncoded = encodeURIComponent(value);
    if (urlEncoded !== value) variants.push(urlEncoded);
  } catch {
    // ignore encoding errors
  }

  return variants;
}

/**
 * Replace all occurrences of secret values (and their encoded variants) in text.
 */
function redactSecrets(text, secrets) {
  if (!text || typeof text !== 'string') return text;

  let modified = text;
  for (const [name, value] of secrets) {
    const variants = secretVariants(value);
    for (const variant of variants) {
      if (variant.length < 4) continue; // avoid replacing trivially short strings
      const pattern = new RegExp(escapeRegex(variant), 'g');
      modified = modified.replace(pattern, `[vault:${name}]`);
    }
  }
  return modified;
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const raw = await readStdin();
  let input;
  try {
    input = JSON.parse(raw || '{}');
  } catch {
    // unparseable input, pass through
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  // load secrets once at start
  const secrets = loadSecrets();
  if (secrets.size === 0) {
    // no secrets to redact, pass through
    process.stdout.write(raw);
    process.exit(0);
    return;
  }

  let changed = false;

  // format 1: { output: { stdout, stderr } }
  if (input.output && typeof input.output === 'object') {
    if (typeof input.output.stdout === 'string') {
      const redacted = redactSecrets(input.output.stdout, secrets);
      if (redacted !== input.output.stdout) {
        input.output.stdout = redacted;
        changed = true;
      }
    }
    if (typeof input.output.stderr === 'string') {
      const redacted = redactSecrets(input.output.stderr, secrets);
      if (redacted !== input.output.stderr) {
        input.output.stderr = redacted;
        changed = true;
      }
    }
  }

  // format 2: { result: "..." }
  if (typeof input.result === 'string') {
    const redacted = redactSecrets(input.result, secrets);
    if (redacted !== input.result) {
      input.result = redacted;
      changed = true;
    }
  }

  if (changed) {
    process.stdout.write(JSON.stringify(input));
  } else {
    process.stdout.write(raw);
  }

  process.exit(0);
}

main().catch(() => process.exit(0));
