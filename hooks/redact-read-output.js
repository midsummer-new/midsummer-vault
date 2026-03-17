#!/usr/bin/env node

/**
 * PostToolUse hook for Read: 5-layer secret detection and redaction.
 *
 * Layer 0: Known vault secrets (exact match from vault CLI)
 * Layer 1: Known service prefixes (sk_live_, AKIA, ghp_, etc.)
 * Layer 2: Structural patterns (JWTs, connection strings, private keys)
 * Layer 3: Shannon entropy detection (high-entropy strings)
 * Layer 4: Keyword proximity boost (lowers entropy threshold near secret keywords)
 *
 * Redacts with [vault:NAME] for layer 0, [DETECTED:TYPE] for layers 1-4.
 * Does NOT store detected secrets — read hook is output-only.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');

const LOG = '/tmp/vault-hook-debug.log';

function log(msg) {
  try { fs.appendFileSync(LOG, '[' + new Date().toISOString() + '] [read] ' + msg + '\n'); } catch {}
}

// ─── Stdin ──────────────────────────────────────────────────────────────────

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
  });
}

// ─── Layer 0: Known Vault Secrets ───────────────────────────────────────────

function loadSecrets() {
  const secrets = new Map();

  try {
    const namesRaw = execFileSync('vault', ['list'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000,
      encoding: 'utf8',
    });

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

        if (value.length >= 4) {
          secrets.set(name, value);
        }
      } catch {
        // individual secret fetch failed, skip
      }
    }
  } catch {
    // vault CLI not found or errored
  }

  return secrets;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function secretVariants(value) {
  const variants = [value];

  try {
    const b64 = Buffer.from(value, 'utf8').toString('base64');
    if (b64 !== value) variants.push(b64);
  } catch {}

  try {
    const urlEncoded = encodeURIComponent(value);
    if (urlEncoded !== value) variants.push(urlEncoded);
  } catch {}

  return variants;
}

function redactKnownSecrets(text, secrets) {
  if (!text || typeof text !== 'string') return text;

  let modified = text;
  for (const [name, value] of secrets) {
    const variants = secretVariants(value);
    for (const variant of variants) {
      if (variant.length < 4) continue;
      const pattern = new RegExp(escapeRegex(variant), 'g');
      modified = modified.replace(pattern, '[vault:' + name + ']');
    }
  }
  return modified;
}

// ─── Layer 1: Known Service Prefixes ────────────────────────────────────────

const KNOWN_PREFIXES = [
  [/\bsk_live_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_KEY'],
  [/\bsk_test_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_TEST_KEY'],
  [/\bpk_live_[a-zA-Z0-9]{10,99}\b/g, 'STRIPE_PUB_KEY'],
  [/\bsk-ant-api03-[a-zA-Z0-9_-]{80,}\b/g, 'ANTHROPIC_KEY'],
  [/\bsk-proj-[a-zA-Z0-9_-]{40,}\b/g, 'OPENAI_KEY'],
  [/\bsk-[a-zA-Z0-9]{40,50}\b/g, 'OPENAI_LEGACY_KEY'],
  [/\bAKIA[A-Z2-7]{16}\b/g, 'AWS_ACCESS_KEY'],
  [/\bAIza[a-zA-Z0-9_-]{35}\b/g, 'GOOGLE_API_KEY'],
  [/\bghp_[a-zA-Z0-9]{36,}\b/g, 'GITHUB_PAT'],
  [/\bgho_[a-zA-Z0-9]{36,}\b/g, 'GITHUB_OAUTH'],
  [/\bgithub_pat_[a-zA-Z0-9_]{80,}\b/g, 'GITHUB_FINE_PAT'],
  [/\bglpat-[a-zA-Z0-9_-]{20,}\b/g, 'GITLAB_PAT'],
  [/\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g, 'SLACK_BOT_TOKEN'],
  [/\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b/g, 'SLACK_USER_TOKEN'],
  [/\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g, 'SENDGRID_KEY'],
  [/\bnpm_[a-zA-Z0-9]{36,}\b/g, 'NPM_TOKEN'],
  [/\bvercel_[a-zA-Z0-9]{24,}\b/g, 'VERCEL_TOKEN'],
  [/\bsntrys_[a-zA-Z0-9+/]{50,}\b/g, 'SENTRY_TOKEN'],
  [/\bhvs\.[a-zA-Z0-9_-]{24,}\b/g, 'HASHICORP_TOKEN'],
  [/\bshpat_[a-fA-F0-9]{32}\b/g, 'SHOPIFY_PAT'],
  [/\bre_[a-zA-Z0-9]{30,}\b/g, 'RESEND_KEY'],
];

// ─── Layer 2: Structural Patterns ───────────────────────────────────────────

const STRUCTURAL = [
  [/\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.[a-zA-Z0-9/\\_-]{10,}=*)\b/g, 'JWT'],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{20,}?-----END/g, 'PRIVATE_KEY'],
  [/\b((?:postgres|mysql|mongodb|redis|amqp|mssql)(?:ql)?:\/\/[^\s'"]{10,})\b/g, 'CONNECTION_STRING'],
];

// ─── Layer 3+4: Entropy + Keyword Proximity ─────────────────────────────────

const B64 = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
const HEX = new Set('0123456789abcdefABCDEF');
const THRESHOLDS = { hex: 3.0, base64: 4.5, mixed: 4.0 };
const ENTROPY_RE = /(?<![a-zA-Z0-9_/+=\-])([a-zA-Z0-9_/+=\-]{30,})(?![a-zA-Z0-9_/+=\-])/g;
const KW_RE = /\b(password|passwd|pwd|secret|token|key|apikey|api_key|credential|auth|private|access_key|secret_key|bearer)\b/gi;

// skip patterns: code constructs that look high-entropy but aren't secrets
const SKIP_PATTERNS = [
  /^https?:/,                     // URLs
  /^[a-z][a-zA-Z]*\(/,           // function calls
  /^\$\{\{/,                     // template expressions
  /^(your|changeme|placeholder|example|xxxxxxx|test)/i, // placeholders
  /^\d+$/,                        // pure numbers
  /^(.)\1+$/,                     // repeated chars
  /^[a-z]+$/,                     // all lowercase (English words, variable names)
  /^[A-Z_]+$/,                    // all uppercase/underscore (constants)
  /^(import|export|require|from|function|const|let|var|class|interface|type|extends|implements)\b/, // JS keywords
  /^node_modules\//,             // node module paths
  /^@[a-z]/,                     // npm scoped packages
  /^[a-z]+(-[a-z]+){2,}/,       // kebab-case identifiers (CSS classes, HTML attrs)
  /^[a-z][a-zA-Z]+\.[a-z][a-zA-Z]+/, // dotted identifiers (object.property)
];

function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let h = 0;
  const n = s.length;
  for (const v of Object.values(f)) {
    const p = v / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function charset(s) {
  let b = 0, h = 0;
  for (const c of s) {
    if (B64.has(c)) b++;
    if (HEX.has(c)) h++;
  }
  if (h / s.length > 0.95) return 'hex';
  if (b / s.length > 0.95) return 'base64';
  return 'mixed';
}

function looksSecret(s) {
  if (s.length < 30) return false;

  // skip code-like strings
  for (const pat of SKIP_PATTERNS) {
    if (pat.test(s)) return false;
  }

  // skip path-like strings (multiple slashes)
  if (s.includes('/') && s.split('/').length > 2) return false;

  const e = entropy(s);
  const t = THRESHOLDS[charset(s)] || 4.0;
  if (e < t) return false;

  // require at least 2 of: uppercase, lowercase, digits
  const u = /[A-Z]/.test(s), l = /[a-z]/.test(s), d = /[0-9]/.test(s);
  return [u, l, d].filter(Boolean).length >= 2;
}

// ─── Multi-layer Detection ──────────────────────────────────────────────────

function detectAndRedact(text) {
  if (!text || typeof text !== 'string') return { text: text, count: 0 };

  let modified = text;
  let count = 0;
  const detections = [];

  // layer 1: known prefixes
  for (const [re, name] of KNOWN_PREFIXES) {
    const pat = new RegExp(re.source, re.flags);
    let m;
    while ((m = pat.exec(modified)) !== null) {
      if (m[0].length < 10) continue;
      // skip if already redacted
      if (modified.substring(Math.max(0, m.index - 10), m.index).includes('[vault:') ||
          modified.substring(Math.max(0, m.index - 12), m.index).includes('[DETECTED:')) continue;
      modified = modified.replace(m[0], '[DETECTED:' + name + ']');
      detections.push(name);
      count++;
      pat.lastIndex = 0; // reset after replacement
    }
  }

  // layer 2: structural
  for (const [re, name] of STRUCTURAL) {
    const pat = new RegExp(re.source, re.flags);
    let m;
    while ((m = pat.exec(modified)) !== null) {
      const v = m[1] || m[0];
      if (v.length < 10) continue;
      if (v.includes('[vault:') || v.includes('[DETECTED:')) continue;
      modified = modified.replace(v, '[DETECTED:' + name + ']');
      detections.push(name);
      count++;
      pat.lastIndex = 0;
    }
  }

  // layer 3+4: entropy + keyword proximity
  ENTROPY_RE.lastIndex = 0;
  let em;
  while ((em = ENTROPY_RE.exec(modified)) !== null) {
    const candidate = em[1];
    if (candidate.includes('[vault:') || candidate.includes('[DETECTED:')) continue;
    if (!looksSecret(candidate)) continue;

    // layer 4: check keyword proximity (80 chars window)
    const windowStart = Math.max(0, em.index - 80);
    const windowEnd = Math.min(modified.length, em.index + candidate.length + 80);
    const window = modified.substring(windowStart, windowEnd);
    KW_RE.lastIndex = 0;
    const nearKeyword = KW_RE.test(window);

    const label = nearKeyword ? 'HIGH_ENTROPY_SECRET' : 'HIGH_ENTROPY';
    modified = modified.replace(candidate, '[DETECTED:' + label + ']');
    detections.push(label);
    count++;
    ENTROPY_RE.lastIndex = 0; // reset after replacement
  }

  if (count > 0) {
    log('detected ' + count + ' unknown secrets: ' + detections.join(', '));
  }

  return { text: modified, count: count };
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

  // layer 0: known vault secrets
  const secrets = loadSecrets();
  let changed = false;

  // format 1: { output: { stdout, stderr } }
  if (input.output && typeof input.output === 'object') {
    if (typeof input.output.stdout === 'string') {
      const redacted = redactKnownSecrets(input.output.stdout, secrets);
      if (redacted !== input.output.stdout) {
        input.output.stdout = redacted;
        changed = true;
      }
    }
    if (typeof input.output.stderr === 'string') {
      const redacted = redactKnownSecrets(input.output.stderr, secrets);
      if (redacted !== input.output.stderr) {
        input.output.stderr = redacted;
        changed = true;
      }
    }
  }

  // format 2: { result: "..." }
  if (typeof input.result === 'string') {
    const redacted = redactKnownSecrets(input.result, secrets);
    if (redacted !== input.result) {
      input.result = redacted;
      changed = true;
    }
  }

  // layers 1-4: unknown secret detection on the (already vault-redacted) text
  if (input.output && typeof input.output === 'object') {
    if (typeof input.output.stdout === 'string') {
      const result = detectAndRedact(input.output.stdout);
      if (result.count > 0) {
        input.output.stdout = result.text;
        changed = true;
      }
    }
    if (typeof input.output.stderr === 'string') {
      const result = detectAndRedact(input.output.stderr);
      if (result.count > 0) {
        input.output.stderr = result.text;
        changed = true;
      }
    }
  }

  if (typeof input.result === 'string') {
    const result = detectAndRedact(input.result);
    if (result.count > 0) {
      input.result = result.text;
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
